#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nginx 请求频率自动化分析报告生成器
"""

import re
import gzip
import json
import math
import statistics
import html
import argparse
import os
import sys
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Set, Any, Optional, Iterator
from dataclasses import dataclass, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

# ==================== 配置常量 ====================

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+)'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

DEFAULT_SENSITIVE_PATHS = {
    '/login', '/register', '/reset', '/forgot', '/password',
    '/admin', '/manage', '/console', '/debug', '/dashboard',
    '/api/admin', '/api/auth', '/export', '/backup', '/upload',
    '/.env', '/.git', '/config', '/phpMyAdmin', '/phpmyadmin',
    '/wp-login.php', '/wp-admin', '/actuator', '/swagger'
}

TIME_WINDOWS = {
    '10m': 600,
    '30m': 1800,
    '1h': 3600,
    '24h': 86400
}

# 优化: 使用有限大小的内存缓存
MAX_CACHE_SIZE = 10000


# ==================== 数据类 ====================

@dataclass
class LogEntry:
    """单条日志记录"""
    ip: str
    path: str
    status: str
    timestamp: datetime
    method: str = ""


@dataclass
class RateStats:
    """频率统计数据"""
    avg_qps: float
    max_qps: float
    p95_qps: float
    p99_qps: float
    total_requests: int
    suggest_rps: int
    human_readable: str
    volatility: float = 0.0


@dataclass
class PathAnalysis:
    """路径分析结果"""
    path: str
    stats: RateStats
    is_sensitive: bool
    window_suggestions: Dict[str, int]
    window_human: Dict[str, str]
    unique_ips: int = 0


@dataclass
class IPAnalysis:
    """IP分析结果"""
    ip: str
    stats: RateStats
    unique_paths: int = 0
    error_rate: float = 0.0


@dataclass
class RiskItem:
    """风险项"""
    ip: str
    path: str
    risk_score: float
    stats: RateStats
    reason: str = ""


# ==================== 工具函数 ====================

class ProgressTracker:
    """进度跟踪器"""

    def __init__(self, total: int, desc: str = "Processing"):
        self.total = total
        self.current = 0
        self.desc = desc
        self.last_percent = -1

    def update(self, amount: int = 1):
        self.current += amount
        if self.total > 0:
            percent = int(100 * self.current / self.total)
            if percent != self.last_percent and percent % 5 == 0:
                print(f"[{self.desc}] {percent}% ({self.current:,}/{self.total:,})",
                      file=sys.stderr, flush=True)
                self.last_percent = percent


class TimeWindowCache:
    """时间窗口聚合缓存"""

    def __init__(self, max_size: int = MAX_CACHE_SIZE):
        self.cache: Dict[Tuple[str, int], List[float]] = {}
        self.max_size = max_size

    def get(self, key: str, window: int, per_sec: Counter) -> List[float]:
        cache_key = (key, window)
        if cache_key in self.cache:
            return self.cache[cache_key]

        result = aggregate_requests_by_window(per_sec, window)

        if len(self.cache) < self.max_size:
            self.cache[cache_key] = result

        return result


def parse_log_time(time_str: str) -> Optional[datetime]:
    """解析日志时间，增强错误处理"""
    try:
        return datetime.strptime(time_str, TIME_FORMAT)
    except ValueError:
        # 处理时区格式问题
        if len(time_str) >= 5 and time_str[-5] not in ('+', '-'):
            try:
                fixed = time_str[:-5] + ' ' + time_str[-5:]
                return datetime.strptime(fixed, TIME_FORMAT)
            except ValueError:
                pass
    return None


def open_log_file(filepath: str):
    """智能打开日志文件"""
    if filepath.endswith('.gz'):
        return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
    return open(filepath, 'r', encoding='utf-8', errors='ignore')


def compute_percentile(data: List[float], p: float) -> float:
    """计算百分位数"""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = int(len(sorted_data) * p / 100)
    return sorted_data[min(index, len(sorted_data) - 1)]


def calculate_adaptive_threshold(
        data: List[float],
        method: str = "percentile",
        sensitivity: float = 1.0
) -> float:
    """自适应阈值计算"""
    if not data:
        return 1.0

    if method == "percentile":
        return max(1.0, compute_percentile(data, 95) * sensitivity)

    elif method == "mean_std":
        if len(data) < 2:
            return float(data[0]) if data else 1.0
        mean_val = statistics.mean(data)
        std_dev = statistics.stdev(data) if len(data) > 1 else 0
        return max(1.0, (mean_val + 2 * std_dev) * sensitivity)

    elif method == "iqr":
        if len(data) < 4:
            return max(1.0, max(data) * sensitivity) if data else 1.0
        q1 = compute_percentile(data, 25)
        q3 = compute_percentile(data, 75)
        iqr = q3 - q1
        upper_fence = q3 + 1.5 * iqr
        return max(1.0, upper_fence * sensitivity)

    elif method == "mad":  # 新增: Median Absolute Deviation
        if len(data) < 2:
            return float(data[0]) if data else 1.0
        median = statistics.median(data)
        mad = statistics.median([abs(x - median) for x in data])
        return max(1.0, (median + 3 * mad) * sensitivity)

    return max(1.0, compute_percentile(data, 95) * sensitivity)


def aggregate_requests_by_window(
        per_sec_counter: Counter,
        window_seconds: int
) -> List[float]:
    """将请求聚合到时间窗口"""
    if not per_sec_counter:
        return []

    time_points = sorted(
        (datetime.strptime(k, "%Y-%m-%d %H:%M:%S"), v)
        for k, v in per_sec_counter.items()
    )

    if not time_points:
        return []

    start_time = time_points[0][0]
    end_time = time_points[-1][0]
    current = start_time
    window_qps = []
    i = 0

    while current <= end_time:
        window_end = current + timedelta(seconds=window_seconds)
        total_in_window = 0

        while i < len(time_points) and time_points[i][0] < window_end:
            total_in_window += time_points[i][1]
            i += 1

        avg_qps = total_in_window / window_seconds if window_seconds > 0 else 0
        window_qps.append(avg_qps)
        current = window_end

    return window_qps


def rps_to_human_readable(rate_rps: float, max_denom: int = 3600) -> str:
    """将 r/s 转换为人类可读格式"""
    if rate_rps <= 0:
        return "禁止访问"

    candidates = [
        (10, "10秒"),
        (30, "30秒"),
        (60, "分钟"),
        (300, "5分钟"),
        (600, "10分钟"),
        (1800, "30分钟"),
        (3600, "小时")
    ]

    best_desc = f"{rate_rps:.1f} 次/秒"
    min_error = float('inf')

    for seconds, name in candidates:
        if seconds > max_denom:
            continue
        total_requests = rate_rps * seconds
        rounded = math.ceil(total_requests)
        actual_rps = rounded / seconds
        error = abs(actual_rps - rate_rps)

        if error < min_error or (error == min_error and rounded == int(rounded)):
            min_error = error
            if name in ("分钟", "小时"):
                best_desc = f"每{name}最多{rounded}次"
            else:
                best_desc = f"每{name}最多{rounded}次"

    return best_desc


def detect_anomalies(qps_list: List[float], threshold: float = 3.0) -> List[int]:
    """检测异常值索引"""
    if len(qps_list) < 10:
        return []

    median = statistics.median(qps_list)
    mad = statistics.median([abs(x - median) for x in qps_list])

    if mad == 0:
        return []

    anomalies = []
    for i, qps in enumerate(qps_list):
        z_score = abs(qps - median) / (mad * 1.4826)  # 1.4826 是常数转换因子
        if z_score > threshold:
            anomalies.append(i)

    return anomalies


# ==================== 日志解析 ====================

class LogParser:
    """优化的日志解析器"""

    def __init__(self,
                 time_window: Optional[Tuple[datetime, datetime]] = None,
                 target_ip: Optional[str] = None,
                 target_path: Optional[str] = None):
        self.time_window = time_window
        self.target_ip = target_ip
        self.target_path = target_path
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'filtered_lines': 0,
            'errors': 0
        }

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """解析单行日志"""
        self.stats['total_lines'] += 1

        match = LOG_PATTERN.search(line)
        if not match:
            return None

        log_time = parse_log_time(match.group('time'))
        if not log_time:
            self.stats['errors'] += 1
            return None

        # 时间窗口过滤
        if self.time_window:
            start, end = self.time_window
            if log_time < start or log_time > end:
                return None

        ip = match.group('ip')
        raw_path = match.group('path')
        clean_path = raw_path.split('?')[0].rstrip('/')
        status = match.group('status')
        method = match.group('method')

        # IP/路径过滤
        if self.target_ip and ip != self.target_ip:
            return None
        if self.target_path and clean_path != self.target_path:
            return None

        self.stats['parsed_lines'] += 1

        return LogEntry(
            ip=ip,
            path=clean_path,
            status=status,
            timestamp=log_time,
            method=method
        )

    def parse_file(self, filepath: str) -> Iterator[LogEntry]:
        """流式解析文件"""
        try:
            with open_log_file(filepath) as f:
                for line in f:
                    entry = self.parse_line(line)
                    if entry:
                        yield entry
        except Exception as e:
            print(f"[ERROR] 读取 {filepath} 失败: {e}", file=sys.stderr)
            self.stats['errors'] += 1


class DataAggregator:
    """数据聚合器"""

    def __init__(self, sensitive_paths: Set[str]):
        self.sensitive_paths = sensitive_paths
        self.global_per_sec = Counter()
        self.path_per_sec = defaultdict(Counter)
        self.ip_per_sec = defaultdict(Counter)
        self.ip_path_per_sec = defaultdict(Counter)
        self.status_code_stats = Counter()
        self.ip_paths = defaultdict(set)
        self.path_ips = defaultdict(set)
        self.ip_errors = defaultdict(int)
        self.actual_start: Optional[datetime] = None
        self.actual_end: Optional[datetime] = None

    def add_entry(self, entry: LogEntry):
        """添加日志条目"""
        sec_key = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        # 更新计数器
        self.global_per_sec[sec_key] += 1
        self.path_per_sec[entry.path][sec_key] += 1
        self.ip_per_sec[entry.ip][sec_key] += 1
        self.status_code_stats[entry.status] += 1

        # 记录 IP-路径关系
        self.ip_paths[entry.ip].add(entry.path)
        self.path_ips[entry.path].add(entry.ip)

        # 错误统计
        if entry.status.startswith('4') or entry.status.startswith('5'):
            self.ip_errors[entry.ip] += 1

        # 敏感路径特殊处理
        if entry.path in self.sensitive_paths:
            self.ip_path_per_sec[(entry.ip, entry.path)][sec_key] += 1

        # 更新时间范围
        if self.actual_start is None:
            self.actual_start = self.actual_end = entry.timestamp
        else:
            if entry.timestamp < self.actual_start:
                self.actual_start = entry.timestamp
            if entry.timestamp > self.actual_end:
                self.actual_end = entry.timestamp

    def get_result(self) -> Dict[str, Any]:
        """获取聚合结果"""
        if self.actual_start is None:
            now = datetime.now()
            self.actual_start = self.actual_end = now

        return {
            'global_per_sec': self.global_per_sec,
            'path_per_sec': self.path_per_sec,
            'ip_per_sec': self.ip_per_sec,
            'ip_path_per_sec': self.ip_path_per_sec,
            'status_code_stats': self.status_code_stats,
            'ip_paths': self.ip_paths,
            'path_ips': self.path_ips,
            'ip_errors': self.ip_errors,
            'time_window': (self.actual_start, self.actual_end)
        }


def analyze_logs_optimized(
        logfiles: List[str],
        time_window: Optional[Tuple[datetime, datetime]],
        sensitive_paths: Set[str],
        target_ip: Optional[str] = None,
        target_path: Optional[str] = None,
        max_workers: int = 4
) -> Dict[str, Any]:
    """优化的日志分析（支持并发）"""

    if time_window:
        start, end = time_window
        print(f"[INFO] 分析时间窗口: {start} → {end}", file=sys.stderr)
    else:
        print("[INFO] 分析全部日志数据", file=sys.stderr)

    parser = LogParser(time_window, target_ip, target_path)
    aggregator = DataAggregator(sensitive_paths)

    # 单文件情况不使用并发
    if len(logfiles) == 1:
        for entry in parser.parse_file(logfiles[0]):
            aggregator.add_entry(entry)
    else:
        # 多文件并发处理
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(list, parser.parse_file(f)): f
                for f in logfiles
            }

            for future in as_completed(futures):
                filepath = futures[future]
                try:
                    entries = future.result()
                    for entry in entries:
                        aggregator.add_entry(entry)
                    print(f"[INFO] 完成: {filepath}", file=sys.stderr)
                except Exception as e:
                    print(f"[ERROR] {filepath}: {e}", file=sys.stderr)

    result = aggregator.get_result()
    result['stats'] = parser.stats
    result['total_processed'] = parser.stats['parsed_lines']

    print(f"[INFO] 处理完成: {result['total_processed']:,} 条有效日志", file=sys.stderr)
    return result


# ==================== 统计分析 ====================

def create_rate_stats(qps_list: List[float], sensitivity: float = 0.85) -> RateStats:
    """创建频率统计对象"""
    if not qps_list:
        return RateStats(0, 0, 0, 0, 0, 1, "每10秒最多1次")

    total = sum(qps_list)
    avg = statistics.mean(qps_list)
    max_qps = max(qps_list)
    p95 = compute_percentile(qps_list, 95)
    p99 = compute_percentile(qps_list, 99)

    # 使用多种方法计算阈值
    thresholds = [
        calculate_adaptive_threshold(qps_list, method, sensitivity)
        for method in ["percentile", "mean_std", "iqr", "mad"]
    ]
    suggest_rps = max(1, round(statistics.median(thresholds)))

    # 计算波动性
    volatility = (statistics.stdev(qps_list) / avg) if len(qps_list) > 1 and avg > 0 else 0

    return RateStats(
        avg_qps=avg,
        max_qps=max_qps,
        p95_qps=p95,
        p99_qps=p99,
        total_requests=int(total),
        suggest_rps=suggest_rps,
        human_readable=rps_to_human_readable(suggest_rps),
        volatility=volatility
    )


def analyze_global_stats(global_per_sec: Counter, cache: TimeWindowCache) -> Dict[str, Any]:
    """分析全局统计"""
    base_qps = list(global_per_sec.values())

    if not base_qps:
        fallback_stats = RateStats(0, 0, 0, 0, 0, 10, "每10秒最多10次")
        return {
            'base': fallback_stats,
            'windows': {name: fallback_stats for name in TIME_WINDOWS}
        }

    base_stats = create_rate_stats(base_qps, sensitivity=0.8)

    window_stats = {}
    for name, seconds in TIME_WINDOWS.items():
        window_qps = cache.get('global', seconds, global_per_sec)
        if window_qps:
            stats = create_rate_stats(window_qps, sensitivity=0.8)
            stats.human_readable = rps_to_human_readable(stats.suggest_rps, max_denom=seconds)
            window_stats[name] = stats
        else:
            window_stats[name] = base_stats

    return {'base': base_stats, 'windows': window_stats}


def analyze_paths(
        path_per_sec: Dict[str, Counter],
        sensitive_paths: Set[str],
        path_ips: Dict[str, Set[str]],
        cache: TimeWindowCache
) -> List[PathAnalysis]:
    """分析路径统计"""
    results = []

    for path, sec_counter in path_per_sec.items():
        qps_list = list(sec_counter.values())
        if not qps_list:
            continue

        base_stats = create_rate_stats(qps_list, sensitivity=0.85)

        # 计算各时间窗口建议
        window_suggestions = {}
        window_human = {}

        for name, seconds in TIME_WINDOWS.items():
            window_qps = cache.get(f'path_{path}', seconds, sec_counter)
            if window_qps:
                stats = create_rate_stats(window_qps, sensitivity=0.85)
                window_suggestions[name] = stats.suggest_rps
                window_human[name] = rps_to_human_readable(stats.suggest_rps, max_denom=seconds)
            else:
                window_suggestions[name] = base_stats.suggest_rps
                window_human[name] = base_stats.human_readable

        results.append(PathAnalysis(
            path=path,
            stats=base_stats,
            is_sensitive=path in sensitive_paths,
            window_suggestions=window_suggestions,
            window_human=window_human,
            unique_ips=len(path_ips.get(path, set()))
        ))

    return sorted(results, key=lambda x: x.stats.total_requests, reverse=True)


def analyze_ips(
        ip_per_sec: Dict[str, Counter],
        ip_paths: Dict[str, Set[str]],
        ip_errors: Dict[str, int]
) -> List[IPAnalysis]:
    """分析IP统计"""
    results = []

    for ip, sec_counter in ip_per_sec.items():
        qps_list = list(sec_counter.values())
        if not qps_list:
            continue

        stats = create_rate_stats(qps_list, sensitivity=0.8)
        total_req = stats.total_requests
        error_count = ip_errors.get(ip, 0)
        error_rate = (error_count / total_req * 100) if total_req > 0 else 0

        results.append(IPAnalysis(
            ip=ip,
            stats=stats,
            unique_paths=len(ip_paths.get(ip, set())),
            error_rate=error_rate
        ))

    return sorted(results, key=lambda x: x.stats.total_requests, reverse=True)


def analyze_risks(
        ip_path_per_sec: Dict[Tuple[str, str], Counter],
        ip_errors: Dict[str, int]
) -> List[RiskItem]:
    """分析风险项"""
    results = []

    for (ip, path), sec_counter in ip_path_per_sec.items():
        qps_list = list(sec_counter.values())
        if not qps_list:
            continue

        stats = create_rate_stats(qps_list, sensitivity=0.7)

        # 增强的风险评分
        base_score = (stats.max_qps * 0.5 + stats.p95_qps * 0.3 + stats.p99_qps * 0.2)
        volume_factor = math.log(stats.total_requests + 1)
        error_count = ip_errors.get(ip, 0)
        error_factor = 1 + (error_count / stats.total_requests if stats.total_requests > 0 else 0)

        risk_score = base_score * volume_factor * error_factor

        # 风险阈值
        if stats.max_qps >= 10 or stats.total_requests > 200 or risk_score > 50:
            reason = []
            if stats.max_qps >= 10:
                reason.append(f"高峰值QPS({stats.max_qps})")
            if stats.total_requests > 500:
                reason.append(f"大量请求({stats.total_requests})")
            if error_count > 50:
                reason.append(f"高错误率({error_count})")

            results.append(RiskItem(
                ip=ip,
                path=path,
                risk_score=round(risk_score, 2),
                stats=stats,
                reason=" | ".join(reason) if reason else "综合风险"
            ))

    return sorted(results, key=lambda x: x.risk_score, reverse=True)


# ==================== HTML 生成 ====================

def generate_html_report(
        start: datetime,
        end: datetime,
        total: int,
        global_result: Dict[str, Any],
        path_analyses: List[PathAnalysis],
        ip_analyses: List[IPAnalysis],
        risk_items: List[RiskItem],
        status_stats: List[Dict[str, Any]],
        nginx_conf: str,
        target_ip: Optional[str] = None,
        target_path: Optional[str] = None
) -> str:
    """生成HTML报告"""

    # 标题和过滤信息
    title_parts = ["Nginx 请求频率分析报告"]
    filter_info_html = ""

    if target_ip or target_path:
        filters = []
        if target_ip:
            filters.append(f"IP={target_ip}")
            title_parts.append(f"(IP: {target_ip})")
        if target_path:
            filters.append(f"路径={target_path}")
            title_parts.append(f"(路径: {target_path})")
        filter_info_html = f'<div class="filter-info"><p><strong>筛选条件:</strong> {" & ".join(filters)}</p></div>'

    title = " ".join(title_parts)

    # 全局统计
    base_stats = global_result['base']
    global_html = f"""
        <h2>🌍 全局请求频率 (QPS)</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{base_stats.avg_qps:.1f}</div>
                <div class="metric-label">平均 QPS</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{base_stats.max_qps:.0f}</div>
                <div class="metric-label">峰值 QPS</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{base_stats.p95_qps:.1f}</div>
                <div class="metric-label">P95 QPS</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{base_stats.volatility:.2f}</div>
                <div class="metric-label">波动性</div>
            </div>
        </div>
        <div class="recommendation">
            <p><strong>💡 建议全局限流:</strong> <code>rate={base_stats.suggest_rps}r/s</code> 
            <span class="human-readable">({html.escape(base_stats.human_readable)})</span></p>
        </div>
        <h3>⏱️ 多时间窗口限流建议</h3>
        <table class="stats-table">
            <tr><th>窗口</th><th>建议 (r/s)</th><th>可读建议</th><th>P95 QPS</th></tr>
    """

    for name in ['10m', '30m', '1h', '24h']:
        w = global_result['windows'][name]
        global_html += f"<tr><td><strong>{name}</strong></td><td>{w.suggest_rps}</td><td>{html.escape(w.human_readable)}</td><td>{w.p95_qps:.1f}</td></tr>"
    global_html += "</table>"

    # 路径统计
    sensitive = [p for p in path_analyses if p.is_sensitive]
    normal = [p for p in path_analyses if not p.is_sensitive]

    paths_html = '<h2>🚀 路径请求频率分析</h2>'

    if sensitive:
        paths_html += '<h3>⚠️ 敏感路径</h3><table class="stats-table sensitive">'
        paths_html += '<tr><th>路径</th><th>总调用</th><th>独立IP</th><th>平均QPS</th><th>P95</th><th>波动性</th><th>建议限流</th></tr>'
        for p in sensitive[:50]:
            paths_html += f"""<tr>
                <td><code>{html.escape(p.path)}</code></td>
                <td>{p.stats.total_requests:,}</td>
                <td>{p.unique_ips}</td>
                <td>{p.stats.avg_qps:.2f}</td>
                <td>{p.stats.p95_qps:.1f}</td>
                <td>{p.stats.volatility:.2f}</td>
                <td>{p.stats.suggest_rps} r/s<br><small>{html.escape(p.stats.human_readable)}</small></td>
            </tr>"""
        paths_html += '</table>'

    if normal:
        paths_html += '<h3>📊 普通路径 (Top 100)</h3><table class="stats-table">'
        paths_html += '<tr><th>路径</th><th>总调用</th><th>独立IP</th><th>平均QPS</th><th>P95</th><th>建议限流</th></tr>'
        for p in normal[:100]:
            vol_class = "high-volatility" if p.stats.volatility > 1.0 else ""
            paths_html += f"""<tr class="{vol_class}">
                <td><code>{html.escape(p.path)}</code></td>
                <td>{p.stats.total_requests:,}</td>
                <td>{p.unique_ips}</td>
                <td>{p.stats.avg_qps:.2f}</td>
                <td>{p.stats.p95_qps:.1f}</td>
                <td>{p.stats.suggest_rps} r/s</td>
            </tr>"""
        if len(normal) > 100:
            paths_html += f'<tr><td colspan="6" class="more-info">还有 {len(normal) - 100} 条未显示</td></tr>'
        paths_html += '</table>'

    # IP统计
    ips_html = '<h2>🖥️ IP 请求频率分析 (Top 100)</h2><table class="stats-table">'
    ips_html += '<tr><th>IP地址</th><th>总请求</th><th>独立路径</th><th>平均QPS</th><th>P95 QPS</th><th>错误率</th><th>建议限流</th></tr>'
    for ip_analysis in ip_analyses[:100]:
        error_class = "high-error" if ip_analysis.error_rate > 10 else ""
        ips_html += f"""<tr class="{error_class}">
            <td><code>{html.escape(ip_analysis.ip)}</code></td>
            <td>{ip_analysis.stats.total_requests:,}</td>
            <td>{ip_analysis.unique_paths}</td>
            <td>{ip_analysis.stats.avg_qps:.2f}</td>
            <td>{ip_analysis.stats.p95_qps:.1f}</td>
            <td>{ip_analysis.error_rate:.1f}%</td>
            <td>{ip_analysis.stats.suggest_rps} r/s</td>
        </tr>"""
    if len(ip_analyses) > 100:
        ips_html += f'<tr><td colspan="7" class="more-info">还有 {len(ip_analyses) - 100} 个IP未显示</td></tr>'
    ips_html += '</table>'

    # 风险项
    risks_html = '<h2>🛡️ 高风险 IP + 路径组合（防暴力破解）</h2>'
    if not risk_items:
        risks_html += '<p class="success-msg">✅ 未发现高风险行为</p>'
    else:
        risks_html += '<table class="stats-table risk-table">'
        risks_html += '<tr><th>IP</th><th>路径</th><th>总请求</th><th>峰值QPS</th><th>P95</th><th>风险评分</th><th>原因</th><th>建议限流</th></tr>'
        for risk in risk_items[:30]:
            risk_level = "critical" if risk.risk_score > 200 else "high" if risk.risk_score > 100 else "medium"
            risks_html += f"""<tr class="risk-{risk_level}">
                <td><code>{html.escape(risk.ip)}</code></td>
                <td><code>{html.escape(risk.path)}</code></td>
                <td>{risk.stats.total_requests:,}</td>
                <td>{risk.stats.max_qps:.0f}</td>
                <td>{risk.stats.p95_qps:.1f}</td>
                <td><strong>{risk.risk_score}</strong></td>
                <td><small>{html.escape(risk.reason)}</small></td>
                <td>{risk.stats.suggest_rps} r/s</td>
            </tr>"""
        risks_html += '</table>'

    # 状态码统计
    status_html = '<h2>📈 HTTP 状态码分布</h2><table class="stats-table status-table">'
    status_html += '<tr><th>状态码</th><th>数量</th><th>占比</th><th>类型</th></tr>'
    for stat in status_stats:
        type_class = stat['type'].replace('_', '-')
        status_html += f"""<tr class="{type_class}">
            <td><strong>{stat['code']}</strong></td>
            <td>{stat['count']:,}</td>
            <td>{stat['percentage']:.2f}%</td>
            <td>{stat['type']}</td>
        </tr>"""
    status_html += '</table>'

    # 完整HTML
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 40px; 
                     border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }}
        h1 {{ color: #2c3e50; margin-bottom: 10px; font-size: 2.5em; }}
        h2 {{ color: #34495e; margin: 30px 0 20px; padding-bottom: 10px; 
             border-bottom: 3px solid #3498db; }}
        h3 {{ color: #555; margin: 20px 0 10px; }}

        .summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .summary p {{ margin: 5px 0; font-size: 1.1em; }}

        .filter-info {{ background: #e3f2fd; padding: 15px; border-radius: 8px; 
                       margin: 15px 0; border-left: 4px solid #2196f3; }}

        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px; margin: 20px 0; }}
        .metric-card {{ background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                       padding: 20px; border-radius: 8px; text-align: center; 
                       box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .metric-value {{ font-size: 2.5em; font-weight: bold; color: #2c3e50; }}
        .metric-label {{ font-size: 0.9em; color: #7f8c8d; margin-top: 5px; }}

        .recommendation {{ background: #d4edda; border: 1px solid #c3e6cb; 
                         padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .recommendation code {{ background: #fff; padding: 4px 8px; border-radius: 4px;
                               color: #d63384; font-weight: bold; }}
        .human-readable {{ color: #28a745; font-style: italic; }}

        .stats-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; 
                       box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .stats-table th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
        .stats-table td {{ padding: 10px; border-bottom: 1px solid #ecf0f1; }}
        .stats-table tr:hover {{ background: #f8f9fa; }}
        .stats-table.sensitive {{ border-left: 4px solid #ff9800; }}
        .stats-table.risk-table {{ border-left: 4px solid #f44336; }}

        .high-volatility {{ background: #fff3cd !important; }}
        .high-error {{ background: #f8d7da !important; }}
        .risk-critical {{ background: #f8d7da !important; font-weight: bold; }}
        .risk-high {{ background: #fff3cd !important; }}
        .risk-medium {{ background: #d1ecf1 !important; }}

        .success {{ background: #d4edda !important; }}
        .client-error {{ background: #fff3cd !important; }}
        .server-error {{ background: #f8d7da !important; }}

        .more-info {{ text-align: center; color: #6c757d; font-style: italic; }}
        .success-msg {{ color: #28a745; font-size: 1.2em; padding: 20px; text-align: center; }}

        pre {{ background: #2d2d2d; color: #f8f8f2; padding: 20px; border-radius: 8px; 
              overflow-x: auto; line-height: 1.5; }}
        code {{ font-family: 'Courier New', monospace; }}

        @media print {{ body {{ background: white; }} .container {{ box-shadow: none; }} }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 {html.escape(title)}</h1>
        <div class="summary">
            <p><strong>⏰ 时间窗口:</strong> {start.strftime('%Y-%m-%d %H:%M:%S')} → {end.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>📝 总请求数:</strong> {total:,}</p>
            <p><strong>🔍 路径数:</strong> {len(path_analyses)} | <strong>🖥️ 独立IP:</strong> {len(ip_analyses)} | <strong>⚠️ 风险项:</strong> {len(risk_items)}</p>
        </div>
        {filter_info_html}
        {global_html}
        {paths_html}
        {ips_html}
        {risks_html}
        {status_html}
        <h2>⚙️ Nginx 限流配置建议</h2>
        <pre>{html.escape(nginx_conf)}</pre>
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; 
                      text-align: center; color: #6c757d; font-size: 0.9em;">
            <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Nginx Rate Analyzer v3.0</p>
        </footer>
    </div>
</body>
</html>"""

    return html_content


def generate_nginx_config(
        global_result: Dict[str, Any],
        path_analyses: List[PathAnalysis]
) -> str:
    """生成Nginx配置建议"""
    base = global_result['base']

    config = f"""# ===== Nginx 限流配置建议 =====
# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

# 1. 全局限流区域
limit_req_zone $binary_remote_addr zone=global:10m rate={base.suggest_rps}r/s;

# 2. 路径级限流区域
"""

    for p in path_analyses:
        if p.is_sensitive or p.stats.total_requests > 1000:
            zone_name = re.sub(r'[^a-zA-Z0-9]', '_', p.path.lstrip('/')) or "default"
            config += f"limit_req_zone $binary_remote_addr zone={zone_name}:10m rate={p.stats.suggest_rps}r/s;\n"

    config += """
# 3. 使用示例
server {
    # 全局限流
    location / {
        limit_req zone=global burst=20 nodelay;
        limit_req_status 429;
    }
"""

    for p in path_analyses:
        if p.is_sensitive:
            zone_name = re.sub(r'[^a-zA-Z0-9]', '_', p.path.lstrip('/')) or "sensitive"
            burst = max(5, p.stats.suggest_rps // 2)
            config += f"""
    # 敏感路径: {p.path}
    location {p.path} {{
        limit_req zone={zone_name} burst={burst} nodelay;
        limit_req_status 429;
        # 建议: {p.stats.human_readable}
    }}
"""

    config += "}\n"
    return config


def generate_status_stats(status_code_stats: Counter) -> List[Dict[str, Any]]:
    """生成状态码统计"""
    total = sum(status_code_stats.values())
    if total == 0:
        return []

    def get_type(code: str) -> str:
        try:
            c = int(code)
            if 200 <= c < 300:
                return "success"
            elif 300 <= c < 400:
                return "redirect"
            elif 400 <= c < 500:
                return "client_error"
            elif 500 <= c < 600:
                return "server_error"
            else:
                return "other"
        except ValueError:
            return "unknown"

    return [
        {
            'code': code,
            'count': count,
            'percentage': round(count / total * 100, 2),
            'type': get_type(code)
        }
        for code, count in status_code_stats.most_common()
    ]


# ==================== 主程序 ====================

def print_cli_summary(
        start: datetime,
        end: datetime,
        total: int,
        global_result: Dict[str, Any],
        path_analyses: List[PathAnalysis],
        ip_analyses: List[IPAnalysis],
        risk_items: List[RiskItem],
        target_ip: Optional[str] = None,
        target_path: Optional[str] = None
):
    """打印CLI摘要"""
    print("\n" + "=" * 70)
    print("📈 Nginx 请求频率分析摘要")
    if target_ip or target_path:
        filters = []
        if target_ip:
            filters.append(f"IP={target_ip}")
        if target_path:
            filters.append(f"路径={target_path}")
        print(f"筛选条件: {', '.join(filters)}")
    print("=" * 70)
    print(f"时间窗口: {start.strftime('%Y-%m-%d %H:%M')} → {end.strftime('%Y-%m-%d %H:%M')}")
    print(f"总请求数: {total:,}\n")

    base = global_result['base']
    print("🌍 全局 QPS:")
    print(f"  平均: {base.avg_qps:.1f} | 峰值: {base.max_qps:.0f} | P95: {base.p95_qps:.1f} | P99: {base.p99_qps:.1f}")
    print(f"💡 建议全局限流: {base.suggest_rps} r/s ({base.human_readable})\n")

    print("⏱️  多时间窗口限流建议:")
    for name in ['10m', '30m', '1h', '24h']:
        w = global_result['windows'][name]
        print(f"  {name:>4} → {w.suggest_rps:>3} r/s ({w.human_readable})")

    sensitive = [p for p in path_analyses if p.is_sensitive]
    if sensitive:
        print(f"\n🚀 敏感路径限流建议 (共{len(sensitive)}个):")
        for p in sensitive[:10]:
            print(f"  {p.path:<35} → {p.stats.suggest_rps:>2} r/s ({p.stats.human_readable})")

    print(f"\n🖥️  Top 10 IP (共{len(ip_analyses)}个):")
    for ip in ip_analyses[:10]:
        print(
            f"  {ip.ip:<17} → 请求:{ip.stats.total_requests:>7,} | P95:{ip.stats.p95_qps:>5.1f} | 路径:{ip.unique_paths:>3}")

    if risk_items:
        print(f"\n⚠️  高风险行为 (Top 5 / 共{len(risk_items)}个):")
        for r in risk_items[:5]:
            print(f"  {r.ip} → {r.path}")
            print(f"    评分:{r.risk_score:.1f} | {r.reason}")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Nginx 请求频率自动化分析报告生成器 (优化版 v3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s access.log --last 24h
  %(prog)s *.log.gz --target-ip 192.168.1.100
  %(prog)s access.log --sensitive-paths "/api,/admin" --output report.html
        """
    )

    parser.add_argument("logfiles", nargs='+', help="一个或多个日志文件（支持 .gz）")
    parser.add_argument("--last", help="分析最近时间，如 '1h', '24h', '7d'")
    parser.add_argument("--sensitive-paths", help="自定义敏感路径（逗号分隔）")
    parser.add_argument("--target-ip", help="指定分析的IP地址")
    parser.add_argument("--target-path", help="指定分析的路径")
    parser.add_argument("--output", help="HTML报告输出路径")
    parser.add_argument("--workers", type=int, default=4, help="并发线程数（默认4）")

    args = parser.parse_args()

    # 设置输出文件名
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"rate_report_{timestamp}.html"

    # 敏感路径
    sensitive_paths = set(DEFAULT_SENSITIVE_PATHS)
    if args.sensitive_paths:
        sensitive_paths.update(
            p.strip().rstrip('/') for p in args.sensitive_paths.split(',') if p.strip()
        )

    # 时间窗口
    time_window = None
    if args.last:
        try:
            if args.last.endswith('h'):
                delta = timedelta(hours=int(args.last[:-1]))
            elif args.last.endswith('d'):
                delta = timedelta(days=int(args.last[:-1]))
            else:
                raise ValueError("--last 必须以 h 或 d 结尾，如 '1h', '24h', '7d'")
            now = datetime.now().astimezone()
            time_window = (now - delta, now)
        except Exception as e:
            print(f"[ERROR] 时间窗口解析失败: {e}", file=sys.stderr)
            sys.exit(1)

    # 分析日志
    try:
        data = analyze_logs_optimized(
            args.logfiles,
            time_window,
            sensitive_paths,
            args.target_ip,
            args.target_path,
            args.workers
        )
    except Exception as e:
        print(f"[ERROR] 日志分析失败: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    if data['total_processed'] == 0:
        print("❌ 指定条件内无有效日志", file=sys.stderr)
        sys.exit(1)

    # 统计分析
    cache = TimeWindowCache()
    global_result = analyze_global_stats(data['global_per_sec'], cache)
    path_analyses = analyze_paths(data['path_per_sec'], sensitive_paths, data['path_ips'], cache)
    ip_analyses = analyze_ips(data['ip_per_sec'], data['ip_paths'], data['ip_errors'])
    risk_items = analyze_risks(data['ip_path_per_sec'], data['ip_errors'])
    status_stats = generate_status_stats(data['status_code_stats'])

    # 生成配置
    nginx_conf = generate_nginx_config(global_result, path_analyses)

    # 生成HTML
    start, end = data['time_window']
    html_content = generate_html_report(
        start, end, data['total_processed'],
        global_result, path_analyses, ip_analyses, risk_items, status_stats,
        nginx_conf, args.target_ip, args.target_path
    )

    # 保存HTML
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(html_content)

    # 保存JSON
    json_path = Path(args.output).with_suffix('.json')
    json_data = {
        'summary': {
            'time_window': [start.isoformat(), end.isoformat()],
            'total_requests': data['total_processed'],
            'global_stats': asdict(global_result['base']),
            'path_count': len(path_analyses),
            'ip_count': len(ip_analyses),
            'risk_count': len(risk_items)
        },
        'paths': [
            {
                'path': p.path,
                'stats': asdict(p.stats),
                'is_sensitive': p.is_sensitive,
                'unique_ips': p.unique_ips
            }
            for p in path_analyses[:100]
        ],
        'ips': [
            {
                'ip': ip.ip,
                'stats': asdict(ip.stats),
                'unique_paths': ip.unique_paths,
                'error_rate': ip.error_rate
            }
            for ip in ip_analyses[:100]
        ],
        'risks': [
            {
                'ip': r.ip,
                'path': r.path,
                'risk_score': r.risk_score,
                'reason': r.reason
            }
            for r in risk_items[:50]
        ]
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)

    # 打印摘要
    print_cli_summary(start, end, data['total_processed'], global_result,
                      path_analyses, ip_analyses, risk_items,
                      args.target_ip, args.target_path)

    print(f"\n📄 完整报告已保存至: {os.path.abspath(args.output)}")
    print(f"💾 JSON 数据已保存至: {os.path.abspath(json_path)}")
    print("✅ 分析完成!\n")


if __name__ == '__main__':
    main()
