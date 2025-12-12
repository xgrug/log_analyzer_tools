#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生产环境限流策略分析与推荐工具 v2.0
主要优化:
- 内存优化: 流式处理大文件
- 性能提升: 并行处理、缓存优化
- 功能增强: 异常检测、趋势分析、A/B测试模拟
- 生产适配: 更丰富的报告、告警建议
"""

import re
import gzip
import mmap
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
import argparse
import os
import sys
import json
from typing import List, Set, Optional, Callable, Tuple, Dict, Any, Iterator
import ipaddress
from dataclasses import dataclass, asdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import bisect
import hashlib

# ========================
# 配置与常量
# ========================
DEFAULT_WINDOW_SEC = 10
DEFAULT_MAX_REQ = 40
ANALYSIS_WINDOWS = [1, 5, 10, 30, 60]
MAX_URI_TRACK = 100_000  # 提高到 10 万
CHUNK_SIZE = 100_000  # 分块处理大小
MAX_MEMORY_RECORDS = 5_000_000  # 内存记录上限

DEFAULT_EXCLUDE_UA_KEYWORDS = [
    'bot', 'spider', 'crawler', 'scan', 'python-requests',
    'curl', 'wget', 'httpclient', 'go-http', 'java/', 'masscan',
    'headless', 'selenium', 'phantom'
]

DEFAULT_LOG_FORMAT = '$remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'


# ========================
# 数据类
# ========================
@dataclass
class RequestRecord:
    """请求记录"""
    ip: str
    timestamp: datetime
    path: str
    status: int


@dataclass
class BurstAnalysis:
    """突发分析结果"""
    window_sec: int
    max_burst: int
    p50: int
    p90: int
    p95: int
    p99: int
    avg: float


@dataclass
class AnomalyAlert:
    """异常告警"""
    type: str  # 'spike', 'sustained_high', 'distributed_attack'
    severity: str  # 'low', 'medium', 'high', 'critical'
    ip: Optional[str]
    description: str
    metric_value: float
    threshold: float


# ========================
# 日志解析器（优化版）
# ========================
class OptimizedLogParser:
    """优化的日志解析器，支持多种格式和缓存"""

    def __init__(self, log_format: str):
        self.pattern = self._compile_pattern(log_format)
        self.has_ua = '$http_user_agent' in log_format
        self._cache = {}  # 缓存解析结果
        self._parse_failures = 0

    def _compile_pattern(self, log_format: str) -> re.Pattern:
        """编译日志格式为正则表达式"""

        # 如果是默认格式，直接使用预定义的正则
        if log_format == DEFAULT_LOG_FORMAT:
            pattern = (
                r'(?P<ip>\S+)\s+-\s+-\s+'
                r'\[(?P<time>[^\]]+)\]\s+'
                r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
                r'(?P<status>\d+)\s+'
                r'(?P<bytes>\S+)\s+'
                r'"(?P<referer>[^"]*)"\s+'
                r'"(?P<user_agent>[^"]*)"'
            )
            try:
                compiled = re.compile(pattern)
                print(f"[DEBUG] 使用默认日志格式正则", file=sys.stderr)
                return compiled
            except re.error as e:
                print(f"[ERROR] 正则表达式编译失败: {e}", file=sys.stderr)
                sys.exit(1)

        # 自定义格式处理
        # 定义变量到正则的映射
        var_patterns = {
            '$remote_addr': r'(?P<ip>\S+)',
            '$time_local': r'(?P<time>[^\]]+)',
            '$request': r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"',
            '$status': r'(?P<status>\d+)',
            '$body_bytes_sent': r'(?P<bytes>\S+)',
            '$http_referer': r'"(?P<referer>[^"]*)"',
            '$http_user_agent': r'"(?P<user_agent>[^"]*)"',
            '$request_time': r'(?P<req_time>\S+)',
        }

        # 构建正则表达式
        pattern = log_format

        # 替换变量为正则
        for var, regex in var_patterns.items():
            pattern = pattern.replace(var, regex)

        # 转义方括号
        pattern = pattern.replace('[', r'\[').replace(']', r'\]')

        # 处理空格和连字符
        pattern = re.sub(r'\s+', r'\\s+', pattern)

        try:
            compiled = re.compile(pattern)
            print(f"[DEBUG] 自定义格式正则: {pattern[:150]}...", file=sys.stderr)
            return compiled
        except re.error as e:
            print(f"[ERROR] 正则表达式编译失败: {e}", file=sys.stderr)
            print(f"[ERROR] 模式: {pattern}", file=sys.stderr)
            sys.exit(1)

    def parse(self, line: str) -> Optional[Dict[str, str]]:
        """解析单行日志"""
        line = line.strip()
        if not line:
            return None

        # 简单缓存
        line_hash = hash(line[:100])
        if line_hash in self._cache:
            return self._cache[line_hash]

        match = self.pattern.match(line)  # 使用 match 而不是 search
        if not match:
            self._parse_failures += 1
            # 只打印前几个失败的样例
            if self._parse_failures <= 5:
                print(f"[DEBUG] 解析失败 #{self._parse_failures}: {line[:200]}", file=sys.stderr)
            return None

        result = match.groupdict()

        # 验证必需字段
        if not result.get('ip') or not result.get('status') or not result.get('time'):
            self._parse_failures += 1
            return None

        if len(self._cache) < 10000:
            self._cache[line_hash] = result

        return result

    def get_stats(self) -> Dict[str, int]:
        """获取解析统计"""
        return {
            'cache_size': len(self._cache),
            'parse_failures': self._parse_failures
        }


def parse_log_time(time_str: str) -> datetime:
    """解析 Nginx 时间格式（支持多种格式）"""
    time_str = time_str.strip()

    # 尝试多种常见格式
    formats = [
        "%d/%b/%Y:%H:%M:%S %z",  # 标准 Nginx: 01/Jan/2024:12:00:00 +0800
        "%d/%b/%Y:%H:%M:%S",  # 无时区
        "%Y-%m-%d %H:%M:%S",  # ISO 格式
        "%d/%b/%Y %H:%M:%S",  # 空格分隔
    ]

    for fmt in formats:
        try:
            return datetime.strptime(time_str, fmt)
        except ValueError:
            continue

    # 尝试手动处理时区
    parts = time_str.split()
    if len(parts) >= 2:
        date_part = parts[0]
        tz_part = parts[1] if len(parts) > 1 else None

        for fmt in ["%d/%b/%Y:%H:%M:%S", "%d/%b/%Y %H:%M:%S"]:
            try:
                dt = datetime.strptime(date_part, fmt)
                if tz_part:
                    # 简单处理时区（如 +0800）
                    try:
                        return datetime.strptime(f"{date_part} {tz_part}", f"{fmt} %z")
                    except:
                        return dt
                return dt
            except ValueError:
                continue

    raise ValueError(f"无法解析时间格式: {time_str}")


def open_log_file(filepath: str):
    """智能打开日志文件（支持压缩）"""
    if filepath.endswith('.gz'):
        return gzip.open(filepath, 'rt', encoding='utf-8', errors='replace')
    return open(filepath, 'r', encoding='utf-8', errors='replace')


def align_to_window(dt: datetime, window_sec: int) -> datetime:
    """对齐到时间窗口"""
    ts = int(dt.timestamp())
    aligned = (ts // window_sec) * window_sec
    return datetime.fromtimestamp(aligned, tz=dt.tzinfo or None)


# ========================
# 过滤器（优化版）
# ========================
class IPFilter:
    """IP 过滤器（支持 CIDR 和快速查找）"""

    def __init__(self, ip_list: List[str], exclude_file: Optional[str] = None):
        self.networks = set()
        self.single_ips = set()
        self._load_ips(ip_list, exclude_file)

    def _load_ips(self, ip_list: List[str], exclude_file: Optional[str]):
        items = list(ip_list)
        if exclude_file and os.path.exists(exclude_file):
            with open(exclude_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        items.append(line)

        for item in items:
            item = item.strip()
            if not item:
                continue
            try:
                if '/' in item:
                    net = ipaddress.IPv4Network(item, strict=False)
                    self.networks.add(net)
                else:
                    # 单 IP 直接存储，避免网络对象开销
                    self.single_ips.add(item)
            except Exception as e:
                print(f"[WARN] 无效 IP: {item} ({e})", file=sys.stderr)

    def is_excluded(self, ip_str: str) -> bool:
        """检查 IP 是否被排除"""
        if ip_str in self.single_ips:
            return True

        if not self.networks:
            return False

        try:
            ip = ipaddress.IPv4Address(ip_str)
            for net in self.networks:
                if ip in net:
                    return True
        except Exception:
            pass

        return False


class StatusFilter:
    """HTTP 状态码过滤器（增强版）"""

    def __init__(self, include_pattern: str, exclude_pattern: Optional[str]):
        self.include_codes = self._parse_pattern(include_pattern)
        self.exclude_codes = self._parse_pattern(exclude_pattern) if exclude_pattern else set()

        # 预定义的错误状态码（会自动排除，除非明确包含）
        self.error_codes = set(range(400, 600))  # 4xx, 5xx 全部视为错误

        # 如果用户明确包含了错误码，则不自动排除
        self.auto_exclude_errors = not (self.include_codes & self.error_codes)

    def _parse_pattern(self, pattern: str) -> Set[int]:
        """解析状态码模式（如 2**,3**,200,301）"""
        codes = set()
        if not pattern:
            return codes

        for part in pattern.split(','):
            part = part.strip()
            if part.endswith('**'):
                # 范围匹配
                prefix = int(part[0])
                codes.update(range(prefix * 100, (prefix + 1) * 100))
            elif part.endswith('*'):
                # 十位匹配，如 20* 匹配 200-209
                prefix = int(part[:-1])
                codes.update(range(prefix * 10, (prefix + 1) * 10))
            elif '-' in part:
                # 范围匹配，如 200-299
                start, end = part.split('-')
                codes.update(range(int(start), int(end) + 1))
            elif part.isdigit():
                codes.add(int(part))

        return codes

    def accept(self, status_code: int) -> bool:
        """判断状态码是否接受"""
        # 优先检查排除列表
        if status_code in self.exclude_codes:
            return False

        # 自动排除错误码（除非用户明确包含）
        if self.auto_exclude_errors and status_code in self.error_codes:
            return False

        # 检查包含列表
        return status_code in self.include_codes

    def get_filter_info(self) -> Dict[str, Any]:
        """获取过滤器信息"""
        return {
            'include_codes_count': len(self.include_codes),
            'exclude_codes_count': len(self.exclude_codes),
            'auto_exclude_errors': self.auto_exclude_errors,
            'example_included': sorted(list(self.include_codes))[:10],
            'example_excluded': sorted(list(self.exclude_codes))[:10]
        }


class UAFilter:
    """User-Agent 过滤器（优化匹配）"""

    def __init__(self, exclude_keywords: List[str]):
        self.keywords = [kw.lower() for kw in exclude_keywords]

    def should_exclude(self, ua: str) -> bool:
        """判断 UA 是否应该排除"""
        if not ua or not self.keywords:
            return False

        ua_lower = ua.lower()
        return any(kw in ua_lower for kw in self.keywords)


# ========================
# 流式记录提取（内存优化）
# ========================
def stream_records(
        logfiles: List[str],
        ip_filter: IPFilter,
        status_filter: StatusFilter,
        ua_filter: UAFilter,
        log_parser: OptimizedLogParser,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        max_records: int = MAX_MEMORY_RECORDS
) -> Iterator[RequestRecord]:
    """流式提取记录（生成器，节省内存）"""

    total_raw = 0
    total_kept = 0
    parse_errors = 0
    filter_stats = {
        'ip_excluded': 0,
        'status_excluded': 0,
        'ua_excluded': 0,
        'time_excluded': 0,
        'parse_failed': 0
    }

    # 状态码分布统计（用于显示错误影响）
    status_distribution = Counter()

    for logfile in logfiles:
        if not os.path.exists(logfile):
            print(f"[WARN] 文件不存在: {logfile}", file=sys.stderr)
            continue

        print(f"[INFO] 处理文件: {logfile}", file=sys.stderr)

        with open_log_file(logfile) as f:
            for line in f:
                total_raw += 1

                # 定期输出进度
                if total_raw % 50000 == 0:
                    print(f"[INFO] 已处理 {total_raw:,} 行，保留 {total_kept:,} 条 "
                          f"(解析失败: {filter_stats['parse_failed']}, "
                          f"IP过滤: {filter_stats['ip_excluded']}, "
                          f"状态码过滤: {filter_stats['status_excluded']})",
                          file=sys.stderr)

                parsed = log_parser.parse(line)
                if not parsed:
                    filter_stats['parse_failed'] += 1
                    continue

                # IP 过滤
                ip = parsed.get('ip', '')
                if not ip or ip == '-':
                    filter_stats['parse_failed'] += 1
                    continue

                if ip_filter.is_excluded(ip):
                    filter_stats['ip_excluded'] += 1
                    continue

                # 状态码过滤
                status_str = parsed.get('status', '')
                if not status_str or not status_str.isdigit():
                    filter_stats['parse_failed'] += 1
                    continue

                status_code = int(status_str)

                # 统计状态码分布（所有状态码）
                status_distribution[status_code] += 1

                if not status_filter.accept(status_code):
                    filter_stats['status_excluded'] += 1
                    continue

                # UA 过滤
                ua = parsed.get('user_agent', '') if log_parser.has_ua else ''
                if ua_filter.should_exclude(ua):
                    filter_stats['ua_excluded'] += 1
                    continue

                # 时间解析
                try:
                    log_time = parse_log_time(parsed['time'])
                except Exception as e:
                    filter_stats['parse_failed'] += 1
                    if parse_errors < 3:
                        print(f"[DEBUG] 时间解析失败: {parsed.get('time', 'N/A')} - {e}", file=sys.stderr)
                    parse_errors += 1
                    continue

                # 时间范围过滤
                if time_range:
                    start, end = time_range
                    if log_time < start or log_time > end:
                        filter_stats['time_excluded'] += 1
                        continue

                path = parsed.get('path', '/')

                total_kept += 1
                yield RequestRecord(ip, log_time, path, status_code)

                # 安全上限
                if total_kept >= max_records:
                    print(f"[WARN] 已达到记录上限 {max_records:,}，停止加载", file=sys.stderr)
                    break

    # 最终统计
    print(f"\n[INFO] ========== 处理统计 ==========", file=sys.stderr)
    print(f"[INFO] 总行数: {total_raw:,}", file=sys.stderr)
    print(f"[INFO] 有效请求: {total_kept:,}", file=sys.stderr)
    print(f"[INFO] 过滤统计:", file=sys.stderr)
    print(f"[INFO]   - 解析失败: {filter_stats['parse_failed']:,}", file=sys.stderr)
    print(f"[INFO]   - IP 过滤: {filter_stats['ip_excluded']:,}", file=sys.stderr)
    print(f"[INFO]   - 状态码过滤: {filter_stats['status_excluded']:,}", file=sys.stderr)
    print(f"[INFO]   - UA 过滤: {filter_stats['ua_excluded']:,}", file=sys.stderr)
    print(f"[INFO]   - 时间过滤: {filter_stats['time_excluded']:,}", file=sys.stderr)

    # 状态码分布分析
    print(f"\n[INFO] ========== 状态码分布 ==========", file=sys.stderr)

    # 按类别统计
    status_by_category = {
        '2xx (成功)': 0,
        '3xx (重定向)': 0,
        '4xx (客户端错误)': 0,
        '5xx (服务端错误)': 0,
        '其他': 0
    }

    for status, count in status_distribution.items():
        if 200 <= status < 300:
            status_by_category['2xx (成功)'] += count
        elif 300 <= status < 400:
            status_by_category['3xx (重定向)'] += count
        elif 400 <= status < 500:
            status_by_category['4xx (客户端错误)'] += count
        elif 500 <= status < 600:
            status_by_category['5xx (服务端错误)'] += count
        else:
            status_by_category['其他'] += count

    total_status = sum(status_by_category.values())
    for category, count in status_by_category.items():
        if count > 0:
            percentage = count / total_status * 100
            print(f"[INFO]   {category}: {count:,} ({percentage:.2f}%)", file=sys.stderr)

    # Top 错误状态码
    error_codes = [(code, count) for code, count in status_distribution.items() if code >= 400]
    if error_codes:
        error_codes.sort(key=lambda x: x[1], reverse=True)
        print(f"\n[INFO] ========== Top 5 错误状态码 ==========", file=sys.stderr)
        for code, count in error_codes[:5]:
            percentage = count / total_status * 100
            print(f"[INFO]   {code}: {count:,} ({percentage:.2f}%)", file=sys.stderr)

        total_errors = sum(count for _, count in error_codes)
        error_rate = total_errors / total_status * 100
        print(f"\n[INFO] 总错误率: {error_rate:.2f}%", file=sys.stderr)

        if error_rate > 10:
            print(f"[WARN] ⚠️  错误率较高（>{error_rate:.1f}%），这些错误请求已自动排除，不影响限流策略", file=sys.stderr)
        elif error_rate > 5:
            print(f"[INFO] ℹ️  错误率适中（{error_rate:.1f}%），已自动排除", file=sys.stderr)
        else:
            print(f"[INFO] ✅ 错误率较低（{error_rate:.1f}%）", file=sys.stderr)

    # 打印解析器统计
    parser_stats = log_parser.get_stats()
    print(f"\n[INFO] 解析器缓存大小: {parser_stats['cache_size']}", file=sys.stderr)


# ========================
# 核心分析引擎
# ========================
class RateLimitAnalyzer:
    """限流分析引擎"""

    def __init__(self, records: List[RequestRecord]):
        self.records = records
        self.ip_timings = defaultdict(list)
        self.uri_counter = Counter()
        self.uri_timings = defaultdict(list)

        self._build_indexes()

    def _build_indexes(self):
        """构建索引（优化查询性能）"""
        print("[INFO] 构建分析索引...", file=sys.stderr)

        for rec in self.records:
            self.ip_timings[rec.ip].append(rec.timestamp)
            self.uri_counter[rec.path] += 1

            if len(self.uri_timings) < MAX_URI_TRACK:
                self.uri_timings[rec.path].append(rec.timestamp)

        # 排序以加速后续分析
        for ip in self.ip_timings:
            self.ip_timings[ip].sort()

        for uri in self.uri_timings:
            self.uri_timings[uri].sort()

    def evaluate_policy(self, window_sec: int, max_req: int) -> Dict[str, Any]:
        """评估当前限流策略"""
        ip_window_counter = defaultdict(Counter)

        for ip, timings in self.ip_timings.items():
            for t in timings:
                window_start = align_to_window(t, window_sec)
                ip_window_counter[ip][window_start] += 1

        violations = []
        all_bursts = []
        violation_ips = set()

        for ip, windows in ip_window_counter.items():
            for cnt in windows.values():
                all_bursts.append(cnt)
                if cnt > max_req:
                    violations.append(cnt)
                    violation_ips.add(ip)

        return {
            'window_seconds': window_sec,
            'current_limit': max_req,
            'total_requests': len(self.records),
            'total_unique_ips': len(self.ip_timings),
            'violations_count': len(violations),
            'violation_ips_count': len(violation_ips),
            'global_max_burst': max(all_bursts) if all_bursts else 0,
            'burst_analysis': self._compute_percentiles(all_bursts),
            'violation_ratio': len(violations) / max(len(all_bursts), 1)
        }

    def analyze_bursts(self) -> Dict[int, BurstAnalysis]:
        """分析不同时间窗口的突发"""
        results = {}

        for window in ANALYSIS_WINDOWS:
            all_bursts = []

            for timings in self.ip_timings.values():
                bursts = self._compute_sliding_window_bursts(timings, window)
                all_bursts.extend(bursts)

            if all_bursts:
                sorted_bursts = sorted(all_bursts)
                results[window] = BurstAnalysis(
                    window_sec=window,
                    max_burst=max(all_bursts),
                    p50=self._percentile(sorted_bursts, 50),
                    p90=self._percentile(sorted_bursts, 90),
                    p95=self._percentile(sorted_bursts, 95),
                    p99=self._percentile(sorted_bursts, 99),
                    avg=sum(all_bursts) / len(all_bursts)
                )

        return results

    def detect_anomalies(self, threshold_multiplier: float = 3.0) -> List[AnomalyAlert]:
        """异常检测（基于统计阈值）"""
        alerts = []

        # 计算基线（P95）
        all_counts = []
        for timings in self.ip_timings.values():
            all_counts.append(len(timings))

        if not all_counts:
            return alerts

        sorted_counts = sorted(all_counts)
        p95_baseline = self._percentile(sorted_counts, 95)
        threshold = p95_baseline * threshold_multiplier

        # 检测异常 IP
        for ip, timings in self.ip_timings.items():
            count = len(timings)

            if count > threshold:
                severity = 'critical' if count > threshold * 2 else 'high'
                alerts.append(AnomalyAlert(
                    type='spike',
                    severity=severity,
                    ip=ip,
                    description=f'IP {ip} 请求量 {count} 远超基线 {p95_baseline:.0f}',
                    metric_value=count,
                    threshold=threshold
                ))

        # 检测分布式攻击（大量低频 IP）
        low_freq_ips = [ip for ip, t in self.ip_timings.items() if len(t) < 10]
        if len(low_freq_ips) > len(self.ip_timings) * 0.7:  # 70% 都是低频
            alerts.append(AnomalyAlert(
                type='distributed_attack',
                severity='medium',
                ip=None,
                description=f'检测到 {len(low_freq_ips)} 个低频 IP（可能是分布式攻击）',
                metric_value=len(low_freq_ips),
                threshold=len(self.ip_timings) * 0.7
            ))

        return alerts

    def recommend_limits(self, safety_margin: float = 0.2) -> Dict[str, Any]:
        """推荐限流参数（支持多窗口）"""
        burst_analysis = self.analyze_bursts()

        # 多时间窗口推荐
        multi_window_recommendations = {}

        for window_sec in [10, 30, 60, 300, 3600, 86400]:  # 10s, 30s, 1min, 5min, 1h, 24h
            window_bursts = self._compute_window_bursts(window_sec)
            if not window_bursts:
                continue

            sorted_bursts = sorted(window_bursts)
            p99 = self._percentile(sorted_bursts, 99)
            p95 = self._percentile(sorted_bursts, 95)
            avg = sum(window_bursts) / len(window_bursts)

            # 根据窗口大小计算 rate
            if window_sec <= 60:
                # 短窗口：基于突发计算
                rate_per_sec = p99 / window_sec
            else:
                # 长窗口：基于平均值计算
                rate_per_sec = avg / window_sec

            rate_per_sec = max(1, round(rate_per_sec * (1 + safety_margin)))

            # 计算 burst（根据窗口调整）
            if window_sec <= 10:
                burst_base = p99
            elif window_sec <= 60:
                burst_base = max(p95, p99 * 0.8)
            else:
                burst_base = p95

            burst = max(5, int(burst_base * (1 + safety_margin)))

            # 生成三种模式
            multi_window_recommendations[f'{window_sec}s'] = {
                'window_seconds': window_sec,
                'window_display': self._format_duration(window_sec),
                'statistics': {
                    'p95': p95,
                    'p99': p99,
                    'avg': round(avg, 1),
                    'max': max(window_bursts)
                },
                'strict': {
                    'rate': max(1, rate_per_sec // 2),
                    'burst': max(5, int(burst * 0.5)),
                    'description': '严格模式：适用于高安全需求场景'
                },
                'balanced': {
                    'rate': rate_per_sec,
                    'burst': burst,
                    'description': '均衡模式：推荐的生产配置'
                },
                'loose': {
                    'rate': rate_per_sec * 2,
                    'burst': int(burst * 1.5),
                    'description': '宽松模式：适用于突发高峰场景'
                }
            }

        # 传统的基于分析窗口的推荐（保持向后兼容）
        rate_base = burst_analysis.get(60)
        if rate_base:
            rate_rps = max(1, round(rate_base.p99 / 60 * (1 + safety_margin)))
        else:
            rate_rps = 10

        burst_1s = burst_analysis.get(1, BurstAnalysis(1, 10, 5, 8, 9, 10, 7))
        burst_5s = burst_analysis.get(5, BurstAnalysis(5, 20, 10, 15, 18, 20, 14))

        burst_base = max(burst_1s.p99, burst_5s.p99)
        burst_base = int(burst_base * (1 + safety_margin))

        return {
            'multi_window': multi_window_recommendations,
            'default': {
                'strict': {
                    'rate': max(rate_rps // 2, 1),
                    'burst': max(5, int(burst_base * 0.5)),
                    'description': '严格模式：适用于高安全需求场景'
                },
                'balanced': {
                    'rate': rate_rps,
                    'burst': max(10, burst_base),
                    'description': '均衡模式：推荐的生产配置'
                },
                'loose': {
                    'rate': rate_rps * 2,
                    'burst': max(20, int(burst_base * 2)),
                    'description': '宽松模式：适用于突发高峰场景'
                }
            },
            'burst_analysis': {k: asdict(v) for k, v in burst_analysis.items()}
        }

    def _compute_window_bursts(self, window_sec: int) -> List[int]:
        """计算指定窗口的所有突发"""
        all_bursts = []
        window_td = timedelta(seconds=window_sec)

        for timings in self.ip_timings.values():
            if not timings:
                continue

            left = 0
            for right in range(len(timings)):
                while timings[right] - timings[left] > window_td:
                    left += 1
                all_bursts.append(right - left + 1)

        return all_bursts

    @staticmethod
    def _format_duration(seconds: int) -> str:
        """格式化时长显示"""
        if seconds < 60:
            return f"{seconds}秒"
        elif seconds < 3600:
            return f"{seconds // 60}分钟"
        elif seconds < 86400:
            return f"{seconds // 3600}小时"
        else:
            return f"{seconds // 86400}天"

    def analyze_uri_patterns(self, top_n: int = 30) -> Dict[str, Any]:
        """分析 URI 访问模式"""
        top_uris = self.uri_counter.most_common(top_n)

        uri_details = []
        for uri, count in top_uris:
            timings = self.uri_timings.get(uri, [])
            if not timings:
                continue

            # 计算 10s 最大突发
            max_burst = self._compute_max_burst(timings, 10)

            # 判断 URI 类型
            uri_type = self._classify_uri(uri)

            uri_details.append({
                'uri': uri,
                'request_count': count,
                'max_burst_10s': max_burst,
                'uri_type': uri_type,
                'recommended_burst': self._recommend_uri_burst(uri_type, max_burst)
            })

        return {
            'top_uris': uri_details,
            'total_unique_uris': len(self.uri_counter)
        }

    def simulate_policy(self, rate: int, burst: int) -> Dict[str, Any]:
        """模拟限流策略效果（A/B 测试）"""
        blocked_requests = 0
        blocked_ips = set()
        ip_tokens = {}  # 令牌桶模拟

        for rec in sorted(self.records, key=lambda x: x.timestamp):
            ip = rec.ip

            if ip not in ip_tokens:
                ip_tokens[ip] = {
                    'tokens': burst,
                    'last_refill': rec.timestamp
                }

            bucket = ip_tokens[ip]

            # 补充令牌
            time_delta = (rec.timestamp - bucket['last_refill']).total_seconds()
            new_tokens = time_delta * rate
            bucket['tokens'] = min(burst, bucket['tokens'] + new_tokens)
            bucket['last_refill'] = rec.timestamp

            # 消耗令牌
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
            else:
                blocked_requests += 1
                blocked_ips.add(ip)

        return {
            'rate': rate,
            'burst': burst,
            'total_requests': len(self.records),
            'blocked_requests': blocked_requests,
            'blocked_ratio': blocked_requests / len(self.records),
            'affected_ips': len(blocked_ips),
            'pass_through_ratio': 1 - (blocked_requests / len(self.records))
        }

    # ---- 辅助方法 ----

    def _compute_sliding_window_bursts(self, timings: List[datetime], window_sec: int) -> List[int]:
        """滑动窗口突发计算"""
        if not timings:
            return []

        bursts = []
        left = 0
        window_td = timedelta(seconds=window_sec)

        for right in range(len(timings)):
            while timings[right] - timings[left] > window_td:
                left += 1
            bursts.append(right - left + 1)

        return bursts

    def _compute_max_burst(self, timings: List[datetime], window_sec: int) -> int:
        """计算最大突发"""
        bursts = self._compute_sliding_window_bursts(timings, window_sec)
        return max(bursts) if bursts else 0

    @staticmethod
    def _percentile(sorted_data: List[int], p: float) -> int:
        """计算百分位数"""
        if not sorted_data:
            return 0
        index = int(len(sorted_data) * p / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]

    @staticmethod
    def _compute_percentiles(data: List[int]) -> Dict[str, int]:
        """计算多个百分位数"""
        if not data:
            return {'p50': 0, 'p90': 0, 'p95': 0, 'p99': 0}

        sorted_data = sorted(data)
        return {
            'p50': RateLimitAnalyzer._percentile(sorted_data, 50),
            'p90': RateLimitAnalyzer._percentile(sorted_data, 90),
            'p95': RateLimitAnalyzer._percentile(sorted_data, 95),
            'p99': RateLimitAnalyzer._percentile(sorted_data, 99),
        }

    @staticmethod
    def _classify_uri(uri: str) -> str:
        """分类 URI（用于差异化限流）"""
        uri_lower = uri.lower()

        if any(kw in uri_lower for kw in ['login', 'auth', 'signin', 'authenticate']):
            return 'auth'
        elif any(kw in uri_lower for kw in ['pay', 'checkout', 'order', 'purchase']):
            return 'payment'
        elif any(kw in uri_lower for kw in ['api', 'v1', 'v2', 'graphql']):
            return 'api'
        elif any(kw in uri_lower for kw in ['admin', 'manage', 'dashboard']):
            return 'admin'
        elif any(kw in uri_lower for kw in ['static', 'assets', 'cdn', '.js', '.css', '.jpg', '.png']):
            return 'static'
        else:
            return 'general'

    @staticmethod
    def _recommend_uri_burst(uri_type: str, max_burst: int) -> int:
        """根据 URI 类型推荐 burst"""
        # 基础 burst（加 20% 安全边际）
        base = int(max_burst * 1.2)

        # 按类型调整
        adjustments = {
            'auth': 0.5,  # 认证类严格
            'payment': 0.6,  # 支付类严格
            'api': 1.0,  # API 正常
            'admin': 0.7,  # 管理类较严
            'static': 2.0,  # 静态资源宽松
            'general': 1.0  # 普通页面
        }

        multiplier = adjustments.get(uri_type, 1.0)
        return max(3, int(base * multiplier))


# ========================
# 报告生成
# ========================
class ReportGenerator:
    """报告生成器"""

    @staticmethod
    def print_summary(analyzer: RateLimitAnalyzer, eval_result: Dict[str, Any]):
        """打印摘要"""
        print("\n" + "=" * 70)
        print("📊 限流策略分析报告")
        print("=" * 70)

        print(f"\n【数据概览】")
        print(f"  总请求数: {eval_result['total_requests']:,}")
        print(f"  独立 IP 数: {eval_result['total_unique_ips']:,}")
        print(f"  分析窗口: {eval_result['window_seconds']}秒")
        print(f"  当前限制: {eval_result['current_limit']} 次/窗口")

        print(f"\n【当前策略评估】")
        print(f"  违规次数: {eval_result['violations_count']:,}")
        print(f"  违规 IP 数: {eval_result['violation_ips_count']}")
        print(f"  违规比例: {eval_result['violation_ratio']:.2%}")
        print(f"  全局最大突发: {eval_result['global_max_burst']}")

        burst = eval_result['burst_analysis']
        print(f"\n【突发分布】")
        print(f"  P50: {burst['p50']}  P90: {burst['p90']}  P95: {burst['p95']}  P99: {burst['p99']}")

        # 策略建议
        if eval_result['violation_ratio'] < 0.01:
            print(f"\n✅ 策略合理（违规 <1%）")
        elif eval_result['violation_ratio'] < 0.05:
            print(f"\n⚠️  建议适当放宽（违规 <5%）")
        else:
            print(f"\n❌ 策略过严（违规 ≥5%），建议调整！")

    @staticmethod
    def print_recommendations(recommendations: Dict[str, Any]):
        """打印推荐配置（支持多窗口）"""
        print("\n" + "=" * 90)
        print("🎯 多时间窗口限流策略推荐")
        print("=" * 90)

        if 'multi_window' in recommendations:
            # 新版多窗口推荐
            multi_window = recommendations['multi_window']

            # 打印对比表
            print("\n【时间窗口对比表】")
            print(f"{'窗口':<10} {'P95':<8} {'P99':<8} {'平均':<8} {'最大':<8} | {'推荐rate':<12} {'推荐burst':<12}")
            print("-" * 90)

            for window_key in sorted(multi_window.keys(), key=lambda x: int(x.rstrip('s'))):
                window_data = multi_window[window_key]
                stats = window_data['statistics']
                balanced = window_data['balanced']

                print(f"{window_data['window_display']:<10} "
                      f"{stats['p95']:<8} "
                      f"{stats['p99']:<8} "
                      f"{stats['avg']:<8.1f} "
                      f"{stats['max']:<8} | "
                      f"{balanced['rate']}r/s{'':<7} "
                      f"{balanced['burst']}")

            # 详细推荐（选择几个关键窗口）
            key_windows = ['10s', '60s', '3600s']
            for window_key in key_windows:
                if window_key not in multi_window:
                    continue

                window_data = multi_window[window_key]
                print(f"\n{'=' * 90}")
                print(f"【{window_data['window_display']} 窗口限流配置】")
                print(f"{'=' * 90}")

                print(f"\n统计数据: P95={window_data['statistics']['p95']}, "
                      f"P99={window_data['statistics']['p99']}, "
                      f"平均={window_data['statistics']['avg']:.1f}, "
                      f"最大={window_data['statistics']['max']}")

                for mode in ['strict', 'balanced', 'loose']:
                    config = window_data[mode]
                    print(f"\n【{mode.upper()} 模式】{config['description']}")
                    print(f"  rate={config['rate']}r/s  burst={config['burst']}")

                    # Nginx 配置示例
                    zone_name = f"{mode}_{window_data['window_seconds']}s"
                    print(f"\n  # http 块配置")
                    print(f"  limit_req_zone $binary_remote_addr zone={zone_name}:10m rate={config['rate']}r/s;")
                    print(f"\n  # server/location 块配置")
                    print(f"  limit_req zone={zone_name} burst={config['burst']} nodelay;")

        # 传统推荐（默认模式）
        if 'default' in recommendations:
            print(f"\n{'=' * 90}")
            print("【默认推荐配置（10秒窗口）】")
            print(f"{'=' * 90}")

            for mode in ['strict', 'balanced', 'loose']:
                config = recommendations['default'][mode]
                print(f"\n【{mode.upper()} 模式】{config['description']}")
                print(f"  rate={config['rate']}r/s  burst={config['burst']}")

        # 使用建议
        print(f"\n{'=' * 90}")
        print("💡 使用建议")
        print(f"{'=' * 90}")
        print("""
1. 短窗口（10s-60s）适合：
   - 防止瞬时突发攻击
   - API 接口保护
   - 登录/认证端点

2. 中窗口（5min-1h）适合：
   - 业务逻辑限流
   - 防止账号滥用
   - 爬虫控制

3. 长窗口（24h）适合：
   - 每日配额限制
   - 防止持续性滥用
   - 付费 API 限额

4. 组合使用（多层防护）：
   limit_req zone=short_window burst=20 nodelay;  # 10秒窗口
   limit_req zone=long_window burst=1000;         # 1小时窗口
""")

    @staticmethod
    def print_uri_analysis(uri_analysis: Dict[str, Any]):
        """打印 URI 分析"""
        print("\n" + "=" * 70)
        print("🌐 URI 访问模式分析")
        print("=" * 70)

        print(f"\n  总 URI 数量: {uri_analysis['total_unique_uris']:,}")
        print(f"\n  {'URI':<45} {'请求量':<12} {'10s突发':<10} {'类型':<10} {'推荐burst'}")
        print("  " + "-" * 95)

        for uri_info in uri_analysis['top_uris'][:15]:
            uri = uri_info['uri'][:44]
            count = uri_info['request_count']
            burst = uri_info['max_burst_10s']
            uri_type = uri_info['uri_type']
            rec_burst = uri_info['recommended_burst']

            print(f"  {uri:<45} {count:<12,} {burst:<10} {uri_type:<10} {rec_burst}")

    @staticmethod
    def print_anomalies(alerts: List[AnomalyAlert]):
        """打印异常告警"""
        if not alerts:
            print("\n✅ 未检测到异常流量")
            return

        print("\n" + "=" * 70)
        print("⚠️  异常流量告警")
        print("=" * 70)

        # 按严重程度分组
        by_severity = defaultdict(list)
        for alert in alerts:
            by_severity[alert.severity].append(alert)

        severity_order = ['critical', 'high', 'medium', 'low']
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }

        for severity in severity_order:
            if severity not in by_severity:
                continue

            print(f"\n{severity_icons[severity]} {severity.upper()} 级别告警:")
            for alert in by_severity[severity]:
                print(f"  - {alert.description}")
                if alert.ip:
                    print(f"    IP: {alert.ip}")
                print(f"    指标值: {alert.metric_value:.0f} (阈值: {alert.threshold:.0f})")

    @staticmethod
    def print_simulation(sim_result: Dict[str, Any]):
        """打印策略模拟结果"""
        print("\n" + "=" * 70)
        print("🧪 策略效果模拟（令牌桶算法）")
        print("=" * 70)

        print(f"\n  配置: rate={sim_result['rate']}r/s, burst={sim_result['burst']}")
        print(f"  总请求: {sim_result['total_requests']:,}")
        print(f"  被拦截: {sim_result['blocked_requests']:,} ({sim_result['blocked_ratio']:.2%})")
        print(f"  放行率: {sim_result['pass_through_ratio']:.2%}")
        print(f"  受影响 IP: {sim_result['affected_ips']}")

        if sim_result['blocked_ratio'] < 0.01:
            print("\n  ✅ 策略宽松，几乎无误杀")
        elif sim_result['blocked_ratio'] < 0.05:
            print("\n  ⚖️  策略均衡，误杀率可接受")
        else:
            print("\n  ⚠️  策略严格，可能影响正常用户")

    @staticmethod
    def generate_nginx_config(recommendations: Dict[str, Any], uri_analysis: Dict[str, Any]) -> str:
        """生成完整的 Nginx 配置（支持多窗口）"""
        config = []

        config.append("# ============================================")
        config.append("# Nginx 多层限流配置（基于日志分析生成）")
        config.append("# ============================================\n")

        # 多窗口限流区定义
        if 'multi_window' in recommendations:
            config.append("# 1. 多时间窗口限流区定义（http 块）")
            multi_window = recommendations['multi_window']

            # 为每个窗口的 balanced 模式生成配置
            for window_key in sorted(multi_window.keys(), key=lambda x: int(x.rstrip('s'))):
                window_data = multi_window[window_key]
                balanced = window_data['balanced']
                zone_name = f"limit_{window_data['window_seconds']}s"

                config.append(f"\n# {window_data['window_display']} 窗口 (P99={window_data['statistics']['p99']})")
                config.append(f"limit_req_zone $binary_remote_addr zone={zone_name}:10m rate={balanced['rate']}r/s;")

        # URI 级别限流区
        config.append("\n# 2. URI 级别限流区（按类型分类）")
        uri_types = defaultdict(list)
        for uri_info in uri_analysis['top_uris'][:10]:
            uri_types[uri_info['uri_type']].append(uri_info)

        for uri_type in ['auth', 'payment', 'api']:
            if uri_type in uri_types:
                config.append(f"limit_req_zone $binary_remote_addr zone={uri_type}_zone:5m rate=5r/s;")

        # server 块配置 - 多层防护
        config.append("\n# 3. 多层限流配置示例（server 块）")
        config.append("server {")
        config.append("    # ... 其他配置 ...")
        config.append("")

        # 方案A: 单一窗口（简单）
        config.append("    # ========== 方案 A: 单一窗口（推荐新手使用） ==========")
        if 'multi_window' in recommendations and '10s' in recommendations['multi_window']:
            balanced_10s = recommendations['multi_window']['10s']['balanced']
            config.append(f"    # 10秒窗口全局限流")
            config.append(f"    limit_req zone=limit_10s burst={balanced_10s['burst']} nodelay;")

        # 方案B: 双层防护（推荐）
        config.append("\n    # ========== 方案 B: 双层防护（推荐生产使用） ==========")
        config.append("    # 短窗口：防止瞬时突发")
        if 'multi_window' in recommendations and '10s' in recommendations['multi_window']:
            burst_10s = recommendations['multi_window']['10s']['balanced']['burst']
            config.append(f"    limit_req zone=limit_10s burst={burst_10s} nodelay;")

        config.append("\n    # 长窗口：防止持续滥用")
        if 'multi_window' in recommendations and '3600s' in recommendations['multi_window']:
            burst_1h = recommendations['multi_window']['3600s']['balanced']['burst']
            config.append(f"    limit_req zone=limit_3600s burst={burst_1h};")

        # 方案C: 多层防护（高级）
        config.append("\n    # ========== 方案 C: 三层防护（高安全场景） ==========")
        windows = ['10s', '60s', '3600s']
        for window_key in windows:
            if 'multi_window' in recommendations and window_key in recommendations['multi_window']:
                window_data = recommendations['multi_window'][window_key]
                burst = window_data['balanced']['burst']
                nodelay = ' nodelay' if window_key == '10s' else ''
                config.append(f"    # limit_req zone=limit_{window_data['window_seconds']}s burst={burst}{nodelay};")

        # URI 特定配置
        config.append("\n    # ========== URI 级别精细化限流 ==========")

        config.append("\n    # 认证接口（最严格）")
        for uri_info in uri_types.get('auth', [])[:3]:
            config.append(f"    location = {uri_info['uri']} {{")
            config.append(f"        limit_req zone=auth_zone burst={uri_info['recommended_burst']} nodelay;")
            if 'multi_window' in recommendations and '60s' in recommendations['multi_window']:
                config.append(f"        limit_req zone=limit_60s burst=20;  # 额外的1分钟限制")
            config.append("        # ... 其他配置 ...")
            config.append("    }")

        config.append("\n    # 支付接口（严格）")
        for uri_info in uri_types.get('payment', [])[:3]:
            config.append(f"    location ~ {uri_info['uri']} {{")
            config.append(f"        limit_req zone=payment_zone burst={uri_info['recommended_burst']} nodelay;")
            config.append("        # ... 其他配置 ...")
            config.append("    }")

        config.append("\n    # API 接口（适中）")
        for uri_info in uri_types.get('api', [])[:3]:
            config.append(f"    location ~ ^{uri_info['uri']} {{")
            config.append(f"        limit_req zone=api_zone burst={uri_info['recommended_burst']} nodelay;")
            config.append("        # ... 其他配置 ...")
            config.append("    }")

        config.append("}")

        # 监控和日志配置
        config.append("\n# 4. 监控和日志配置")
        config.append("limit_req_log_level warn;  # 记录被限流的请求")
        config.append("limit_req_status 429;      # 返回 429 状态码")

        # 使用说明
        config.append("\n# ============================================")
        config.append("# 使用说明")
        config.append("# ============================================")
        config.append("""
# 1. 选择合适的方案：
#    - 方案A: 适合流量简单的小型应用
#    - 方案B: 推荐大多数生产环境使用
#    - 方案C: 适合高安全需求场景

# 2. 窗口选择建议：
#    - 10s:  防止瞬时突发、DDoS 攻击
#    - 60s:  API 接口常规保护
#    - 1h:   防止账号滥用、爬虫
#    - 24h:  每日配额、付费限制

# 3. burst 参数说明：
#    - nodelay: 立即处理突发，超过则拒绝（适合短窗口）
#    - 无 nodelay: 排队等待（适合长窗口，避免瞬时拒绝）

# 4. 灰度上线步骤：
#    a) 先在测试环境验证配置
#    b) 生产环境从 loose 模式开始
#    c) 监控 429 错误率，逐步调整
#    d) 最终稳定在 balanced 模式

# 5. 监控指标：
#    - 429 错误率 < 0.5%: 配置合理
#    - 429 错误率 0.5-2%: 可以接受
#    - 429 错误率 > 2%: 需要放宽限制
""")

        return "\n".join(config)

    @staticmethod
    def save_json_report(
            eval_result: Dict[str, Any],
            recommendations: Dict[str, Any],
            uri_analysis: Dict[str, Any],
            anomalies: List[AnomalyAlert],
            sim_result: Optional[Dict[str, Any]],
            output_file: str
    ):
        """保存 JSON 报告"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'evaluation': eval_result,
            'recommendations': recommendations,
            'uri_analysis': uri_analysis,
            'anomalies': [asdict(a) for a in anomalies],
            'simulation': sim_result
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n💾 JSON 报告已保存: {os.path.abspath(output_file)}")


# ========================
# 命令行入口
# ========================
def parse_time_range(last_arg: str) -> Tuple[datetime, datetime]:
    """解析时间范围参数"""
    now = datetime.now().astimezone()

    match = re.match(r'(\d+)([hdw])', last_arg.lower())
    if not match:
        raise ValueError("时间格式错误，应为: 1h, 24h, 7d, 1w")

    value, unit = int(match.group(1)), match.group(2)

    if unit == 'h':
        delta = timedelta(hours=value)
    elif unit == 'd':
        delta = timedelta(days=value)
    elif unit == 'w':
        delta = timedelta(weeks=value)
    else:
        raise ValueError(f"不支持的时间单位: {unit}")

    return (now - delta, now)


def main():
    parser = argparse.ArgumentParser(
        description="生产环境限流策略分析工具 v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基础分析
  %(prog)s access.log

  # 分析最近 24 小时
  %(prog)s access.log --last 24h

  # 自定义限流参数评估
  %(prog)s access.log --window 10 --limit 40

  # 完整报告（含 JSON 输出）
  %(prog)s access.log --last 24h --output-json report.json --output-config nginx.conf

  # 排除内部 IP
  %(prog)s access.log --exclude-ip "10.0.0.0/8,192.168.0.0/16"
        """
    )

    # 必需参数
    parser.add_argument("logfiles", nargs='+', help="日志文件路径（支持 .gz 压缩）")

    # 分析参数
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SEC,
                        help=f"时间窗口（秒，默认 {DEFAULT_WINDOW_SEC}）")
    parser.add_argument("--limit", type=int, default=DEFAULT_MAX_REQ,
                        help=f"当前限流阈值（默认 {DEFAULT_MAX_REQ}）")
    parser.add_argument("--last", type=str, help="分析时间范围，如: 1h, 24h, 7d")
    parser.add_argument("--margin", type=float, default=0.2,
                        help="安全边际系数（默认 0.2 = 20%%）")

    # 过滤器
    parser.add_argument("--exclude-ip", type=str, default="",
                        help="排除的 IP/CIDR，逗号分隔")
    parser.add_argument("--exclude-file", type=str,
                        help="排除 IP 列表文件（每行一个）")
    parser.add_argument("--include-status", type=str, default="2**,3**",
                        help="包含的状态码模式（默认 2**,3** = 只统计成功请求，自动排除 4xx/5xx）")
    parser.add_argument("--exclude-status", type=str,
                        help="额外排除的状态码（如 301,302）")
    parser.add_argument("--include-errors", action="store_true",
                        help="包含 4xx/5xx 错误码（默认自动排除）")
    parser.add_argument("--exclude-ua", type=str,
                        help="额外排除的 UA 关键词，逗号分隔")
    parser.add_argument("--no-exclude-ua", action="store_true",
                        help="禁用 UA 过滤")

    # 日志格式
    parser.add_argument("--log-format", type=str, default=DEFAULT_LOG_FORMAT,
                        help="自定义日志格式")

    # 高级功能
    parser.add_argument("--detect-anomalies", action="store_true",
                        help="启用异常检测")
    parser.add_argument("--anomaly-threshold", type=float, default=3.0,
                        help="异常检测阈值倍数（默认 3.0）")
    parser.add_argument("--simulate", action="store_true",
                        help="模拟推荐策略的效果")

    # 输出
    parser.add_argument("--output-json", type=str,
                        help="JSON 报告输出路径")
    parser.add_argument("--output-config", type=str,
                        help="Nginx 配置文件输出路径")
    parser.add_argument("--quiet", action="store_true",
                        help="静默模式（仅输出文件）")
    parser.add_argument("--debug", action="store_true",
                        help="调试模式（显示详细的解析信息）")
    parser.add_argument("--test-parse", type=int,
                        help="测试模式：只解析前 N 行并显示结果")

    args = parser.parse_args()

    # ---- 测试模式 ----
    if args.test_parse:
        print(f"[TEST] 测试模式：解析前 {args.test_parse} 行", file=sys.stderr)
        print(f"[TEST] 使用日志格式: {args.log_format}\n", file=sys.stderr)

        log_parser = OptimizedLogParser(args.log_format)

        test_count = 0
        success_count = 0

        for logfile in args.logfiles:
            if not os.path.exists(logfile):
                print(f"[ERROR] 文件不存在: {logfile}", file=sys.stderr)
                continue

            print(f"[TEST] 读取文件: {logfile}\n", file=sys.stderr)

            with open_log_file(logfile) as f:
                for line in f:
                    test_count += 1
                    if test_count > args.test_parse:
                        break

                    print(f"{'=' * 70}")
                    print(f"[TEST] 第 {test_count} 行:")
                    print(f"  原始日志: {line.strip()}")

                    parsed = log_parser.parse(line)
                    if parsed:
                        success_count += 1
                        print(f"  ✓ 解析成功:")
                        for key, value in parsed.items():
                            if value:
                                display_value = value[:80] + '...' if len(value) > 80 else value
                                print(f"    {key:12} = {display_value}")
                    else:
                        print(f"  ✗ 解析失败")
                    print()

        print(f"{'=' * 70}")
        print(f"[TEST] 测试完成: {success_count}/{test_count} 行成功解析 ({success_count / test_count * 100:.1f}%)")

        if success_count == 0:
            print(f"\n[建议] 日志格式可能不匹配。你的日志样例:")
            print(
                f"  139.224.207.164 - - [11/Dec/2025:00:00:06 +0800] \"GET /api/global HTTP/1.1\" 200 693 \"-\" \"node\"")
            print(f"\n[建议] 这是标准的 Nginx combined 格式，应该可以自动解析。")
            print(f"[建议] 如果还是失败，请检查:")
            print(f"  1. 文件编码是否为 UTF-8")
            print(f"  2. 是否有特殊字符或格式异常")
            print(f"  3. 尝试使用 --debug 参数获取更多信息")

        sys.exit(0)

    # ---- 初始化过滤器 ----
    print("[INFO] 初始化过滤器...", file=sys.stderr)

    ip_filter = IPFilter(
        args.exclude_ip.split(',') if args.exclude_ip else [],
        args.exclude_file
    )

    # 如果用户要包含错误码，需要修改 include_status
    include_status = args.include_status
    if args.include_errors:
        # 添加 4xx 和 5xx
        include_status = f"{include_status},4**,5**"
        print(f"[INFO] 已启用错误码统计（包含 4xx/5xx）", file=sys.stderr)

    status_filter = StatusFilter(include_status, args.exclude_status)

    # 打印状态码过滤信息
    filter_info = status_filter.get_filter_info()
    print(f"[INFO] 状态码过滤配置:", file=sys.stderr)
    print(f"[INFO]   - 包含状态码数量: {filter_info['include_codes_count']}", file=sys.stderr)
    print(f"[INFO]   - 排除状态码数量: {filter_info['exclude_codes_count']}", file=sys.stderr)
    print(f"[INFO]   - 自动排除 4xx/5xx: {'是' if filter_info['auto_exclude_errors'] else '否'}", file=sys.stderr)
    if filter_info['example_included']:
        print(f"[INFO]   - 示例包含: {filter_info['example_included']}", file=sys.stderr)

    exclude_ua_keywords = [] if args.no_exclude_ua else DEFAULT_EXCLUDE_UA_KEYWORDS.copy()
    if args.exclude_ua:
        exclude_ua_keywords.extend([kw.strip().lower() for kw in args.exclude_ua.split(',')])
    ua_filter = UAFilter(exclude_ua_keywords)

    print(f"[INFO] User-Agent 过滤: {len(exclude_ua_keywords)} 个关键词", file=sys.stderr)

    log_parser = OptimizedLogParser(args.log_format)

    # ---- 解析时间范围 ----
    time_range = None
    if args.last:
        try:
            time_range = parse_time_range(args.last)
            print(f"[INFO] 分析时间范围: {time_range[0]} 至 {time_range[1]}", file=sys.stderr)
        except ValueError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            sys.exit(1)

    # ---- 提取记录（流式处理）----
    print("[INFO] 开始提取日志记录...", file=sys.stderr)
    records = list(stream_records(
        args.logfiles,
        ip_filter,
        status_filter,
        ua_filter,
        log_parser,
        time_range
    ))

    if not records:
        print("[ERROR] 未找到有效记录，请检查日志文件和过滤条件", file=sys.stderr)
        sys.exit(1)

    # ---- 分析 ----
    print("[INFO] 开始分析...", file=sys.stderr)
    analyzer = RateLimitAnalyzer(records)

    eval_result = analyzer.evaluate_policy(args.window, args.limit)
    recommendations = analyzer.recommend_limits(args.margin)
    uri_analysis = analyzer.analyze_uri_patterns()

    # 异常检测
    anomalies = []
    if args.detect_anomalies:
        print("[INFO] 执行异常检测...", file=sys.stderr)
        anomalies = analyzer.detect_anomalies(args.anomaly_threshold)

    # 策略模拟
    sim_result = None
    if args.simulate and 'balanced' in recommendations:
        print("[INFO] 模拟推荐策略效果...", file=sys.stderr)
        balanced = recommendations['balanced']
        sim_result = analyzer.simulate_policy(balanced['rate'], balanced['burst'])

    # ---- 输出报告 ----
    if not args.quiet:
        reporter = ReportGenerator()
        reporter.print_summary(analyzer, eval_result)
        reporter.print_recommendations(recommendations)
        reporter.print_uri_analysis(uri_analysis)

        if anomalies:
            reporter.print_anomalies(anomalies)

        if sim_result:
            reporter.print_simulation(sim_result)

    # ---- 保存文件 ----
    if args.output_json:
        ReportGenerator.save_json_report(
            eval_result,
            recommendations,
            uri_analysis,
            anomalies,
            sim_result,
            args.output_json
        )

    if args.output_config:
        config_content = ReportGenerator.generate_nginx_config(recommendations, uri_analysis)
        with open(args.output_config, 'w', encoding='utf-8') as f:
            f.write(config_content)
        print(f"📝 Nginx 配置已保存: {os.path.abspath(args.output_config)}", file=sys.stderr)

    print("\n✨ 分析完成！", file=sys.stderr)


if __name__ == '__main__':
    main()