#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全能 Nginx 日志分析器（v8 - 支持多文件 + 时间窗口 + 性能优化 + 功能增强）
作者：Xgrug
"""

import re
import gzip
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from functools import lru_cache
import argparse
import os
import json
import csv
import sys

# 日志正则（兼容 combined 格式）
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

DEFAULT_SENSITIVE_PATHS = {
    '/login', '/register', '/admin', '/export', '/backup',
    '/wx/login', '/api/wx/login-check', '/user/reset', '/oauth',
    '/api/admin', '/manage', '/console', '/debug', '/test'
}


class LogAnalyzer:
    """Nginx日志分析器主类"""

    def __init__(self, args):
        self.args = args
        self.time_start, self.time_end = get_time_window(args)
        self.ip_details = defaultdict(lambda: {
            'paths': Counter(),
            'uas': Counter(),
            'statuses': Counter(),
            'total': 0
        })
        self.total_lines = 0
        self.filtered_lines = 0
        self.output_format = getattr(args, 'output_format', 'text')

    def anonymize_ip(self, ip):
        """匿名化IP地址（隐藏最后一段）"""
        if self.args.anonymize_ip:
            parts = ip.split('.')
            if len(parts) == 4:
                return '.'.join(parts[:-1] + ['x'])
        return ip

    def load_and_parse_logs(self, logfiles):
        """加载并解析日志文件"""
        if self.time_start:
            print(
                f"🕒 时间窗口: {self.time_start.strftime('%Y-%m-%d %H:%M:%S %z')} → {self.time_end.strftime('%Y-%m-%d %H:%M:%S %z')}\n")

        for logfile in logfiles:
            if not os.path.exists(logfile):
                self._print_warning(f"日志文件不存在，跳过 → {logfile}")
                continue
            try:
                with open_log_file(logfile) as f:
                    for line in f:
                        self.total_lines += 1
                        match = LOG_PATTERN.search(line)
                        if not match:
                            continue

                        try:
                            log_time = parse_log_time(match.group('time'))
                        except Exception:
                            continue

                        if self.time_start and (log_time < self.time_start or log_time > self.time_end):
                            continue

                        # 过滤状态码
                        if self.args.filter_status:
                            status_class = classify_status_code_class(match.group('status'))
                            if status_class != self.args.filter_status:
                                continue

                        self.filtered_lines += 1

                        ip = match.group('ip')
                        raw_path = match.group('path')
                        path = raw_path.split('?')[0]  # 缓存结果避免重复计算
                        status = match.group('status')
                        ua = match.group('ua').strip() or '-'

                        self.ip_details[ip]['paths'][path] += 1
                        self.ip_details[ip]['uas'][ua] += 1
                        self.ip_details[ip]['statuses'][status] += 1
                        self.ip_details[ip]['total'] += 1
            except Exception as e:
                self._print_error(f"读取日志文件失败：{logfile} → {e}")
                continue

        if self.time_start:
            print(f"📊 共读取 {self.total_lines:,} 行，{self.filtered_lines:,} 行在时间窗口内\n")

    def _print_warning(self, message):
        """打印警告信息"""
        if self.output_format == 'text':
            print(f"⚠️  {message}")

    def _print_error(self, message):
        """打印错误信息"""
        if self.output_format == 'text':
            print(f"❌ {message}")

    def analyze(self):
        """执行分析任务"""
        # 加载日志
        self.load_and_parse_logs(self.args.logfiles)

        # 根据不同模式执行分析
        if self.args.group_by == "freq-status":
            self._group_by_freq_status()
            return

        # 构建全局统计
        self._build_global_stats()

        # 执行特定查询
        if self.args.path:
            self._analyze_path()
            return

        if self.args.ip:
            self._analyze_ip()
            return

        # 执行全局分析
        self._global_analysis()

    def _build_global_stats(self):
        """构建全局统计数据"""
        self.path_details = defaultdict(lambda: {
            'ips': Counter(),
            'statuses': Counter(),
            'uas': Counter(),
            'total': 0
        })
        self.ip_counter = Counter()
        self.path_counter = Counter()
        self.status_counter = Counter()
        self.status_class_counter = Counter()

        for ip, detail in self.ip_details.items():
            self.ip_counter[ip] = detail['total']
            for path, cnt in detail['paths'].items():
                self.path_counter[path] += cnt
                self.path_details[path]['ips'][ip] += cnt
                self.path_details[path]['total'] += cnt
            for status, cnt in detail['statuses'].items():
                self.status_counter[status] += cnt
                self.status_class_counter[classify_status_for_display(status)] += cnt
            for ua, cnt in detail['uas'].items():
                for path in detail['paths']:
                    self.path_details[path]['uas'][ua] += cnt

    def _group_by_freq_status(self):
        """按频率和状态码分组分析"""
        groups = {
            '🔴 高频 + 高错误率': [],
            '🟠 高频 + 低错误率（可能合法）': [],
            '🟡 中频 + 敏感路径集中': [],
            '🔵 中频 + 高错误率（非敏感）': [],
            '🟢 低频 + 全成功': [],
            '⚪ 低频 + 高错误率': [],
        }

        for ip, detail in self.ip_details.items():
            total = detail['total']
            error_count = sum(
                cnt for status, cnt in detail['statuses'].items()
                if 400 <= int(status) < 600
            )
            error_rate = error_count / total if total > 0 else 0

            sensitive_count = sum(
                cnt for path, cnt in detail['paths'].items()
                if is_sensitive_path(path, self.args.sensitive_paths)
            )
            sensitive_ratio = sensitive_count / total if total > 0 else 0

            if total >= self.args.high_freq:
                if error_rate >= self.args.error_rate:
                    groups['🔴 高频 + 高错误率'].append((ip, total, error_rate, sensitive_ratio))
                else:
                    groups['🟠 高频 + 低错误率（可能合法）'].append((ip, total, error_rate, sensitive_ratio))
            elif total >= self.args.mid_freq:
                if sensitive_ratio >= self.args.sensitive_ratio:
                    groups['🟡 中频 + 敏感路径集中'].append((ip, total, error_rate, sensitive_ratio))
                elif error_rate >= self.args.error_rate:
                    groups['🔵 中频 + 高错误率（非敏感）'].append((ip, total, error_rate, sensitive_ratio))
            else:
                if error_rate == 0:
                    groups['🟢 低频 + 全成功'].append((ip, total, error_rate, sensitive_ratio))
                elif error_rate >= self.args.error_rate:
                    groups['⚪ 低频 + 高错误率'].append((ip, total, error_rate, sensitive_ratio))

        if self.output_format == 'json':
            result = {}
            for group_name, ips in groups.items():
                if ips:
                    result[group_name] = []
                    sorted_ips = sorted(ips, key=lambda x: x[1], reverse=True)[:self.args.top]
                    for ip, total, err, sens in sorted_ips:
                        result[group_name].append({
                            'ip': self.anonymize_ip(ip),
                            'requests': total,
                            'error_rate': round(err * 100, 1),
                            'sensitive_ratio': round(sens * 100, 1)
                        })
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif self.output_format == 'csv':
            writer = csv.writer(sys.stdout)
            writer.writerow(['group', 'ip', 'requests', 'error_rate_%', 'sensitive_ratio_%'])
            for group_name, ips in groups.items():
                if ips:
                    sorted_ips = sorted(ips, key=lambda x: x[1], reverse=True)[:self.args.top]
                    for ip, total, err, sens in sorted_ips:
                        writer.writerow([
                            group_name,
                            self.anonymize_ip(ip),
                            total,
                            round(err * 100, 1),
                            round(sens * 100, 1)
                        ])
        else:  # text format
            print("🔍 按 [请求频率 + 状态码特征] 分组的 IP 列表\n")
            any_output = False
            for group_name, ips in groups.items():
                if ips:
                    any_output = True
                    print(f"{group_name}:")
                    sorted_ips = sorted(ips, key=lambda x: x[1], reverse=True)[:self.args.top]
                    for ip, total, err, sens in sorted_ips:
                        print(f"  - {self.anonymize_ip(ip):<15}: {total:>6} 次, "
                              f"错误率 {err * 100:5.1f}%, "
                              f"敏感接口 {sens * 100:5.1f}%")
                    print()
            if not any_output:
                print("✅ 未发现符合当前阈值条件的 IP")

    def _analyze_path(self):
        """分析特定路径"""
        clean_path = self.args.path.split('?')[0]
        if clean_path not in self.path_details:
            if self.output_format == 'text':
                print(f"❌ 路径 '{self.args.path}' 在指定时间窗口内未出现")
            return

        detail = self.path_details[clean_path]

        if self.output_format == 'json':
            result = {
                'path': clean_path,
                'total_requests': detail['total'],
                'status_distribution': {},
                'top_ips': [],
                'top_user_agents': []
            }

            for status, cnt in detail['statuses'].most_common():
                cls = classify_status_for_display(status).split()[0]
                result['status_distribution'][status] = {
                    'count': cnt,
                    'class': cls
                }

            for ip, cnt in detail['ips'].most_common(10):
                result['top_ips'].append({
                    'ip': self.anonymize_ip(ip),
                    'count': cnt
                })

            for ua, cnt in detail['uas'].most_common(5):
                display_ua = ua[:60] + '...' if len(ua) > 60 else ua
                result['top_user_agents'].append({
                    'user_agent': display_ua,
                    'count': cnt
                })

            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif self.output_format == 'csv':
            writer = csv.writer(sys.stdout)
            writer.writerow(['type', 'value', 'count'])

            # 状态码分布
            for status, cnt in detail['statuses'].most_common():
                cls = classify_status_for_display(status).split()[0]
                writer.writerow(['status', f"{status} ({cls})", cnt])

            # Top IPs
            for ip, cnt in detail['ips'].most_common(10):
                writer.writerow(['ip', self.anonymize_ip(ip), cnt])

            # Top User-Agents
            for ua, cnt in detail['uas'].most_common(5):
                display_ua = ua[:60] + '...' if len(ua) > 60 else ua
                writer.writerow(['user_agent', display_ua, cnt])
        else:  # text format
            print(f"🔍 详细分析路径: {clean_path}")
            print(f"总访问次数: {detail['total']}")

            print("\n📊 状态码分布:")
            for status, cnt in detail['statuses'].most_common():
                cls = classify_status_for_display(status).split()[0]
                print(f"  - {status} ({cls}): {cnt} 次")

            print(f"\n🌐 Top {min(10, len(detail['ips']))} 访问 IP:")
            for ip, cnt in detail['ips'].most_common(10):
                print(f"  - {self.anonymize_ip(ip)}: {cnt} 次")

            print(f"\n📱 Top User-Agent (前 5):")
            for ua, cnt in detail['uas'].most_common(5):
                display_ua = ua[:60] + '...' if len(ua) > 60 else ua
                print(f"  - {display_ua}: {cnt} 次")

    def _analyze_ip(self):
        """分析特定IP"""
        if self.args.ip not in self.ip_details:
            if self.output_format == 'text':
                print(f"❌ IP {self.args.ip} 在指定时间窗口内未出现")
            return

        detail = self.ip_details[self.args.ip]

        if self.output_format == 'json':
            result = {
                'ip': self.anonymize_ip(self.args.ip),
                'total_requests': detail['total'],
                'status_distribution': {},
                'top_paths': [],
                'top_user_agents': []
            }

            for status, cnt in detail['statuses'].most_common():
                cls = classify_status_for_display(status).split()[0]
                result['status_distribution'][status] = {
                    'count': cnt,
                    'class': cls
                }

            for path, cnt in detail['paths'].most_common(10):
                result['top_paths'].append({
                    'path': path,
                    'count': cnt
                })

            for ua, cnt in detail['uas'].most_common(3):
                display_ua = ua[:60] + '...' if len(ua) > 60 else ua
                result['top_user_agents'].append({
                    'user_agent': display_ua,
                    'count': cnt
                })

            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif self.output_format == 'csv':
            writer = csv.writer(sys.stdout)
            writer.writerow(['type', 'value', 'count'])

            # 状态码分布
            for status, cnt in detail['statuses'].most_common():
                cls = classify_status_for_display(status).split()[0]
                writer.writerow(['status', f"{status} ({cls})", cnt])

            # Top Paths
            for path, cnt in detail['paths'].most_common(10):
                writer.writerow(['path', path, cnt])

            # Top User-Agents
            for ua, cnt in detail['uas'].most_common(3):
                display_ua = ua[:60] + '...' if len(ua) > 60 else ua
                writer.writerow(['user_agent', display_ua, cnt])
        else:  # text format
            print(f"🔍 详细分析 IP: {self.anonymize_ip(self.args.ip)}")
            print(f"总请求次数: {detail['total']}")

            print("\n📊 状态码分布:")
            for status, cnt in detail['statuses'].most_common():
                cls = classify_status_for_display(status).split()[0]
                print(f"  - {status} ({cls}): {cnt} 次")

            print(f"\n🚀 Top {min(10, len(detail['paths']))} 访问路径:")
            for path, cnt in detail['paths'].most_common(10):
                print(f"  - {path}: {cnt} 次")

            print(f"\n📱 Top User-Agent (前 3):")
            for ua, cnt in detail['uas'].most_common(3):
                display_ua = ua[:60] + '...' if len(ua) > 60 else ua
                print(f"  - {display_ua}: {cnt} 次")

    def _global_analysis(self):
        """全局分析"""
        if self.output_format == 'json':
            result = {
                'summary': {
                    'total_lines': self.total_lines,
                    'filtered_lines': self.filtered_lines
                },
                'status_classes': {},
                'ip_groups': {},
                'top_ips': [],
                'top_paths': []
            }

            # 状态码分类统计
            for cls, count in self.status_class_counter.most_common():
                result['status_classes'][cls] = count

            # IP分组统计
            ip_groups = self._group_ips_by_request_count()
            for group, count in ip_groups.items():
                result['ip_groups'][group] = count

            # Top IPs
            for i, (ip, count) in enumerate(self.ip_counter.most_common(self.args.top), 1):
                result['top_ips'].append({
                    'rank': i,
                    'ip': self.anonymize_ip(ip),
                    'requests': count
                })

            # Top Paths
            for i, (path, count) in enumerate(self.path_counter.most_common(self.args.top), 1):
                result['top_paths'].append({
                    'rank': i,
                    'path': path,
                    'requests': count
                })

            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif self.output_format == 'csv':
            writer = csv.writer(sys.stdout)

            # 状态码分类统计
            writer.writerow(['section', 'item', 'count'])
            for cls, count in self.status_class_counter.most_common():
                writer.writerow(['status_class', cls, count])

            # IP分组统计
            ip_groups = self._group_ips_by_request_count()
            for group, count in ip_groups.items():
                writer.writerow(['ip_group', group, count])

            # Top IPs
            writer.writerow([])  # 空行分隔
            writer.writerow(['rank', 'ip', 'requests'])
            for i, (ip, count) in enumerate(self.ip_counter.most_common(self.args.top), 1):
                writer.writerow([i, self.anonymize_ip(ip), count])

            # Top Paths
            writer.writerow([])  # 空行分隔
            writer.writerow(['rank', 'path', 'requests'])
            for i, (path, count) in enumerate(self.path_counter.most_common(self.args.top), 1):
                writer.writerow([i, path, count])
        else:  # text format
            print(f"📊 全能日志分析报告（Top {self.args.top}）\n")
            print("=" * 70)

            print("🚦 状态码分类统计:")
            for cls, count in self.status_class_counter.most_common():
                print(f"  {cls:<20} → {count:>8} 次")
            print()

            groups = self._group_ips_by_request_count()
            print("📁 IP 请求量分组:")
            for group, count in groups.items():
                print(f"  {group:<25} → {count:>6} 个 IP")
            print()

            print(f"🔝 Top {self.args.top} 请求 IP:")
            for i, (ip, count) in enumerate(self.ip_counter.most_common(self.args.top), 1):
                print(f"{i:2}. {self.anonymize_ip(ip):<15} → {count:>8} 次")
            print()

            print(f"🚀 Top {self.args.top} 访问路径:")
            for i, (path, count) in enumerate(self.path_counter.most_common(self.args.top), 1):
                print(f"{i:2}. {path:<40} → {count:>8} 次")

    def _group_ips_by_request_count(self, high=None, mid=None):
        """根据请求次数对IP进行分组"""
        if high is None:
            high = self.args.high_freq
        if mid is None:
            mid = self.args.mid_freq

        groups = {
            f'超高频 (≥{high:,})': 0,
            f'高频 ({mid:,} ~ {high - 1:,})': 0,
            f'中频 (100 ~ {mid - 1:,})': 0,
            '低频 (<100)': 0
        }
        for count in self.ip_counter.values():
            if count >= high:
                groups[f'超高频 (≥{high:,})'] += 1
            elif count >= mid:
                groups[f'高频 ({mid:,} ~ {high - 1:,})'] += 1
            elif count >= 100:
                groups[f'中频 (100 ~ {mid - 1:,})'] += 1
            else:
                groups['低频 (<100)'] += 1
        return groups


def parse_log_time(time_str):
    """解析 Nginx 时间戳"""
    try:
        return datetime.strptime(time_str, TIME_FORMAT)
    except ValueError:
        if len(time_str) >= 5 and time_str[-5] not in ('+', '-'):
            # 尝试修复时区前无空格的情况，如 "10/Dec/2025:10:30:45+0800"
            fixed = time_str[:-5] + ' ' + time_str[-5:]
            return datetime.strptime(fixed, TIME_FORMAT)
        raise


def get_time_window(args):
    """返回 (start, end) datetime 范围（aware）"""
    now = datetime.now().astimezone()
    if args.today:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, now
    if args.last:
        unit = args.last[-1].lower()
        value = int(args.last[:-1])
        delta = timedelta(hours=value) if unit == 'h' else timedelta(days=value)
        start = now - delta
        return start, now
    return None, None


def open_log_file(filepath):
    """智能打开 .log 或 .log.gz 文件"""
    try:
        if filepath.endswith('.gz'):
            return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
        else:
            return open(filepath, 'r', encoding='utf-8', errors='ignore')
    except PermissionError:
        raise Exception("Permission denied")
    except FileNotFoundError:
        raise Exception("File not found")
    except Exception as e:
        raise Exception(f"Unknown error opening file: {str(e)}")


@lru_cache(maxsize=1024)
def classify_status_for_display(status):
    """带缓存的状态码显示映射"""
    s = int(status)
    if 200 <= s < 300:
        return "✅ 2xx 成功"
    elif 300 <= s < 400:
        return "🔀 3xx 重定向"
    elif 400 <= s < 500:
        return "⚠️ 4xx 客户端错误"
    elif 500 <= s < 600:
        return "💥 5xx 服务端错误"
    else:
        return "❓ 其他"


def classify_status_code_class(status):
    """分类状态码类别"""
    s = int(status)
    if 200 <= s < 300:
        return "2xx"
    elif 300 <= s < 400:
        return "3xx"
    elif 400 <= s < 500:
        return "4xx"
    elif 500 <= s < 600:
        return "5xx"
    else:
        return "other"


def is_sensitive_path(path, sensitive_paths_set):
    """判断是否为敏感路径"""
    clean = path.split('?')[0].rstrip('/')
    for sp in sensitive_paths_set:
        # 更严格的路径匹配规则，防止误命中类似 /admin -> /administrator
        if clean == sp or (sp.endswith('/') and clean.startswith(sp)):
            return True
    return False


def parse_sensitive_paths(paths_str):
    """解析敏感路径列表"""
    if not paths_str:
        return DEFAULT_SENSITIVE_PATHS
    parsed = set()
    for p in paths_str.split(','):
        stripped = p.strip()
        if stripped.startswith('/'):
            parsed.add(stripped.rstrip('/'))
        else:
            print(f"⚠️ 忽略非法路径: {stripped} （必须以 '/' 开头）")
    return parsed


def main():
    parser = argparse.ArgumentParser(
        description="全能 Nginx 日志分析器（支持多文件、时间窗口、GZ 压缩）",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("logfiles", nargs='+', help="一个或多个日志文件（支持 .gz）")
    parser.add_argument("--top", type=int, default=20, help="Top N 数量（默认 20）")

    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument("--last", type=str, help="最近时间，如 '1h', '24h', '7d'")
    time_group.add_argument("--today", action="store_true", help="仅今天")

    query_group = parser.add_mutually_exclusive_group()
    query_group.add_argument("--ip", help="查询特定 IP")
    query_group.add_argument("--path", help="查询特定路径")
    query_group.add_argument("--group-by", choices=["freq-status"], help="按频率+状态分组")

    parser.add_argument("--high-freq", type=int, default=1000, help="高频阈值（默认 1000）")
    parser.add_argument("--mid-freq", type=int, default=100, help="中频阈值（默认 100）")
    parser.add_argument("--error-rate", type=float, default=0.5, help="错误率阈值（0.0~1.0）")
    parser.add_argument("--sensitive-ratio", type=float, default=0.5, help="敏感路径占比阈值")
    parser.add_argument("--sensitive-paths", type=str, help="自定义敏感路径（逗号分隔）")

    # 新增功能参数
    parser.add_argument("--output-format", choices=["text", "json", "csv"], default="text",
                        help="输出格式(text/json/csv)")
    parser.add_argument("--filter-status", choices=["2xx", "3xx", "4xx", "5xx"], help="只分析特定状态码类别")
    parser.add_argument("--anonymize-ip", action="store_true", help="输出时隐藏IP最后一段")

    args = parser.parse_args()

    args.sensitive_paths = parse_sensitive_paths(args.sensitive_paths)

    if args.last:
        if not re.match(r'^\d+[hd]$', args.last, re.IGNORECASE):
            parser.error("--last 必须是数字+h/d，如 '1h', '24h', '7d'")

    if not (0.0 <= args.error_rate <= 1.0):
        parser.error("--error-rate 必须在 0.0 ~ 1.0 之间")
    if not (0.0 <= args.sensitive_ratio <= 1.0):
        parser.error("--sensitive-ratio 必须在 0.0 ~ 1.0 之间")

    # 执行分析
    analyzer = LogAnalyzer(args)
    analyzer.analyze()


if __name__ == '__main__':
    main()