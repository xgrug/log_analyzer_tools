# **Nginx 请求频率自动化分析报告生成器**

*—— 智能限流配置建议 · 安全风险识别 · 高性能日志解析*

## 📌 一、概述

- 自动解析 **原始或 `.gz` 压缩的 Nginx 日志**
- 生成 **交互式 HTML 报告 + JSON 数据 + Nginx 配置建议**
- 支持 **时间窗口筛选、IP/路径定向分析**

> ✅ 适用于：DDoS 防护、API 限流调优、安全审计、容量规划。

## ⚙️ 三、安装与依赖

### 环境要求

- Python ≥ 3.7（推荐 3.9+）
- 无第三方依赖（仅使用标准库）

## 🧪 四、使用方法

### 基础命令

```bash
python nginx_rate_analyzer.py /var/log/nginx/access.log
```

> 自动生成 `rate_report_20251211_1430.html` + `.json`

### 常用参数

| 参数                  | 说明            | 示例                                |
|---------------------|---------------|-----------------------------------|
| `logfiles`          | 日志文件路径（支持通配符） | `logs/*.log`, `access.log.gz`     |
| `--last`            | 分析最近时间段       | `--last 1h`, `--last 24h`         |
| `--target-ip`       | 仅分析指定 IP      | `--target-ip 203.0.113.5`         |
| `--target-path`     | 仅分析指定路径       | `--target-path /api/v1/login`     |
| `--sensitive-paths` | 自定义敏感路径（逗号分隔） | `--sensitive-paths "/pay,/admin"` |
| `--output`          | 指定 HTML 输出路径  | `--output my_report.html`         |

### 实战示例

#### 1. **安全审计：检查暴力破解行为**

```bash
python nginx_rate_analyzer.py access.log --last 6h --target-path /login
```

> 重点关注“高风险 IP + 路径组合”表格

#### 2. **API 限流调优**

```bash
python nginx_rate_analyzer.py api_access.log.gz --sensitive-paths "/api/v1/pay,/api/v1/export"
```

> 查看“敏感路径”限流建议（通常设为 `burst=5 nodelay`）

#### 3. **全局容量评估**

```bash
python nginx_rate_analyzer.py /data/nginx/logs/*.log --last 7d
```

> 获取 P99 QPS 和全局限流建议

---

## 📊 五、报告内容详解

生成的 HTML 报告包含以下模块：

### 1. **全局请求频率 (QPS)**

- 平均/峰值/P95/P99 QPS
- **全局限流建议**：`rate=XXr/s`

### 2. **路径请求频率 (RPM)**

- **敏感路径**：高亮显示，建议严格限流
- **普通路径**：按请求量排序，标注“波动性指数”（高波动需关注）

### 3. **IP 行为分析**

- Top 100 IP 的总请求、P95 QPS
- 异常 IP 可能是爬虫或攻击源

### 4. **高风险行为检测**

- 结合 **路径敏感度 + 请求频率 + 总量** 计算风险评分
- 自动标记需重点防护的 `(IP, Path)` 组合

### 5. **HTTP 状态码分布**

- 成功率 vs 错误率（4xx/5xx）
- 快速发现服务异常或滥用

### 6. **Nginx 限流配置建议**

- 自动生成 `limit_req_zone` 和 `location` 配置片段
- 可直接复制到 `nginx.conf` 使用

---

## 🔐 六、安全设计

- **HTML 转义**：所有动态内容（IP、路径）经 `html.escape()` 处理，防止 XSS
- **路径规范化**：自动去除查询参数（`/login?user=admin` → `/login`）
- **错误容忍**：跳过格式错误的日志行，不影响整体分析
- **内存优化**：仅存储聚合数据，不加载原始日志到内存

---

## 📦 七、输出文件说明

| 文件                   | 内容     | 用途             |
|----------------------|--------|----------------|
| `rate_report_*.html` | 可视化报告  | 浏览器打开查看分析结果    |
| `rate_report_*.json` | 结构化数据  | 供其他系统消费（如监控平台） |
| 控制台输出                | CLI 摘要 | 快速获取关键指标       |

> 💡 JSON 数据包含：限流阈值、高风险项、Top IP/Path 列表、Nginx 配置片段