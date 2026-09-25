# 🌐 DNS 代理服务 - 简化版

## 🚀 快速开始

### 1. 编译项目

```bash
# 本地编译（输出 bin/dnsproxy）
go build -o bin/dnsproxy .

# 或使用 Makefile（输出 build/dnsproxy）
make build

# 交叉编译 Linux amd64（输出 build/dnsproxy-linux-amd64）
make build-linux

# 开发时直接跑
go run .
```

### 2. 运行服务

```bash
./bin/dnsproxy
```

程序**不接受任何命令行参数，也没有配置文件**。有两点必须注意：

- 配置全部存在 `./data/config.db`（SQLite）里，程序**以当前工作目录为基准**读写 `./data/` 与 `./logs/`。因此要在固定目录下启动，否则会在不同目录各建一套库（systemd 单元里用 `WorkingDirectory` 固定了这一点）。
- 首次启动时 `./data/config.db` 不存在，程序用内置默认值建库并落库：

| 项 | 默认值 |
|---|---|
| DNS 监听 | `:53`（同时开 UDP 与 TCP） |
| Web 管理端 | `:5380` |
| 上游 | 阿里 DoH、腾讯 DoH、腾讯 UDP |
| 分流列表 | 「定向域名」30 分钟刷新、「中国域名」24 小时刷新 |
| 缓存 | TTL 5 分钟 / 最多 5000 条 |

> 默认端口 53 是特权端口，非 root 运行会绑定失败。本地开发可先用 `sudo`，或先起在非特权端口、再进 Web 端改 `listen_port`。

### 3. 打开管理端

浏览器访问 `http://<主机>:5380`。端口、上游、分流规则、ECS、A/AAAA 偏好档位、缓存策略、解析日志都在这里改。

## 📋 功能特性

### 核心功能
- **DNS代理**：支持UDP、DoT、DoH协议
- **云服务替换**：自动检测并替换Cloudflare和AWS的IP地址
- **智能缓存**：高性能DNS缓存系统，支持异步刷新
- **定向解析**：支持指定域名使用特定DNS服务器

### 已移除功能
- ~~智能分流~~：不再根据地理位置分流DNS查询
- ~~监控指标~~：移除了Prometheus指标收集

## 🔧 配置说明

配置的**唯一来源**是 `./data/config.db`，没有 YAML 配置文件（旧版的 `config.yaml` 已废弃，程序不会读取）。

- `settings` 表：`key='config'` 一行，存整份配置的 JSON
- `overrides` 表：本地域名篡改记录，优先级最高，命中即返回、不走缓存与上游

改配置只有一条路：Web 管理端 `PUT /api/config`，保存后分两类：

- **热字段**（上游、分流列表、ECS、A/AAAA 偏好档位、缓存时长等）：立即生效，`restart_required=false`
- **重启字段**（`listen_port`、`web_addr`、`log_format`）：已落库但需重启进程，`restart_required=true`，执行 `systemctl restart dnsproxy`

### 数据文件（`./data/`）

| 文件 | 用途 |
|---|---|
| `config.db` | 配置库（唯一配置来源） |
| `query_log.db` | 解析日志库，独立存储；默认保留 3 天 / 最多 20 万条 |
| `designated.yaml`、`china_domains.yaml` | 各分流列表的域名清单；缺失时按列表里配置的 URL 自动下载 |
| `cf_mrs_file4.txt`、`cf_mrs_file6.txt`、`aws.txt` | 云服务 IP 段，用于云 IP 替换 |

## 📊 项目结构

### `internal/` - 核心代码
- **config/**: 配置管理模块（`config.go` 内存模型、`json.go` JSON 双向映射、`store.go` SQLite 读写）
- **dns/**: DNS处理核心逻辑
- **querylog/**: 解析日志库
- **recovery/**: 启动编排与 panic 恢复
- **web/**: Web 管理端（`admin.html` + REST API）
- **utils/**: 通用工具函数

### `data/` - 数据文件
- 配置库与解析日志库（SQLite）
- 分流列表域名清单、云服务 IP 段文件

## 🚀 部署

生产环境用 systemd 守护，单元模板与安装脚本在 `scripts/service/`。

```bash
# 1) 交叉编译
GOOS=linux GOARCH=amd64 go build -o build/dnsproxy-linux-amd64 .

# 2) 上传到目标机的程序目录
scp build/dnsproxy-linux-amd64 root@<host>:/opt/dnsProxy/dnsproxy.new

# 3) 首次部署：安装并启用 systemd 单元（会先备份已有的同名单元）
scp -r scripts/service root@<host>:/tmp/
ssh root@<host> 'bash /tmp/service/install_service.sh'

# 4) 后续升级：备份旧二进制 → 覆盖 → 重启 → 自检
ssh root@<host> 'bash /opt/dnsProxy/deploy_remote.sh'
```

`deploy_remote.sh` 里的程序目录（`/opt/dnsProxy`）与端口断言（`53` / `5380`）是主机相关的，换机器或改端口时需要同步修改。它部署前会打印待部署文件的 sha256 供核对，出错可从同目录的 `dnsproxy.bak.<时间戳>` 回滚。

> **重启会有约 5 秒中断**：进程启动时要加载云服务 IP 段与分流列表，之后才绑定端口。请在低峰时段操作。

## 🤝 贡献

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request