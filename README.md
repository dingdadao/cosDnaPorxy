# 🌐 DNS 代理服务 - 简化版

## �� 快速开始

### 1. 编译项目

```bash
# 本地编译
go build -o bin/dnsproxy main.go

# 或使用指定Go版本
/Users/dension/.goenv/versions/1.23.9/bin/go build -o bin/dnsproxy main.go
```

### 2. 运行服务

```bash
# 使用默认配置文件
./bin/dnsproxy

# 指定配置文件
./bin/dnsproxy -c config.yaml
```

### 3. 配置说明

- 主配置文件：`config.yaml`
- 白名单域名：`data/whitelist.txt`
- 定向域名：`data/designated.txt`

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

### 基本配置
```yaml
# DNS服务监听端口
listen_port: 5354

# 上游DNS服务器列表
upstream:
  - "223.5.5.5:53" # 阿里DNS
  - "119.29.29.29:53" # 腾讯DNS
  - "8.8.8.8:53" # Google DNS

# 云服务IP替换配置
replace_cf_domain: "cf-cname.example.com" # Cloudflare替换域名
replace_aws_domain: "aws-cname.example.com" # AWS替换域名
```

### 缓存配置
```yaml
cache:
  max_items: 5000 # 最大缓存条目数
  ttl: "5m" # 缓存TTL
  refresh_threshold: "30s" # 刷新阈值
  enable_async_refresh: true # 启用异步刷新
  max_async_workers: 5 # 异步工作线程数
  eviction_policy: "user_query_time" # 淘汰策略
```

## 📊 项目结构

### `internal/` - 核心代码
- **config/**: 配置管理模块
- **dns/**: DNS处理核心逻辑
- **utils/**: 通用工具函数

### `data/` - 数据文件
- IP范围数据文件
- 白名单和定向域名文件

## 🚀 部署

1. 编译项目：`go build -o bin/dnsproxy main.go`
2. 复制配置文件到目标服务器
3. 运行服务：`./bin/dnsproxy -c config.yaml`

## 🤝 贡献

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request
