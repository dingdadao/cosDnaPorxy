# 🌐 DNS 代理服务 - 项目结构说明

## 📁 项目目录结构

```
cosDnaPorxy/
├── main.go                    # 主入口文件
├── go.mod                     # Go模块文件
├── go.sum                     # Go依赖锁定文件
├── .gitignore                 # Git忽略文件
├── .go-version               # Go版本文件
│
├── internal/                  # 内部代码模块
│   ├── config/               # 配置管理
│   │   └── config.go         # 配置结构体和加载逻辑
│   ├── dns/                  # DNS核心功能
│   │   ├── handler.go        # DNS处理器核心逻辑
│   │   ├── server.go         # DNS服务器启动逻辑
│   │   └── types.go          # DNS相关类型定义
│   ├── geosite/              # 地理位置管理
│   │   └── manager.go        # Geosite数据管理
│   ├── metrics/              # 监控指标
│   │   └── collector.go      # Prometheus指标收集
│   └── utils/                # 工具函数
│       ├── domain.go         # 域名处理工具
│       ├── errors.go         # 错误处理工具
│       └── logger.go         # 日志工具
│
├── configs/                   # 配置文件目录
│   ├── config.yaml           # 主配置文件
│   ├── jp.yaml              # 日本特定域名配置
│   ├── whitelist.txt        # 白名单域名
│   ├── designated.txt       # 定向域名配置
│   ├── fullchain.pem        # TLS证书（需要添加）
│   └── privkey.pem          # TLS私钥（需要添加）
│
├── data/                     # 数据文件目录
│   ├── geosite.dat          # 地理位置数据
│   ├── geosite.proto        # 地理位置协议定义
│   ├── aws.txt              # AWS IP范围数据
│   ├── cloudflare-v4.txt    # Cloudflare IPv4范围
│   └── cloudflare-v6.txt    # Cloudflare IPv6范围
│
├── docs/                     # 文档目录
│   ├── README.md            # 项目说明文档
│   ├── OPTIMIZATION_GUIDE.md # 优化指南
│   └── REFACTOR_GUIDE.md    # 重构指南
│
├── scripts/                  # 脚本目录
│   ├── shell/               # Shell脚本
│   │   └── updatecartv2.1.sh # 证书更新脚本
│   └── test/                # 测试脚本
│       ├── README.md        # 测试说明文档
│       ├── test_dns.sh      # 基础DNS测试
│       ├── test_doh_*.sh    # DoH功能测试
│       ├── test_cname_*.sh  # CNAME解析测试
│       └── test_*.sh        # 其他功能测试
│
├── bin/                      # 可执行文件目录
│   └── dnsupdate            # 编译后的可执行文件
│
├── build/                    # 构建输出目录（GitHub Actions使用）
│
├── v2ray.com/               # V2Ray协议相关（第三方）
│   └── core/common/protocol/
│       └── geosite.pb.go    # 地理位置协议生成代码
│
├── vendor/                  # Go依赖包（第三方）
└── .github/                 # GitHub配置
```

## 🚀 快速开始

### 1. 编译项目

```bash
# 本地编译
go build -o bin/dnsupdate main.go

# 或使用指定Go版本
/Users/dension/.goenv/versions/1.23.9/bin/go build -o bin/dnsupdate main.go
```

### 2. 运行服务

```bash
# 使用默认配置文件
./bin/dnsupdate

# 指定配置文件
./bin/dnsupdate -c configs/config.yaml
```

### 3. 配置说明

- 主配置文件：`configs/config.yaml`
- 白名单域名：`configs/whitelist.txt`
- 定向域名：`configs/designated.txt`

## 📋 目录说明

### `internal/` - 核心代码

- **config/**: 配置管理模块
- **dns/**: DNS 处理核心逻辑
- **geosite/**: 地理位置数据管理
- **metrics/**: 监控指标收集
- **utils/**: 通用工具函数

### `configs/` - 配置文件

- 所有配置文件集中管理
- 便于部署和维护
- 支持多环境配置

### `data/` - 数据文件

- 地理位置数据
- IP 范围数据
- 协议定义文件

### `docs/` - 文档

- 项目说明文档
- 优化指南
- 重构指南

### `scripts/` - 脚本工具

- 证书更新脚本
- 部署脚本
- 维护脚本

### `build/` - 构建输出

- 编译后的可执行文件
- 便于分发和部署

## 🔧 开发指南

### 添加新功能

1. 在 `internal/` 下创建相应模块
2. 更新配置文件（如需要）
3. 添加文档说明
4. 编写测试用例

### 修改配置

1. 编辑 `configs/config.yaml`
2. 更新相关文件路径
3. 重启服务生效

### 部署

1. 编译项目：`go build -o bin/dnsupdate main.go`
2. 复制配置文件到目标服务器
3. 运行服务：`./bin/dnsupdate -c configs/config.yaml`

### 测试

```bash
# 运行测试脚本
cd scripts/test
chmod +x *.sh
./test_dns.sh

# 查看测试说明
cat README.md
```

## 📊 监控

### Prometheus 指标

- 访问 `http://localhost:9090/metrics` 查看指标
- 支持查询统计、延迟监控、缓存命中率等

### 日志

- 支持不同级别的日志输出
- 可通过配置文件调整日志级别

## 🤝 贡献

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request

## 📄 许可证

本项目采用 MIT 许可证。

---

_最后更新：2024 年 12 月_
