# 📁 整理后的项目目录结构

## 🎯 整理目标

- 将测试脚本统一管理到 `scripts/test/` 目录
- 将可执行文件移动到 `bin/` 目录
- 清理不必要的文件（如 .DS_Store）
- 更新文档反映新的目录结构

## 📂 当前目录结构

```
cosDnaPorxy/
├── main.go                    # 主入口文件
├── go.mod                     # Go模块文件
├── go.sum                     # Go依赖锁定文件
├── .gitignore                 # Git忽略文件
├── .go-version               # Go版本文件
├── Makefile                   # 构建脚本
├── config.yaml               # 当前使用的配置文件
├── fullchain.pem             # TLS证书
├── privkey.pem               # TLS私钥
│
├── bin/                       # 可执行文件目录
│   └── dnsupdate             # 编译后的可执行文件
│
├── build/                     # 构建输出目录（GitHub Actions使用）
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
│   └── designated.txt       # 定向域名配置
│
├── data/                     # 数据文件目录
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
│   └── test/                # 测试脚本目录
│       ├── README.md        # 测试说明文档
│       ├── test_dns.sh      # 基础DNS测试
│       ├── test_doh_connectivity.sh # DoH连通性测试
│       ├── test_doh_fixed.sh # DoH修复后功能测试
│       ├── test_upstream_doh.sh # 上游DoH配置测试
│       ├── test_cname_resolution.sh # CNAME解析测试
│       ├── simple_cname_test.sh # 简单CNAME测试
│       ├── test_dns_protocols.sh # 多协议DNS测试
│       ├── test_multiprotocol.sh # 多协议并发测试
│       └── test_geosite.go  # Geosite功能测试
│
├── .github/                  # GitHub配置
│   └── workflows/
│       └── go-build.yml     # GitHub Actions构建配置
│
├── v2ray.com/               # V2Ray协议相关（第三方）
├── vendor/                  # Go依赖包（第三方）
└── .git/                    # Git版本控制
```

## 🔄 整理变更

### 新增目录

- `bin/` - 存放编译后的可执行文件
- `scripts/test/` - 统一管理所有测试脚本

### 移动文件

- 所有 `test_*.sh` 脚本 → `scripts/test/`
- `simple_cname_test.sh` → `scripts/test/`
- `test_geosite.go` → `scripts/test/`
- `dnsupdate` 可执行文件 → `bin/`

### 删除文件

- `.DS_Store` - macOS 系统文件

### 更新文档

- `README.md` - 更新目录结构和使用说明
- `scripts/test/README.md` - 新增测试脚本说明文档

## 🚀 使用说明

### 编译和运行

```bash
# 编译
go build -o bin/dnsupdate main.go

# 运行
./bin/dnsupdate
```

### 运行测试

```bash
# 进入测试目录
cd scripts/test

# 给脚本添加执行权限
chmod +x *.sh

# 运行测试
./test_dns.sh
```

### 查看测试说明

```bash
cat scripts/test/README.md
```

## 📋 目录说明

### `bin/` - 可执行文件

- 存放编译后的程序
- 便于管理和分发

### `scripts/test/` - 测试脚本

- 按功能分类的测试脚本
- 包含详细的使用说明
- 支持快速功能验证

### `build/` - 构建输出

- 保留给 GitHub Actions 使用
- 自动构建多平台版本

## ✅ 整理完成

项目目录结构已整理完成，现在更加清晰和规范：

- 测试脚本统一管理
- 可执行文件集中存放
- 文档及时更新
- 便于维护和使用
