# 🌐 DNS 代理服务 - 项目结构说明


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
- 白名单域名：`configs/whitelist.txt` 尝试移除
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

