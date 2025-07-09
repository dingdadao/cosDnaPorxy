# DNS代理服务 Makefile

# 变量定义
BINARY_NAME=dnsproxy
BUILD_DIR=build
CONFIG_DIR=configs
DATA_DIR=data

# Go相关变量
GO=go
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)

# 版本信息
VERSION?=1.0.0
BUILD_TIME=$(shell date +%FT%T%z)
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

.PHONY: all build clean run test help

# 默认目标
all: clean build

# 构建项目
build:
	@echo "构建 DNS 代理服务..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)"

# 交叉编译
build-linux:
	@echo "构建 Linux 版本..."
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go

build-windows:
	@echo "构建 Windows 版本..."
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go

build-darwin:
	@echo "构建 macOS 版本..."
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go

# 构建所有平台
build-all: build-linux build-windows build-darwin
	@echo "所有平台构建完成"

# 运行服务
run:
	@echo "启动 DNS 代理服务..."
	$(GO) run main.go -c $(CONFIG_DIR)/config.yaml

# 开发模式运行（带调试信息）
dev:
	@echo "开发模式启动..."
	$(GO) run -race main.go -c $(CONFIG_DIR)/config.yaml

# 测试
test:
	@echo "运行测试..."
	$(GO) test -v ./...

# 测试覆盖率
test-coverage:
	@echo "运行测试覆盖率..."
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

# 代码格式化
fmt:
	@echo "格式化代码..."
	$(GO) fmt ./...

# 代码检查
lint:
	@echo "代码检查..."
	golangci-lint run

# 依赖管理
deps:
	@echo "更新依赖..."
	$(GO) mod tidy
	$(GO) mod download

# 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# 安装依赖工具
install-tools:
	@echo "安装开发工具..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# 初始化项目
init:
	@echo "初始化项目..."
	mkdir -p $(BUILD_DIR) $(CONFIG_DIR) $(DATA_DIR) docs scripts
	@echo "项目初始化完成"

# 创建发布包
release: build-all
	@echo "创建发布包..."
	@mkdir -p release
	@cp $(BUILD_DIR)/* release/
	@cp -r $(CONFIG_DIR) release/
	@cp -r $(DATA_DIR) release/
	@cp README.md release/
	@echo "发布包已创建: release/"

# 帮助信息
help:
	@echo "DNS代理服务 Makefile 命令:"
	@echo ""
	@echo "构建相关:"
	@echo "  build        - 构建项目"
	@echo "  build-linux  - 构建 Linux 版本"
	@echo "  build-windows- 构建 Windows 版本"
	@echo "  build-darwin - 构建 macOS 版本"
	@echo "  build-all    - 构建所有平台"
	@echo "  clean        - 清理构建文件"
	@echo ""
	@echo "运行相关:"
	@echo "  run          - 运行服务"
	@echo "  dev          - 开发模式运行"
	@echo ""
	@echo "测试相关:"
	@echo "  test         - 运行测试"
	@echo "  test-coverage- 测试覆盖率"
	@echo ""
	@echo "代码质量:"
	@echo "  fmt          - 格式化代码"
	@echo "  lint         - 代码检查"
	@echo ""
	@echo "项目管理:"
	@echo "  deps         - 更新依赖"
	@echo "  init         - 初始化项目"
	@echo "  install-tools- 安装开发工具"
	@echo "  release      - 创建发布包"
	@echo "  help         - 显示帮助信息" 