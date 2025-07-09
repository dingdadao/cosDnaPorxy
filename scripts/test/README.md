# 测试脚本说明

本目录包含 DNS 代理服务器的各种测试脚本。

## 测试脚本列表

### 基础功能测试

- `test_dns.sh` - 基础 DNS 解析测试
- `test_dns_protocols.sh` - 多协议 DNS 测试（UDP/TCP/DoH/DoT）
- `test_multiprotocol.sh` - 多协议并发测试

### DoH 功能测试

- `test_doh_fixed.sh` - DoH 修复后功能测试
- `test_doh_connectivity.sh` - DoH 连通性测试
- `test_upstream_doh.sh` - 上游 DoH 配置测试

### CNAME 解析测试

- `test_cname_resolution.sh` - CNAME 解析功能测试
- `simple_cname_test.sh` - 简单 CNAME 测试

### 其他测试

- `test_geosite.go` - Geosite 功能测试

## 使用方法

1. 确保 DNS 代理服务正在运行（默认端口 5354）
2. 给脚本添加执行权限：`chmod +x *.sh`
3. 运行测试：`./test_script_name.sh`

## 测试前准备

```bash
# 启动服务
./bin/dnsupdate

# 运行测试
cd scripts/test
chmod +x *.sh
./test_dns.sh
```

## 注意事项

- 测试前请确保服务已启动
- 部分测试需要网络连接
- DoH 测试可能受网络环境影响
