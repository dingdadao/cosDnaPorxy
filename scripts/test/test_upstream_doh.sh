#!/bin/bash

echo "=== 测试上游直接配置DoH ==="
echo "配置说明：upstream.cn/not_cn 直接写 DoH 地址"
echo

# 测试国内域名（应该使用国内DoH）
echo "1. 测试国内域名 baidu.com (应该走国内DoH):"
dig @127.0.0.1 -p 5354 baidu.com +short
echo

# 测试国外域名（应该使用国外DoH）
echo "2. 测试国外域名 google.com (应该走国外DoH):"
dig @127.0.0.1 -p 5354 google.com +short
echo

# 测试国外域名（应该使用国外DoH）
echo "3. 测试国外域名 github.com (应该走国外DoH):"
dig @127.0.0.1 -p 5354 github.com +short
echo

# 测试CNAME解析
echo "4. 测试CNAME解析 s3.amazonaws.com (应该走国外DoH):"
dig @127.0.0.1 -p 5354 s3.amazonaws.com +short
echo

# 测试AAAA记录
echo "5. 测试AAAA记录 google.com (应该走国外DoH):"
dig @127.0.0.1 -p 5354 google.com AAAA +short
echo

# 测试国内域名
echo "6. 测试国内域名 qq.com (应该走国内DoH):"
dig @127.0.0.1 -p 5354 qq.com +short
echo

echo "=== 测试完成 ==="
echo "注意：所有查询都应该通过DoH进行，不再使用传统UDP/TCP DNS"
echo "可以通过服务日志查看DoH查询的详细信息"
