#!/bin/bash

echo "=== 测试修复后的DoH功能 ==="
echo

# 测试国内域名（应该使用国内DNS）
echo "1. 测试国内域名 baidu.com:"
dig @127.0.0.1 -p 5354 baidu.com +short
echo

# 测试国外域名（应该使用国外DNS，可能包含DoH）
echo "2. 测试国外域名 google.com:"
dig @127.0.0.1 -p 5354 google.com +short
echo

# 测试国外域名（应该使用国外DNS，可能包含DoH）
echo "3. 测试国外域名 github.com:"
dig @127.0.0.1 -p 5354 github.com +short
echo

# 测试CNAME解析
echo "4. 测试CNAME解析 s3.amazonaws.com:"
dig @127.0.0.1 -p 5354 s3.amazonaws.com +short
echo

# 测试AAAA记录
echo "5. 测试AAAA记录 google.com:"
dig @127.0.0.1 -p 5354 google.com AAAA +short
echo

echo "=== 测试完成 ==="
echo "注意：如果DoH配置正确，国外域名查询应该会尝试使用DoH服务器"
echo "可以通过服务日志查看DoH查询的详细信息"
