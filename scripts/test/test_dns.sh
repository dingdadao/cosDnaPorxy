#!/bin/bash

echo "=== DNS分流测试 ==="
echo "测试时间: $(date)"
echo

# 测试国内域名
echo "1. 测试国内域名 (应该使用国内DNS):"
echo "baidu.com:"
dig @127.0.0.1 -p 5354 baidu.com +short
echo

echo "qq.com:"
dig @127.0.0.1 -p 5354 qq.com +short
echo

echo "taobao.com:"
dig @127.0.0.1 -p 5354 taobao.com +short
echo

# 测试国外域名
echo "2. 测试国外域名 (应该使用国外DNS):"
echo "google.com:"
dig @127.0.0.1 -p 5354 google.com +short
echo

echo "facebook.com:"
dig @127.0.0.1 -p 5354 facebook.com +short
echo

echo "twitter.com:"
dig @127.0.0.1 -p 5354 twitter.com +short
echo

# 测试白名单域名
echo "3. 测试白名单域名 (x.com):"
echo "x.com:"
dig @127.0.0.1 -p 5354 x.com +short
echo

# 测试指定DNS域名
echo "4. 测试指定DNS域名 (wechat.com):"
echo "wechat.com:"
dig @127.0.0.1 -p 5354 wechat.com +short
echo

echo "=== 测试完成 ===" 