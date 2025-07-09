#!/bin/bash

echo "=== 简单CNAME解析测试 ==="
echo "测试时间: $(date)"
echo

# 测试函数
test_domain() {
    local domain=$1
    local description=$2
    
    echo "测试: $description"
    echo "域名: $domain"
    
    # 测试A记录解析
    echo "A记录:"
    a_result=$(dig @127.0.0.1 -p 5354 $domain A +short 2>/dev/null | head -3)
    if [[ -n "$a_result" ]]; then
        echo "✅ $a_result"
    else
        echo "❌ 解析失败"
    fi
    
    # 测试CNAME记录
    echo "CNAME记录:"
    cname_result=$(dig @127.0.0.1 -p 5354 $domain CNAME +short 2>/dev/null)
    if [[ -n "$cname_result" ]]; then
        echo "✅ $cname_result"
    else
        echo "❌ 无CNAME记录"
    fi
    
    echo
}

# 测试一些域名
test_domain "pages.github.com" "GitHub Pages (CNAME -> A)"
test_domain "www.google.com" "Google (直接A记录)"
test_domain "s3.amazonaws.com" "AWS S3 (CNAME -> A)"

echo "=== 测试完成 ===" 