#!/bin/bash

echo "=== CNAME解析准确性测试 ==="
echo "测试时间: $(date)"
echo

# 测试函数
test_cname() {
    local domain=$1
    local description=$2
    
    echo "测试 $description:"
    echo "域名: $domain"
    
    # 使用dig测试CNAME解析
    echo "CNAME记录:"
    cname_result=$(dig @127.0.0.1 -p 5354 $domain CNAME +short 2>/dev/null)
    if [[ -n "$cname_result" ]]; then
        echo "✅ CNAME: $cname_result"
    else
        echo "❌ 无CNAME记录"
    fi
    
    # 测试A记录解析
    echo "A记录解析:"
    a_result=$(dig @127.0.0.1 -p 5354 $domain A +short 2>/dev/null)
    if [[ -n "$a_result" ]]; then
        echo "✅ A记录: $a_result"
    else
        echo "❌ 无A记录"
    fi
    
    # 测试完整解析过程
    echo "完整解析过程:"
    full_result=$(dig @127.0.0.1 -p 5354 $domain A +trace 2>/dev/null | head -20)
    if [[ -n "$full_result" ]]; then
        echo "✅ 解析成功"
        echo "$full_result" | head -5
    else
        echo "❌ 解析失败"
    fi
    
    echo
}

# 测试一些常见的CNAME域名
echo "1. 测试GitHub Pages (CNAME -> A记录):"
test_cname "pages.github.com" "GitHub Pages"

echo "2. 测试Cloudflare (CNAME -> A记录):"
test_cname "www.cloudflare.com" "Cloudflare"

echo "3. 测试AWS (CNAME -> A记录):"
test_cname "s3.amazonaws.com" "AWS S3"

echo "4. 测试Google (直接A记录):"
test_cname "www.google.com" "Google"

echo "5. 测试复杂CNAME链:"
test_cname "docs.github.com" "GitHub Docs"

echo "=== 对比测试：直接查询上游DNS ==="
echo

# 对比测试：直接查询上游DNS
echo "直接查询8.8.8.8:"
direct_result=$(dig @8.8.8.8 pages.github.com A +short 2>/dev/null)
echo "8.8.8.8结果: $direct_result"

echo "通过代理查询:"
proxy_result=$(dig @127.0.0.1 -p 5354 pages.github.com A +short 2>/dev/null)
echo "代理结果: $proxy_result"

if [[ "$direct_result" == "$proxy_result" ]]; then
    echo "✅ 结果一致，CNAME解析准确"
else
    echo "❌ 结果不一致，可能存在解析问题"
fi

echo
echo "=== 测试完成 ===" 