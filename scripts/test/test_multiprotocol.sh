#!/bin/bash

echo "=== 多协议DNS支持测试 ==="
echo "测试时间: $(date)"
echo

# 测试函数
test_domain() {
    local domain=$1
    local expected_type=$2
    
    echo "测试域名: $domain (期望: $expected_type)"
    result=$(dig @127.0.0.1 -p 5354 "$domain" +short 2>/dev/null | head -1)
    
    if [[ -n "$result" ]]; then
        echo "✅ 成功: $result"
        
        # 简单判断IP类型
        if [[ $result =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]]; then
            echo "   类型: 私有IP"
        elif [[ $result =~ ^(59\.|182\.|123\.|113\.|203\.) ]]; then
            echo "   类型: 国内IP"
        else
            echo "   类型: 国外IP"
        fi
    else
        echo "❌ 失败"
    fi
    echo
}

echo "1. 国内域名测试 (应该使用国内DNS):"
test_domain "baidu.com" "国内DNS"
test_domain "taobao.com" "国内DNS"
test_domain "qq.com" "国内DNS"

echo "2. 国外域名测试 (应该使用国外DNS):"
test_domain "google.com" "国外DNS"
test_domain "facebook.com" "国外DNS"
test_domain "github.com" "国外DNS"
test_domain "twitter.com" "国外DNS"

echo "3. 白名单域名测试:"
test_domain "x.com" "白名单"

echo "4. 指定DNS域名测试:"
test_domain "wechat.com" "指定DNS"

echo "=== 测试完成 ==="
echo
echo "说明:"
echo "- 国内域名应该返回国内IP地址"
echo "- 国外域名应该返回国外IP地址"
echo "- 如果国外域名返回国内IP，说明UDP劫持仍然存在"
echo "- 如果国外域名返回国外IP，说明DoH/DoT绕过成功" 