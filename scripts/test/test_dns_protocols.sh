#!/bin/bash

echo "=== DNS协议测试 ==="
echo "测试时间: $(date)"
echo

# 测试函数
test_dns() {
    local name=$1
    local server=$2
    local protocol=$3
    
    echo "测试 $name ($protocol):"
    echo "服务器: $server"
    
    # 使用dig测试
    if [[ $server == https://* ]]; then
        # DoH测试
        result=$(dig +https "$server" google.com +short 2>/dev/null | head -1)
    elif [[ $server == tls://* ]]; then
        # DoT测试
        result=$(dig +tls "$server" google.com +short 2>/dev/null | head -1)
    elif [[ $server == tcp://* ]]; then
        # TCP测试
        result=$(dig +tcp "$server" google.com +short 2>/dev/null | head -1)
    else
        # UDP测试
        result=$(dig "$server" google.com +short 2>/dev/null | head -1)
    fi
    
    if [[ -n "$result" ]]; then
        echo "✅ 成功: $result"
    else
        echo "❌ 失败"
    fi
    echo
}

echo "1. 测试国内DNS服务器:"
test_dns "腾讯DNS" "119.29.29.29:53" "UDP"
test_dns "阿里DNS" "223.5.5.5:53" "UDP"
test_dns "腾讯DNS" "tcp://119.29.29.29:53" "TCP"
test_dns "阿里DNS" "tcp://223.5.5.5:53" "TCP"

echo "2. 测试国外DNS服务器:"
test_dns "Google DNS" "8.8.8.8:53" "UDP"
test_dns "Google DNS" "tcp://8.8.8.8:53" "TCP"
test_dns "Google DNS" "https://dns.google/dns-query" "DoH"
test_dns "Cloudflare DNS" "https://cloudflare-dns.com/dns-query" "DoH"

echo "3. 测试我们的DNS代理:"
echo "测试代理服务器 (127.0.0.1:5354):"
result=$(dig @127.0.0.1 -p 5354 google.com +short 2>/dev/null | head -1)
if [[ -n "$result" ]]; then
    echo "✅ 成功: $result"
else
    echo "❌ 失败"
fi

echo
echo "=== 测试完成 ===" 