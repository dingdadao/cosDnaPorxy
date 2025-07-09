#!/bin/bash

echo "=== DoH连通性测试 ==="
echo "测试时间: $(date)"
echo

# 测试函数
test_doh() {
    local name=$1
    local url=$2
    
    echo "测试 $name:"
    echo "URL: $url"
    
    # 使用curl测试DoH连通性
    start_time=$(date +%s.%N)
    
    # 测试HTTP连接
    http_result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null)
    
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "N/A")
    
    if [[ "$http_result" == "200" ]]; then
        echo "✅ HTTP连接成功 (状态码: $http_result, 耗时: ${duration}s)"
    else
        echo "❌ HTTP连接失败 (状态码: $http_result, 耗时: ${duration}s)"
    fi
    
    # 使用dig测试DoH查询
    echo "DoH查询测试:"
    doh_result=$(dig +https "$url" google.com +short 2>/dev/null | head -1)
    if [[ -n "$doh_result" ]]; then
        echo "✅ DoH查询成功: $doh_result"
    else
        echo "❌ DoH查询失败"
    fi
    
    echo
}

# 测试国内DoH服务器
echo "1. 测试国内DoH服务器:"
test_doh "腾讯DoH" "https://doh.pub/dns-query"
test_doh "阿里DoH" "https://dns.alidns.com/dns-query"
test_doh "360DoH" "https://doh.360.cn/dns-query"

# 测试国际DoH服务器
echo "2. 测试国际DoH服务器:"
test_doh "Google DoH" "https://dns.google/dns-query"
test_doh "Cloudflare DoH" "https://cloudflare-dns.com/dns-query"
test_doh "Quad9 DoH" "https://dns.quad9.net/dns-query"

echo "=== 网络环境检测 ==="
echo

# 检测网络环境
echo "检测网络环境:"
echo "外网连通性:"
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ 外网连通正常"
else
    echo "❌ 外网连通异常"
fi

echo "HTTPS连通性:"
if curl -s --connect-timeout 5 https://www.google.com >/dev/null 2>&1; then
    echo "✅ HTTPS连通正常"
else
    echo "❌ HTTPS连通异常"
fi

echo
echo "=== 建议 ==="
echo "1. 如果DoH连接失败，建议使用传统DNS (UDP/TCP)"
echo "2. 如果网络环境不稳定，DoH可能不如传统DNS可靠"
echo "3. 可以尝试不同的DoH服务器"
echo
echo "=== 测试完成 ===" 