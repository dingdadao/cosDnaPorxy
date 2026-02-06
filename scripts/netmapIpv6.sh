#!/bin/sh
# 配置区 - 匹配你的设备接口
IFACE_V6_WAN1="wan1_6"
IFACE_V6_WAN2="wan2_6"
PPPOE_WAN1="pppoe-wan1"
PPPOE_WAN2="pppoe-wan2"
LOG_TAG="IPv6-DYN-NETMAP"

# 依赖检查函数
check_dep() {
    if ! command -v "$1" >/dev/null 2>&1; then
        logger -t "${LOG_TAG}" "缺失依赖: $1"
        exit 1
    fi
}
check_dep ubus
check_dep jq
check_dep ip6tables

# 修复解析逻辑：适配ubus返回的 mask 字段，兼容所有掩码长度
get_v6_prefix() {
    local iface="$1"
    # 读取address和mask字段（修正字段名，匹配你的设备返回格式）
    local addr
    addr=$(ubus call network.interface."${iface}" status 2>/dev/null | jq -r '.["ipv6-prefix"][0].address' 2>/dev/null)
    local mask
    mask=$(ubus call network.interface."${iface}" status 2>/dev/null | jq -r '.["ipv6-prefix"][0].mask' 2>/dev/null)

    # 严格校验有效性，排除null/空值
    if [ "${addr}" != "null" ] && [ -n "${addr}" ] && [ "${mask}" != "null" ] && [ -n "${mask}" ]; then
        echo "${addr}/${mask}"
    else
        echo ""
    fi
}

# 动态获取双线路完整前缀（含掩码）
PREFIX_WAN1=$(get_v6_prefix "${IFACE_V6_WAN1}")
PREFIX_WAN2=$(get_v6_prefix "${IFACE_V6_WAN2}")

# 记录获取结果到系统日志
logger -t "${LOG_TAG}" "前缀获取结果: ${IFACE_V6_WAN1}=${PREFIX_WAN1:-失效} ${IFACE_V6_WAN2}=${PREFIX_WAN2:-失效}"

# 清空所有旧NAT规则，避免冲突
ip6tables -t nat -F
ip6tables -t nat -X

# 核心逻辑：仅当两个前缀都有效时，配置NETMAP规则
if [ -n "${PREFIX_WAN1}" ] && [ -n "${PREFIX_WAN2}" ]; then
    ip6tables -t nat -A POSTROUTING -o "${PPPOE_WAN1}" -j NETMAP --to "${PREFIX_WAN1}"
    ip6tables -t nat -A POSTROUTING -o "${PPPOE_WAN2}" -j NETMAP --to "${PREFIX_WAN2}"
    logger -t "${LOG_TAG}" "双前缀校验通过，NETMAP规则配置完成"
else
    logger -t "${LOG_TAG}" "前缀无效，已清空所有NAT规则，未配置NETMAP"
fi

exit 0