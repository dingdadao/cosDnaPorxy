#!/bin/bash
set -euo pipefail
# 开启严格模式，脚本异常时立即退出，提升安全性

# ===================== 配置区（统一修改此处即可）=====================
# 临时下载目录
DOWNLOAD_DIR="/tmp"
# 目标规则目录
TARGET_DIR="/opt/mosdns/rules"
# 下载地址
GEOIP_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
GEOSITE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
# 定义文件全称（路径+文件名）
TMP_GEOIP="${DOWNLOAD_DIR}/geoip.dat"
TMP_GEOSITE="${DOWNLOAD_DIR}/geosite.dat"
TARGET_GEOIP="${TARGET_DIR}/geoip.dat"
TARGET_GEOSITE="${TARGET_DIR}/geosite.dat"
# =====================================================================

# 定义更新规则的主函数，替代goto跳转
update_rules() {
    echo "[INFO] 移动新文件到目标目录，覆盖旧文件"
    mv -f "${TMP_GEOIP}" "${TMP_GEOSITE}" "${TARGET_DIR}/" || { echo "[ERROR] 文件移动失败"; exit 1; }

    echo "[INFO] 安全清理旧的解压规则文件（全路径模式）"
    rm -f \
    "${TARGET_DIR}/geoip_cloudflare.txt" \
    "${TARGET_DIR}/geoip_cn.txt" \
    "${TARGET_DIR}/geoip_private.txt" \
    "${TARGET_DIR}/geosite_cn.txt" \
    "${TARGET_DIR}/geosite_geolocation-!cn.txt" \
    "${TARGET_DIR}/geosite_gfw.txt"

    echo "[INFO] 解压 geosite.dat 规则文件"
    v2dat unpack geosite -o "${TARGET_DIR}" -f 'geolocation-!cn' -f 'gfw' -f 'cn' "${TARGET_GEOSITE}" || { echo "[ERROR] geosite 解压失败"; exit 1; }

    echo "[INFO] 解压 geoip.dat 规则文件"
    v2dat unpack geoip -o "${TARGET_DIR}" -f 'cloudflare' -f 'private' -f 'cn' "${TARGET_GEOIP}" || { echo "[ERROR] geoip 解压失败"; exit 1; }

    echo "[INFO] 重启 mosdns 服务"
    systemctl restart mosdns.service || { echo "[ERROR] 服务重启失败，检查服务状态"; exit 1; }

    # 执行完成提示
    echo "=========================================================="
    echo "[SUCCESS] 规则文件更新完成，mosdns服务已重启"
    echo "更新目录：${TARGET_DIR}"
    echo "=========================================================="
    exit 0
}

# 1. 创建目标目录（不存在则创建）
if [ ! -d "${TARGET_DIR}" ]; then
    echo "[INFO] 创建目标目录: ${TARGET_DIR}"
    mkdir -p "${TARGET_DIR}" || { echo "[ERROR] 目录创建失败，检查权限"; exit 1; }
fi

# 2. 下载最新文件到 /tmp 目录
echo "[INFO] 开始下载最新规则文件到 ${DOWNLOAD_DIR}"
wget -q --show-progress -O "${TMP_GEOIP}" "${GEOIP_URL}" || { echo "[ERROR] geoip.dat 下载失败"; exit 1; }
wget -q --show-progress -O "${TMP_GEOSITE}" "${GEOSITE_URL}" || { echo "[ERROR] geosite.dat 下载失败"; exit 1; }

# 3. 校验下载文件非空，防止无效文件
echo "[INFO] 校验下载文件有效性"
for file in "${TMP_GEOIP}" "${TMP_GEOSITE}"; do
    if [ ! -s "${file}" ]; then
        echo "[ERROR] ${file} 文件为空，终止操作"
        rm -f "${file}"
        exit 1
    fi
done

# 4. 判断目标目录是否存在旧文件，不存在则直接执行更新流程
if [ ! -f "${TARGET_GEOIP}" ] || [ ! -f "${TARGET_GEOSITE}" ]; then
    echo "[INFO] 目标目录无旧规则文件，执行全量更新"
    update_rules
fi

# 5. 对比文件MD5哈希值，判断文件是否一致（最精准的对比方式）
echo "[INFO] 对比新旧文件哈希值，校验是否需要更新"
MD5_TMP_GEOIP=$(md5sum "${TMP_GEOIP}" | awk '{print $1}')
MD5_TMP_GEOSITE=$(md5sum "${TMP_GEOSITE}" | awk '{print $1}')
MD5_TARGET_GEOIP=$(md5sum "${TARGET_GEOIP}" | awk '{print $1}')
MD5_TARGET_GEOSITE=$(md5sum "${TARGET_GEOSITE}" | awk '{print $1}')

# 6. 哈希值一致则删除临时文件，退出脚本；不一致则执行更新
if [ "${MD5_TMP_GEOIP}" == "${MD5_TARGET_GEOIP}" ] && [ "${MD5_TMP_GEOSITE}" == "${MD5_TARGET_GEOSITE}" ]; then
    echo "[INFO] 规则文件无更新，与当前版本一致，脚本退出"
    rm -f "${TMP_GEOIP}" "${TMP_GEOSITE}"
    exit 0
else
    echo "[INFO] 检测到文件更新，开始执行规则更新流程"
    update_rules
fi