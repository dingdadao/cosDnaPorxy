#!/bin/bash
set -e

# ========= 基础路径与常量 =========
BASE_ROOT=$(cd "$(dirname "$0")"; pwd)
DATE_TIME=$(date +%Y%m%d%H%M%S)
ACME_BIN_PATH="${BASE_ROOT}/acme.sh"
TEMP_PATH="${BASE_ROOT}/temp"
DOCKER_PATH="/vol2/1000/job/syno-acme/certificate"
GITHUB_TOKEN=${GITHUB_TOKEN:-""}

# ========= 日志函数 =========
log() { echo -e "[\033[32mINFO\033[0m] $1"; }
error() { echo -e "[\033[31mERROR\033[0m] $1" >&2; }

# ========= 代理设置 =========
#export http_proxy="http://openwrt.niao.fun:7890"
#export https_proxy="http://openwrt.niao.fun:7890"

# ========= 安装或更新 acme.sh =========
installAcme() {
  log "检查 acme.sh 是否需要安装/更新..."
  ACME_SH_FILE="${ACME_BIN_PATH}/acme.sh"

  if [[ -z "$GITHUB_TOKEN" ]]; then
    error "GITHUB_TOKEN 未设置，退出"
    exit 1
  fi

  LATEST_VERSION=$(curl -sL -H "Authorization: token ${GITHUB_TOKEN}" \
    "https://api.github.com/repos/acmesh-official/acme.sh/releases/latest" |
    grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

  if [[ -z "$LATEST_VERSION" ]]; then
    error "无法获取最新版本"
    return 1
  fi

  CURRENT_VERSION=$(grep 'VER=' "$ACME_SH_FILE" 2>/dev/null | awk -F '=' '{print $2}' | tr -d ' "')

  if [[ ! -f "$ACME_SH_FILE" || "$CURRENT_VERSION" != "$LATEST_VERSION" ]]; then
    log "安装 acme.sh v$LATEST_VERSION..."
    mkdir -p "$TEMP_PATH" && cd "$TEMP_PATH"
    curl -L -o acme.sh.tar.gz "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${LATEST_VERSION}.tar.gz"
    tar zxvf acme.sh.tar.gz
    cd acme.sh-*/
    ./acme.sh --install --nocron --home "${ACME_BIN_PATH}"
    rm -rf "$TEMP_PATH"
    log "acme.sh 安装完成"
  else
    log "acme.sh 已是最新版本，跳过更新"
  fi
}

# ========= 申请证书 =========
generateCrt() {
  log "开始申请证书..."

  [[ -f "${BASE_ROOT}/config" ]] || { error "配置文件 config 缺失"; exit 1; }
  source "${BASE_ROOT}/config"

  [[ "${CERT_SERVER}" == "zerossl" ]] && \
    "${ACME_BIN_PATH}/acme.sh" --register-account -m "${ACCOUNT_EMAIL}" --server zerossl

  "${ACME_BIN_PATH}/acme.sh" --force --log \
    --issue --server "${CERT_SERVER}" --dns "${DNS}" --dnssleep "${DNS_SLEEP}" \
    -d "${DOMAIN}" -d "*.${DOMAIN}"

  "${ACME_BIN_PATH}/acme.sh" --force --installcert -d "${DOMAIN}" -d "*.${DOMAIN}" \
    --certpath "${DOCKER_PATH}/cert.pem" \
    --key-file "${DOCKER_PATH}/privkey.pem" \
    --fullchain-file "${DOCKER_PATH}/fullchain.pem"
}

# ========= 推送证书 =========
pushCertToFn() {
  log "推送证书到设备 fn..."
  REMOTE_CRT_PATH="/usr/trim/var/trim_connect/ssls/niao.fun/1738999332/niao.fun.crt"
  REMOTE_KEY_PATH="/usr/trim/var/trim_connect/ssls/niao.fun/1738999332/niao.fun.key"
  CERT_NAME="niao.fun"

  cp -r "${DOCKER_PATH}/fullchain.pem" "$REMOTE_CRT_PATH" && log "证书传输成功" || error "证书传输失败"
  cp -r "${DOCKER_PATH}/privkey.pem" "$REMOTE_KEY_PATH" && log "私钥传输成功" || error "私钥传输失败"

  NEW_EXPIRY_DATE=$(openssl x509 -enddate -noout -in "${DOCKER_PATH}/fullchain.pem" | sed "s/^.*=//")
  NEW_EXPIRY_TIMESTAMP=$(date -d "${NEW_EXPIRY_DATE}" +%s%3N)

  ssh "${REMOTE_USER}@${REMOTE_HOST}" <<EOF
set -e
psql -U postgres -d trim_connect -c "UPDATE cert SET valid_to='${NEW_EXPIRY_TIMESTAMP}' WHERE domain='${CERT_NAME}'"
systemctl restart webdav.service smbftpd.service trim_nginx.service
EOF

  log "fn 设备证书更新完成"
}

# ========= 主流程函数 =========
updateCrt() {
  log "执行 updateCrt 流程"
  installAcme
  generateCrt

  for device in ${TARGET_DEVICES//,/ }; do
    case $device in
      fn) pushCertToFn ;;
      *) log "未知设备: $device, 忽略" ;;
    esac
  done

  log "证书更新流程完成"
}

tongbuCrt() {
  local devices=$1
  log "同步证书到远程: $devices"
  for device in ${devices//,/ }; do
    case $device in
      fn) pushCertToFn ;;
      dns) pushCertToDns ;;  # 示例：未来你可添加此函数
      pve) pushCertToPve ;;
      *) log "未知设备: $device，忽略" ;;
    esac
  done
  log "同步完成"
}


revertCrt() {
  log "回滚证书..."
  BACKUP_PATH=$(cat "${BASE_ROOT}/backup/latest" 2>/dev/null)
  if [[ -d "$BACKUP_PATH" ]]; then
    cp -rf "$BACKUP_PATH/certificate/"* "${CRT_BASE_PATH}"
    cp -rf "$BACKUP_PATH/package_cert/"* "${PKG_CRT_BASE_PATH}"
    log "回滚完成"
  else
    error "备份路径不存在：$BACKUP_PATH"
  fi
}

# ========= 参数解析 =========
ACTION=$1
TARGET_DEVICES=${2:-fn} # 默认为 fn，可传入 fn,dns,pve

case "$ACTION" in
  update)
    updateCrt
    ;;
  tongbu)
    tongbuCrt "$TARGET_DEVICES"
    ;;
  revert)
    revertCrt
    ;;
  *)
    echo "Usage: $0 {update|tongbu|revert} [fn,dns,pve,...]"
    exit 1
esac
