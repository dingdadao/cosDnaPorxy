# 🌐 Go DNS 代理服务：Cloudflare 检测与自动替换方案

一个轻量级、功能强大的 DNS 代理服务器，具备 Cloudflare 节点识别能力，自动替换为指定 IP，专为隐私增强与防篡改设计！

## 🚀 项目亮点

- 🔍 **自动识别 Cloudflare 节点**
- 🔁 **使用优选域名解析的IP去处理替换其他托管在cf的域名对应IP**
- 📦 **自带缓存机制，节省带宽**
- 🔄 **定时刷新 Cloudflare 节点列表**
- ⚡  **超轻量部署，适用于边缘设备**
- 📜 **兼容 / CIDR 格式 IP 列表**

---

## 🧠 使用场景

- CDN 节点探测绕过
- 替代 Cloudflare 返回的 A/AAAA 记录
- 基于 DNS 实现域名级智能调度
- 内网 DNS 劫持 + 云防御回源域名自定义方案

---

## 🔧 配置说明

项目启动时会读取 `config.yaml` 配置文件。配置示例如下：

```yaml
listen_port: 5353               # 本地监听端口
upstream:                      # 上游 DNS 服务列表（支持多个）
  - "udp://1.1.1.1:53"
  - "udp://8.8.8.8:53"
cf_mrs_url4: "https://example.com/cf_ipv4.mrs"    # Cloudflare IPv4 列表
cf_mrs_url6: "https://example.com/cf_ipv6.mrs"    # Cloudflare IPv6 列表
cf_mrs_cache: "./cf.mrs"                          # 缓存文件路径
replace_domain: "proxy.example.com"               # 匹配命中时替换的域名解析后的IP
cf_cache_time: "12h"                              # 刷新间隔（支持 1h、12h、24h 等）
replace_cache_time: "30m"                         # 域名替换的域名解析后的IP缓存时间，就不会重复询问上游了
whitelist_file: "./whitelist.txt"                 # 白名单域名一行一条支持通配符*.domain.*
designated_domain: "./designated.txt"             # 指定域名走指定dns 如wx 在旅游环境的时候dns解析不是最优IP，那么通配符*.xx.com 119.29.29.29 就可以解决这个问题
log_level: "debug"                                # 开启日志
doh_port: 443                                     # 开启doh 0关闭
dot_port: 853                                     # 开启dot 0关闭
tls_cert_file: "./cert.pem"                       # 证书路径，注意权限
tls_key_file: "./privkey.pem"                     # 证书key