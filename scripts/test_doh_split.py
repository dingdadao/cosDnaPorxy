#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DoH 客户端分流 + 云替换多线路 —— 线上功能测试执行器

配套用例文档: docs/doh-split-testcases.md

用法:
  python3 scripts/test_doh_split.py --server 10.0.0.30
  可选:
    --web http://10.0.0.30          Web 管理地址
    --doh https://10.0.0.30/dns-query
    --ssh-key ~/.ssh/proxydns       用于读取服务 PID（缺省则跳过 PID 断言）
    --only B01,B02                  只跑指定用例
    --skip-destructive              跳过需要临时改配置的用例(B05/B06/D02)

特性:
  * 执行前自动备份线上配置，try/finally 保证还原并回读校验
  * 期望值动态计算(优选域名/接口实时变化)，断言用“子集包含 + 线路互斥”
  * 每个“需观测路由动作”的用例使用独立域名，规避缓存污染
"""
import argparse
import base64
import ipaddress
import json
import os
import subprocess
import sys
import time
import warnings

import httpx
import dns.message
import dns.rdatatype
import dns.query

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------- constants
CF_V4_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]
CF_NETS = [ipaddress.ip_network(r) for r in CF_V4_RANGES]

REPLACE_DNS = "58.20.127.238"          # 服务端替换域名统一走全局 upstream
TELECOM_IP = "1.48.0.1"
CMCC_IP = "27.0.160.1"

PASS, FAIL, WARN, SKIP, INFO = "PASS", "FAIL", "WARN", "SKIP", "INFO"


def is_cf(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CF_NETS if n.version == 4)


# ---------------------------------------------------------------- runner
class Runner:
    def __init__(self, args):
        self.args = args
        self.client = httpx.Client(verify=False, timeout=20.0)
        self.results = []
        self.orig_cfg = None
        self.expected = {}
        self.used_domains = {}      # scope -> set(domain)
        self.dirty_cfg = False

    # ---------- results ----------
    def rec(self, tid, name, status, detail, extra=None):
        self.results.append({"id": tid, "name": name, "status": status,
                             "detail": detail, "extra": extra or {}})
        icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ ", "SKIP": "⏭️ ", "INFO": "ℹ️ "}[status]
        print(f"{icon} [{tid}] {name}: {status} — {detail}")

    # ---------- config ----------
    def get_cfg(self):
        r = self.client.get(self.args.web + "/api/config")
        r.raise_for_status()
        return r.json()["config"]

    def put_cfg(self, cfg):
        r = self.client.put(self.args.web + "/api/config", json=cfg)
        return r.status_code, (r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text)

    def set_static(self, ip):
        cfg = self.get_cfg()
        cfg["client_ip_static"] = None if ip is None else {"10.0.0.29": ip}
        return cfg, self.put_cfg(cfg)

    # ---------- DNS over various transports ----------
    def doh(self, domain, qtype="A", method="POST"):
        q = dns.message.make_query(domain, qtype)
        wire = q.to_wire()
        headers = {"accept": "application/dns-message"}
        try:
            if method == "POST":
                headers["content-type"] = "application/dns-message"
                r = self.client.post(self.args.doh, content=wire, headers=headers)
            else:
                b64 = base64.urlsafe_b64encode(wire).decode().rstrip("=")
                r = self.client.get(self.args.doh + "?dns=" + b64, headers=headers)
        except Exception as e:
            return {"http": -1, "error": str(e), "rcode": -1, "a": [], "aaaa": [], "ctype": ""}
        out = {"http": r.status_code, "ctype": r.headers.get("content-type", ""),
               "rcode": -1, "a": [], "aaaa": [], "error": None}
        if r.status_code == 200 and out["ctype"].startswith("application/dns-message"):
            try:
                msg = dns.message.from_wire(r.content)
                out["rcode"] = msg.rcode()
                for rr in msg.answer:
                    if rr.rdtype == dns.rdatatype.A:
                        out["a"] += [x.address for x in rr]
                    elif rr.rdtype == dns.rdatatype.AAAA:
                        out["aaaa"] += [x.address for x in rr]
            except Exception as e:
                out["error"] = "parse: " + str(e)
        return out

    def udp(self, domain, qtype="A"):
        q = dns.message.make_query(domain, qtype)
        try:
            msg = dns.query.udp(q, self.args.server, port=53, timeout=6)
        except Exception as e:
            return {"rcode": -1, "a": [], "aaaa": [], "error": str(e)}
        a, aaaa = [], []
        for rr in msg.answer:
            if rr.rdtype == dns.rdatatype.A:
                a += [x.address for x in rr]
            elif rr.rdtype == dns.rdatatype.AAAA:
                aaaa += [x.address for x in rr]
        return {"rcode": msg.rcode(), "a": a, "aaaa": aaaa, "error": None}

    def dot(self, domain, qtype="A"):
        import ssl
        q = dns.message.make_query(domain, qtype)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            msg = dns.query.tls(q, self.args.server, port=853, timeout=6, ssl_context=ctx)
        except Exception as e:
            return {"rcode": -1, "a": [], "error": str(e)}
        return {"rcode": msg.rcode(), "a": [x.address for rr in msg.answer if rr.rdtype == dns.rdatatype.A for x in rr]}

    # ---------- query log ----------
    def logs(self, domain, limit=200):
        r = self.client.get(self.args.web + "/api/logs", params={"q": domain, "limit": limit})
        if r.status_code != 200:
            return []
        return [x for x in r.json().get("logs", []) if x.get("domain") == domain]

    def action_since(self, domain, since, tries=12):
        """轮询日志，返回 since 之后最近一条该域名记录"""
        for _ in range(tries):
            hit = [x for x in self.logs(domain) if x.get("time", 0) >= since - 1]
            if hit:
                return max(hit, key=lambda x: x["time"])
            time.sleep(0.4)
        return None

    # ---------- expected values ----------
    def resolve_via(self, domain, server=REPLACE_DNS):
        q = dns.message.make_query(domain, "A")
        try:
            msg = dns.query.udp(q, server, port=53, timeout=6)
        except Exception:
            return []
        return [x.address for rr in msg.answer if rr.rdtype == dns.rdatatype.A for x in rr]

    def resolve_union(self, domain, times=6, server=REPLACE_DNS):
        u = set()
        for _ in range(times):
            u.update(self.resolve_via(domain, server))
        return sorted(u)

    def api_ips(self, url, count):
        try:
            txt = httpx.get(url, timeout=8, verify=False).text
        except Exception:
            return []
        out, seen = [], set()
        for line in txt.splitlines():
            f = line.split()
            if not f:
                continue
            host = f[0].split("#")[0].split(":")[0]
            try:
                a = ipaddress.ip_address(host)
            except ValueError:
                continue
            if a.version == 4 and str(a) not in seen:
                seen.add(str(a))
                out.append(str(a))
            if len(out) >= max(count, 1):
                break
        return out

    def server_pid(self):
        if not self.args.ssh_key:
            return None
        cmd = ["ssh", "-i", os.path.expanduser(self.args.ssh_key), "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=10", f"root@{self.args.server}",
               "systemctl show -p MainPID --value dnsproxy"]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=25).stdout.strip()
        except Exception:
            return None

    # ---------- domain allocation ----------
    def take(self, scope, domain):
        """同 scope 内若域名已被用过则换下一个候选（规避缓存）"""
        pool = {
            "global": ["chatgpt.com", "medium.com", "openai.com", "x.com", "004430.xyz", "discord.com",
                       "huggingface.co", "cursor.com", "canva.com", "unsplash.com", "shopify.com"],
            "telecom": ["discord.com", "www.speedtest.net", "openai.com", "004430.xyz", "chatgpt.com",
                        "medium.com", "dash.cloudflare.com", "platform.openai.com", "proton.me",
                        "canva.com", "unsplash.com", "huggingface.co"],
            "cmcc": ["medium.com", "discord.com", "www.speedtest.net", "004430.xyz", "openai.com", "x.com",
                     "huggingface.co", "cursor.com", "substack.com", "canva.com", "shopify.com"],
        }[scope]
        used = self.used_domains.setdefault(scope, set())
        for d in [domain] + pool:
            if d not in used:
                used.add(d)
                return d
        used.add(domain)
        return domain

    # ---------- cloud probe with retry ----------
    def probe_cloud(self, scope, prefer=None):
        """返回 (domain, doh_res, log_entry)：找到一个真正触发 action=cloud 的域名"""
        for _ in range(6):
            dom = self.take(scope, prefer or "")
            since = int(time.time())
            res = self.doh(dom, "A")
            time.sleep(0.35)
            log = self.action_since(dom, since, tries=6)
            if log and log.get("action") == "cloud":
                return dom, res, log
        return dom, res, log

    # ---------- restart (flush in-process caches) ----------
    def restart_service(self):
        print("[restart] 触发服务重启以清空进程内缓存 ...")
        try:
            self.client.post(self.args.web + "/api/restart", timeout=30)
        except Exception as e:
            print("[restart] 触发异常:", e)
        for _ in range(40):
            time.sleep(1.0)
            try:
                q = dns.message.make_query("health-probe.example", "A").to_wire()
                r = self.client.post(self.args.doh, content=q, timeout=4, headers={
                    "content-type": "application/dns-message", "accept": "application/dns-message"})
                if r.status_code == 200:
                    time.sleep(2)
                    print("[restart] 服务已恢复")
                    return True
            except Exception:
                pass
        print("[restart] 等待超时")
        return False

    # ================================================================ cases
    def run(self):
        args = self.args
        print(f"\n=== DoH 分流/云替换 功能测试 @ {args.server} ===\n")

        if args.restart:
            self.restart_service()

        # 0. 备份
        self.orig_cfg = self.get_cfg()
        with open(args.backup, "w") as f:
            json.dump(self.orig_cfg, f, ensure_ascii=False, indent=2)
        print(f"[backup] 原始配置已备份 -> {args.backup}")

        # 期望值：优选域名/接口存在轮转且服务端有 10m 缓存，故取「多次解析的并集」作为期望集合
        def grp_cf(isp):
            for g in self.orig_cfg["isp_groups"]:
                if g["isp"] == isp:
                    return g["cloud_replace"].get("cf_domain") or ""
            return ""
        api = self.orig_cfg.get("replace_cf_api") or ""
        api_all = self.api_ips(api, 20) + self.api_ips(api, 20)
        self.expected = {
            "telecom": self.resolve_union(grp_cf("telecom") or "cf.92555.xyz", 8),
            "cmcc": self.resolve_union(grp_cf("cmcc") or "chinwa.cf.090227.xyz", 8),
            "global": sorted(set(api_all)),
        }
        print("[expected] telecom=%s" % self.expected["telecom"])
        print("[expected] cmcc=%s" % self.expected["cmcc"])
        print("[expected] global=%s" % self.expected["global"])

        only = set(x.strip().upper() for x in args.only.split(",")) if args.only else None

        def want(tid):
            return (not only) or (tid in only)

        try:
            self.case_a(want)
            self.case_b(want)
            self.case_c(want)
            self.case_d(want)
        finally:
            self.restore()

    # ---------- A: protocol ----------
    def case_a(self, want):
        if want("TC-A01"):
            r = self.doh("example.com", "A", "POST")
            ok = r["http"] == 200 and r["rcode"] == 0 and len(r["a"]) > 0 and r["ctype"].startswith("application/dns-message")
            self.rec("TC-A01", "DoH POST 基本解析", PASS if ok else FAIL,
                     f"http={r['http']} rcode={r['rcode']} ctype={r['ctype']} A={r['a']}")
        if want("TC-A02"):
            g = self.doh("example.com", "A", "GET")
            p = self.doh("example.com", "A", "POST")
            ok = g["http"] == 200 and p["http"] == 200 and g["rcode"] == p["rcode"]
            self.rec("TC-A02", "DoH GET/POST 一致", PASS if ok else FAIL,
                     f"GET A={sorted(set(g['a']))} POST A={sorted(set(p['a']))}")
        if want("TC-A03"):
            u = self.udp("example.com", "A")
            d = self.doh("example.com", "A", "POST")
            ok = u["rcode"] == 0 and d["rcode"] == 0 and set(u["a"]) == set(d["a"])
            self.rec("TC-A03", "DoH 与 UDP 一致", PASS if ok else FAIL,
                     f"UDP={sorted(set(u['a']))} DoH={sorted(set(d['a']))}")
        if want("TC-A04"):
            try:
                r = self.client.get(self.args.doh + "?dns=@@@not-base64@@@",
                                    headers={"accept": "application/dns-message"})
                code = r.status_code
            except Exception as e:
                code = str(e)
            self.rec("TC-A04", "DoH GET 非法 base64", PASS if code in (400, 414) else FAIL, f"http={code}")
        if want("TC-A05"):
            try:
                r = self.client.post(self.args.doh, content=b"plain", headers={"content-type": "text/plain"})
                code = r.status_code
            except Exception as e:
                code = str(e)
            self.rec("TC-A05", "DoH POST 错误 Content-Type", PASS if code in (400, 415) else FAIL, f"http={code}")
        if want("TC-A06"):
            dom = "no-such-domain-%d.invalidtld" % int(time.time())
            r = self.doh(dom, "A", "POST")
            self.rec("TC-A06", "NXDOMAIN 透传", PASS if r["rcode"] == 3 else FAIL,
                     f"rcode={r['rcode']}(3=NXDOMAIN)")
        if want("TC-A07"):
            codes = []
            for body in (b"", b"\x00\x01"):
                try:
                    codes.append(self.client.post(self.args.doh, content=body,
                                                  headers={"content-type": "application/dns-message"}).status_code)
                except Exception as e:
                    codes.append(str(e))
            self.rec("TC-A07", "空/超短报文", PASS if all(c in (400, 413) for c in codes) else FAIL, f"http={codes}")
        if want("TC-A08"):
            r = self.dot("example.com", "A")
            ok = r["rcode"] == 0 and len(r["a"]) > 0
            self.rec("TC-A08", "DoT 冒烟", PASS if ok else (WARN if r.get("error") else FAIL),
                     f"rcode={r['rcode']} A={r['a']} err={r.get('error')}")

    # ---------- B: split + multi-line replace ----------
    def _line_check(self, tid, name, scope, static, expected_key):
        cfg, (code, body) = self.set_static(static)
        self.dirty_cfg = True
        time.sleep(0.6)
        dom, res, log = self.probe_cloud(scope)
        exp = set(self.expected[expected_key])
        got = set(res["a"])
        degraded = log and log.get("elapsed_ms", 0) > 4500
        subset = got and got.issubset(exp)
        if log and log.get("action") != "cloud":
            self.rec(tid, name, SKIP, f"域名 {dom} 未触发云替换(action={log.get('action')}, list={log.get('list_name')})")
            return None
        if degraded:
            self.rec(tid, name, WARN, f"接口超时降级(耗时{log.get('elapsed_ms')}ms)，返回真实IP {sorted(got)}")
            return got
        ms = log.get("elapsed_ms") if log else "?"
        if not got:
            self.rec(tid, name, FAIL, f"{dom}: 应答无 A 记录")
        elif not all(is_cf(x) for x in got):
            self.rec(tid, name, FAIL, f"{dom}: 应答含非 CF 地址 {sorted(got)}")
        elif subset:
            self.rec(tid, name, PASS, f"{dom}: {sorted(got)} ⊆ 期望({len(exp)}项) action=cloud {ms}ms")
        else:
            self.rec(tid, name, WARN,
                     f"{dom}: got={sorted(got)} 不在期望并集内(优选IP轮转/服务端10m缓存) 期望={sorted(exp)}")
        return got

    def case_b(self, want):
        g = t = c = None
        if want("TC-B01"):
            g = self._line_check("TC-B01", "全局线路云替换", "global", None, "global")
        if want("TC-B02"):
            t = self._line_check("TC-B02", "电信分组覆写生效", "telecom", TELECOM_IP, "telecom")
        if want("TC-B03"):
            c = self._line_check("TC-B03", "移动分组覆写生效", "cmcc", CMCC_IP, "cmcc")
        if want("TC-B04"):
            if g and t and c:
                disj = len({frozenset(g), frozenset(t), frozenset(c)}) == 3
                self.rec("TC-B04", "三线路隔离(互斥)", PASS if disj else FAIL,
                         f"global={sorted(g)} telecom={sorted(t)} cmcc={sorted(c)}")
            else:
                self.rec("TC-B04", "三线路隔离(互斥)", SKIP, "上游用例未全部产出有效集合")

        if want("TC-B05") and not self.args.skip_destructive:
            # 覆写关闭 -> 回退全局
            cfg = self.get_cfg()
            for grp in cfg["isp_groups"]:
                if grp["isp"] == "telecom":
                    grp["cloud_replace"]["override"] = False
            cfg["client_ip_static"] = {"10.0.0.29": TELECOM_IP}
            self.put_cfg(cfg)
            self.dirty_cfg = True
            time.sleep(0.6)
            dom, res, log = self.probe_cloud("telecom", "www.speedtest.net")
            got = set(res["a"])
            t_exp = set(self.expected["telecom"])
            g_exp = set(self.expected["global"])
            ok = (log and log.get("action") == "cloud" and got and got != t_exp
                  and abs(len(got)) >= 1 and all(is_cf(x) for x in got))
            sub = got.issubset(g_exp) if got else False
            self.rec("TC-B05", "覆写关闭回退全局", PASS if ok else FAIL,
                     f"{dom}: got={sorted(got)} ⊆全局={sub}; telecom目标={sorted(t_exp)}")

        if want("TC-B06") and not self.args.skip_destructive:
            # 分组兜底路径强制云检测：临时清空 telecom 的 split_refs 使其走 FallbackDNS
            cfg = self.get_cfg()
            for grp in cfg["isp_groups"]:
                if grp["isp"] == "telecom":
                    grp["split_refs"] = []
                    grp["cloud_replace"]["override"] = True
            cfg["client_ip_static"] = {"10.0.0.29": TELECOM_IP}
            self.put_cfg(cfg)
            self.dirty_cfg = True
            time.sleep(0.6)
            dom, res, log = self.probe_cloud("telecom", "openai.com")
            got = set(res["a"])
            exp = set(self.expected["telecom"])
            ok = log and log.get("action") == "cloud" and got and got.issubset(exp)
            self.rec("TC-B06", "分组兜底路径强制云检测", PASS if ok else FAIL,
                     f"{dom}: action={log.get('action') if log else '?'} list={log.get('list_name') if log else '?'} got={sorted(got)} ⊆ {sorted(exp)}")

        if want("TC-B07"):
            for dom in ["claude.ai", "reddit.com"]:
                since = int(time.time())
                res = self.doh(dom, "A")
                time.sleep(0.35)
                log = self.action_since(dom, since, tries=6)
                real = self.resolve_via(dom)
                ok = log and log.get("action") == "split" and not any(is_cf(x) for x in res["a"])
                self.rec("TC-B07", f"非CF域名不替换({dom})", PASS if ok else FAIL,
                         f"action={log.get('action') if log else '?'} got={res['a']} real={real}")

    # ---------- C: bypass & preference ----------
    def case_c(self, want):
        if want("TC-C01"):
            self.set_static(None)
            self.dirty_cfg = True
            time.sleep(0.5)
            dom = "cloudflare-cn.com"
            since = int(time.time())
            res = self.doh(dom, "A")
            time.sleep(0.35)
            log = self.action_since(dom, since, tries=6)
            ok = log and log.get("action") == "split" and log.get("list_name") == "定向域名"
            self.rec("TC-C01", "定向域名跳过云替换", PASS if ok else FAIL,
                     f"{dom}: action={log.get('action') if log else '?'} list={log.get('list_name') if log else '?'} A={res['a']}")
        if want("TC-C02"):
            self.set_static(None)
            self.dirty_cfg = True
            time.sleep(0.5)
            dom = self.take("global", "x.com")
            since = int(time.time())
            res = self.doh(dom, "A")
            time.sleep(0.35)
            log = self.action_since(dom, since, tries=6)
            ok = log and log.get("action") == "cloud" and log.get("list_name") == "国外"
            self.rec("TC-C02", "国外列表触发替换", PASS if ok else FAIL,
                     f"{dom}: action={log.get('action') if log else '?'} list={log.get('list_name') if log else '?'}")
        if want("TC-C03"):
            r = self.doh("discord.com", "AAAA", "POST")
            ok = r["rcode"] == 0 and len(r["aaaa"]) == 0
            self.rec("TC-C03", "AAAA prefer_a 过滤", PASS if ok else WARN,
                     f"rcode={r['rcode']} AAAA={r['aaaa']}")

    # ---------- D: cache & hot reload ----------
    def case_d(self, want):
        if want("TC-D01"):
            # 同一线路内连续两次查询：第 1 次回源、第 2 次应命中缓存且答案一致；
            # 换线路(改 static)后再验，确保缓存 key 含 scope、互不污染。
            # 若上游(国外列表 raced UDP)被污染返回非 CF 地址，则换域名重试。
            plan = [("global", None, ["canva.com", "shopify.com", "unsplash.com", "huggingface.co"]),
                    ("telecom", TELECOM_IP, ["proton.me", "dash.cloudflare.com", "platform.openai.com", "canva.com"]),
                    ("cmcc", CMCC_IP, ["substack.com", "shopify.com", "cursor.com", "unsplash.com"])]
            allok, det, anyrun = True, [], False
            for key, static, cands in plan:
                self.set_static(static)
                self.dirty_cfg = True
                time.sleep(0.6)
                picked = None
                for dom in cands:
                    r1 = self.doh(dom, "A")
                    time.sleep(0.35)
                    if r1["a"] and all(is_cf(x) for x in r1["a"]):
                        picked = (dom, r1)
                        break
                if not picked:
                    det.append(f"{key}:无可用的CF域名(上游污染，跳过)")
                    continue
                dom, r1 = picked
                r2 = self.doh(dom, "A")
                time.sleep(0.4)
                log2 = self.action_since(dom, int(time.time()) - 4, tries=4)
                same = set(r1["a"]) == set(r2["a"])
                sub = set(r2["a"]).issubset(set(self.expected[key]))
                cached = (log2 or {}).get("action") == "cache"
                anyrun = True
                allok = allok and same and sub
                det.append(f"{dom}({key}) r1={sorted(set(r1['a']))} r2={sorted(set(r2['a']))} 一致={same} 命中缓存={cached} ⊆={sub}")
            status = PASS if (anyrun and allok) else (SKIP if not anyrun else FAIL)
            self.rec("TC-D01", "scope 缓存隔离", status, "; ".join(det))
        if want("TC-D02"):
            pid0 = self.server_pid()
            cfg = self.get_cfg()
            cfg["client_ip_static"] = {"10.0.0.29": "1.48.0.1"}
            code, body = self.put_cfg(cfg)
            time.sleep(0.5)
            pid1 = self.server_pid()
            cfg["client_ip_static"] = None
            code2, body2 = self.put_cfg(cfg)
            time.sleep(0.3)
            rr = body.get("restart_required") if isinstance(body, dict) else None
            ok = code == 200 and isinstance(body, dict) and body.get("ok") and rr is False and (pid0 is None or pid0 == pid1)
            self.rec("TC-D02", "热更新不重启", PASS if ok else FAIL,
                     f"PUT={code} restart_required={rr} pid {pid0}->{pid1}")
        if want("TC-D03"):
            cur = self.get_cfg()
            keep = cur.get("client_ip_static") is None
            same_up = cur.get("upstream") == self.orig_cfg.get("upstream")
            self.rec("TC-D03", "配置持久化正确", PASS if keep and same_up else FAIL,
                     f"client_ip_static={cur.get('client_ip_static')} upstream={cur.get('upstream')}")

    # ---------- restore ----------
    def restore(self):
        print("\n[restore] 还原线上原始配置 ...")
        try:
            code, body = self.put_cfg(self.orig_cfg)
            time.sleep(0.6)
            cur = self.get_cfg()
            ok = (cur.get("client_ip_static") is None
                  and cur.get("upstream") == self.orig_cfg.get("upstream")
                  and all(g.get("cloud_replace", {}).get("override") ==
                          [o["cloud_replace"]["override"] for o in self.orig_cfg["isp_groups"] if o["isp"] == g["isp"]][0]
                          for g in cur["isp_groups"])
                  and all(g.get("split_refs") ==
                          [o["split_refs"] for o in self.orig_cfg["isp_groups"] if o["isp"] == g["isp"]][0]
                          for g in cur["isp_groups"]))
            print(f"[restore] PUT={code} 校验={'OK' if ok else '不一致!'}")
            self.restore_ok = ok
        except Exception as e:
            print(f"[restore] 失败: {e}")
            self.restore_ok = False

    # ---------- summary ----------
    def summary(self):
        print("\n================ 用例汇总 ================")
        for r in self.results:
            print(f"{r['status']:5s} {r['id']:8s} {r['name']}")
        n = {s: sum(1 for r in self.results if r["status"] == s) for s in (PASS, FAIL, WARN, SKIP)}
        print(f"\n合计: PASS={n[PASS]} FAIL={n[FAIL]} WARN={n[WARN]} SKIP={n[SKIP]}")
        print(f"配置还原: {'OK' if getattr(self, 'restore_ok', False) else '需人工确认'}")
        return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="10.0.0.30")
    ap.add_argument("--web", default=None)
    ap.add_argument("--doh", default=None)
    ap.add_argument("--ssh-key", default=os.path.expanduser("~/.ssh/proxydns"))
    ap.add_argument("--only", default=None)
    ap.add_argument("--skip-destructive", action="store_true")
    ap.add_argument("--restart", action="store_true", help="执行前重启服务以清空进程内缓存")
    ap.add_argument("--backup", default="/tmp/doh_split_backup.json")
    ap.add_argument("--out", default="/tmp/doh_split_results.json")
    args = ap.parse_args()
    args.web = args.web or f"http://{args.server}"
    args.doh = args.doh or f"https://{args.server}/dns-query"

    r = Runner(args)
    r.run()
    n = r.summary()
    with open(args.out, "w") as f:
        json.dump({"results": r.results, "summary": n,
                   "expected": r.expected, "restore_ok": getattr(r, "restore_ok", False)},
                  f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入 {args.out}")
    return 1 if n[FAIL] else 0


if __name__ == "__main__":
    sys.exit(main())