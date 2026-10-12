#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsproxy 性能测试：UDP:53 vs DoH(443)

设计要点：
  * DoH 采用 ApacheBench(ab, -k 长连接) 作为独立负载源 —— 避免 Python 客户端自身成为瓶颈
    （实测 httpx/asyncio 客户端会把 DoH 吞吐严重低估）。
  * UDP 采用「每并发一条持久化 socket」的 asyncio 客户端，避免每查询新建 socket 的开销。
  * 每阶段采集服务端进程 CPU(基于 /proc/<pid>/stat 的 tick 差) 与 MemAvailable、loadavg。

指标：QPS、平均、P50/P95/P99、错误率。
维度：传输(UDP/DoH) × 并发(20/50/100) × 缓存(热/冷)。
冷缓存 = 每次查询唯一域名(必然回源)。

用法:
  python3 scripts/perf_doh.py --server 10.0.0.30
  python3 scripts/perf_doh.py --server 10.0.0.30 --quick
"""
import argparse
import asyncio
import base64
import json
import os
import random
import re
import socket
import string
import subprocess
import time
import warnings

import dns.message

warnings.filterwarnings("ignore")

HOT_DOMAINS = ["chatgpt.com", "medium.com", "discord.com", "openai.com", "example.com"]


def pctl(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    k = min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1))))
    return s[k]


class Perf:
    def __init__(self, args):
        self.args = args
        self._cores = None
        self._b64 = base64.urlsafe_b64encode(
            dns.message.make_query("example.com", "A").to_wire()).decode().rstrip("=")

    # ---------------- server helpers ----------------
    def ssh(self, cmd, timeout=30):
        full = ["ssh", "-i", os.path.expanduser(self.args.ssh_key), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=10", f"root@{self.args.server}", cmd]
        try:
            return subprocess.run(full, capture_output=True, text=True, timeout=timeout).stdout.strip()
        except Exception:
            return ""

    def pid(self):
        return self.ssh("systemctl show -p MainPID --value dnsproxy").strip()

    def cpu_ticks(self, pid):
        st = self.ssh(f"cat /proc/{pid}/stat 2>/dev/null")
        try:
            f = st.split()
            return int(f[13]) + int(f[14])
        except Exception:
            return None

    def mem_avail(self):
        try:
            return int(self.ssh("awk '/MemAvailable/{print $2}' /proc/meminfo")) // 1024
        except Exception:
            return None

    def cores(self):
        if self._cores is None:
            try:
                self._cores = int(self.ssh("nproc") or 2)
            except Exception:
                self._cores = 2
        return self._cores

    # ---------------- DoH via ab ----------------
    def ab_doh(self, concurrency, n):
        url = f"https://{self.args.server}/dns-query?dns={self._b64}"
        cmd = ["ab", "-n", str(n), "-c", str(concurrency), "-k", "-q", url]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout
        rps = float(re.search(r"Requests per second:\s+([\d.]+)", out).group(1)) if re.search(r"Requests per second:\s+([\d.]+)", out) else 0.0
        mean = float(re.search(r"Time per request:\s+([\d.]+) \[ms\] \(mean\)", out).group(1)) if re.search(r"Time per request:\s+([\d.]+) \[ms\] \(mean\)", out) else 0.0
        failed = int(re.search(r"Failed requests:\s+(\d+)", out).group(1)) if re.search(r"Failed requests:\s+(\d+)", out) else 0
        non2xx = int(re.search(r"Non-2xx responses:\s+(\d+)", out).group(1)) if re.search(r"Non-2xx responses:\s+(\d+)", out) else 0
        complete = int(re.search(r"Complete requests:\s+(\d+)", out).group(1)) if re.search(r"Complete requests:\s+(\d+)", out) else 0
        pct = {}
        tbl = re.search(r"Percentage of the requests served within a certain time \(ms\)(.*)", out, re.S)
        if tbl:
            for m in re.finditer(r"(\d+)%\s+(\d+)", tbl.group(1)):
                pct[int(m.group(1))] = int(m.group(2))
        return {"qps": round(rps, 1), "avg_ms": round(mean, 2),
                "p50": pct.get(50, 0), "p95": pct.get(95, 0), "p99": pct.get(99, 0),
                "errors": failed + non2xx, "requests": complete,
                "err_rate": round(100.0 * (failed + non2xx) / max(complete, 1), 2)}

    # ---------------- UDP via persistent sockets ----------------
    async def udp_phase(self, concurrency, duration, cold):
        lat, errors, cnt = [], 0, 0
        stop = time.time() + duration

        def domain():
            if cold:
                return "".join(random.choices(string.ascii_lowercase, k=12)) + ".example.com"
            return HOT_DOMAINS[random.randrange(len(HOT_DOMAINS))]

        async def worker():
            nonlocal errors, cnt
            loop = asyncio.get_running_loop()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            s.connect((self.args.server, 53))
            try:
                while time.time() < stop:
                    wire = dns.message.make_query(domain(), "A").to_wire()
                    t0 = time.perf_counter()
                    try:
                        await loop.sock_sendall(s, wire)
                        await asyncio.wait_for(loop.sock_recv(s, 4096), 5)
                        lat.append((time.perf_counter() - t0) * 1000.0)
                    except Exception:
                        errors += 1
                    cnt += 1
            finally:
                s.close()

        await asyncio.gather(*[worker() for _ in range(concurrency)])
        elapsed = duration
        return {"qps": round(len(lat) / elapsed, 1), "avg_ms": round(sum(lat) / len(lat), 2) if lat else 0,
                "p50": round(pctl(lat, 50), 2), "p95": round(pctl(lat, 95), 2), "p99": round(pctl(lat, 99), 2),
                "errors": errors, "requests": cnt, "err_rate": round(100.0 * errors / max(cnt, 1), 2)}

    def measure(self, fn):
        pid = self.pid()
        c0 = self.cpu_ticks(pid) if pid else None
        m0 = self.mem_avail()
        t0 = time.time()
        r = fn()
        el = time.time() - t0
        c1 = self.cpu_ticks(pid) if pid else None
        m1 = self.mem_avail()
        r["srv_cpu_pct"] = round(((c1 - c0) / 100.0) / el / max(self.cores(), 1) * 100.0, 1) if (c0 and c1) else None
        r["srv_mem_mb"] = m1
        r["wall_s"] = round(el, 1)
        return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="10.0.0.30")
    ap.add_argument("--ssh-key", default=os.path.expanduser("~/.ssh/proxydns"))
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="/tmp/perf_results.json")
    args = ap.parse_args()

    p = Perf(args)
    print(f"\n=== dnsproxy 性能测试 @ {args.server} (2核/512MB 生产机) ===")
    print(f"PID={p.pid()} cores={p.cores()} MemAvailable={p.mem_avail()}MB loadavg={p.ssh('cat /proc/loadavg')}")
    levels = [20, 50] if args.quick else [20, 50, 100]
    an = 3000 if args.quick else 8000
    dur = 6 if args.quick else 10
    results = []

    for c in levels:
        tag = f"DoH(热缓存) 并发={c}"
        print(f"\n>>> {tag}  ab -n {an} -c {c} -k ...")
        r = p.measure(lambda c=c, an=an: p.ab_doh(c, an))
        r.update({"tag": tag, "transport": "DoH", "concurrency": c})
        results.append(r)
        print(f"    QPS={r['qps']} avg={r['avg_ms']}ms P50={r['p50']} P95={r['p95']} P99={r['p99']}ms "
              f"错误率={r['err_rate']}% 服务端CPU={r['srv_cpu_pct']}% Mem={r['srv_mem_mb']}MB")
        time.sleep(2)

    for cold in (False, True):
        for c in levels:
            tag = f"UDP({'冷缓存' if cold else '热缓存'}) 并发={c}"
            print(f"\n>>> {tag} 运行 {dur}s ...")
            r = p.measure(lambda c=c, cold=cold: asyncio.run(p.udp_phase(c, dur, cold)))
            r.update({"tag": tag, "transport": "UDP", "concurrency": c})
            results.append(r)
            print(f"    QPS={r['qps']} avg={r['avg_ms']}ms P50={r['p50']} P95={r['p95']} P99={r['p99']}ms "
                  f"错误率={r['err_rate']}% 服务端CPU={r['srv_cpu_pct']}% Mem={r['srv_mem_mb']}MB")
            time.sleep(2)

    print("\n================ 性能汇总 ================")
    print(f"{'场景':24s} {'QPS':>8s} {'avg':>8s} {'P50':>7s} {'P95':>7s} {'P99':>7s} {'错误率':>7s} {'CPU':>7s}")
    for r in results:
        print(f"{r['tag']:24s} {r['qps']:>8.1f} {r['avg_ms']:>7.1f} {r['p50']:>7.1f} {r['p95']:>7.1f} "
              f"{r['p99']:>7.1f} {r['err_rate']:>6.2f}% "
              f"{(str(r['srv_cpu_pct'])+'%') if r['srv_cpu_pct'] is not None else 'n/a':>7s}")
    with open(args.out, "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入 {args.out}")


if __name__ == "__main__":
    main()