<div align="center">

<br/>

**`SPLIT-TUNNEL · TCP UPLOAD · UDP DOWNLOAD · IP SPOOF · AES-256-GCM OBFS`**

**`sendmmsg BATCH · 256-SHARD MUX · BBR CONGESTION · io_uring · ZERO-COPY`**

<br/>

![QS-Tunnel demo](q.jpg)

<br/>

[![Version](https://img.shields.io/badge/VERSION-2.0.0-00f5ff?style=for-the-badge&logo=github&logoColor=white&labelColor=020510)](https://github.com/Qteam-official/QS-Tunnel/releases)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white&labelColor=020510)](https://golang.org)
[![Linux](https://img.shields.io/badge/Linux-5.1+-ff9500?style=for-the-badge&logo=linux&logoColor=white&labelColor=020510)](https://github.com/Qteam-official/QS-Tunnel)
[![License](https://img.shields.io/badge/License-MIT-00ff9f?style=for-the-badge&labelColor=020510)](LICENSE)

[![Stars](https://img.shields.io/github/stars/Qteam-official/QS-Tunnel?style=for-the-badge&color=ff2d78&labelColor=020510&logo=github&label=⭐%20STARS)](https://github.com/Qteam-official/QS-Tunnel/stargazers)
[![Issues](https://img.shields.io/github/issues/Qteam-official/QS-Tunnel?style=for-the-badge&color=bf5fff&labelColor=020510&logo=github&label=🐛%20ISSUES)](https://github.com/Qteam-official/QS-Tunnel/issues)
[![Telegram](https://img.shields.io/badge/💬%20Telegram-@Q__teams-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white&labelColor=020510)](https://t.me/Q_teams)
[![YouTube](https://img.shields.io/badge/▶%20YouTube-@Q--TEAM-FF0000?style=for-the-badge&logo=youtube&logoColor=white&labelColor=020510)](https://youtube.com/@Q-TEAM-official)

<br/>

> `🇮🇷` [**مستندات فارسی**](#-مستندات-فارسی) &nbsp;`|`&nbsp; `🇬🇧` [**English Docs**](#-english-documentation)

<br/>

---

### ⚠️ Research & Educational Use Only

This project is intended **strictly for research and educational purposes**.  
We bear no responsibility for misuse or illegal activities. Users are solely responsible for how they use this software.  
In some regions, improper use may carry **legal consequences**.

---

</div>

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                               ARCHITECTURE  v2.0                                     │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  Browser ──SOCKS5──▶ CLIENT ──TCP──▶ xray/v2ray ──TCP──▶ SERVER ──▶ 🌍 Net        │
│                         ▲                                      │                     │
│                         └──── UDP Direct (sendmmsg batch) ◀───┘                     │
│                                  + IP Spoof (AF_PACKET)                              │
│                                  + AES-256-GCM Obfs                                 │
│                                                                                      │
│  Upload  : TCP via local proxy (xray / v2ray / sing-box)  →  censorship bypass      │
│  Download: UDP direct · sendmmsg batch · 256-shard mux    →  129x syscall speedup   │
│  Spoof   : AF_PACKET raw socket · forged source IP        →  correlation resistant   │
│  Obfs    : AES-256-GCM + QUIC-like header · port 443      →  deep DPI evasion       │
│  Engine  : BBR congestion · io_uring · zero-copy splice   →  kernel-level speed     │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## `🇬🇧` English Documentation

### What is QS-Tunnel?

**QS-Tunnel** is a high-performance **split-tunnel** proxy engineered for maximum throughput and traffic stealth. Upload and download travel through **completely separate paths** — TCP for censorship bypass, raw UDP for speed. v2.0 rewrites the core engine with production-grade concurrency, tested against 10,000+ concurrent connections.

| Path | Protocol | Route | Benefit |
|------|----------|-------|---------|
| ⬆ **Upload** | TCP | Client → xray/v2ray → Server | Censorship bypass |
| ⬇ **Download** | UDP + sendmmsg | Server → Client (direct) | 129× batch speedup |
| 🎭 **IP Spoof** | AF_PACKET | Forged source IP on UDP | Correlation-resistant |
| 🔐 **Obfs** | AES-256-GCM | QUIC Short Header · port 443 | Beats deep DPI |
| ⚡ **Engine** | io_uring + splice | Zero-copy kernel path | Near wire-speed |

---

### What's New in v2.0

```
┌──────────────────────────────────────────────────────────────────────────┐
│  v2.0  ENGINE OVERHAUL                                                    │
├──────────────────────┬───────────────────────────────────────────────────┤
│  sendmmsg batch UDP  │  32 packets in 1 syscall · 129× speedup           │
│  256-shard mux       │  lock contention → near-zero at 10K+ connections  │
│  BBR congestion      │  Google's BDP model · auto-tuning bandwidth        │
│  io_uring async I/O  │  Linux 5.1+ · submission ring · no blocking       │
│  zero-copy splice()  │  TCP→UDP kernel path · 0 user-space memcpy        │
│  download pool       │  NumCPU×2 workers · no goroutine per connection    │
│  reconnect jitter    │  exponential backoff + random jitter               │
│  race-free reasm     │  sync.Map Manager · deadlock-proof                 │
│  GC tuning           │  GOGC=200 · fewer pauses under peak load           │
│  flow control fix    │  2s timeout + drop counter instead of 8s block     │
└──────────────────────┴───────────────────────────────────────────────────┘
```

---

### Feature Matrix

```
┌──────────────────────────────────┬────────┬────────────────────────────────────────┐
│ FEATURE                          │ STATUS │ DESCRIPTION                            │
├──────────────────────────────────┼────────┼────────────────────────────────────────┤
│ Split upload / download          │  [ON]  │ TCP up · UDP down · fully independent  │
│ sendmmsg batch send              │  [ON]  │ 32 pkts per syscall · 129× speedup     │
│ 256-shard stream mux             │  [ON]  │ zero-contention at 10K+ streams        │
│ IP Spoof (AF_PACKET)             │  [ON]  │ Raw socket · forge any source IP       │
│ Obfs mode (AES-256-GCM)          │  [ON]  │ QUIC Short Header · port 443 · DPI safe│
│ BBR congestion control           │  [ON]  │ Startup → Drain → ProbeBW phases       │
│ io_uring async I/O               │  [ON]  │ Linux 5.1+ · kernel polling thread     │
│ Zero-copy splice()               │  [ON]  │ TCP→UDP without user-space copy        │
│ Download worker pool             │  [ON]  │ NumCPU×2 · no goroutine per connection │
│ Reconnect jitter                 │  [ON]  │ Prevents thundering herd on TCP drop   │
│ Race-free reassembly             │  [ON]  │ 25/25 stress tests · race detector     │
│ GC-tuned runtime                 │  [ON]  │ GOGC=200 · fewer pauses at peak        │
│ Per-stream TCP                   │  [ON]  │ One drop never kills other streams     │
│ Auto IP / gateway detection      │  [ON]  │ Zero manual network config             │
│ Flow control                     │  [ON]  │ Window-based · 2s timeout · drop meter │
│ JSON config + CLI flags          │  [ON]  │ Priority merge · --gen-config          │
│ Random key generator             │  [ON]  │ --gen-key → 32-byte CSPRNG             │
│ Dashboard HTTP UI                │  [ON]  │ Auth · stats · xui setup · DNS flush   │
│ 3x-ui / x-ui integration         │  [ON]  │ Auto inbound · routing · outbounds     │
│ DNS cache (LRU + TTL)            │  [ON]  │ 4096-entry · async sweep every 200ms   │
│ MTU auto-fragment                │  [ON]  │ Splits oversized frames automatically  │
│ Metrics HTTP endpoint            │  [ON]  │ /metrics JSON · Prometheus-compatible  │
│ High concurrency                 │  [ON]  │ 10,000+ concurrent streams tested      │
│ Idle timeout                     │  [ON]  │ Auto-cleanup · configurable TTL        │
└──────────────────────────────────┴────────┴────────────────────────────────────────┘
```

---

### Performance Benchmarks

```
  Hardware: Intel Xeon @ 2.1 GHz · 1 core (production typically 4–32 cores)

  BenchmarkProtoEncodeUDP    →    15.6 ns/op  ·  90,220 MB/s  ·  0 allocs
  BenchmarkProtoDecodeTCPHdr →     0.16 ns/op  (inlined by compiler)
  BenchmarkReasmInOrder      →   148.9 ns/op  ·  1 alloc/op
  BenchmarkSendpool          →   105.5 ns/op  ·  13,264 MB/s  ·  0 allocs
  BenchmarkShardedMap        →    96.1 ns/op  ·  0 allocs

  sendto   (single syscall)  →      316,000 pps
  sendmmsg (batch ×32)       →   40,776,000 pps   [ 129× faster ]
```

---

### Quick Start

```bash
# Clone & build
git clone https://github.com/Qteam-official/QS-Tunnel
cd QS-Tunnel
go build -ldflags="-s -w" -o bin/server ./cmd/server
go build -ldflags="-s -w" -o bin/client ./cmd/client

# Generate shared obfs key (both sides must use the same key)
./bin/client --gen-key

# Generate config templates
./bin/server --gen-config   # → server.json
./bin/client --gen-config   # → client.json

# Deploy
sudo ./bin/server --config server.json   # on VPS
     ./bin/client --config client.json   # on local machine

# Point browser SOCKS5 → 127.0.0.1:1080
```

---

### Server Config (`server.json`)

```jsonc
{
  "listen_addr":        "0.0.0.0:9000",
  "download_src_port":  9001,

  // Transport: "udp" = fast (default)  |  "obfs" = AES-256-GCM, DPI-resistant
  "transport_mode":     "udp",
  "obfs_key":           "",          // 64-char hex — generate with --gen-key

  // IP Spoof — forge UDP source IP (requires root / CAP_NET_RAW)
  "spoof_ip":           "",          // e.g. "1.2.3.4"
  "spoof_interface":    "",          // auto-detected from routing table
  "spoof_gateway":      "",          // auto-detected from /proc/net/route

  "max_clients":        1000,        // semaphore — hard cap
  "flow_window_bytes":  131072,      // 128 KB per stream
  "dial_timeout_sec":   5,
  "idle_timeout_sec":   120,

  // Dashboard
  "dashboard_addr":     "0.0.0.0:8080",
  "dashboard_key":      "changeme",  // change this!

  "metrics_addr":       "127.0.0.1:9090",
  "verbose":            false
}
```

---

### Client Config (`client.json`)

```jsonc
{
  "server_addr":    "VPS_IP:9000",
  "upload_proxy":   "127.0.0.1:10808",  // local xray / v2ray / sing-box
  "local_socks":    "127.0.0.1:1080",
  "download_port":  8000,

  "my_public_ip":   "",                 // auto-detected via routing table ✨

  "transport_mode": "udp",              // must match server
  "obfs_key":       "",

  "max_streams":    512,

  // Dashboard
  "dashboard_addr": "127.0.0.1:8081",
  "dashboard_key":  "changeme",

  // 3x-ui auto-setup
  "xui": {
    "panel_url":    "http://127.0.0.1:2053",
    "username":     "admin",
    "password":     "",
    "inbound_port": 1111
  },

  "metrics_addr":   "127.0.0.1:9091",
  "verbose":        false
}
```

---

### Transport Modes

<details>
<summary><b>▶ UDP — fast, any port (default)</b></summary>

Zero encryption overhead. sendmmsg batches 32 packets per syscall for 129× throughput.

```bash
sudo ./bin/server --listen-addr 0.0.0.0:9000 --download-src-port 9001
     ./bin/client --server VPS_IP:9000 --download-port 8000
```
</details>

<details>
<summary><b>▶ OBFS — AES-256-GCM, indistinguishable from QUIC/HTTPS</b></summary>

Every download packet is encrypted and wrapped in a QUIC Short Header. DPI sees standard HTTPS on port 443.

```
Wire format:
  [ 0x4X | 8B connID | 8B pktNum | AES-256-GCM(nonce+ciphertext+tag) ]
      ↑                                ↑
   QUIC Short Header flag          encrypted — entropy ≈ random noise
```

```bash
./bin/client --gen-key

sudo ./bin/server \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY

./bin/client \
  --download-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY
```
</details>

<details>
<summary><b>▶ IP Spoof — forge UDP source IP (requires root)</b></summary>

The server crafts raw AF_PACKET Ethernet frames with a forged IP. The client receives downloads appearing to originate from any IP — breaking traffic correlation and IP-based analysis.

Interface and gateway are **auto-detected** from the kernel routing table.

```bash
# Basic spoof
sudo ./bin/server --spoof-ip 1.2.3.4

# Maximum stealth: Spoof + Obfs combined
sudo ./bin/server \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY \
  --spoof-ip 1.2.3.4
```

> Requires `CAP_NET_RAW` or root on the VPS.
</details>

<details>
<summary><b>▶ Engine internals — io_uring · BBR · zero-copy · sendmmsg</b></summary>

**sendmmsg batch**
32 UDP frames dispatched in a single syscall:
```
single sendto   →    316K pps
sendmmsg ×32    → 40,776K pps   (129× faster)
```

**io_uring (Linux 5.1+)**
Submission and completion rings bypass the traditional syscall path. No context switches per packet — per-packet kernel overhead drops from ~500ns to ~80ns.

**BBR Congestion Control**
Google's Bottleneck Bandwidth and RTT algorithm:
- `Startup`: probes bandwidth with 2.885× pacing gain
- `Drain`: empties the queue
- `ProbeBW`: 8-cycle gain wheel, self-tuning
- `ProbeRTT`: re-measures minimum RTT every 10s

**Zero-copy splice()**
Download data moves TCP socket → pipe → UDP socket entirely inside the kernel. No memcpy into user space. Reduces CPU usage by 30–50% on high-throughput links.

**256-shard stream map**
Instead of one RWMutex over all streams, 256 independent shards. At 10K concurrent connections, lock contention drops to near-zero.
</details>

---

### Dashboard

```
Server:  http://VPS_IP:8080
Client:  http://127.0.0.1:8081
```

Session-based auth (1-hour token) · rate-limited to 5 attempts before 60s lockout.

Features: live stream counters · upload/download bytes · reconnect count · flow drops · DNS cache flush · 3x-ui auto-setup · config save/reload · one-click restart.

---

### CLI Reference

<details>
<summary><b>Client flags</b></summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | — | JSON config file |
| `--server` | — | Server `IP:port` |
| `--upload-proxy` | `127.0.0.1:10808` | Local SOCKS5 (xray/v2ray) |
| `--local-socks` | `127.0.0.1:1080` | Browser proxy listener |
| `--download-port` | `8000` | UDP download port |
| `--my-public-ip` | auto | Your public IP |
| `--transport-mode` | `udp` | `udp` or `obfs` |
| `--obfs-key` | — | 64-char hex key |
| `--max-streams` | `512` | Max concurrent streams |
| `--dashboard-addr` | `127.0.0.1:8081` | Dashboard HTTP |
| `--dashboard-key` | — | Dashboard password |
| `--metrics-addr` | `127.0.0.1:9091` | Metrics HTTP |
| `--gen-config` | — | Write `client.json` template |
| `--gen-key` | — | Generate random obfs key |
| `-v` | — | Verbose logging |

</details>

<details>
<summary><b>Server flags</b></summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | — | JSON config file |
| `--listen-addr` | `0.0.0.0:9000` | TCP listen address |
| `--download-src-port` | `9001` | UDP source port |
| `--transport-mode` | `udp` | `udp` or `obfs` |
| `--obfs-key` | — | 64-char hex key |
| `--spoof-ip` | — | Fake UDP source IP |
| `--spoof-interface` | auto | Network interface |
| `--spoof-gateway` | auto | Gateway MAC lookup |
| `--max-clients` | `1000` | Max connected clients |
| `--dashboard-addr` | `0.0.0.0:8080` | Dashboard HTTP |
| `--dashboard-key` | — | Dashboard password |
| `--metrics-addr` | `127.0.0.1:9090` | Metrics HTTP |
| `--gen-config` | — | Write `server.json` template |
| `--gen-key` | — | Generate random obfs key |
| `-v` | — | Verbose logging |

</details>

---

### Metrics

```bash
curl http://127.0.0.1:9090/metrics | python3 -m json.tool
```

```json
{
  "active_streams":    42,
  "active_clients":    8,
  "total_streams":     1024,
  "upload_bytes":      52428800,
  "download_bytes":    524288000,
  "reconnects":        3,
  "flow_drops":        0,
  "rejected_conns":    0,
  "reassembly_drops":  0,
  "flow_acks_sent":    32768,
  "dns_hits":          891,
  "dns_misses":        133,
  "uptime_sec":        3600
}
```

---

### High Concurrency Tuning

```bash
# /etc/sysctl.conf
net.core.somaxconn          = 65535
net.ipv4.tcp_tw_reuse       = 1
net.ipv4.tcp_fin_timeout    = 15
net.core.rmem_max           = 134217728
net.core.wmem_max           = 134217728
net.core.netdev_max_backlog = 65536
sysctl -p

# /etc/security/limits.conf
* soft nofile 1000000
* hard nofile 1000000

# Run
ulimit -n 1000000
GOGC=400 sudo ./bin/server --config server.json
```

`server.json` for large deployments:

```jsonc
{
  "max_clients":       5000,
  "flow_window_bytes": 131072,
  "idle_timeout_sec":  60,
  "dial_timeout_sec":  5
}
```

For maximum throughput (disable GC entirely):

```bash
GOGC=off GOMEMLIMIT=4GiB sudo ./bin/server --config server.json
```

---

### Requirements

```
• Go 1.22+
• Linux kernel 5.1+  (for io_uring)
• VPS with public IP
• xray / v2ray / sing-box on client  (upload path)
• root or CAP_NET_RAW on server      (IP Spoof only)
```

---

## `🇮🇷` مستندات فارسی

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            معماری سیستم  v2.0                                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  مرورگر ──SOCKS5──▶ کلاینت ──TCP──▶ xray/v2ray ──TCP──▶ سرور ──▶ 🌍          │
│                         ▲                                     │                  │
│                         └──── UDP (sendmmsg batch) ◀──────────┘                 │
│                                  + IP Spoof (AF_PACKET)                          │
│                                  + AES-256-GCM Obfs                              │
│                                                                                  │
│  آپلود  : TCP از xray/v2ray/sing-box        →  دور زدن فیلتر                   │
│  دانلود : UDP مستقیم · sendmmsg · ۱۲۹×      →  حداکثر سرعت                     │
│  Spoof  : جعل IP مبدا با AF_PACKET          →  مقاوم در برابر correlation       │
│  Obfs   : AES-256-GCM + QUIC-like header    →  شکست DPI عمیق                   │
│  Engine : io_uring + splice + BBR           →  سرعت در سطح kernel              │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### چرا QS-Tunnel؟

```
معمولی:     مرورگر ──▶ proxy ──▶ سرور ──▶ مقصد ──▶ proxy ──▶ مرورگر
                            [ همه از یک مسیر ]

QS-Tunnel:  آپلود  ──▶ xray ──▶ سرور ──▶ مقصد
            دانلود ◀── UDP مستقیم (sendmmsg · IP Spoof · Obfs) ────
```

---

### جدول ویژگی‌ها v2.0

```
┌────────────────────────────────┬──────────────────────────────────────────────────┐
│ ویژگی                          │ توضیح                                            │
├────────────────────────────────┼──────────────────────────────────────────────────┤
│ sendmmsg batch UDP             │ ۳۲ پکت در یه syscall · ۱۲۹× سریع‌تر             │
│ 256-shard stream map           │ بدون lock contention در ۱۰,۰۰۰+ connection        │
│ BBR congestion control         │ الگوریتم گوگل · تنظیم خودکار bandwidth          │
│ io_uring async I/O             │ Linux 5.1+ · polling · بدون context switch       │
│ Zero-copy splice()             │ TCP→UDP بدون کپی به user-space                   │
│ Download worker pool           │ NumCPU×2 worker · بدون goroutine per connection  │
│ Reconnect jitter               │ backoff نمایی + تصادفی · بدون reconnect storm    │
│ Reasm بدون race condition      │ sync.Map · 25/25 تست با -race detector           │
│ Flow control بهبودیافته        │ timeout 2s + drop counter جای block 8s           │
│ IP Spoof (AF_PACKET)           │ جعل IP مبدا با raw socket                        │
│ Obfs (AES-256-GCM)             │ QUIC-like header · پورت 443 · شکست DPI          │
│ Dashboard HTTP                 │ احراز هویت · آمار · xui · DNS flush              │
│ 3x-ui / x-ui integration       │ ساخت خودکار inbound · routing · outbound         │
│ DNS cache (LRU + TTL)          │ ۴۰۹۶ entry · async sweep هر ۲۰۰ms              │
│ MTU auto-fragment              │ تقسیم خودکار فریم‌های بزرگ                       │
│ GC tuning                      │ GOGC=200 · pause کمتر در peak load               │
│ متریک realtime                 │ /metrics JSON · سازگار با Prometheus              │
│ مقیاس بالا                     │ تست با ۱۰,۰۰۰+ stream همزمان                   │
└────────────────────────────────┴──────────────────────────────────────────────────┘
```

---

### Benchmark واقعی

```
  CPU: Intel Xeon @ 2.1 GHz · 1 core

  ProtoEncodeUDP    →    15.6 ns/op  ·  90,220 MB/s  ·  0 alloc
  ProtoDecodeTCP    →     0.16 ns/op  (inline شده توسط compiler)
  ReasmInOrder      →   148.9 ns/op  ·  1 alloc/op
  Sendpool          →   105.5 ns/op  ·  13,264 MB/s  ·  0 alloc
  ShardedMap        →    96.1 ns/op  ·  0 alloc

  sendto تکی        →      316,000 pps  (baseline)
  sendmmsg ×32      →   40,776,000 pps  [ ۱۲۹× سریع‌تر ]
```

---

### شروع سریع

```bash
git clone https://github.com/Qteam-official/QS-Tunnel
cd QS-Tunnel
go build -ldflags="-s -w" -o bin/server ./cmd/server
go build -ldflags="-s -w" -o bin/client ./cmd/client

# کلید obfs مشترک بساز (هر دو طرف باید یکی داشته باشن)
./bin/client --gen-key

# template config
./bin/server --gen-config
./bin/client --gen-config

# اجرا روی VPS
sudo ./bin/server --config server.json

# اجرا روی سیستم خودت
./bin/client --config client.json

# مرورگر: SOCKS5 → 127.0.0.1:1080
```

---

### حالت‌های Transport

<details>
<summary><b>▶ UDP — سریع، هر پورت (پیش‌فرض)</b></summary>

بدون overhead رمزنگاری. sendmmsg 32 پکت رو در یه syscall میفرسته — 129× سریع‌تر از sendto معمولی.

```bash
./bin/server --download-src-port 9001
./bin/client --download-port 8000
```
</details>

<details>
<summary><b>▶ Obfs — AES-256-GCM، از دید DPI شبیه QUIC/HTTPS</b></summary>

هر پکت دانلود رمز میشه و با QUIC Short Header ارسال میشه. فایروال‌ها HTTPS معمولی روی پورت 443 می‌بینند.

```bash
./bin/client --gen-key

sudo ./bin/server \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY

./bin/client \
  --download-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY
```
</details>

<details>
<summary><b>▶ IP Spoof — جعل IP مبدا UDP (نیاز به root)</b></summary>

سرور با AF_PACKET raw socket پکت‌های اترنت کامل می‌سازد. کلاینت دانلود رو از IP جعلی دریافت می‌کند.

Interface و gateway اگر خالی باشند **خودکار** از routing table kernel تشخیص داده می‌شوند.

```bash
# Spoof ساده
sudo ./bin/server --spoof-ip 1.2.3.4

# حداکثر پنهان‌کاری: Spoof + Obfs
sudo ./bin/server \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY \
  --spoof-ip 1.2.3.4
```
</details>

<details>
<summary><b>▶ Dashboard — پنل مدیریت HTTP</b></summary>

```
سرور:   http://VPS:8080
کلاینت: http://127.0.0.1:8081
```

امکانات: آمار real-time · راه‌اندازی خودکار 3x-ui · فلاش DNS cache · ذخیره config · restart یک‌کلیکه

احراز هویت با token 1 ساعته — rate limit: 5 بار اشتباه → 60 ثانیه lock.
</details>

---

### تنظیم OS برای ترافیک بالا

```bash
# /etc/sysctl.conf
net.core.somaxconn          = 65535
net.ipv4.tcp_tw_reuse       = 1
net.ipv4.tcp_fin_timeout    = 15
net.core.rmem_max           = 134217728
net.core.wmem_max           = 134217728
net.core.netdev_max_backlog = 65536
sysctl -p

# /etc/security/limits.conf
* soft nofile 1000000
* hard nofile 1000000

# اجرا
ulimit -n 1000000
GOGC=400 sudo ./bin/server --config server.json
```

برای deployment بزرگ:

```jsonc
{
  "max_clients":       5000,
  "flow_window_bytes": 131072,
  "idle_timeout_sec":  60,
  "dial_timeout_sec":  5
}
```

---

### اولویت تنظیمات

```
--flag صریح   ◀── بالاترین اولویت
config.json   ◀── میانی
auto-detect   ◀── هوشمند (IP · gateway · interface)
default       ◀── پایین‌ترین
```

```bash
# ترکیب config + override با flag
./bin/client --config client.json --server NEW_VPS:9000 -v
```

---

### نیازمندی‌ها

```
• Go 1.22+
• Linux kernel 5.1+  (برای io_uring)
• VPS با IP عمومی
• xray / v2ray / sing-box روی کلاینت  (آپلود)
• root یا CAP_NET_RAW روی سرور        (فقط برای IP Spoof)
```

---

<div align="center">

<br/>

[![Telegram](https://img.shields.io/badge/💬%20کانال%20تلگرام-@Q__teams-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white&labelColor=020510)](https://t.me/Q_teams)
[![YouTube](https://img.shields.io/badge/▶%20یوتیوب-@Q--TEAM--official-FF0000?style=for-the-badge&logo=youtube&logoColor=white&labelColor=020510)](https://youtube.com/@Q-TEAM-official)
[![Issues](https://img.shields.io/badge/🐛%20گزارش%20باگ-GitHub-bf5fff?style=for-the-badge&logo=github&logoColor=white&labelColor=020510)](https://github.com/Qteam-official/QS-Tunnel/issues)

<br/>

**`⭐ اگه پروژه مفید بود ستاره بدید — Star if useful ⭐`**

<br/>

`MIT License — free to use, modify, and distribute`

</div>
