# TeaTun — a fast point-to-point ICMP tunnel

A small, self-contained tunnel that carries IP traffic between **two servers**
inside ICMP echo packets. Built for the Iran ⇄ abroad (kharej) server pair: on
paths where TCP/UDP are throttled but ping flows, TeaTun moves your traffic as
ordinary-looking ping/pong.

The core is a clean Go engine with no cgo; the `teatun.sh` manager drives
creation, forwarding, tuning and diagnostics through `systemd`.

---

## Highlights

**Correct by design**

- **No kernel-reflection breakage.** Tunnel packets carry a **direction byte**,
  so when the peer host auto-answers an echo request the reflected copy is
  rejected instead of being re-ingested as return traffic. The tunnel is correct
  whether or not you block ping (blocking it is still recommended so your uplink
  isn't doubled by reflected echoes — menu option 6).
- **Rules bound to the real device.** Per-tunnel `iptables` (FORWARD, NAT, MSS
  clamp) is applied to the actual TUN device read from the config, not the
  tunnel's instance name.
- **Auto-matching `icmp_id`.** The manager derives a stable default from the
  unordered pair of endpoint IPs, so both servers compute the same id without
  you copying it across.

**Fast**

- `recvmmsg` batched receive on the hot inbound path.
- Multi-queue TUN with one reader **and** one writer goroutine per queue, so
  egress reads and ingress writes run on separate cores without lock contention.
- Kernel **BPF socket filter**: the raw socket only wakes userspace for echoes
  carrying this tunnel's id.
- Per-socket tuning: `SO_RCVBUF/SNDBUF` (force variants), `SO_BUSY_POLL`,
  `SO_PRIORITY`, `IP_TOS` (DSCP), plus `TCPMSS` clamping for transit TCP.
- Thin encapsulation only — no added reliability/crypto layer, so it adds almost
  nothing to the underlying path RTT.

**Operable**

- Loopback health/metrics endpoint (`http://127.0.0.1:<health_port>/stats`).
- Periodic keepalives keep NAT open and drive a real liveness signal.
- Clean shutdown, leveled logging, throughput stats every `stats_interval_secs`.

---

## Install & run

On **each** server (Debian/Ubuntu, run as root):

```bash
# place the binary next to the script, or let the manager download it
chmod +x teatun-linux-amd64 && mv teatun-linux-amd64 teatun
chmod +x teatun.sh && ./teatun.sh
```

The menu:

1. **Create tunnel** — pick IRAN (server) or KHAREJ (client), enter the two
   public IPs, pick a performance profile. Create the matching tunnel on the
   other server with the **same `icmp_id`** (the suggested default already
   matches if you enter the same IP pair on both ends).
2. **Manage tunnels** — restart, logs, health/stats, delete.
3. **Port forwarding** — DNAT a local port to a destination reached over the
   tunnel (e.g. `tcp :443 -> 155.155.1.2:443`).
4. **Optimize host** — RAM/CPU-based `sysctl` + journal cap (also applied
   automatically on first install).
5. **Abuse defender** — block outbound to known abuse ranges (peers whitelisted).
6. **Ping control** — block the kernel's auto ping-reply so your uplink isn't
   doubled by reflected echoes. Optional; the tunnel works either way.

The two endpoints reach each other over the private `155.155.x.0/24` link
(e.g. `155.155.1.1` ⇄ `155.155.1.2`). Point your services/forwards at those.

**Lowest ping:** choose profile **latency** or **gaming** at create time
(busy-poll + `fq_codel` + DSCP EF). **Most bandwidth:** choose **throughput**.

---

## Building from source

Needs Go ≥ 1.21.

```bash
./build.sh all      # -> dist/teatun-linux-amd64, dist/teatun-linux-arm64
```

---

## Config reference (`/etc/teatun/<name>.toml`)

| key | meaning |
|-----|---------|
| `mode` | `server` (iran) or `client` (kharej) |
| `local_ip` / `remote_ip` | this host's and the peer's public IPv4 |
| `local_tun` / `peer_tun` | the private tunnel addresses, e.g. `155.155.1.1/24` |
| `tun_name` | TUN device, e.g. `tun1` |
| `mtu` | tunnel MTU (default 1320) |
| `icmp_id` | **must be identical on both ends** |
| `icmp_send_type` / `icmp_recv_type` | 8 = echo request, 0 = echo reply |
| `recv_batch_size` | `recvmmsg` batch on the receive path |
| `busy_poll_us`, `dscp`, `so_priority`, `sock_buf_bytes` | socket tuning |
| `workers` | reader/writer goroutines (and TUN queues, capped at 16) |
| `health_port` | loopback status endpoint; 0 disables |
| `tun_qdisc` | queueing discipline set on the TUN device |

---

## راهنمای سریع (فارسی)

**TeaTun** یک تونل ICMP نقطه‌به‌نقطه بین **دو سرور** است (ایران ⇄ خارج). ترافیک شما را
داخل بسته‌های ping جابه‌جا می‌کند، برای مسیرهایی که TCP/UDP محدود شده ولی ping کار می‌کند.

**نصب:** روی **هر دو** سرور به‌عنوان root:

```bash
chmod +x teatun-linux-amd64 && mv teatun-linux-amd64 teatun
chmod +x teatun.sh && ./teatun.sh
```

از منو گزینه‌ی **۱ (Create tunnel)** را بزنید: یک طرف را IRAN (سرور) و طرف دیگر را
KHAREJ (کلاینت) انتخاب کنید، IP عمومی هر دو سرور را وارد کنید و یک پروفایل کارایی
بردارید. روی سرور دوم هم همین کار را تکرار کنید؛ فقط دقت کنید **`icmp_id` دو طرف
یکی باشد** (اگر همان جفت IP را وارد کنید، مقدار پیشنهادی خودش یکی درمی‌آید).

دو سر تونل از طریق آدرس خصوصی `155.155.x.0/24` به هم می‌رسند
(مثلاً `155.155.1.1` ⇄ `155.155.1.2`). سرویس‌ها و فورواردهایتان را روی همین آدرس‌ها تنظیم کنید.

برای **کم‌ترین پینگ** پروفایل **latency** یا **gaming** را انتخاب کنید؛ برای **بیشترین پهنای‌باند** پروفایل **throughput** را.

**نکته:** گزینه‌ی **۶ (Ping control)** پاسخ خودکار ping کرنل را می‌بندد تا آپلود شما
روی بعضی هاست‌ها دوبار حساب نشود. اختیاری است؛ تونل در هر حالت کار می‌کند.
