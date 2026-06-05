"""
PacketScope — Phase 1: Data Ingestion
tcpdump 檔案解析器，移植並強化自原 HTML 版本
支援格式：-tttt / -tt / -nn / -v / -q
"""

import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── RFC 1918 / Loopback 判斷 ────────────────────────────────────────────────

def is_private(ip: str) -> bool:
    if ip in ("[IPv6]", "", "unknown"):
        return False
    try:
        p = list(map(int, ip.split(".")))
        return (
            p[0] == 10
            or (p[0] == 172 and 16 <= p[1] <= 31)
            or (p[0] == 192 and p[1] == 168)
            or p[0] == 127
        )
    except Exception:
        return False


# ── 資料結構 ────────────────────────────────────────────────────────────────

@dataclass
class Packet:
    # 時間
    ts: float           # epoch seconds (float)
    rel: float = 0.0    # 相對時間（秒，第一封包 = 0）

    # 網路
    src_ip:   str = ""
    dst_ip:   str = ""
    src_port: int = 0
    dst_port: int = 0
    proto:    str = "TCP"   # TCP / UDP / ICMP / ARP / IPv6 / OTHER

    # TCP
    flags:    str = ""      # e.g. "S", "SA", "PA", "R", "F"
    seq:      int = 0
    ack:      int = 0
    win:      int = 0
    ttl:      int = 0

    # Payload
    length:   int = 0       # bytes

    # 衍生標記（Phase 2 用）
    is_private_src: bool = False
    is_private_dst: bool = False
    direction:      str = ""   # "out" / "in" / "internal" / "external"
    is_half_flow:   bool = False   # 只有 SYN 沒有 SYN-ACK


# ── Timestamp 解析 ──────────────────────────────────────────────────────────

_TS_FULL   = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+)")
_TS_TIME   = re.compile(r"^(\d{2}:\d{2}:\d{2}\.\d+)")
_TS_UNIX   = re.compile(r"^(\d+\.\d{4,})")

def _parse_ts(s: str) -> Optional[float]:
    m = _TS_FULL.match(s)
    if m:
        dt_str = f"{m.group(1)}T{m.group(2)}+00:00"
        try:
            return datetime.fromisoformat(dt_str).timestamp()
        except ValueError:
            pass

    m = _TS_TIME.match(s)
    if m:
        parts = m.group(1).split(":")
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])

    m = _TS_UNIX.match(s)
    if m:
        return float(m.group(1))

    return None


# ── 單行解析 ────────────────────────────────────────────────────────────────

# IPv4 with port:  192.168.1.1.12345 > 8.8.8.8.443
_IP4_PORT  = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)"
)
# IPv4 without port (ICMP etc)
_IP4_NPORT = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})"
)
_FLAGS     = re.compile(r"Flags \[([^\]]+)\]")
_LENGTH    = re.compile(r"length (\d+)")
_SEQ       = re.compile(r"seq (\d+)(?::(\d+))?")
_ACK_RE    = re.compile(r"ack (\d+)")
_WIN       = re.compile(r"win (\d+)")
_TTL       = re.compile(r"ttl (\d+)")


def parse_line(raw: str) -> Optional[Packet]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    has_ip = " IP " in raw or " IP6 " in raw or " ARP " in raw
    if not has_ip:
        return None

    # ── Timestamp ──
    ts = _parse_ts(raw)
    if ts is None:
        return None

    pkt = Packet(ts=ts)

    # ── Protocol ──
    if " ARP " in raw:
        pkt.proto = "ARP"
    elif " IP6 " in raw:
        pkt.proto = "IPv6"
        pkt.src_ip = "[IPv6]"
        pkt.dst_ip = "[IPv6]"
    else:
        pkt.proto = "TCP"   # 預設，後面再更新

    # ── IP + Port ──
    m = _IP4_PORT.search(raw)
    if m:
        pkt.src_ip, pkt.src_port = m.group(1), int(m.group(2))
        pkt.dst_ip, pkt.dst_port = m.group(3), int(m.group(4))
    elif pkt.proto not in ("ARP", "IPv6"):
        m2 = _IP4_NPORT.search(raw)
        if m2:
            pkt.src_ip, pkt.dst_ip = m2.group(1), m2.group(2)
            pkt.proto = "ICMP"
        else:
            return None

    # ── Protocol refinement ──
    if pkt.proto not in ("ARP", "IPv6", "ICMP"):
        raw_up = raw.upper()
        if ": ICMP" in raw or " ICMP " in raw:
            pkt.proto = "ICMP"
        elif ": UDP" in raw or " UDP " in raw_up:
            pkt.proto = "UDP"
        else:
            pkt.proto = "TCP"

    # ── TCP fields ──
    m = _FLAGS.search(raw);  pkt.flags  = m.group(1) if m else ""
    m = _SEQ.search(raw);    pkt.seq    = int(m.group(1)) if m else 0
    m = _ACK_RE.search(raw); pkt.ack    = int(m.group(1)) if m else 0
    m = _WIN.search(raw);    pkt.win    = int(m.group(1)) if m else 0
    m = _TTL.search(raw);    pkt.ttl    = int(m.group(1)) if m else 0
    m = _LENGTH.search(raw); pkt.length = int(m.group(1)) if m else 0

    # ── 衍生欄位 ──
    pkt.is_private_src = is_private(pkt.src_ip)
    pkt.is_private_dst = is_private(pkt.dst_ip)

    if pkt.is_private_src and not pkt.is_private_dst:
        pkt.direction = "out"
    elif not pkt.is_private_src and pkt.is_private_dst:
        pkt.direction = "in"
    elif pkt.is_private_src and pkt.is_private_dst:
        pkt.direction = "internal"
    else:
        pkt.direction = "external"

    return pkt


# ── 批次解析 ────────────────────────────────────────────────────────────────

def parse_capture(text: str) -> list[Packet]:
    packets: list[Packet] = []
    errors = 0

    for line in text.splitlines():
        try:
            p = parse_line(line)
            if p:
                packets.append(p)
        except Exception:
            errors += 1

    if not packets:
        return packets

    # 相對時間
    t0 = packets[0].ts
    for p in packets:
        p.rel = round(p.ts - t0, 6)

    # Half-flow 標記（SYN 沒有回應的）
    syn_set: set[tuple] = set()
    for p in packets:
        if p.proto == "TCP":
            if p.flags == "S":   # pure SYN
                syn_set.add((p.src_ip, p.dst_ip, p.dst_port))
            elif "A" in p.flags and "S" in p.flags:  # SYN-ACK
                key = (p.dst_ip, p.src_ip, p.src_port)
                syn_set.discard(key)

    for p in packets:
        if p.proto == "TCP" and p.flags == "S":
            p.is_half_flow = (p.src_ip, p.dst_ip, p.dst_port) in syn_set

    if errors:
        print(f"[parser] 跳過 {errors} 行（格式不符）", file=sys.stderr)

    return packets


def parse_file(path: str | Path) -> list[Packet]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    packets = parse_capture(text)
    print(f"[parser] 解析完成：{len(packets)} 個封包，來源：{path}")
    return packets


# ── CLI 快速測試 ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法：python parser.py <tcpdump.txt>")
        sys.exit(1)

    pkts = parse_file(sys.argv[1])
    if pkts:
        protos: dict[str, int] = {}
        dirs:   dict[str, int] = {}
        for p in pkts:
            protos[p.proto] = protos.get(p.proto, 0) + 1
            dirs[p.direction] = dirs.get(p.direction, 0) + 1

        print(f"  時間跨度  : {pkts[-1].rel:.2f}s")
        print(f"  協定分布  : {protos}")
        print(f"  方向分布  : {dirs}")
        half = sum(1 for p in pkts if p.is_half_flow)
        print(f"  Half-flow : {half}")
