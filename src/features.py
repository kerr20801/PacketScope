"""
PacketScope — Phase 2: Feature Engineering
將封包序列聚合成 Flow 特徵向量，供 Phase 3 ML 模型使用

特徵維度：
  Flow-based    : byte_rate, pkt_rate, avg_pkt_size, size_std, size_entropy
  TCP Flags     : syn_ratio, ack_ratio, rst_ratio, fin_ratio, psh_ratio
  Half-flow     : is_half_flow (環境雜訊標記，不直接標惡意)
  Direction     : direction encoding
  Port          : dst_port, is_wellknown_port, is_suspicious_port
  Temporal      : duration, inter_arrival_mean, inter_arrival_cv (Beaconing)
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd

from parser import Packet, is_private


# ── 可疑 Port 清單（繼承自原 HTML 版本） ────────────────────────────────────

SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 6666, 6667, 6668,
    9001, 9050, 1080,
    23, 69, 161, 5900, 3389, 135, 139, 445,
    2222, 4545, 8888,
}

HIGH_RISK_PORTS = {4444, 1337, 31337, 6666, 6667, 6668}


# ── Flow Key ─────────────────────────────────────────────────────────────────

def flow_key(p: Packet, window_id: int) -> tuple:
    """5-tuple + 時間窗 → Flow 唯一鍵"""
    return (p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto, window_id)


# ── 單一 Flow 特徵 ───────────────────────────────────────────────────────────

@dataclass
class FlowFeatures:
    # 識別
    window_id:  int   = 0
    src_ip:     str   = ""
    dst_ip:     str   = ""
    src_port:   int   = 0
    dst_port:   int   = 0
    proto:      str   = ""
    direction:  str   = ""

    # 統計
    pkt_count:      int   = 0
    total_bytes:    int   = 0
    duration:       float = 0.0
    byte_rate:      float = 0.0    # bytes/s
    pkt_rate:       float = 0.0    # pkts/s
    avg_pkt_size:   float = 0.0
    std_pkt_size:   float = 0.0
    size_entropy:   float = 0.0    # 封包大小分布熵值

    # TCP flags 比例
    syn_ratio:  float = 0.0
    ack_ratio:  float = 0.0
    rst_ratio:  float = 0.0
    fin_ratio:  float = 0.0
    psh_ratio:  float = 0.0

    # 時序
    inter_arrival_mean: float = 0.0
    inter_arrival_std:  float = 0.0
    inter_arrival_cv:   float = 0.0   # CV < 0.25 → Beaconing 嫌疑

    # 標記
    is_half_flow:        bool  = False
    is_suspicious_port:  bool  = False
    is_high_risk_port:   bool  = False
    is_wellknown_port:   bool  = False  # port <= 1024
    half_flow_ratio:     float = 0.0    # 這個 flow 裡 half-flow 封包比例


def _shannon_entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    total = sum(values)
    if total == 0:
        return 0.0
    counts: dict[int, int] = defaultdict(int)
    for v in values:
        counts[v] += 1
    entropy = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def build_flow_features(packets: list[Packet], window_sec: int = 30) -> pd.DataFrame:
    """
    把封包列表依「時間窗 + 5-tuple」聚合成 Flow 特徵表

    Args:
        packets   : Phase 1 解析出的封包列表
        window_sec: 聚合時間窗（秒），建議 10~30s

    Returns:
        pd.DataFrame，每行是一個 Flow 的特徵向量
    """
    if not packets:
        return pd.DataFrame()

    # 依時間窗分桶
    buckets: dict[tuple, list[Packet]] = defaultdict(list)
    for p in packets:
        wid = int(p.rel // window_sec)
        key = (p.src_ip, p.dst_ip, p.dst_port, p.proto, wid)
        buckets[key].append(p)

    rows: list[FlowFeatures] = []

    for (src_ip, dst_ip, dst_port, proto, wid), pkts in buckets.items():
        if not pkts:
            continue

        f = FlowFeatures(
            window_id = wid,
            src_ip    = src_ip,
            dst_ip    = dst_ip,
            dst_port  = dst_port,
            proto     = proto,
            direction = pkts[0].direction,
            pkt_count = len(pkts),
        )

        # ── 流量統計 ──
        sizes = [p.length for p in pkts]
        times = sorted(p.rel for p in pkts)

        f.total_bytes  = sum(sizes)
        f.avg_pkt_size = np.mean(sizes) if sizes else 0.0
        f.std_pkt_size = float(np.std(sizes)) if len(sizes) > 1 else 0.0
        f.size_entropy = _shannon_entropy(sizes)
        f.duration     = times[-1] - times[0] if len(times) > 1 else 0.0

        if f.duration > 0:
            f.byte_rate = f.total_bytes / f.duration
            f.pkt_rate  = f.pkt_count  / f.duration
        else:
            f.byte_rate = float(f.total_bytes)
            f.pkt_rate  = float(f.pkt_count)

        # ── TCP Flags ──
        if proto == "TCP":
            n = len(pkts)
            f.syn_ratio = sum(1 for p in pkts if "S" in (p.flags or "") and "A" not in (p.flags or "")) / n
            f.ack_ratio = sum(1 for p in pkts if "A" in (p.flags or "")) / n
            f.rst_ratio = sum(1 for p in pkts if "R" in (p.flags or "")) / n
            f.fin_ratio = sum(1 for p in pkts if "F" in (p.flags or "")) / n
            f.psh_ratio = sum(1 for p in pkts if "P" in (p.flags or "")) / n

        # ── Inter-arrival（Beaconing 偵測用） ──
        if len(times) >= 3:
            iats = [times[i] - times[i-1] for i in range(1, len(times))]
            f.inter_arrival_mean = float(np.mean(iats))
            f.inter_arrival_std  = float(np.std(iats))
            f.inter_arrival_cv   = (
                f.inter_arrival_std / f.inter_arrival_mean
                if f.inter_arrival_mean > 0 else 0.0
            )

        # ── Half-flow ──
        half_cnt = sum(1 for p in pkts if p.is_half_flow)
        f.half_flow_ratio = half_cnt / len(pkts)
        f.is_half_flow    = half_cnt > 0

        # ── Port 標記 ──
        f.is_suspicious_port = dst_port in SUSPICIOUS_PORTS
        f.is_high_risk_port  = dst_port in HIGH_RISK_PORTS
        f.is_wellknown_port  = 0 < dst_port <= 1024

        rows.append(f)

    df = pd.DataFrame([vars(r) for r in rows])
    print(f"[feature] 聚合完成：{len(df)} 個 Flow（window={window_sec}s）")
    return df


# ── 供 Phase 3 使用的數值特徵欄位 ────────────────────────────────────────────

NUMERIC_FEATURES = [
    "pkt_count", "total_bytes", "duration",
    "byte_rate", "pkt_rate",
    "avg_pkt_size", "std_pkt_size", "size_entropy",
    "syn_ratio", "ack_ratio", "rst_ratio", "fin_ratio", "psh_ratio",
    "inter_arrival_mean", "inter_arrival_std", "inter_arrival_cv",
    "half_flow_ratio",
    "is_suspicious_port", "is_high_risk_port", "is_wellknown_port",
]


def get_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """從 DataFrame 提取數值特徵矩陣，補 NaN 為 0"""
    cols = [c for c in NUMERIC_FEATURES if c in df.columns]
    X = df[cols].fillna(0).astype(float).values
    return X


# ── CLI 測試 ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from parser import parse_file

    if len(sys.argv) < 2:
        print("用法：python features.py <tcpdump.txt> [window_sec]")
        sys.exit(1)

    path = sys.argv[1]
    win  = int(sys.argv[2]) if len(sys.argv) > 2 else 30

    pkts = parse_file(path)
    df   = build_flow_features(pkts, window_sec=win)

    print(df[["src_ip","dst_ip","dst_port","proto","pkt_count",
              "byte_rate","syn_ratio","inter_arrival_cv","is_suspicious_port"]].to_string())
