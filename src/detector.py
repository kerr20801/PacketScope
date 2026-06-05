"""
PacketScope — Phase 3: 雙軌異常偵測
  軌道 A : ECOD + Isolation Forest → Flow Anomaly Score
  軌道 B : Graph PageRank          → Node Centrality Score
  融合   : LightGBM 將兩軌分數 + 特徵 → 最終風險排序
"""

import sys
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import networkx as nx
import lightgbm as lgb

from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest
from sklearn.preprocessing import MinMaxScaler

from features import build_flow_features, get_feature_matrix, NUMERIC_FEATURES
from parser import parse_file


# ══════════════════════════════════════════════════════════════════════════════
#  軌道 A：ECOD + Isolation Forest
# ══════════════════════════════════════════════════════════════════════════════

def run_track_a(df: pd.DataFrame, X: np.ndarray) -> pd.DataFrame:
    """
    對特徵矩陣跑 ECOD 和 IF，輸出異常分數（0~1，越高越異常）
    """
    n = len(X)
    if n < 4:
        df["ecod_score"] = 0.5
        df["if_score"]   = 0.5
        df["track_a"]    = 0.5
        return df

    contamination = min(0.3, max(0.05, 10 / n))

    # ECOD：無參數，不需調整
    ecod = ECOD(contamination=contamination)
    ecod.fit(X)
    ecod_raw = ecod.decision_scores_

    # Isolation Forest
    iforest = IForest(contamination=contamination, random_state=42, n_estimators=100)
    iforest.fit(X)
    if_raw = iforest.decision_scores_

    # 歸一化到 0~1
    scaler = MinMaxScaler()
    df["ecod_score"] = scaler.fit_transform(ecod_raw.reshape(-1, 1)).flatten()
    df["if_score"]   = scaler.fit_transform(if_raw.reshape(-1, 1)).flatten()

    # 加權平均（ECOD 主導，IF 輔助）
    df["track_a"] = df["ecod_score"] * 0.6 + df["if_score"] * 0.4

    print(f"[track_a] ECOD+IF 完成，高分 Flow（>0.7）: "
          f"{(df['track_a'] > 0.7).sum()} / {n}")
    return df


# ══════════════════════════════════════════════════════════════════════════════
#  軌道 B：Graph Analytics (PageRank + Degree)
# ══════════════════════════════════════════════════════════════════════════════

def run_track_b(df: pd.DataFrame) -> pd.DataFrame:
    """
    把 Flow 轉成有向圖，計算每個 IP 節點的 PageRank 和出度
    高 PageRank = 可疑跳板 / Pivot 節點
    """
    G = nx.DiGraph()

    for _, row in df.iterrows():
        src, dst = row["src_ip"], row["dst_ip"]
        w = float(row.get("pkt_count", 1))
        if G.has_edge(src, dst):
            G[src][dst]["weight"] += w
        else:
            G.add_edge(src, dst, weight=w)

    if len(G.nodes) == 0:
        df["src_pagerank"]   = 0.0
        df["src_degree"]     = 0
        df["track_b_src"]    = 0.0
        df["track_b_dst"]    = 0.0
        return df

    # PageRank
    try:
        pr = nx.pagerank(G, alpha=0.85, weight="weight", max_iter=200)
    except Exception:
        pr = {n: 1/len(G.nodes) for n in G.nodes}

    # Out-degree（掃描行為）
    out_deg = dict(G.out_degree())
    in_deg  = dict(G.in_degree())

    # 歸一化
    max_pr  = max(pr.values())  if pr  else 1
    max_od  = max(out_deg.values()) if out_deg else 1
    max_id  = max(in_deg.values())  if in_deg  else 1

    df["src_pagerank"] = df["src_ip"].map(lambda ip: pr.get(ip, 0) / max_pr)
    df["dst_pagerank"] = df["dst_ip"].map(lambda ip: pr.get(ip, 0) / max_pr)
    df["src_out_deg"]  = df["src_ip"].map(lambda ip: out_deg.get(ip, 0) / max_od)
    df["dst_in_deg"]   = df["dst_ip"].map(lambda ip: in_deg.get(ip, 0)  / max_id)

    # Track B 分數 = src 的 PageRank（跳板偵測）+ out_degree（掃描偵測）
    df["track_b_src"] = df["src_pagerank"] * 0.5 + df["src_out_deg"] * 0.5
    df["track_b_dst"] = df["dst_pagerank"] * 0.5 + df["dst_in_deg"]  * 0.5

    pivot_count = (df["src_pagerank"] > 0.5).sum()
    print(f"[track_b] Graph 完成，高中心度節點（>0.5）: {pivot_count} / {len(G.nodes)} 個 IP")
    return df


# ══════════════════════════════════════════════════════════════════════════════
#  融合：LightGBM 排序
# ══════════════════════════════════════════════════════════════════════════════

FUSION_FEATURES = [
    "track_a", "track_b_src", "track_b_dst",
    "ecod_score", "if_score",
    "src_pagerank", "src_out_deg",
    "is_suspicious_port", "is_high_risk_port",
    "syn_ratio", "rst_ratio",
    "inter_arrival_cv",
    "half_flow_ratio",
    "byte_rate", "avg_pkt_size",
]

def run_fusion(df: pd.DataFrame) -> pd.DataFrame:
    """
    用 LightGBM 的 rank 模式做無監督融合排序。
    沒有標注資料 → 用規則產生「軟標籤」作為 proxy target，
    讓 LightGBM 學習各特徵的非線性組合。
    """
    cols = [c for c in FUSION_FEATURES if c in df.columns]
    if not cols or len(df) < 4:
        # 退化：直接用 track_a 加權
        df["risk_score"] = df.get("track_a", 0.5)
        df["risk_rank"]  = df["risk_score"].rank(ascending=False).astype(int)
        return df

    X_fuse = df[cols].fillna(0).astype(float).values

    # 軟標籤：基於規則的初始分數
    soft_label = (
        df.get("track_a", pd.Series(0, index=df.index)) * 0.4 +
        df.get("track_b_src", pd.Series(0, index=df.index)) * 0.3 +
        df.get("is_high_risk_port", pd.Series(0, index=df.index)).astype(float) * 0.2 +
        df.get("syn_ratio", pd.Series(0, index=df.index)) * 0.1
    ).values

    # LightGBM 回歸（學習 soft label 的非線性組合）
    model = lgb.LGBMRegressor(
        n_estimators=80,
        learning_rate=0.1,
        max_depth=4,
        num_leaves=15,
        min_child_samples=2,
        verbose=-1,
        random_state=42,
    )
    model.fit(X_fuse, soft_label)
    pred = model.predict(X_fuse)

    # 歸一化
    scaler = MinMaxScaler()
    df["risk_score"] = scaler.fit_transform(pred.reshape(-1, 1)).flatten()
    df["risk_rank"]  = df["risk_score"].rank(ascending=False).astype(int)

    # 特徵重要性（Top 5）
    importances = sorted(
        zip(cols, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:5]
    print(f"[fusion]  LightGBM Top 特徵: {[f'{n}={v}' for n,v in importances]}")
    return df


# ══════════════════════════════════════════════════════════════════════════════
#  主流程
# ══════════════════════════════════════════════════════════════════════════════

RISK_LABELS = {
    (0.80, 1.01): ("CRITICAL", "🔴"),
    (0.60, 0.80): ("HIGH",     "🟠"),
    (0.40, 0.60): ("MEDIUM",   "🟡"),
    (0.20, 0.40): ("LOW",      "🔵"),
    (0.00, 0.20): ("INFO",     "⚪"),
}

def label_risk(score: float) -> tuple[str, str]:
    for (lo, hi), (label, icon) in RISK_LABELS.items():
        if lo <= score < hi:
            return label, icon
    return "INFO", "⚪"


def run_detection(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        print("[detector] 無資料可分析")
        return df

    X = get_feature_matrix(df)

    print(f"\n{'='*60}")
    print(f"  PacketScope Phase 3 — 異常偵測")
    print(f"  Flow 數量：{len(df)}，特徵維度：{X.shape[1]}")
    print(f"{'='*60}")

    df = run_track_a(df, X)
    df = run_track_b(df)
    df = run_fusion(df)

    # 加上可讀標籤
    df["risk_level"], df["risk_icon"] = zip(*df["risk_score"].map(label_risk))

    return df


def print_report(df: pd.DataFrame, top_n: int = 20):
    if df.empty:
        return

    print(f"\n{'='*60}")
    print(f"  風險排行 Top {top_n}")
    print(f"{'='*60}")

    cols = ["risk_rank", "risk_icon", "risk_level", "risk_score",
            "src_ip", "dst_ip", "dst_port", "proto",
            "pkt_count", "track_a", "track_b_src",
            "is_suspicious_port"]
    cols = [c for c in cols if c in df.columns]

    top = df.sort_values("risk_score", ascending=False).head(top_n)
    for _, row in top.iterrows():
        icon  = row.get("risk_icon", "")
        level = row.get("risk_level", "")
        score = row.get("risk_score", 0)
        src   = row.get("src_ip", "")
        dst   = row.get("dst_ip", "")
        port  = int(row.get("dst_port", 0))
        proto = row.get("proto", "")
        cnt   = int(row.get("pkt_count", 0))
        ta    = row.get("track_a", 0)
        tb    = row.get("track_b_src", 0)
        susp  = "⚠ SUSP_PORT" if row.get("is_suspicious_port") else ""

        print(f"  {icon} [{level:<8}] {score:.3f}  "
              f"{src:<18} → {dst:<18}:{port:<5} {proto:<4} "
              f"pkts={cnt:<4} A={ta:.2f} B={tb:.2f}  {susp}")

    # 統計摘要
    counts = df["risk_level"].value_counts()
    print(f"\n  摘要：", end="")
    for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = counts.get(lvl, 0)
        if n:
            print(f"{lvl}={n}  ", end="")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法：python detector.py <tcpdump.txt> [window_sec]")
        sys.exit(1)

    path = sys.argv[1]
    win  = int(sys.argv[2]) if len(sys.argv) > 2 else 30

    pkts = parse_file(path)
    df   = build_flow_features(pkts, window_sec=win)
    df   = run_detection(df)
    print_report(df, top_n=20)
