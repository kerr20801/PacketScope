# 🔍 PacketScope — tcpdump 威脅分析器

> 貼上 tcpdump 輸出，馬上知道網路裡在發生什麼。本機處理，資料不外傳。

[![HTML](https://img.shields.io/badge/純前端-HTML%2FJS-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 解決什麼問題

沒有 SIEM、沒有 NetFlow、沒有 Graylog — 只有 tcpdump 的原始輸出。

這個工具讓你把 tcpdump 貼進去，10秒內看到：
- 誰在 Beaconing 呼叫 C2
- 誰在掃 Port
- 哪台機器在往外傳大量資料
- 哪個時間點有流量異常暴增

---

## 偵測項目

| 威脅類型 | 嚴重度 | 說明 |
|---------|--------|------|
| Beaconing / C2 心跳 | 🔴 HIGH | 固定間隔對外連線（低 CV 值），符合 C2 heartbeat 特徵 |
| Port Scan（垂直） | 🔴 HIGH | 30秒內掃 10+ 個 Port（SYN flood 模式） |
| Host Scan（水平） | 🔴 HIGH | 30秒內掃 10+ 個主機（同 Port） |
| 可疑 Port | 🔴 HIGH | Metasploit 4444、後門 1337/31337、IRC botnet 等 |
| 流量異常暴增 | 🔴/🟡 | CUSUM 演算法偵測基線外的爆增 |
| 外傳流量偏大 | 🟡 MEDIUM | 往外部 IP 傳送異常大量資料（可能 Exfil） |
| 封包尺寸異常 | 🟡 MEDIUM | 平均封包大小遠超中位數 |
| DNS 查詢頻率異常 | 🟡 MEDIUM | 高頻 DNS（DGA / DNS Tunnel 特徵） |
| 可疑 Port（低危） | 🔵 LOW | Telnet/RDP/VNC/SMB 等明文或高風險協定 |

---

## 支援格式

```bash
# 推薦（含完整時間戳）
tcpdump -tttt -nn > capture.txt

# 含 Flags 詳細資訊
tcpdump -tttt -nn -v > capture.txt

# 安靜模式（含 length）
tcpdump -tttt -nn -q > capture.txt

# 存 pcap 後轉文字
tcpdump -w capture.pcap
tcpdump -tttt -nn -r capture.pcap > capture.txt
```

---

## 使用方法

1. 開啟 `index.html`（不需伺服器，直接瀏覽器開）
2. 貼上 tcpdump 輸出，或拖曳 `.txt` 檔案
3. 點 **▶ 分析封包**
4. 查看威脅清單、流量時間軸、Top 來源 IP

---

## 架構

```
單一 HTML 檔案，無外部依賴
├── Parser        — 支援 -tttt / -tt / -nn 多種 tcpdump 格式
├── Detectors     — 6 種威脅偵測模組（純 JS 實作）
│   ├── Beaconing — 間隔 CV 分析（< 0.25 判定規律心跳）
│   ├── Port Scan — 滑動視窗 30s + 唯一 Port/Host 計數
│   ├── Exfil     — 外傳流量統計 + 封包尺寸 IQR 異常
│   ├── Spike     — CUSUM 流量基線偵測
│   ├── SuspPort  — 已知惡意/高風險 Port 名單
│   └── DNS       — 查詢頻率異常
├── Charts        — 純 Canvas 時間軸 + Top IP 長條圖
└── Table         — 可搜尋、可過濾、可排序封包明細
```

---

---

## PacketScope Plus（ML 強化版）

> 適合長期監控場景，例如 Honeypot + Switch SPAN Port 持續分析。

`src/` 目錄內為 Python ML 版本，在規則制偵測之上加了兩層分析：

### 設計場景

```
Internet
    ↓
Switch WAN Port
    ├── 正常流量 → Firewall → 內網
    └── SPAN Mirror → 分析機
                        ↓
                   tcpdump 持續抓包
                        ↓
                   PacketScope Plus
                        ↓
                   風險排行 + 告警
```

Honeypot 接收攻擊流量，SPAN port 複製完整 WAN 流量——兩者結合，看得到所有攻擊嘗試，不只是打到 Honeypot 的部分。

### 雙軌 ML 架構

**軌道 A：Flow 異常偵測**
- ECOD（無參數，不需標注資料）+ Isolation Forest
- 偵測封包大小、時序、TCP flag 比例等統計特徵的異常

**軌道 B：Graph 節點分析**
- 把所有 Flow 建成有向圖，計算每個 IP 的 PageRank
- 高 PageRank = 大量其他節點通過此 IP 中轉 → 可疑跳板 / Pivot 節點
- 橫向移動在 Graph 上特別明顯

**融合：LightGBM 排序**
- 用軟標籤（規則產生初始分數）訓練，不需要人工標注
- 輸出統一風險分數（0~1）+ 風險等級（CRITICAL / HIGH / MEDIUM / LOW）

### 使用方式

```bash
pip install -r requirements.txt

# 分析 tcpdump 檔案
python src/detector.py capture.txt

# 指定時間窗（預設 30s）
python src/detector.py capture.txt 60

# 持續監控（搭配 cron 或 watch）
tcpdump -tttt -nn -i eth0 > /tmp/wan.txt &
watch -n 30 "python src/detector.py /tmp/wan.txt"
```

### 與 HTML 版本的差異

| | index.html | src/ (Plus) |
|---|---|---|
| 安裝 | 零依賴 | pip install |
| 輸入 | 貼上 / 拖曳 | CLI 檔案路徑 |
| 偵測方式 | 規則制 | ML + Graph |
| 適合場景 | 快速查一筆封包 | 持續監控 / Honeypot |
| 告警 | 無 | 可接 TG / ELK |

---

## 同系列工具

**[log-anonymizer](https://github.com/kerr20801/log-anonymizer)** — Log 遮蔽 + Z-score/IQR/CUSUM 異常偵測

兩個工具定位不同：log-anonymizer 看 syslog/app log，PacketScope 看網路層。

---

## Built by

**Kerr** — Security & DevOps tooling  
[github.com/kerr20801](https://github.com/kerr20801)

---

## License

MIT
