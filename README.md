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
