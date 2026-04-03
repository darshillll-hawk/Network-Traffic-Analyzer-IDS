# 🛡 NTA-IDS — Network Traffic Analyzer & Intrusion Detection System

A real-time network traffic monitoring and intrusion detection dashboard built with **Python**, **Scapy**, and **Flask**.

---

## 🚀 Features

- 📡 **Live packet capture** — TCP, UDP, ICMP, DNS
- 🚨 **Intrusion detection** — Port scan, SYN flood, ICMP flood, DNS burst, traffic flood, suspicious port access
- 📊 **Real-time dashboard** — Auto-refreshes every 5 seconds without page reload
- 🔍 **IP filter** — Filter packets by source or destination IP live
- 📈 **Stats panel** — Protocol breakdown, top source IPs, alert severity counts
- 🗑 **Clear button** — Wipe all data for clean demos
- 🔒 **Thread-safe storage** — No race conditions between sniffer and Flask threads

---

## 📁 Project Structure

```
nta-ids/
├── app.py            # Flask web server + API routes
├── sniffer.py        # Packet capture using Scapy
├── detector.py       # Intrusion detection logic
├── storage.py        # Thread-safe JSON file storage
├── templates/
│   └── index.html    # Dashboard UI
├── packets.json      # Auto-created at runtime
├── alerts.json       # Auto-created at runtime
├── requirements.txt
└── README.md
```

> ⚠️ Move `index.html` into a `templates/` folder — Flask requires it there.

---

## ⚙️ Installation

```bash
# 1. Clone or download the project
git clone https://github.com/yourusername/nta-ids.git
cd nta-ids

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Set network interface
export SNIFF_IFACE=eth0     # Linux
# or leave unset for auto-detect
```

---

## ▶️ Running

```bash
# Packet sniffing requires root/admin privileges
sudo python app.py
```

Then open your browser at: **http://localhost:5000**

---

## 🛡 Detection Rules

| Alert Type             | Trigger Condition                                  | Severity |
|------------------------|----------------------------------------------------|----------|
| Traffic Flood          | Single IP sends 50+ packets                        | High     |
| Port Scan Detected     | Single IP probes 10+ unique ports                  | High     |
| SYN Flood              | Single IP sends 20+ SYN-only TCP packets           | Critical |
| ICMP Flood             | Single IP sends 15+ ICMP packets                   | High     |
| DNS Query Burst        | Single IP makes 25+ DNS queries                    | Medium   |
| Suspicious Port Access | Connection to SSH, RDP, SMB, MySQL, VNC, etc.      | Medium   |

> All detections include a 60-second cooldown per IP to prevent alert spam.

---

## 🧪 Tech Stack

- **Python 3.10+**
- **Scapy** — packet capture and analysis
- **Flask** — lightweight web framework
- **Vanilla JS** — live dashboard updates via `fetch()` API
- **JSON** — lightweight file-based storage

---

## 👨‍💻 Author

**Darshil Rakesh Tolia**  
M.S. Information Systems — Pace University  
Network Engineer & CS Instructor — Bard High School Early College  
[LinkedIn](https://linkedin.com/in/darshil-tolia)
