# 🚀 AirStrike — Enhanced README

Here's a polished, expanded version of your README with improved formatting, badges, tables, examples, and modern structure.
<p align="center">
  <img src="assets/wifi.jpg" alt="AirStrike Banner" width="100%">
</p>

<h1 align="center">AirStrike</h1>

<p align="center">
  A Scapy-powered wireless auditing toolkit covering the full WiFi penetration testing workflow — from reconnaissance to offline analysis — in a single Python project.
</p>

<p align="center">
  <a href="#-features"><b>Features</b></a> •
  <a href="#-installation"><b>Installation</b></a> •
  <a href="#-usage"><b>Usage</b></a> •
  <a href="#-workflow"><b>Workflow</b></a> •
  <a href="#-troubleshooting"><b>Troubleshooting</b></a> •
  <a href="#-roadmap"><b>Roadmap</b></a> •
  <a href="#-license"><b>License</b></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/scapy-2.5+-green.svg" alt="Scapy">
  <img src="https://img.shields.io/badge/license-MIT-purple.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/status-active-success.svg" alt="Status">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs">
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/<YOUR_USERNAME>/AirStrike?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/<YOUR_USERNAME>/AirStrike?style=social" alt="Forks">
  <img src="https://img.shields.io/github/issues/<YOUR_USERNAME>/AirStrike" alt="Issues">
  <img src="https://img.shields.io/github/last-commit/<YOUR_USERNAME>/AirStrike" alt="Last Commit">
</p>

---

## 📖 Table of Contents

- [⚠️ Disclaimer](#️-disclaimer--هشدار)
- [✨ Features](#-features--قابلیتها)
- [📁 Project Structure](#-project-structure--ساختار-پروژه)
- [🛠 Installation](#-installation--نصب)
- [⚙️ Adapter Setup](#️-adapter-setup-linux--آمادهسازی-آداپتور)
- [🚀 Usage](#-usage--نحوه-استفاده)
- [🧪 Full Workflow](#-full-workflow--workflow-کامل)
- [🧯 Troubleshooting](#-troubleshooting--عیبیابی)
- [🗺 Roadmap](#-roadmap--نقشه-راه)
- [🤝 Contributing](#-contributing--مشارکت)
- [📜 License](#-license--لایسنس)
- [🙏 Credits](#-credits--اعتبارها)

---

## ⚠️ Disclaimer / هشدار

> **This project is intended strictly for educational purposes and authorized security testing.**

> این پروژه **صرفاً برای اهداف آموزشی و تست امنیتی مجاز** طراحی شده.

Using these tools against networks you do **not own** or **do not have explicit written permission** to test is **illegal** in most jurisdictions and may result in criminal charges.

استفاده از این ابزارها روی شبکه‌هایی که **مالکش نیستی** یا **مجوز کتبی صریح برای تست‌شون نداری**، در اکثر کشورها **غیرقانونی** است و می‌تونه پیگرد قضایی داشته باشه.

**The author assumes no responsibility for any misuse or damage caused by this software.**
**نویسنده هیچ مسئولیتی در قبال سوءاستفاده یا خسارت ناشی از این نرم‌افزار نمی‌پذیرد.**

---

## ✨ Features / قابلیت‌ها

| Module | Feature | Description |
|:---:|---|---|
| 📡 | **Network Scanning** | Discover APs, clients, probe requests, and channels in real time. |
| 💥 | **Deauth Attack** | Disconnect clients to force re-authentication for handshake capture. |
| 🤝 | **Handshake Capture** | Sniff and save WPA/WPA2 4-way EAPOL handshakes to `.pcap`. |
| 🔓 | **Offline Cracking** | Verify handshakes against a wordlist (PBKDF2 + HMAC-SHA1). |
| 💾 | **Credential Extraction** | Dump locally stored WiFi passwords (Linux / Windows). |
| 🧩 | **Modular Design** | Every module runs standalone — plug in new techniques easily. |

> New techniques (PMKID, WPS, Evil Twin, …) can be plugged in without breaking the core design.
> تکنیک‌های جدید بدون به‌هم‌ریختن ساختار اصلی قابل اضافه شدن هستن.

---

## 📁 Project Structure / ساختار پروژه

```
AirStrike/
├── src/                          # Source code / کدها
│   ├── __init__.py
│   ├── WScanner.py               # Live WiFi scanner / اسکنر زنده
│   ├── Deauth.py                 # Deauth attack / حمله Deauth
│   ├── Whandshake.py             # Handshake capture / گرفتن handshake
│   ├── wpa_cracker.py            # Offline cracker / کرکر آفلاین
│   └── saved_ap_extractor.py     # Credential extractor / استخراج پسوردها
├── tests/                        # Unit tests / تست‌ها
│   └── test.py
├── docs/                         # Help files / فایل‌های راهنما
│   ├── help_WScanner.txt
│   ├── help_Deauth.txt
│   ├── help_Handshake.txt
│   ├── help_WCrack.txt
│   └── help_Saved_AP.txt
├── assets/
│   └── wifi.jpg                  # Banner image
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🛠 Installation / نصب

### Prerequisites / پیش‌نیازها

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.8+ | Required |
| OS | Linux (recommended), Windows | Kali / Parrot / Ubuntu work best |
| Wireless adapter | — | Must support **monitor mode** + **packet injection** |
| Privileges | — | Root required for capture/injection |

### Clone / کلون

```bash
git clone https://github.com/<YOUR_USERNAME>/AirStrike.git
cd AirStrike
```

### Install dependencies / نصب وابستگی‌ها

```bash
pip install -r requirements.txt
```

Or manually / یا دستی:

```bash
pip install scapy tabulate keyboard
```

<details>
<summary><b>📦 requirements.txt</b></summary>

```
scapy>=2.5.0
tabulate>=0.9.0
keyboard>=0.13.5
```
</details>

---

## ⚙️ Adapter Setup (Linux) / آماده‌سازی آداپتور

```bash
# Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# → Now use wlan0mon as the interface

# Restore normal mode
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

<details>
<summary><b>🔧 Alternative with <code>iw</code> (modern)</b></summary>

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
```
</details>

---

## 🚀 Usage / نحوه استفاده

All modules live in `src/`. Run them from the project root:

```bash
sudo python3 src/WScanner.py <iface>
sudo python3 src/Deauth.py <iface> <ap_mac> [station_mac] [count]
sudo python3 src/Whandshake.py <iface> <channel> <output.pcap>
python3 src/wpa_cracker.py <bssid> <ssid> <pcap_file> <wordlist>
python3 src/saved_ap_extractor.py
```

---

### 📡 1. `WScanner.py` — Live WiFi Scanner

Scans nearby WiFi networks and displays APs, stations, and probe requests in a live-updating table.

```bash
# Basic scan with channel hopping / اسکن ساده با پرش کانال
sudo python3 src/WScanner.py wlan0

# Single channel / یه کانال خاص
sudo python3 src/WScanner.py wlan0 -c 6

# Channels 1 to 13 / کانال‌های 1 تا 13
sudo python3 src/WScanner.py wlan0 -add 13

# 20 packets per channel / 20 پکت از هر کانال
sudo python3 src/WScanner.py wlan0 -count 20

# Pass extra sniff() options
sudo python3 src/WScanner.py wlan0 -c 1 -o store=0 -o inter=0.05
```

**Hotkeys / کلیدهای میانبر:**

| Key | Action |
|:---:|---|
| `Q` | Quit the scanner |

**Sample output / خروجی نمونه:**

```
Wifi Scanner
--------------------------------------------------------------------------------
Channel = 6

APS:
╭─────────────────┬───────────────────┬──────────────┬─────────╮
│ SSID            │ BSSID             │ STATIONS     │ CHANNEL │
├─────────────────┼───────────────────┼──────────────┼─────────┤
│ HomeWiFi        │ AA:BB:CC:DD:EE:FF │ 11:22:33:..  │    6    │
│ Cafe-Guest      │ 12:34:56:78:9A:BC │              │    6    │
╰─────────────────┴───────────────────┴──────────────┴─────────╯

STATIONS:
╭───────────────────┬───────────────────┬────────────────────╮
│ ADDR              │ BSSID             │ Probes             │
├───────────────────┼───────────────────┼────────────────────┤
│ 11:22:33:44:55:66 │ AA:BB:CC:DD:EE:FF │ HomeWiFi, FreeWifi │
╰───────────────────┴───────────────────┴────────────────────╯
```

---

### 💥 2. `Deauth.py` — Deauthentication Attack

Forces clients to disconnect, triggering a new handshake for capture.

```bash
# Broadcast deauth / Deauth broadcast
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF

# Target a specific client, 50 frames
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50

# Infinite loop / حلقه بی‌نهایت
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 100 loop=1

# Flood with no delay / سیل بدون تأخیر
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF ff:ff:ff:ff:ff:ff 500 inter=0
```

**Parameter reference / مرجع پارامترها:**

| Argument | Description | Default |
|---|---|---|
| `iface` | Monitor-mode interface | — |
| `ap_mac` | Target AP BSSID | — |
| `station_mac` | Target client (or broadcast) | `ff:ff:ff:ff:ff:ff` |
| `count` | Frames per direction | `1` |
| `key=value` | Extra `sendp()` kwargs (e.g. `inter=0.1`) | — |

**Notes / نکات:**
- Broadcast deauth doesn't always work on APs with **802.11w (PMF)**.
- Pair this with `Whandshake.py` to capture the resulting handshake.

---

### 🤝 3. `Whandshake.py` — Handshake Capture

Captures WPA/WPA2 4-way handshakes into a `.pcap` file.

```bash
sudo python3 src/Whandshake.py wlan0mon 6 handshake.pcap
```

**Typical workflow / Workflow معمول:**

```bash
# Terminal 1 — start capture
sudo python3 src/Whandshake.py wlan0mon 6 handshake.pcap

# Terminal 2 — force re-authentication
sudo python3 src/Deauth.py wlan0mon AA:BB:CC:DD:EE:FF
```

> 💡 You need **at least 2 EAPOL frames** to crack the handshake.
> حداقل به 2 فریم EAPOL نیاز داری.

**Verify the capture / بررسی صحت فایل:**

```bash
aircrack-ng handshake.pcap
```

---

### 🔓 4. `wpa_cracker.py` — Offline Cracker

Cracks captured handshakes against a wordlist.

```bash
# Basic crack / کرک پایه
python3 src/wpa_cracker.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap rockyou.txt

# Custom wordlist / wordlist سفارشی
python3 src/wpa_cracker.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap ~/wordlists/mylist.txt
```

**Sample output / خروجی نمونه:**

```
[*] Found 4 EAPOL-Key frames
[*] BSSID:      AA:BB:CC:DD:EE:FF
[*] STA:        11:22:33:44:55:66
[*] ANonce:     a1b2c3d4...
[*] SNonce:     e5f6a7b8...
[*] MIC:        9c8d7e6f...
Trying: hunter2
********************************************************************************
Found Password: hunter2
********************************************************************************
```

**Notes / نکات:**

| Feature | Supported |
|---|:---:|
| WPA/WPA2-PSK (HMAC-SHA1) | ✅ |
| WPA (HMAC-MD5) | ⚠️ (edit source) |
| WPA3-SAE | ❌ |
| GPU acceleration | ❌ |

---

### 💾 5. `saved_ap_extractor.py` — Credential Extractor

Dumps locally saved WiFi credentials (Linux / Windows).

```bash
sudo python3 src/saved_ap_extractor.py
```

**As a module / به‌عنوان ماژول:**

```python
from src.saved_ap_extractor import Saved_AP

s = Saved_AP()

# Print a table / چاپ جدول
print(s.tabulate())

# Get list / گرفتن لیست
for ssid, password in s.list_AP():
    print(ssid, "->", password)

# Save to JSON / ذخیره به JSON
s.save("wifi_dump.json", indent=4)
```

**Sample output / خروجی نمونه:**

```
╭─────────────────┬──────────────╮
│ SSID            │ Password     │
├─────────────────┼──────────────┤
│ HomeWiFi        │ hunter2      │
│ Cafe-Guest      │ coffee123    │
╰─────────────────┴──────────────╯
```

**Platform notes / نکات پلتفرم:**

| OS | Path / Method | Notes |
|---|---|---|
| Linux | `/etc/NetworkManager/system-connections/*.nmconnection` | Root-only |
| Windows | `netsh wlan show profiles ... key=clear` | May need elevated shell |

---

## 🧪 Full Workflow / Workflow کامل

| Step | Tool | Goal |
|:---:|---|---|
| 1️⃣ | `WScanner.py` | Find target AP + clients |
| 2️⃣ | `Deauth.py` | Force re-authentication |
| 3️⃣ | `Whandshake.py` | Capture the 4-way handshake |
| 4️⃣ | `wpa_cracker.py` | Crack with a wordlist |
| 5️⃣ | `saved_ap_extractor.py` | Dump local credentials |

**Complete example / مثال کامل:**

```bash
# 0. Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 1. Scan for targets
sudo python3 src/WScanner.py wlan0mon -c 6
# → AP BSSID: AA:BB:CC:DD:EE:FF
# → STA MAC:  11:22:33:44:55:66

# 2. Start capture (terminal 1)
sudo python3 src/Whandshake.py wlan0mon 6 handshake.pcap

# 3. Force re-auth (terminal 2)
sudo python3 src/Deauth.py wlan0mon AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50

# 4. Crack
python3 src/wpa_cracker.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap rockyou.txt

# 5. Dump saved credentials
sudo python3 src/saved_ap_extractor.py
```

---

## 🧯 Troubleshooting / عیب‌یابی

| Issue | Fix |
|---|---|
| `Permission denied` | Run with `sudo`. |
| No packets captured | Check monitor mode & channel. |
| `ModuleNotFoundError: scapy` | `pip install scapy`. |
| `keyboard` import error | `pip install keyboard` + run as root. |
| No APs found | `iw dev <iface> set channel <n>`. |
| `sendp` fails | Adapter doesn't support injection. |
| Handshake not cracking | Verify 4 EAPOL frames, check SSID. |
| Deauth has no effect | AP may use 802.11w (PMF). |
| `iwconfig` not found | Install `wireless-tools` or use `iw`. |

---

## 🗺 Roadmap / نقشه راه

- [x] Network scanning (APs + stations + probes)
- [x] Deauthentication attack
- [x] WPA/WPA2 handshake capture
- [x] Offline dictionary cracking
- [x] Saved credential extraction
- [ ] PMKID attack (clientless) / حمله PMKID بدون کلاینت
- [ ] WPS PIN attack / حمله WPS PIN
- [ ] Evil Twin / rogue AP
- [ ] GPU-accelerated cracking / کرک با شتاب GPU
- [ ] JSON / CSV export for scanner
- [ ] WPA3 detection & fingerprinting
- [ ] Docker image / ایمیج Docker
- [ ] macOS support

---

## 🤝 Contributing / مشارکت

Pull requests are welcome! For major changes, please open an issue first.

PR ها خوش‌آمدن! برای تغییرات بزرگ، اول یه issue باز کن.

```bash
# Fork → Clone → Branch → Commit → Push → PR
git checkout -b feature/my-new-feature
git commit -m "Add: my new feature"
git push origin feature/my-new-feature
```

---

## 📜 License / لایسنس

Released under the **MIT License** with an **Ethical Use Clause**.
تحت **MIT License** با **شرط استفاده اخلاقی** منتشر شده.

See [`LICENSE`](./LICENSE) for details.

---

## 🙏 Credits / اعتبارها

| Project | Purpose |
|---|---|
| [Scapy](https://scapy.net/) | Packet crafting & sniffing |
| [tabulate](https://pypi.org/project/tabulate/) | Table formatting |
| [keyboard](https://pypi.org/project/keyboard/) | Hotkey handling |
| [aircrack-ng](https://www.aircrack-ng.org/) | Handshake verification (recommended) |

---

<p align="center">
  <b>⭐ If you find AirStrike useful, give it a star! ⭐</b><br>
  <b>⭐ اگه AirStrike برات مفید بود، یه ستاره بده! ⭐</b>
</p>

<p align="center">
  Made with ❤️ for the security community
</p>

---

## 🔧 What Changed vs. Your Original

| # | Improvement | Why |
|---|-------------|-----|
| 1 | Added **TOC** with anchor links | Easier navigation on GitHub |
| 2 | Added **status, PRs, stars, forks, issues, last-commit badges** | Standard repo presentation |
| 3 | Converted Features to a **table** | Cleaner, scannable |
| 4 | Added **parameter reference table** for Deauth | All flags visible at a glance |
| 5 | Added **supported/unsupported table** for Cracker | Sets correct expectations |
| 6 | Added **platform table** for Saved_AP | Clarifies Linux vs Windows |
| 7 | Added **Troubleshooting** entries (`iwconfig`, `wireless-tools`) | More common fixes |
| 8 | Added **Roadmap checkboxes for completed items** | Shows progress honestly |
| 9 | Added **Contribution workflow** commands | Lower barrier to PRs |
| 10 | Added **Credits table** | Consistent with the rest |
| 11 | Added **`tests/`** and **`docs/`** to project tree | Reflects actual files |
| 12 | Wrapped `requirements.txt` and `iw` alternative in **collapsible `<details>`** | Cleaner default view |
| 13 | Added **alternate `iw`-based monitor setup** | `airmon-ng` is deprecated on some distros |
| 14 | Added **handshake verification** with `aircrack-ng` | Practical tip |
| 15 | Added **sample `wlan0mon -o` example** | Shows advanced sniff() usage |
| 16 | Standardized **"sample output"** blocks in code fences | Consistent rendering |
| 17 | Added **"Made with ❤️"** footer | Humanizes the project |

---

Want me to also:

- **Translate the entire README into pure English** (remove Persian) for international audiences?
- **Add a GitHub Actions CI badge** and workflow file (`.github/workflows/ci.yml`) that runs `tests/test.py` on every push?
- **Generate a matching `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md`**?