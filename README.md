# 🚀 AirStrike

> A Scapy-powered wireless auditing toolkit covering the full WiFi penetration testing workflow — from reconnaissance to offline analysis — in a single Python project.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/scapy-2.5.0%2B-orange.svg)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-beta-yellow.svg)]()

**Features** • **Installation** • **Usage** • **Workflow** • **Troubleshooting** • **Known Issues** • **Roadmap** • **License**

---

## 📖 Table of Contents

- [⚠️ Disclaimer](#-disclaimer)
- [✨ Features](#-features)
- [📁 Project Structure](#-project-structure)
- [🛠 Installation](#-installation)
- [⚙️ Adapter Setup (Linux)](#️-adapter-setup-linux)
- [🚀 Usage](#-usage)
- [🧪 Full Workflow](#-full-workflow)
- [🧯 Troubleshooting](#-troubleshooting)
- [🐛 Known Issues](#-known-issues)
- [🗺 Roadmap](#-roadmap)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [🙏 Credits](#-credits)

---

## ⚠️ Disclaimer

> **This project is intended strictly for educational purposes and authorized security testing.**
>
> **این پروژه صرفاً برای اهداف آموزشی و تست امنیتی مجاز طراحی شده.**

Using these tools against networks you do **not own** or **do not have explicit written permission** to test is **illegal** in most jurisdictions and may result in criminal charges.

استفاده از این ابزارها روی شبکه‌هایی که **مالکش نیستی** یا **مجوز کتبی صریح برای تست‌شون نداری**، در اکثر کشورها **غیرقانونی** است و می‌تونه پیگرد قضایی داشته باشه.

**The author assumes no responsibility for any misuse or damage caused by this software.**
**نویسنده هیچ مسئولیتی در قبال سوءاستفاده یا خسارت ناشی از این نرم‌افزار نمی‌پذیرد.**

---

## ✨ Features

| Module | Feature | Description |
|--------|---------|-------------|
| 📡 | **Network Scanning** | Discover APs, clients, probe requests, and channels in real time. |
| 💥 | **Deauth Attack** | Disconnect clients to force re-authentication for handshake capture. |
| 🤝 | **Handshake Capture** | Sniff and save WPA/WPA2 4-way EAPOL handshakes to `.pcap`. |
| 🔓 | **Offline Cracking** | Verify handshakes against a wordlist (PBKDF2 + HMAC-SHA1). |
| 💾 | **Credential Extraction** | Dump locally stored WiFi passwords (Linux / Windows). |
| 🧩 | **Modular Design** | Every module runs standalone — plug in new techniques easily. |

> New techniques (PMKID, WPS, Evil Twin, …) can be plugged in without breaking the core design.
> تکنیک‌های جدید بدون به‌هم‌ریختن ساختار اصلی قابل اضافه شدن هستن.

---

## 📁 Project Structure

```text
AirStrike/
├── src/                              # Source code / کدها
│   ├── __init__.py
│   ├── WScanner.py                   # Live WiFi scanner / اسکنر زنده
│   ├── Deauth.py                     # Deauth attack / حمله Deauth
│   ├── HandshakeCapture.py           # Handshake capture / گرفتن handshake
│   ├── WCrack.py                     # Offline cracker / کرکر آفلاین
│   └── Saved_AP.py                   # Credential extractor / استخراج پسوردها
├── tests/                            # Unit tests / تست‌ها
│   └── test.py
├── docs/                             # Extended help files / راهنمای تکمیلی
│   ├── help_WScanner.txt
│   ├── help_Deauth.txt
│   ├── help_HandshakeCapture.txt
│   ├── help_WCrack.txt
│   └── help_Saved_AP.txt
├── assets/
│   └── wifi.jpg                      # Banner image
├── requirements.txt
├── LICENSE
└── README.md
```

> **Note:** File names follow a `CamelCase` convention for the primary class in each module. Rename any legacy references accordingly.

---

## 🛠 Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.8+ | Required |
| OS | Linux (recommended), Windows | Kali / Parrot / Ubuntu work best |
| Wireless adapter | — | Must support **monitor mode** + **packet injection** |
| Privileges | — | Root required for capture/injection |

### Clone

```bash
git clone https://github.com/VoidBreaker-ir/AirStrike.git
cd AirStrike
```

### Install dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install "scapy>=2.5.0" "tabulate>=0.9.0"
```

#### Optional: Hotkey support (`keyboard`)

The `keyboard` module is required **only** for the `Q`-to-quit hotkey in `WScanner.py`. It is **not** installed by default because it needs root and does not work on Wayland or macOS without extra setup.

```bash
pip install keyboard
```

**📦 requirements.txt**

```text
scapy>=2.5.0
tabulate>=0.9.0
# keyboard>=0.13.5  # optional: hotkey support in WScanner
```

---

## ⚙️ Adapter Setup (Linux)

### With `airmon-ng`

```bash
# Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# → Now use wlan0mon as the interface

# Restore normal mode
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

### With `iw` (modern, recommended)

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
```

---

## 🚀 Usage

All modules live in `src/`. Run them from the project root:

```bash
sudo python3 src/WScanner.py <iface>
sudo python3 src/Deauth.py <iface> <ap_mac> [station_mac] [count]
sudo python3 src/HandshakeCapture.py <iface> <channel> <output.pcap>
python3 src/WCrack.py <bssid> <ssid> <pcap_file> <wordlist>
python3 src/Saved_AP.py
```

---

### 📡 1. `WScanner.py` — Live WiFi Scanner

Scans nearby WiFi networks and displays APs, stations, and probe requests in a live-updating table.

```bash
# Basic scan with channel hopping
sudo python3 src/WScanner.py wlan0

# Single channel
sudo python3 src/WScanner.py wlan0 -c 6

# Channels 1 to 13
sudo python3 src/WScanner.py wlan0 -add 13

# 20 packets per channel
sudo python3 src/WScanner.py wlan0 -count 20

# Pass extra sniff() options
sudo python3 src/WScanner.py wlan0 -c 1 -o store=0 -o inter=0.05
```

**Hotkeys:**

| Key | Action |
|-----|--------|
| `Q` | Quit the scanner *(requires `keyboard` module)* |

**Sample output:**

```text
Wifi Scanner
-----------------------------------------------------------------------------
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
# Broadcast deauth
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF

# Target a specific client, 50 frames
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50

# Infinite loop
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 100 loop=1

# Flood with no delay
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF ff:ff:ff:ff:ff:ff 500 inter=0
```

**Parameter reference:**

| Argument | Description | Default |
|----------|-------------|---------|
| `iface` | Monitor-mode interface | — |
| `ap_mac` | Target AP BSSID | — |
| `station_mac` | Target client (or broadcast) | `ff:ff:ff:ff:ff:ff` |
| `count` | Frames per direction | `1` |
| `key=value` | Extra `sendp()` kwargs (e.g. `inter=0.1`) | — |

**Notes:**

- Broadcast deauth doesn't always work on APs with **802.11w (PMF)**.
- Pair this with `HandshakeCapture.py` to capture the resulting handshake.

---

### 🤝 3. `HandshakeCapture.py` — Handshake Capture

Captures WPA/WPA2 4-way handshakes into a `.pcap` file.

```bash
sudo python3 src/HandshakeCapture.py wlan0mon 6 handshake.pcap
```

**Typical workflow:**

```bash
# Terminal 1 — start capture
sudo python3 src/HandshakeCapture.py wlan0mon 6 handshake.pcap

# Terminal 2 — force re-authentication
sudo python3 src/Deauth.py wlan0mon AA:BB:CC:DD:EE:FF
```

> 💡 You need **at least 2 EAPOL frames** to crack the handshake.
> حداقل به 2 فریم EAPOL نیاز داری.

**Verify the capture:**

```bash
aircrack-ng handshake.pcap
```

---

### 🔓 4. `WCrack.py` — Offline Cracker

Cracks captured handshakes against a wordlist.

```bash
# Basic crack
python3 src/WCrack.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap rockyou.txt

# Custom wordlist
python3 src/WCrack.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap ~/wordlists/mylist.txt
```

**Sample output:**

```text
[*] Found 4/4 EAPOL-Key messages
[*] BSSID:  AA:BB:CC:DD:EE:FF
[*] STA:    11:22:33:44:55:66
[*] ANonce: a1b2c3d4...
[*] SNonce: e5f6a7b8...
[*] MIC:    9c8d7e6f...
Trying #1: hunter2
********************************************************************************
[+] Found Password: hunter2
********************************************************************************
```

**Supported algorithms:**

| Feature | Supported |
|---------|-----------|
| WPA/WPA2-PSK (HMAC-SHA1) | ✅ |
| WPA (HMAC-MD5) | ⚠️ (edit source: `versicon=1`) |
| WPA3-SAE | ❌ |
| GPU acceleration | ❌ |

---

### 💾 5. `Saved_AP.py` — Credential Extractor

Dumps locally saved WiFi credentials (Linux / Windows).

```bash
sudo python3 src/Saved_AP.py
```

**As a module:**

```python
from src.Saved_AP import Saved_AP

s = Saved_AP()

# Print a table
print(s.to_table())

# Get list
for ssid, password in s.list_AP():
    print(ssid, "->", password)

# Save to JSON
s.save("wifi_dump.json", indent=4)
```

**Sample output:**

```text
╭─────────────────┬──────────────╮
│ SSID            │ Password     │
├─────────────────┼──────────────┤
│ HomeWiFi        │ hunter2      │
│ Cafe-Guest      │ coffee123    │
╰─────────────────┴──────────────╯
```

**Platform notes:**

| OS | Path / Method | Notes |
|----|---------------|-------|
| Linux | `/etc/NetworkManager/system-connections/*.nmconnection` | Root-only |
| Windows | `netsh wlan show profiles ... key=clear` | May need elevated shell |

---

## 🧪 Full Workflow

| Step | Tool | Goal |
|------|------|------|
| 1️⃣ | `WScanner.py` | Find target AP + clients |
| 2️⃣ | `Deauth.py` | Force re-authentication |
| 3️⃣ | `HandshakeCapture.py` | Capture the 4-way handshake |
| 4️⃣ | `WCrack.py` | Crack with a wordlist |
| 5️⃣ | `Saved_AP.py` | Dump local credentials |

**Complete example:**

```bash
# 0. Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 1. Scan for targets
sudo python3 src/WScanner.py wlan0mon -c 6
# → AP BSSID: AA:BB:CC:DD:EE:FF
# → STA MAC:  11:22:33:44:55:66

# 2. Start capture (terminal 1)
sudo python3 src/HandshakeCapture.py wlan0mon 6 handshake.pcap

# 3. Force re-auth (terminal 2)
sudo python3 src/Deauth.py wlan0mon AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50

# 4. Crack
python3 src/WCrack.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap rockyou.txt

# 5. Dump saved credentials
sudo python3 src/Saved_AP.py
```

---

## 🧯 Troubleshooting

| Issue | Fix |
|-------|-----|
| `Permission denied` | Run with `sudo`. |
| No packets captured | Check monitor mode & channel. |
| `ModuleNotFoundError: scapy` | `pip install scapy`. |
| `keyboard` import error | Optional — install with `pip install keyboard` and run as root for hotkey support. |
| No APs found | `iw dev <iface> set channel <n>`. |
| `sendp` fails | Adapter doesn't support injection. |
| Handshake not cracking | Verify 4 EAPOL frames, check SSID, and see [Known Issues](#-known-issues). |
| Deauth has no effect | AP may use 802.11w (PMF). |
| `iwconfig` not found | Install `wireless-tools` or use `iw`. |
| `tabulate` not installed | `pip install tabulate`. |

---

## 🐛 Known Issues

The following issues are tracked and will be addressed in upcoming releases:

| # | Module | Issue | Status |
|---|--------|-------|--------|
| 1 | `WCrack.py` | MIC computation uses `bytes(packet)` which may include the `RadioTap` header and exclude 802.11 headers. Cracking may fail even with the correct password. | 🔧 In progress |
| 2 | `WScanner.py` | `os.system()` is used to set the channel, which pollutes the terminal UI with `iw` output. | 🔧 Planned |
| 3 | `__init__.py` | `__all__` list does not match actual module names. | 🔧 Planned |
| 4 | `Deauth.py` | `key=value` CLI arguments are passed as strings; numeric values (e.g. `inter=0.1`) need explicit conversion. | 🔧 Planned |
| 5 | `HandshakeCapture.py` | When `iw` exists but fails, `iwconfig` fallback may also fail with a less informative error. | 🔧 Planned |

Contributions to fix any of these are welcome — see [Contributing](#-contributing).

---

## 🗺 Roadmap

- [x] Network scanning (APs + stations + probes)
- [x] Deauthentication attack
- [x] WPA/WPA2 handshake capture
- [x] Offline dictionary cracking
- [x] Saved credential extraction
- [ ] Fix MIC computation bug in `WCrack.py`
- [ ] Unit tests for all modules
- [ ] `argparse`-based CLI for all tools
- [ ] PMKID attack (clientless)
- [ ] WPS PIN attack
- [ ] Evil Twin / rogue AP
- [ ] GPU-accelerated cracking
- [ ] JSON / CSV export for scanner
- [ ] WPA3 detection & fingerprinting
- [ ] Docker image
- [ ] macOS support

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

PR ها خوش‌آمدن! برای تغییرات بزرگ، اول یه issue باز کن.

```bash
# Fork → Clone → Branch → Commit → Push → PR
git checkout -b feature/my-new-feature
git commit -m "Add: my new feature"
git push origin feature/my-new-feature
```

Before submitting a PR, please:

1. Run existing tests: `pytest tests/`
2. Add tests for new functionality where applicable.
3. Update this README if user-facing behavior changes.

---

## 📜 License

Released under the **MIT License**. See [`LICENSE`](LICENSE) for details.

The MIT License permits any use of this software, including commercial and derivative works. **Legal and ethical responsibility for how this software is used rests entirely with the end user.** See the [Disclaimer](#-disclaimer) above.

---

## 🙏 Credits

| Project | Purpose |
|---------|---------|
| [Scapy](https://scapy.net/) | Packet crafting & sniffing |
| [tabulate](https://pypi.org/project/tabulate/) | Table formatting |
| [keyboard](https://pypi.org/project/keyboard/) | Hotkey handling (optional) |
| [aircrack-ng](https://www.aircrack-ng.org/) | Handshake verification (recommended) |

---

**⭐ If you find AirStrike useful, give it a star! ⭐**
**⭐ اگه AirStrike برات مفید بود، یه ستاره بده! ⭐**

Made with ❤️ for the security community
