# 🛡️ Security Suite

A multi-function security toolkit with a Tkinter GUI, built for BSIT-A3103.

## Features

**Application Security**
- **Password Strength Assessment** – scores passwords (0–7) on length, character variety, and common/dictionary word checks
- **Password Generator + Hashing** – generates up to 100 cryptographically secure passwords (12–32 chars) using `secrets`, hashed with SHA-256, SHA-512, or MD5
- **Input Validation & Sanitization** – validates name, email, username, and message fields; detects XSS (`<script>`, `<img>`) and SQL keywords

**Network Security**
- **Port Scanner** – TCP connect scan with presets, banner grabbing, security hints, and TXT/CSV/JSON export
- **Traffic Analyzer** – live packet capture (Scapy) with BPF filters, Top 5 ports/IPs summary, SNI/HTTP Host domain extraction, and export
- **Integration** – click an IP in the Traffic Analyzer summary to scan it in the Port Scanner
- **Dashboard** – latest summary from all modules in one view

## Requirements

- Python 3.10+
- [Npcap](https://npcap.com) (Windows only, required for the Traffic Analyzer)
- Administrator privileges (for packet capture)

## Setup (Windows)

```powershell
git clone https://github.com/lmdclerra/security-suite.git
cd security-suite
python -m venv myvenv
.\myvenv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```powershell
python SecuritySuite.py
```

> For the Traffic Analyzer, open your terminal **as Administrator** before running. All other modules work without admin rights. If Scapy is not installed, the app still runs but the Traffic Analyzer tab is disabled.

## Disclaimer

This project is for **educational purposes only**. Only scan hosts and capture traffic on networks you own or have explicit permission to test. Unauthorized scanning may violate laws such as the Philippine Cybercrime Prevention Act of 2012 (RA 10175).

## Author

**Lerra Mae Dela Cruz**  
BSIT – Networks and Cybersecurity, Mapúa Malayan Digital College
