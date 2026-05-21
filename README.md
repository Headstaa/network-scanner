# Automated Network Scanner & CVE Vulnerability Locator

A lightweight, high-performance Python CLI utility designed for security auditors and network administrators. This tool performs multi-port infrastructure scanning, executes banner grabbing to detect active daemon versions, and cross-references results with public CVE databases to reveal security flaws in real-time.

## 🚀 Key Features
- **TCP Banner Grabbing:** Interrogates open sockets to discover service versions (Apache, OpenSSH, etc.).
- **Live CVE Lookup:** Integrates via REST API with public vulnerability registries to extract active threats dynamically.
- **Flexible Targets:** Supports domain name resolution and precise port selection (`-p 22,80` or `-p 1-100`).
- **Zero Heavy Dependencies:** Optimized modular architecture utilizing low-level Python `socket` APIs.

## 🛠️ Installation & Setup
Clone this repository and ensure dependencies are met:
```bash
git clone [https://github.com/Headstaa/network-scanner.git](https://github.com/Headstaa/network-scanner.git)
cd network-scanner
pip install -r requirements.txt
