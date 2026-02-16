# Farosint

**OSINT & Attack Surface Analysis Framework**

Farosint is a web-based platform for automated reconnaissance and attack surface mapping. It orchestrates multiple security tools through an intuitive dashboard, providing a unified view of targets with interactive visualizations and professional PDF reporting.

Built for security professionals, pentesters, and red team operators.

---

## Features

- **Multi-mode scanning**: Quick, Full/Advanced, and LAN scanning modes.
- **Tool orchestration**: Parallel execution with priority-based worker pool
- **Interactive network graph**: D3.js force-directed visualization of discovered assets
- **PDF reporting**: Professional reports with executive summary and findings
- **Real-time progress**: Live scan status with Server-Sent Events (SSE)
- **CLI support**: Full command-line interface via orchestrator.py
- **Caching and resilience**: Smart caching, automatic retries, and graceful degradation

## Integrated Tools

| Category | Tools |
|---|---|
| Subdomain Discovery | Amass, Subfinder |
| DNS | DNSRecon |
| Port Scanning | Nmap, RustScan |
| Web Analysis | Httpx, WhatWeb |
| Vulnerability Scanning | Nuclei, Nikto |
| Directory Bruteforce | Gobuster |
| LAN Scanning | Nmap (network), Enum4linux, SNMPwalk |
| Reputation | IP Reputation (AbuseIPDB, VirusTotal) |

## Architecture

    Farosint/
    ├── engine/
    │   ├── core/           # Orchestrator, worker pool, task queue, cache
    │   └── modules/        # Individual tool wrappers (nmap, nuclei, etc.)
    ├── gui/
    │   ├── app.py          # Flask application
    │   ├── templates/      # Jinja2 HTML templates
    │   └── static/         # CSS, JS, images
    ├── config/             # YAML configuration files
    ├── data/               # Port database, vulnerability data
    ├── output/             # Scan results and exports
    ├── scripts/            # Utility scripts
    └── tools/              # External tool binaries

## Installation (Debian 12 from scratch)

The automated installer sets up the complete environment: desktop, security tools, branding, SSH, and RDP.

### Step 1: Install Debian 12

Download the ISO from the official site:

    https://www.debian.org/download

During installation:
- Create a user named **`farosint`** (required — the installer expects this username)
- Minimal install is fine (no desktop environment needed, the script installs everything)

### Step 2: Install Farosint

Log in as `farosint`, then run:

    su -
    apt update && apt install -y git
    exit
    git clone https://github.com/3breiten/Farosint.git ~/FAROSINT
    sudo bash ~/FAROSINT/install.sh

### Step 3: Reboot

    sudo reboot

After reboot you'll have the full Farosint desktop with LightDM login screen.

### What the installer does

- **Desktop**: Openbox + LightDM + tint2 + jgmenu (dark theme, Kali-style)
- **Security tools**: Nmap, Nuclei, Amass, Subfinder, Httpx, Nikto, Gobuster, DNSRecon, WhatWeb, enum4linux-ng, theHarvester, RustScan, SNMPwalk
- **Languages**: Go 1.22.5, Python 3.11 (virtualenv)
- **Services**: SSH (port 22), xRDP (port 3389)
- **Branding**: Farosint wallpaper, login screen, avatar, xRDP logo
- **Launchers**: `farosint start`, `farosint cli`, right-click menu with all tools

### Usage

**Web Dashboard:**

    farosint start
    # Opens http://localhost:5000

**CLI Mode:**

    farosint cli

**Direct:**

    python3 gui/app.py                                           # Dashboard
    python3 engine/core/orchestrator.py --target example.com     # CLI

## Scan Modes

| Mode | Description |
|---|---|
| Quick | Subfinder + Httpx + Nmap (top ports) + DNSRecon + Nikto + Gobuster |
| Full/Advanced | All tools with deep scanning, Nuclei templates, extended Nmap |
| LAN | Network discovery, Enum4linux, SNMPwalk, internal vulnerability scanning |

## Screenshots

*Coming soon*

## License

MIT License

## Author

**Mariano Breitenberger** - [LinkedIn](https://www.linkedin.com/in/marianobreitenberger/)
