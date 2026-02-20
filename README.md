# FAROSINT

> Version 1.0.0

**OSINT & Attack Surface Analysis Framework**

FAROSINT is a web-based platform for automated reconnaissance and attack surface mapping. It orchestrates multiple security tools through an intuitive dashboard, providing a unified view of targets with interactive visualizations and professional PDF reporting.

Built for security professionals, pentesters, and red team operators.

---

## Quick Start — Docker (any OS)

The fastest way to run FAROSINT. Works on Linux, macOS, and Windows (WSL2).

### Step 1 — Install Git

**Linux (Debian/Ubuntu):**
```bash
sudo apt update && sudo apt install -y git
```

**Linux (RHEL/Fedora/CentOS):**
```bash
sudo dnf install -y git
```

**macOS:**
```bash
brew install git
# If you don't have Homebrew: https://brew.sh
```

**Windows:**
Download and install from [git-scm.com](https://git-scm.com/download/win), or use **WSL2** (recommended — see below).

> Already have Git? Skip to Step 2.

### Step 2 — Install Docker

Download and install **Docker Desktop** from [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) (Windows/macOS).

**Linux (Debian/Ubuntu):**
```bash
sudo apt update && sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo service docker start
sudo usermod -aG docker $USER && newgrp docker
```

> Already have Docker? Skip to Step 3.

### Step 3 — Run FAROSINT

```bash
git clone https://github.com/3breiten/Farosint.git
cd Farosint
docker compose build   # first time only, ~15 min
docker compose up -d
```

Open **http://localhost:5000** in your browser.

```bash
# Useful commands
docker compose logs -f    # follow logs
docker compose down       # stop
docker compose up -d      # start again (uses cached build)
```

Scan results, database, and logs persist in a Docker volume (`farosint_data`) across restarts.

### Windows — Using WSL2 (recommended)

1. Open **PowerShell as Administrator** and run:
```powershell
wsl --install
```
2. Restart your PC, then open the **Ubuntu** app from the Start menu
3. Inside Ubuntu, follow the **Linux (Debian/Ubuntu)** steps above for Git and Docker
4. Access the dashboard at **http://localhost:5000** from your Windows browser

---

## Full Installation — Debian 12 (dedicated machine / VM)

For a complete environment with desktop, RDP access, branding, and system services.

### Requirements
- Debian 12 (minimal or standard install)
- User named **`farosint`** (required — paths are hardcoded to this username)

### Step 1 — Install Debian 12

Download from [debian.org/download](https://www.debian.org/download).
During installation, create a user named `farosint`.

### Step 2 — Clone the repository

> **Note:** Debian minimal does not include `sudo`. Use `su -` for a root shell.

```bash
# As root
su -
apt update && apt install -y git
exit

# As farosint
git clone https://github.com/3breiten/Farosint.git ~/FAROSINT
```

### Step 3 — Run the installer

```bash
su -
bash /home/farosint/FAROSINT/install.sh
```

Takes ~10–20 minutes. Shows a verification summary at the end.

### Step 4 — Reboot

```bash
reboot
```

After reboot you'll have the full FAROSINT desktop with LightDM login screen.

### What the installer sets up

| Component | Details |
|---|---|
| Desktop | Openbox + LightDM + tint2 (dark theme) |
| Security tools | Nmap, Nuclei, Amass, Subfinder, Httpx, Nikto, Gobuster, DNSRecon, WhatWeb, enum4linux-ng, theHarvester, RustScan, SNMPwalk |
| Languages | Go 1.22.5, Python 3.11 (virtualenv) |
| Services | SSH (port 22), xRDP (port 3389), dashboard autostart |
| Branding | Wallpaper, login screen, avatar, xRDP logo |
| Launchers | `farosint start`, `farosint cli`, right-click menu |

### Usage after installation

```bash
farosint start    # starts dashboard → http://localhost:5000
farosint cli      # command-line mode
farosint status   # check if running
farosint stop     # stop dashboard
```

---

## Features

- **Multi-mode scanning**: Quick, Full/Advanced, and LAN scanning modes
- **Tool orchestration**: Parallel execution with priority-based worker pool
- **Interactive network graph**: D3.js force-directed visualization of discovered assets
- **PDF reporting**: Professional reports with executive summary and findings
- **Real-time progress**: Live scan status via Server-Sent Events (SSE)
- **CVE matching**: Local CVE database + NVD API with automatic fallback
- **CDN/WAF detection**: Identifies Cloudflare, Incapsula, Akamai, and others
- **Dark mode**: Full UI dark mode support
- **CLI support**: Full command-line interface

## Integrated Tools

| Category | Tools |
|---|---|
| Subdomain Discovery | Amass, Subfinder |
| DNS | DNSRecon |
| Port Scanning | Nmap, RustScan |
| Web Analysis | Httpx, WhatWeb |
| Vulnerability Scanning | Nuclei, Nikto |
| Directory Bruteforce | Gobuster |
| LAN Scanning | Nmap (network), Enum4linux-ng, SNMPwalk |
| Reputation | IP Reputation (AbuseIPDB, VirusTotal) |
| OSINT | theHarvester |

## Scan Modes

| Mode | Description |
|---|---|
| Quick | Subfinder + Httpx + Nmap (top ports) + DNSRecon + Nikto + Gobuster |
| Full/Advanced | All tools, deep scanning, Nuclei templates, extended Nmap |
| LAN | Network discovery, Enum4linux-ng, SNMPwalk, internal vulnerability scanning |

## Architecture

```
Farosint/
├── engine/
│   ├── core/           # Orchestrator, worker pool, task queue, cache
│   └── modules/        # Individual tool wrappers (nmap, nuclei, etc.)
├── gui/
│   ├── app.py          # Flask + SocketIO dashboard
│   ├── templates/      # Jinja2 HTML templates
│   └── static/         # CSS, JS, images
├── system/             # Desktop configs, launchers, branding
├── Dockerfile          # Docker image definition
├── docker-compose.yml  # Docker orchestration
└── install.sh          # Debian 12 full installer
```

## Screenshots

*Coming soon*

## License

MIT License

## Author

**Mariano Breitenberger** — [LinkedIn](https://www.linkedin.com/in/marianobreitenberger/)
