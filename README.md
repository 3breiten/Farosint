# Farosint

**OSINT & Attack Surface Analysis Framework**

Farosint is a web-based platform for automated reconnaissance and attack surface mapping. It orchestrates multiple security tools through an intuitive dashboard, providing a unified view of targets with interactive visualizations and professional PDF reporting.

Built for security professionals, pentesters, and red team operators.

---

## Features

- **Multi-mode scanning**: Quick, Full/Advanced, and LAN scanning modes
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

## Quick Start

### Requirements

- Debian 12 / Ubuntu 22.04+
- Python 3.10+
- Security tools (Nmap, Nuclei, Amass, etc.)

### Installation

    git clone https://github.com/3breiten/Farosint.git
    cd Farosint
    python3 -m venv farosint-env
    source farosint-env/bin/activate
    pip install -r requirements.txt

### Usage

**Web Dashboard:**

    python3 gui/app.py
    # Open http://localhost:5000

**CLI Mode:**

    python3 engine/core/orchestrator.py --target example.com --mode full

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
