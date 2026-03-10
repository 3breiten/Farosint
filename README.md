# FAROSINT

> **Version 1.1.0** — [Releases](https://github.com/3breiten/Farosint/releases) · [Changelog](CHANGELOG.md)

**OSINT & Attack Surface Analysis Framework**

FAROSINT is a web-based platform for automated reconnaissance and attack surface mapping. It orchestrates multiple security tools through an intuitive dashboard, providing a unified view of targets with interactive visualizations and professional PDF reporting.

Built for security professionals, pentesters, and red team operators.

---

## Installation

FAROSINT supports three deployment methods:

| Method | Best for |
|--------|----------|
| **Docker** | Any OS — Linux, macOS, Windows (recommended) |
| **ISO Installer** | Bare-metal install via bootable USB |
| **OVA** | VMware or VirtualBox — ready to import |

Full installation instructions are included in each [**Release**](https://github.com/3breiten/Farosint/releases).

---

## Features

- **Multi-mode scanning**: Quick, Full/Advanced, and LAN scanning modes
- **Tool orchestration**: Parallel execution with priority-based worker pool
- **Interactive network graph**: Force-directed visualization of discovered assets
- **PDF reporting**: Professional reports with executive summary and findings
- **Real-time progress**: Live scan status via Server-Sent Events (SSE)
- **CVE matching**: Local CVE database + NVD API with automatic fallback
- **CDN/WAF detection**: Identifies Cloudflare, Incapsula, Akamai, and others
- **Dark mode**: Full UI dark mode support
- **CLI support**: Full command-line interface

---

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

---

## Scan Modes

| Mode | Description |
|---|---|
| Quick | Subfinder + Httpx + Nmap (top ports) + DNSRecon + Nikto + Gobuster |
| Full/Advanced | All tools, deep scanning, Nuclei templates, extended Nmap |
| LAN | Network discovery, Enum4linux-ng, SNMPwalk, internal vulnerability scanning |

---

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

---

## Screenshots

*Coming soon*

---

## License

MIT License

## Author

**Mariano Breitenberger** — [LinkedIn](https://www.linkedin.com/in/marianobreitenberger/)
