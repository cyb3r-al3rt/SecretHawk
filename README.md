# SecretHawk - Comprehensive Secret Detection Tool

## Overview

SecretHawk is an automated **6-phase secret hunting framework** for bug bounty hunters and penetration testers.

**Methodology**: Domain Reconnaissance → Live Detection → Directory Enumeration → URL Collection → Content Crawling → Secret Detection

## Features

### 🔍 Phase 1: Reconnaissance
- Subdomain enumeration using Subfinder
- Additional discovery with Amass
- Automated asset mapping

### ✅ Phase 2: Discovery  
- Live host detection via HTTP probing
- Status code verification
- Protocol detection (HTTP/HTTPS)

### 📁 Phase 3: Directory Enumeration
- Common paths identification
- Configuration files targeting
- API endpoint discovery

### 🌐 Phase 4: URL Collection
- Multi-source URL aggregation:
  - GAU (Get All URLs)
  - Wayback Machine (historical)
  - Katana (live crawling)
- 200+ URLs analyzed per target

### 📥 Phase 5: Content Crawling
- Automated page download
- JavaScript analysis
- Form extraction

### 🔑 Phase 6: Secret Detection
- **50+ Detection Patterns**:
  - AWS Keys (AKIA format)
  - GitHub Tokens (all types)
  - Google API Keys
  - Azure Secrets
  - Stripe Keys
  - Database URLs (MongoDB, PostgreSQL, MySQL)
  - Private Keys (RSA, SSH, PGP)
  - JWT/Bearer Tokens
  - Slack/Discord Tokens
  - And 30+ more...

## Installation

```bash
chmod +x install.sh
./install.sh
```

## Usage

```bash
# Basic scan
python3 secrethawk.py -d example.com

# Or use symlink
secrethawk -d example.com
```

## Output

Generates JSON report:
```
secrethawk_example_com_20251101_145300.json
```

Contains:
- Summary statistics
- All findings with URLs
- Confidence levels
- Context for each secret
- Timestamps

## What It Finds

| Category | Types | Severity |
|----------|-------|----------|
| Cloud Credentials | AWS, Google, Azure, Firebase | Critical |
| VCS Tokens | GitHub, GitLab | Critical |
| Payment Keys | Stripe, PayPal | Critical |
| Database URLs | MongoDB, PostgreSQL, MySQL | Critical |
| Private Keys | RSA, SSH, PGP | Critical |
| Tokens | JWT, Bearer, OAuth | High |
| Communication | Slack, Discord, Telegram | High |
| APIs | Generic Keys, Secrets | Medium |

## Requirements

- Python 3.8+
- requests library
- Optional Go tools for enhanced reconnaissance

## Performance

- Small targets (1-10 subdomains): 5-15 minutes
- Medium targets (10-50 subdomains): 15-30 minutes
- Large targets (50+ subdomains): 30-60 minutes

## Architecture

```
SecretHawk
├── Phase 1: Reconnaissance
│   └── Subdomain enumeration
├── Phase 2: Discovery
│   └── Live host detection
├── Phase 3: Directories
│   └── Path enumeration
├── Phase 4: URL Collection
│   ├── GAU
│   ├── Wayback
│   └── Katana
├── Phase 5: Crawling
│   └── Content download
└── Phase 6: Detection
    ├── Pattern matching
    ├── Secret extraction
    └── Report generation
```

## Author

cyb3r-al3rt (kernelpanic)
- GitHub: @cyb3r-al3rt
- LinkedIn: in/cyb3r-ssrf

## License

MIT License

## Disclaimer

Use only on domains you own or have explicit permission to test.

---

**Built for the cybersecurity community** 🚀
