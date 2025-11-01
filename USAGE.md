# SecretHawk Usage Guide

## Quick Start

```bash
python3 secrethawk.py -d target.com
```

## 6-Phase Methodology

### Phase 1: Reconnaissance
Enumerates subdomains for complete asset discovery.
```
Tools: subfinder, amass
Output: List of subdomains
```

### Phase 2: Discovery
Identifies live hosts and accessible targets.
```
Method: HTTP probing
Output: Live URLs with status codes
```

### Phase 3: Directory Enumeration
Maps directories and common paths.
```
Targets: /api, /admin, /config, /.git, .env, etc.
Output: Directory list
```

### Phase 4: URL Collection
Aggregates URLs from multiple sources.
```
Sources:
- GAU: Aggregated URLs
- Wayback Machine: Historical URLs
- Katana: Live crawling
Output: Complete URL list
```

### Phase 5: Content Crawling
Downloads and analyzes page content.
```
Content: HTML, JavaScript, responses
Output: Raw page data
```

### Phase 6: Secret Detection
Matches against 50+ patterns and generates report.
```
Patterns: AWS, GitHub, Google, Azure, etc.
Output: JSON report with findings
```

## Output Format

```json
{
  "tool": "SecretHawk",
  "version": "2.0.0",
  "target": "example.com",
  "scan_timestamp": "2025-11-01T14:53:00",
  "methodology": "6-Phase Automated Secret Hunting",
  "summary": {
    "subdomains_enumerated": 45,
    "live_hosts_detected": 32,
    "urls_collected": 250,
    "pages_crawled": 150,
    "secrets_found": 12,
    "detection_patterns_used": 50
  },
  "findings": [
    {
      "secret_type": "aws_access_key",
      "secret_value": "AKIAIOSFODNN7EXAMPLE",
      "url": "https://api.example.com/config.js",
      "context": "...aws_key = 'AKIAIOSFODNN7EXAMPLE'...",
      "confidence": "critical",
      "timestamp": "2025-11-01T14:55:30"
    }
  ]
}
```

## Tips

1. **Start small**: Test with single subdomain first
2. **Patient scanning**: Tool takes time to collect URLs
3. **Verify findings**: Manually test critical findings
4. **Report responsibly**: Coordinate with security teams
5. **Check tool installation**: Run `which subfinder` etc.

## Troubleshooting

### Tool not found error
```bash
export PATH=$PATH:$HOME/go/bin
source ~/.bashrc
```

### Slow scanning
- Normal for large targets
- Tool collects comprehensive data
- Wayback queries take time

### No results
- Check internet connectivity
- Verify target is accessible
- Try different protocol (HTTP/HTTPS)

## Performance Tips

- Use on targets < 100 subdomains first
- Reduce max_urls if too slow
- Can interrupt with Ctrl+C anytime
- Results saved even if interrupted

---

For more info: github.com/cyb3r-al3rt/SecretHawk
