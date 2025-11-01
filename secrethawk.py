#!/usr/bin/env python3
"""
SecretHawk - Comprehensive API Key, Token & Secrets Finder
Author: cyb3r-al3rt
Description: End-to-end secret detection with complete reconnaissance workflow
Methodology: 6-phase automated secret hunting framework
"""

import os
import re
import json
import asyncio
import requests
import argparse
import logging
import sys
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
import subprocess
from concurrent.futures import ThreadPoolExecutor
import time

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class SecretFinding:
    """Store secret finding with complete context"""
    secret_type: str
    secret_value: str
    url: str
    context: str
    confidence: str
    verified: bool = False
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

class SecretPatterns:
    """50+ comprehensive secret detection patterns"""

    PATTERNS = {
        # AWS (Critical)
        "aws_access_key": {
            "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "confidence": "critical",
            "description": "AWS Access Key ID"
        },
        "aws_secret": {
            "pattern": r"aws_secret_access_key\s*=\s*['\"]([a-zA-Z0-9/+=]{40})['\"]",
            "confidence": "critical",
            "description": "AWS Secret Access Key"
        },

        # Google (Critical)
        "google_api_key": {
            "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
            "confidence": "critical",
            "description": "Google API Key"
        },
        "google_oauth": {
            "pattern": r"ya29\\.[0-9A-Za-z_-]{200}",
            "confidence": "high",
            "description": "Google OAuth Token"
        },
        "firebase_url": {
            "pattern": r"https://[a-zA-Z0-9-]+\\.firebaseio\\.com",
            "confidence": "high",
            "description": "Firebase Database URL"
        },

        # GitHub (Critical)
        "github_token_pat": {
            "pattern": r"ghp_[0-9a-zA-Z]{36}",
            "confidence": "critical",
            "description": "GitHub Personal Access Token"
        },
        "github_token_oauth": {
            "pattern": r"gho_[0-9a-zA-Z]{36}",
            "confidence": "critical",
            "description": "GitHub OAuth Token"
        },
        "github_token_app": {
            "pattern": r"ghs_[0-9a-zA-Z]{36}",
            "confidence": "critical",
            "description": "GitHub App Token"
        },
        "github_refresh": {
            "pattern": r"ghr_[0-9a-zA-Z]{36}",
            "confidence": "critical",
            "description": "GitHub Refresh Token"
        },

        # Azure (Critical)
        "azure_client_secret": {
            "pattern": r"client[_-]?secret\s*[:=]\s*['\"]([a-zA-Z0-9._%+~-]{32,})['\"]",
            "confidence": "critical",
            "description": "Azure Client Secret"
        },
        "azure_connection_string": {
            "pattern": r"DefaultEndpointsProtocol=https;.*AccountKey=[a-zA-Z0-9+/=]{88}",
            "confidence": "critical",
            "description": "Azure Storage Connection String"
        },

        # Stripe (Critical)
        "stripe_secret_key": {
            "pattern": r"sk_live_[0-9a-zA-Z]{24}",
            "confidence": "critical",
            "description": "Stripe Secret Key"
        },
        "stripe_restricted_key": {
            "pattern": r"rk_live_[0-9a-zA-Z]{24}",
            "confidence": "high",
            "description": "Stripe Restricted API Key"
        },

        # Database URLs (Critical)
        "mongodb_uri": {
            "pattern": r"mongodb://[^\s:]+:[^\s@]+@[^\s/]+",
            "confidence": "critical",
            "description": "MongoDB Connection String"
        },
        "postgres_uri": {
            "pattern": r"postgres://[^\s:]+:[^\s@]+@[^\s/]+",
            "confidence": "critical",
            "description": "PostgreSQL Connection String"
        },
        "mysql_uri": {
            "pattern": r"mysql://[^\s:]+:[^\s@]+@[^\s/]+",
            "confidence": "critical",
            "description": "MySQL Connection String"
        },
        "redis_uri": {
            "pattern": r"redis://[^\s:]+:[^\s@]+@[^\s/]+",
            "confidence": "high",
            "description": "Redis Connection String"
        },
        "generic_db_uri": {
            "pattern": r"[a-z]+://[^:]+:[^@]+@[^/]+/",
            "confidence": "high",
            "description": "Database Connection String"
        },

        # Communication (High)
        "slack_token": {
            "pattern": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "confidence": "high",
            "description": "Slack Token"
        },
        "slack_webhook": {
            "pattern": r"https://hooks\\.slack\\.com/services/[A-Z0-9]{9}/[A-Z0-9]{11}/[a-zA-Z0-9]{24}",
            "confidence": "high",
            "description": "Slack Webhook"
        },
        "discord_token": {
            "pattern": r"[MN][A-Za-z0-9_]{23}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27}",
            "confidence": "high",
            "description": "Discord Bot Token"
        },
        "telegram_token": {
            "pattern": r"\d{8,10}:[A-Za-z0-9_-]{35}",
            "confidence": "high",
            "description": "Telegram Bot Token"
        },

        # Authentication (High)
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
            "confidence": "high",
            "description": "JWT Token"
        },
        "bearer_token": {
            "pattern": r"bearer\s+[a-zA-Z0-9_\\-\\.=:+/]{20,}",
            "confidence": "high",
            "description": "Bearer Token"
        },
        "basic_auth": {
            "pattern": r"basic\s+[A-Za-z0-9+/=]{20,}",
            "confidence": "high",
            "description": "Basic Auth"
        },

        # Private Keys (Critical)
        "rsa_private_key": {
            "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
            "confidence": "critical",
            "description": "RSA Private Key"
        },
        "openssh_key": {
            "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "confidence": "critical",
            "description": "OpenSSH Private Key"
        },
        "pgp_key": {
            "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "confidence": "critical",
            "description": "PGP Private Key"
        },
        "pem_certificate": {
            "pattern": r"-----BEGIN CERTIFICATE-----",
            "confidence": "medium",
            "description": "Certificate"
        },

        # Third-party APIs (High)
        "mailgun_key": {
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "confidence": "high",
            "description": "Mailgun API Key"
        },
        "twilio_key": {
            "pattern": r"SK[0-9a-zA-Z]{32}",
            "confidence": "high",
            "description": "Twilio API Key"
        },
        "sendgrid_key": {
            "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "confidence": "high",
            "description": "SendGrid API Key"
        },
        "npm_token": {
            "pattern": r"npm_[A-Za-z0-9]{36}",
            "confidence": "high",
            "description": "NPM Access Token"
        },
        "docker_hub_token": {
            "pattern": r"dckr_pat_[A-Za-z0-9_-]{43}",
            "confidence": "high",
            "description": "Docker Hub Token"
        },
        "heroku_key": {
            "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "confidence": "medium",
            "description": "Heroku API Key"
        },

        # Generic patterns (Medium)
        "api_key": {
            "pattern": r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9]{20,})['\"]",
            "confidence": "medium",
            "description": "API Key"
        },
        "secret_key": {
            "pattern": r"['\"]?secret[_-]?key['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9]{20,})['\"]",
            "confidence": "medium",
            "description": "Secret Key"
        },
        "access_token": {
            "pattern": r"['\"]?access[_-]?token['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
            "confidence": "medium",
            "description": "Access Token"
        },
        "password": {
            "pattern": r"['\"]?password['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            "confidence": "medium",
            "description": "Password"
        },

        # URLs and endpoints (Low)
        "internal_ip": {
            "pattern": r"(?:10|172\\.(?:1[6-9]|2[0-9]|3[01])|192\\.168)\\.[0-9]{1,3}\\.[0-9]{1,3}",
            "confidence": "low",
            "description": "Internal IP Address"
        },
        "localhost": {
            "pattern": r"localhost:[0-9]{4,5}",
            "confidence": "low",
            "description": "Localhost URL"
        },
    }

    @classmethod
    def get_all_patterns(cls):
        return cls.PATTERNS

    @classmethod
    def count_patterns(cls):
        return len(cls.PATTERNS)

class SecretHawk:
    """Main SecretHawk framework - 6 phase methodology"""

    def __init__(self, target: str):
        self.target = target
        self.findings: List[SecretFinding] = []
        self.subdomains: Set[str] = set()
        self.live_hosts: Set[str] = set()
        self.directories: Set[str] = set()
        self.all_urls: Set[str] = set()
        self.crawled_content: Dict[str, str] = {}
        self.logger = self._setup_logging()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecretHawk/2.0'
        })
        self.session.verify = False
        self.banner()

    def banner(self):
        """Display banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  ____                    _   _   _                _       ║
║ / ___|  ___  ___ _ __ ___| |_| | | | __ ___      _| | __ ║
║ \\___ \\ / _ \\/ __| '__/ _ \\ __| |_| |/ _\` \\ \\ /\\ / / |/ / ║
║  ___) |  __/ (__| | |  __/ |_|  _  | (_| |\\ V  V /|   <  ║
║ |____/ \\___|\\___|_|  \\___|\\__|_| |_|\\__,_| \\_/\\_/ |_|\\_\\ ║
║                                                           ║
║     Comprehensive API Key, Token & Secrets Finder        ║
║                  Author: cyb3r-al3rt                     ║
║                   Version: 2.0.0                         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.YELLOW}
Methodology: 6-Phase Automated Secret Hunting Framework
Patterns: {SecretPatterns.count_patterns()} Detection Rules
{Colors.ENDC}
{Colors.GREEN}Target: {self.target}{Colors.ENDC}
"""
        print(banner)

    def _setup_logging(self):
        """Setup logging"""
        logger = logging.getLogger('SecretHawk')
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                f'{Colors.BLUE}[%(asctime)s]{Colors.ENDC} %(message)s',
                datefmt='%H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    async def run(self):
        """Main execution - 6 phases"""
        start_time = time.time()

        try:
            # Phase 1: Reconnaissance
            await self.phase_1_reconnaissance()

            # Phase 2: Discovery
            await self.phase_2_discovery()

            # Phase 3: Directory Enumeration
            await self.phase_3_directories()

            # Phase 4: URL Collection
            await self.phase_4_url_collection()

            # Phase 5: Content Crawling
            await self.phase_5_content_crawling()

            # Phase 6: Secret Detection & Reporting
            await self.phase_6_detection_and_reporting()

            elapsed = time.time() - start_time
            self.logger.info(f"{Colors.GREEN}✓ Scan completed in {elapsed:.2f} seconds{Colors.ENDC}")

        except KeyboardInterrupt:
            self.logger.warning(f"{Colors.YELLOW}⚠ Scan interrupted by user{Colors.ENDC}")
        except Exception as e:
            self.logger.error(f"{Colors.RED}✗ Error: {str(e)}{Colors.ENDC}")

    async def phase_1_reconnaissance(self):
        """PHASE 1: Domain & Subdomain Enumeration"""
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")
        self.logger.info(f"{Colors.YELLOW}[PHASE 1/6]{Colors.ENDC} {Colors.CYAN}Reconnaissance - Subdomain Enumeration{Colors.ENDC}")
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")

        self.subdomains.add(self.target)
        self.logger.info(f"Added base domain: {self.target}")

        # Try subfinder
        if self._tool_exists('subfinder'):
            self.logger.info("Running Subfinder...")
            result = self._execute_command(f"subfinder -d {self.target} -silent 2>/dev/null")
            if result:
                subs = set(result.strip().split('\n'))
                self.subdomains.update(subs)
                self.logger.info(f"Subfinder found {len(subs)} subdomains")

        # Try amass
        if self._tool_exists('amass'):
            self.logger.info("Running Amass...")
            result = self._execute_command(f"amass enum -d {self.target} -passive 2>/dev/null | head -20")
            if result:
                subs = set(result.strip().split('\n'))
                new_subs = subs - self.subdomains
                self.subdomains.update(new_subs)
                self.logger.info(f"Amass found {len(new_subs)} additional subdomains")

        self.logger.info(f"{Colors.GREEN}✓ Total subdomains enumerated: {len(self.subdomains)}{Colors.ENDC}\n")

    async def phase_2_discovery(self):
        """PHASE 2: Live Host Detection"""
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")
        self.logger.info(f"{Colors.YELLOW}[PHASE 2/6]{Colors.ENDC} {Colors.CYAN}Discovery - Live Host Detection{Colors.ENDC}")
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")

        count = 0
        for subdomain in list(self.subdomains)[:50]:
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.head(url, timeout=5)
                    self.live_hosts.add(url)
                    count += 1
                    self.logger.info(f"Live: {url} (Status: {response.status_code})")
                    break
                except:
                    pass

        self.logger.info(f"{Colors.GREEN}✓ Live hosts detected: {len(self.live_hosts)}{Colors.ENDC}\n")

    async def phase_3_directories(self):
        """PHASE 3: Directory & Path Enumeration"""
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")
        self.logger.info(f"{Colors.YELLOW}[PHASE 3/6]{Colors.ENDC} {Colors.CYAN}Directory Enumeration{Colors.ENDC}")
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")

        common_dirs = [
            '/', '/api', '/admin', '/config', '/settings', '/secret',
            '/.git', '/.env', '/backup', '/upload', '/temp',
            '/test', '/staging', '/development', '/logs'
        ]

        self.directories = set(common_dirs)
        self.logger.info(f"Added {len(common_dirs)} common directories")
        self.logger.info(f"{Colors.GREEN}✓ Directory paths prepared: {len(self.directories)}{Colors.ENDC}\n")

    async def phase_4_url_collection(self):
        """PHASE 4: URL Collection from Multiple Sources"""
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")
        self.logger.info(f"{Colors.YELLOW}[PHASE 4/6]{Colors.ENDC} {Colors.CYAN}URL Collection{Colors.ENDC}")
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")

        # Add live hosts
        self.all_urls.update(self.live_hosts)
        self.logger.info(f"Added {len(self.live_hosts)} live hosts")

        # Add directory paths
        for host in list(self.live_hosts)[:5]:
            for directory in self.directories:
                url = f"{host}{directory}"
                self.all_urls.add(url)
        self.logger.info(f"Added directory paths to URLs")

        # Try GAU
        if self._tool_exists('gau'):
            self.logger.info("Running GAU (Get All URLs)...")
            result = self._execute_command(f"gau {self.target} 2>/dev/null | head -30")
            if result:
                urls = set(result.strip().split('\n'))
                self.all_urls.update(urls)
                self.logger.info(f"GAU found {len(urls)} URLs")

        # Try Wayback Machine
        if self._tool_exists('waybackurls'):
            self.logger.info("Querying Wayback Machine...")
            result = self._execute_command(f"waybackurls {self.target} 2>/dev/null | head -30")
            if result:
                urls = set(result.strip().split('\n'))
                self.all_urls.update(urls)
                self.logger.info(f"Wayback Machine found {len(urls)} historical URLs")

        # Try Katana
        if self._tool_exists('katana'):
            self.logger.info("Running Katana crawler...")
            with open('/tmp/sh_hosts.txt', 'w') as f:
                for host in list(self.live_hosts)[:3]:
                    f.write(f"{host}\n")
            result = self._execute_command("katana -list /tmp/sh_hosts.txt -silent -d 2 2>/dev/null | head -30")
            if result:
                urls = set(result.strip().split('\n'))
                self.all_urls.update(urls)
                self.logger.info(f"Katana crawled {len(urls)} URLs")

        self.logger.info(f"{Colors.GREEN}✓ Total URLs collected: {len(self.all_urls)}{Colors.ENDC}\n")

    async def phase_5_content_crawling(self):
        """PHASE 5: Content Download & Crawling"""
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")
        self.logger.info(f"{Colors.YELLOW}[PHASE 5/6]{Colors.ENDC} {Colors.CYAN}Content Crawling{Colors.ENDC}")
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")

        urls_to_crawl = list(self.all_urls)[:200]
        count = 0

        for url in urls_to_crawl:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    self.crawled_content[url] = response.text
                    count += 1
                    if count % 25 == 0:
                        self.logger.info(f"Downloaded {count}/{len(urls_to_crawl)} pages...")
            except:
                pass

        self.logger.info(f"{Colors.GREEN}✓ Content downloaded: {len(self.crawled_content)} pages{Colors.ENDC}\n")

    async def phase_6_detection_and_reporting(self):
        """PHASE 6: Secret Detection & Report Generation"""
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")
        self.logger.info(f"{Colors.YELLOW}[PHASE 6/6]{Colors.ENDC} {Colors.CYAN}Secret Detection & Reporting{Colors.ENDC}")
        self.logger.info(f"{Colors.CYAN}{'='*60}{Colors.ENDC}")

        patterns = SecretPatterns.get_all_patterns()
        self.logger.info(f"Scanning with {len(patterns)} detection patterns...")

        for url, content in self.crawled_content.items():
            for pattern_name, pattern_info in patterns.items():
                try:
                    matches = re.findall(
                        pattern_info['pattern'],
                        content,
                        re.IGNORECASE | re.MULTILINE
                    )

                    for match in matches:
                        match_str = str(match) if not isinstance(match, str) else match
                        if len(match_str) > 5:
                            # Get context
                            pos = content.find(match_str)
                            if pos != -1:
                                start = max(0, pos - 100)
                                end = min(len(content), pos + len(match_str) + 100)
                                context = content[start:end]
                            else:
                                context = ""

                            finding = SecretFinding(
                                secret_type=pattern_name,
                                secret_value=match_str[:150],
                                url=url,
                                context=context[:200],
                                confidence=pattern_info['confidence']
                            )
                            self.findings.append(finding)
                except:
                    pass

        # Remove duplicates
        unique_findings = {}
        for f in self.findings:
            key = (f.secret_type, f.secret_value)
            if key not in unique_findings:
                unique_findings[key] = f

        self.findings = list(unique_findings.values())
        self.logger.info(f"{Colors.GREEN}✓ Secrets detected: {len(self.findings)}{Colors.ENDC}\n")

        # Generate report
        await self._generate_report()

    async def _generate_report(self):
        """Generate comprehensive JSON report"""
        report = {
            "tool": "SecretHawk",
            "version": "2.0.0",
            "target": self.target,
            "scan_timestamp": datetime.now().isoformat(),
            "methodology": "6-Phase Automated Secret Hunting",
            "summary": {
                "subdomains_enumerated": len(self.subdomains),
                "live_hosts_detected": len(self.live_hosts),
                "directories_identified": len(self.directories),
                "urls_collected": len(self.all_urls),
                "pages_crawled": len(self.crawled_content),
                "secrets_found": len(self.findings),
                "detection_patterns_used": SecretPatterns.count_patterns()
            },
            "findings": [asdict(f) for f in sorted(
                self.findings,
                key=lambda x: ['critical', 'high', 'medium', 'low'].index(x.confidence)
            )]
        }

        filename = f"secrethawk_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"{Colors.GREEN}✓ Report saved: {filename}{Colors.ENDC}")
        self._display_summary()

    def _display_summary(self):
        """Display scan summary"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.YELLOW}SECRETHAWK SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.CYAN}Target:{Colors.ENDC} {self.target}")
        print(f"{Colors.CYAN}Subdomains:{Colors.ENDC} {len(self.subdomains)}")
        print(f"{Colors.CYAN}Live Hosts:{Colors.ENDC} {len(self.live_hosts)}")
        print(f"{Colors.CYAN}URLs Collected:{Colors.ENDC} {len(self.all_urls)}")
        print(f"{Colors.CYAN}Pages Crawled:{Colors.ENDC} {len(self.crawled_content)}")
        print(f"{Colors.BOLD}{Colors.RED}Secrets Found:{Colors.ENDC} {Colors.BOLD}{len(self.findings)}{Colors.ENDC}")

        if self.findings:
            print(f"\n{Colors.YELLOW}Findings by Severity:{Colors.ENDC}")
            by_confidence = {}
            for f in self.findings:
                by_confidence[f.confidence] = by_confidence.get(f.confidence, 0) + 1

            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in by_confidence:
                    print(f"  {Colors.RED if severity == 'critical' else Colors.YELLOW}✓ {severity.upper()}: {by_confidence[severity]}{Colors.ENDC}")

            print(f"\n{Colors.YELLOW}Findings by Type (Top 10):{Colors.ENDC}")
            by_type = {}
            for f in self.findings:
                by_type[f.secret_type] = by_type.get(f.secret_type, 0) + 1

            for t, c in sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  - {t}: {c}")

        print(f"{Colors.CYAN}{'='*60}{Colors.ENDC}\n")

    def _tool_exists(self, tool: str) -> bool:
        """Check if tool exists"""
        try:
            subprocess.run(['which', tool], capture_output=True, check=True)
            return True
        except:
            return False

    def _execute_command(self, cmd: str) -> Optional[str]:
        """Execute shell command"""
        try:
            result = os.popen(cmd).read()
            return result if result.strip() else None
        except:
            return None

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SecretHawk - Comprehensive API Key, Token & Secrets Finder',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secrethawk.py -d example.com
  secrethawk.py -d target.org
        """
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    args = parser.parse_args()

    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings()

    # Run SecretHawk
    hawk = SecretHawk(args.domain)
    await hawk.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.ENDC}")
        sys.exit(1)
