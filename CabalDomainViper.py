#!/usr/bin/env python3
"""
Cabal Domain Viper - OSINT Subdomain Enumeration and HTML Extraction Tool
A security research tool for discovering subdomains and extracting profile IDs, URLs, and files
"""

import argparse
import requests
import dns.resolver
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Any
from collections import defaultdict
import time
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# ASCII Art
DOMAIN_VIPER_ART = f"""{Fore.GREEN}
  _____                        _   __      ___
 |  __ \\                      (_)  \\ \\    / (_)
 | |  | | ___  _ __ ___   __ _ _ _ _\\ \\  / / _ _ __   ___ _ __
 | |  | |/ _ \\| '_ ` _ \\ / _` | | '_ \\ \\/ / | | '_ \\ / _ \\ '__|
 | |__| | (_) | | | | | | (_| | | | | \\  /  | | |_) |  __/ |
 |_____/ \\___/|_| |_| |_|\\__,_|_|_| |_|\\/   |_| .__/ \\___|_|
                                              | |
                                              |_|
{Style.RESET_ALL}"""

SNAKE_1 = f"""{Fore.YELLOW}
         ____
      _,.-'`_ o `;__,
       _.-'` '---'  '
{Style.RESET_ALL}"""

SNAKE_2 = f"""{Fore.CYAN}
                    ____
                 .'`_ o `;__,
       .       .'.'` '---'  '
       .`-...-'.'
        `-...-'
{Style.RESET_ALL}"""

SNAKE_3 = f"""{Fore.MAGENTA}
                        _,.--.
    --..,_           .'`__ o  `;__,
       `'.'.       .'.'`  '---'`  '
            `-...-'
{Style.RESET_ALL}"""

SNAKE_4 = f"""{Fore.RED}
    --..,_                     _,.--.
       `'.'.                .'`__ o  `;__.
          '.'.            .'.'`  '---'`  `
            '.`'--....--'`.'
              `'--....--'`
{Style.RESET_ALL}"""

SNAKES = [SNAKE_1, SNAKE_2, SNAKE_3, SNAKE_4]

def load_api_keys(config_file='config.json') -> Dict:
    """Load API keys from config file"""
    if not os.path.exists(config_file):
        print(f"{Fore.YELLOW}[!] Config file '{config_file}' not found!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Host intelligence features will be disabled.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] See README.md for API setup instructions.{Style.RESET_ALL}")
        return {}

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except json.JSONDecodeError:
        print(f"{Fore.YELLOW}[!] Error parsing config.json. Host intelligence disabled.{Style.RESET_ALL}")
        return {}

def animate_text(text, delay=0.03):
    """Print text with typing animation"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def print_snake(index=None):
    """Print a random or specific snake"""
    import random
    if index is None:
        index = random.randint(0, len(SNAKES) - 1)
    print(SNAKES[index % len(SNAKES)])

def print_section_header(title, snake_index=None):
    """Print a colorful section header with snake"""
    print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
    if snake_index is not None:
        print_snake(snake_index)

class HostIntelligence:
    """Host Intelligence Gathering using multiple APIs"""

    def __init__(self, api_keys: Dict = None):
        self.results = defaultdict(dict)
        self.api_keys = api_keys or {}
        self.enabled = bool(self.api_keys.get('ip2location') and self.api_keys.get('hostio'))

    def is_ip(self, query: str) -> bool:
        """Check if query is an IP address"""
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ipv4_pattern, query))

    def query_ip2location(self, query: str) -> Dict:
        """Query IP2Location.io API"""
        if 'ip2location' not in self.api_keys:
            return {}
        try:
            url = f"https://api.ip2location.io/?key={self.api_keys['ip2location']}&ip={query}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return {'source': 'IP2Location.io', 'data': response.json()}
        except Exception:
            pass
        return {}

    def query_ipapi(self, query: str) -> Dict:
        """Query IP-API.com (No API key required)"""
        try:
            url = f"http://ip-api.com/json/{query}?fields=status,message,continent,country,countryCode,region,city,lat,lon,timezone,isp,org,as,asname,proxy,hosting"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {'source': 'IP-API.com', 'data': data}
        except Exception:
            pass
        return {}

    def query_hostio_dns(self, domain: str) -> Dict:
        """Query Host.io DNS API"""
        if 'hostio' not in self.api_keys:
            return {}
        try:
            url = f"https://host.io/api/dns/{domain}"
            response = requests.get(url, auth=(self.api_keys['hostio'], ''), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    return {'source': 'Host.io-DNS', 'data': data}
        except Exception:
            pass
        return {}

    def query_hostio_web(self, domain: str) -> Dict:
        """Query Host.io Web API"""
        if 'hostio' not in self.api_keys:
            return {}
        try:
            url = f"https://host.io/api/web/{domain}"
            response = requests.get(url, auth=(self.api_keys['hostio'], ''), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    return {'source': 'Host.io-Web', 'data': data}
        except Exception:
            pass
        return {}

    def consolidate_results(self, results: List[Dict]) -> Dict:
        """Consolidate results from multiple APIs"""
        consolidated = {
            'basic': {},
            'location': {},
            'network': {},
            'dns': {},
            'security': {},
            'web': {}
        }

        for result in results:
            if not result or 'data' not in result:
                continue

            data = result['data']

            # Basic info
            for key in ['ip', 'domain', 'query']:
                if key in data and key not in consolidated['basic']:
                    consolidated['basic'][key] = data[key]

            # Location
            for key in ['country', 'countryCode', 'region', 'city', 'lat', 'lon', 'timezone']:
                if key in data and key not in consolidated['location']:
                    consolidated['location'][key] = data[key]

            # Network
            for key in ['isp', 'org', 'as', 'asname']:
                if key in data and key not in consolidated['network']:
                    consolidated['network'][key] = data[key]

            # DNS
            if 'dns' in data:
                for record_type, records in data['dns'].items():
                    if records and record_type not in consolidated['dns']:
                        consolidated['dns'][record_type] = records

            # Security
            for key in ['proxy', 'hosting']:
                if key in data and key not in consolidated['security']:
                    consolidated['security'][key] = data[key]

            # Web
            for key in ['title', 'server', 'redirects']:
                if key in data and key not in consolidated['web']:
                    consolidated['web'][key] = data[key]

        return consolidated

    def gather_intelligence(self, target: str) -> Dict:
        """Gather intelligence for a target"""
        if not self.enabled:
            return {}

        results = []

        if self.is_ip(target):
            results.append(self.query_ip2location(target))
            time.sleep(0.5)
            results.append(self.query_ipapi(target))
        else:
            results.append(self.query_hostio_dns(target))
            time.sleep(0.5)
            results.append(self.query_hostio_web(target))
            time.sleep(0.5)
            results.append(self.query_ipapi(target))

        return self.consolidate_results(results)

    def print_intelligence(self, target: str, intel: Dict):
        """Print intelligence in a formatted way"""
        if not any(intel.values()):
            print(f"{Fore.YELLOW}  No additional intelligence gathered{Style.RESET_ALL}")
            return

        # Basic Information
        if intel['basic']:
            print(f"\n{Fore.GREEN}╔══ BASIC INFORMATION{Style.RESET_ALL}")
            for key, value in intel['basic'].items():
                print(f"{Fore.CYAN}  ├─ {key.title():15}{Style.RESET_ALL}: {Fore.WHITE}{value}{Style.RESET_ALL}")

        # Location
        if intel['location']:
            print(f"\n{Fore.GREEN}╔══ GEOLOCATION{Style.RESET_ALL}")
            for key, value in intel['location'].items():
                print(f"{Fore.CYAN}  ├─ {key.title():15}{Style.RESET_ALL}: {Fore.WHITE}{value}{Style.RESET_ALL}")

        # Network
        if intel['network']:
            print(f"\n{Fore.GREEN}╔══ NETWORK{Style.RESET_ALL}")
            for key, value in intel['network'].items():
                print(f"{Fore.CYAN}  ├─ {key.upper() if len(key) <= 3 else key.title():15}{Style.RESET_ALL}: {Fore.WHITE}{value}{Style.RESET_ALL}")

        # DNS
        if intel['dns']:
            print(f"\n{Fore.GREEN}╔══ DNS RECORDS{Style.RESET_ALL}")
            for record_type, records in intel['dns'].items():
                print(f"{Fore.CYAN}  ├─ {record_type.upper():15}{Style.RESET_ALL}:")
                if isinstance(records, list):
                    for record in records[:5]:
                        print(f"{Fore.WHITE}  │  └─ {record}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.WHITE}  │  └─ {records}{Style.RESET_ALL}")

        # Security
        if intel['security']:
            print(f"\n{Fore.GREEN}╔══ SECURITY FLAGS{Style.RESET_ALL}")
            for key, value in intel['security'].items():
                status = f"{Fore.RED}Yes{Style.RESET_ALL}" if value else f"{Fore.GREEN}No{Style.RESET_ALL}"
                print(f"{Fore.CYAN}  ├─ {key.title():15}{Style.RESET_ALL}: {status}")

        # Web
        if intel['web']:
            print(f"\n{Fore.GREEN}╔══ WEB INFORMATION{Style.RESET_ALL}")
            for key, value in intel['web'].items():
                if isinstance(value, list):
                    print(f"{Fore.CYAN}  ├─ {key.title():15}{Style.RESET_ALL}:")
                    for item in value[:3]:
                        print(f"{Fore.WHITE}  │  └─ {item}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}  ├─ {key.title():15}{Style.RESET_ALL}: {Fore.WHITE}{value}{Style.RESET_ALL}")

class CabalDomainViper:
    def __init__(self, domain: str, wordlist: str = None, threads: int = 10, timeout: int = 5, api_keys: Dict = None):
        self.domain = domain
        self.wordlist = wordlist or self.get_default_wordlist()
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.results = {}
        self.host_intel = HostIntelligence(api_keys)

    def get_default_wordlist(self) -> List[str]:
        """Default common subdomain list"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start',
            'sms', 'office', 'exchange', 'ipv4'
        ]

    def load_wordlist(self) -> List[str]:
        """Load subdomain wordlist from file or use default"""
        if isinstance(self.wordlist, list):
            return self.wordlist
        try:
            with open(self.wordlist, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {self.wordlist}")
            print("[*] Using default wordlist")
            return self.get_default_wordlist()

    def check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS lookup"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            print(f"{Fore.GREEN}[+] Found: {Fore.WHITE}{full_domain}{Style.RESET_ALL}")
            self.found_subdomains.add(full_domain)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return False
        except Exception as e:
            return False

    def enumerate_subdomains(self):
        """Enumerate subdomains using wordlist (silently)"""
        wordlist = self.load_wordlist()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                future.result()

        return self.found_subdomains

    def fetch_html(self, url: str) -> str:
        """Fetch HTML content from URL"""
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True,
                                   verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                return response.text
        except Exception as e:
            pass
        return None

    def extract_profile_ids(self, html: str) -> Set[str]:
        """Extract potential profile IDs from HTML"""
        profile_ids = set()

        # Common profile ID patterns
        patterns = [
            r'profile[_-]?id["\s:=]+([a-zA-Z0-9_-]+)',
            r'user[_-]?id["\s:=]+([a-zA-Z0-9_-]+)',
            r'uid["\s:=]+([a-zA-Z0-9_-]+)',
            r'/user/([a-zA-Z0-9_-]+)',
            r'/profile/([a-zA-Z0-9_-]+)',
            r'data-user-id["\s:=]+([a-zA-Z0-9_-]+)',
            r'data-profile-id["\s:=]+([a-zA-Z0-9_-]+)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            profile_ids.update(matches)

        return profile_ids

    def extract_urls(self, html: str, base_url: str) -> Set[str]:
        """Extract URLs from HTML"""
        urls = set()
        soup = BeautifulSoup(html, 'html.parser')

        for tag in soup.find_all(['a', 'link', 'script', 'img']):
            url = tag.get('href') or tag.get('src')
            if url:
                full_url = urljoin(base_url, url)
                urls.add(full_url)

        return urls

    def extract_files(self, html: str, base_url: str) -> Dict[str, Set[str]]:
        """Extract file references from HTML categorized by type"""
        files = {
            'documents': set(),
            'images': set(),
            'archives': set(),
            'data': set(),
            'media': set(),
            'other': set()
        }

        soup = BeautifulSoup(html, 'html.parser')

        # Document extensions
        doc_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp']
        # Image extensions
        img_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico', 'tiff']
        # Archive extensions
        archive_extensions = ['zip', 'rar', 'tar', 'gz', 'bz2', '7z', 'tgz']
        # Data extensions
        data_extensions = ['json', 'xml', 'csv', 'yaml', 'yml', 'sql', 'db']
        # Media extensions
        media_extensions = ['mp4', 'avi', 'mov', 'mp3', 'wav', 'flac', 'ogg']

        # Extract from all relevant tags
        for tag in soup.find_all(['a', 'img', 'link', 'script', 'source', 'embed', 'object']):
            url = tag.get('href') or tag.get('src') or tag.get('data')
            if url:
                full_url = urljoin(base_url, url)
                ext = urlparse(full_url).path.split('.')[-1].lower()

                if ext in doc_extensions:
                    files['documents'].add(full_url)
                elif ext in img_extensions:
                    files['images'].add(full_url)
                elif ext in archive_extensions:
                    files['archives'].add(full_url)
                elif ext in data_extensions:
                    files['data'].add(full_url)
                elif ext in media_extensions:
                    files['media'].add(full_url)
                elif ext and len(ext) <= 5:  # Likely a file extension
                    files['other'].add(full_url)

        # Also search for file patterns in the HTML text
        all_extensions = doc_extensions + img_extensions + archive_extensions + data_extensions + media_extensions
        pattern = r'["\']([^"\']*\.(' + '|'.join(all_extensions) + r'))["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)

        for match in matches:
            url = match[0]
            full_url = urljoin(base_url, url)
            ext = match[1].lower()

            if ext in doc_extensions:
                files['documents'].add(full_url)
            elif ext in img_extensions:
                files['images'].add(full_url)
            elif ext in archive_extensions:
                files['archives'].add(full_url)
            elif ext in data_extensions:
                files['data'].add(full_url)
            elif ext in media_extensions:
                files['media'].add(full_url)

        return files

    def extract_emails(self, html: str) -> Set[str]:
        """Extract email addresses from HTML"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return set(re.findall(email_pattern, html))

    def extract_api_keys(self, html: str) -> Dict[str, Set[str]]:
        """Extract API keys and secrets from HTML"""
        keys = {
            'api_keys': set(),
            'tokens': set(),
            'secrets': set(),
            'passwords': set(),
            'credentials': set()
        }

        # API key patterns
        patterns = {
            'api_keys': [
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,})["\']',
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
            ],
            'tokens': [
                r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
                r'Bearer\s+([a-zA-Z0-9_\-\.]{20,})',
                r'ghp_[a-zA-Z0-9]{36}',  # GitHub Personal Access Token
                r'gho_[a-zA-Z0-9]{36}',  # GitHub OAuth Token
            ],
            'secrets': [
                r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?client[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?app[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            ],
            'passwords': [
                r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                r'["\']?passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                r'["\']?pwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            ],
            'credentials': [
                r'["\']?database[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'["\']?db[_-]?connection["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'mongodb(\+srv)?://[^\s]+',
                r'mysql://[^\s]+',
                r'postgres://[^\s]+',
            ]
        }

        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    # Handle both string matches and tuple matches from groups
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0] if match[0] else match[1] if len(match) > 1 else ''
                        if match and len(match) > 5:  # Avoid very short matches
                            keys[category].add(match)

        return keys

    def analyze_subdomain(self, subdomain: str) -> Dict:
        """Analyze a subdomain and extract all information"""
        result = {
            'subdomain': subdomain,
            'profile_ids': set(),
            'urls': set(),
            'files': {
                'documents': set(),
                'images': set(),
                'archives': set(),
                'data': set(),
                'media': set(),
                'other': set()
            },
            'api_keys': {
                'api_keys': set(),
                'tokens': set(),
                'secrets': set(),
                'passwords': set(),
                'credentials': set()
            },
            'emails': set(),
            'accessible': False
        }

        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}"
            html = self.fetch_html(url)

            if html:
                result['accessible'] = True
                result['profile_ids'].update(self.extract_profile_ids(html))
                result['urls'].update(self.extract_urls(html, url))

                # Extract categorized files
                files = self.extract_files(html, url)
                for category, file_set in files.items():
                    result['files'][category].update(file_set)

                # Extract API keys and secrets
                api_keys = self.extract_api_keys(html)
                for category, key_set in api_keys.items():
                    result['api_keys'][category].update(key_set)

                result['emails'].update(self.extract_emails(html))
                break

        # Convert sets to lists for JSON serialization
        result['profile_ids'] = list(result['profile_ids'])
        result['urls'] = list(result['urls'])
        result['emails'] = list(result['emails'])

        # Convert file sets to lists
        for category in result['files']:
            result['files'][category] = list(result['files'][category])

        # Convert API key sets to lists
        for category in result['api_keys']:
            result['api_keys'][category] = list(result['api_keys'][category])

        return result

    def analyze_all_subdomains(self):
        """Analyze all found subdomains (silently)"""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.analyze_subdomain, sub): sub
                      for sub in self.found_subdomains}

            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result['accessible']:
                        self.results[subdomain] = result
                except Exception as e:
                    pass  # Silently continue

    def save_results(self, output_file: str):
        """Save results to JSON file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n{Fore.GREEN}[✓] Results saved to {Fore.WHITE}{Style.BRIGHT}{output_file}{Style.RESET_ALL}")

    def print_summary(self):
        """Print organized report: Host Intelligence -> Enumeration -> Extracted Content"""

        # ============================================================
        # SECTION 1: HOST INFORMATION & INTELLIGENCE (FIRST!)
        # ============================================================
        print(f"\n\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{Style.BRIGHT}")
        print("    )                  (                       ")
        print(" ( /(              )   )\ )            )       ")
        print(" )\())          ( /(  (()/(      )  ( /(    )  ")
        print("((_)\   (   (   )\())  /(_))  ( /(  )\())( /(  ")
        print(" _((_)  )\  )\ (_))/  (_))_   )(_))(_))/ )(_)) ")
        print("| || | ((_)((_)| |_    |   \ ((_)_ | |_ ((_)_  ")
        print("| __ |/ _ \(_-<|  _|   | |) |/ _` ||  _|/ _` | ")
        print("|_||_|\___//__/ \__|   |___/ \__,_| \__|\__,_| ")
        print(f"{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")

        print_snake(0)

        print(f"\n{Fore.WHITE}{Style.BRIGHT}PRIMARY DOMAIN ANALYSIS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Target Domain: {Fore.WHITE}{Style.BRIGHT}{self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Subdomains Discovered: {Fore.WHITE}{len(self.found_subdomains)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Accessible Hosts: {Fore.WHITE}{len(self.results)}{Style.RESET_ALL}")

        # Quick stats
        total_profile_ids = sum(len(r['profile_ids']) for r in self.results.values())
        total_emails = sum(len(r['emails']) for r in self.results.values())
        file_counts = {'documents': 0, 'images': 0, 'archives': 0, 'data': 0, 'media': 0, 'other': 0}
        for result in self.results.values():
            for category in file_counts:
                file_counts[category] += len(result['files'][category])
        total_files = sum(file_counts.values())
        key_counts = {'api_keys': 0, 'tokens': 0, 'secrets': 0, 'passwords': 0, 'credentials': 0}
        for result in self.results.values():
            for category in key_counts:
                key_counts[category] += len(result['api_keys'][category])
        total_keys = sum(key_counts.values())

        print(f"{Fore.BLUE}Total Profile IDs: {Fore.WHITE}{total_profile_ids}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Total Files: {Fore.WHITE}{total_files}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total Emails: {Fore.WHITE}{total_emails}{Style.RESET_ALL}")
        if total_keys > 0:
            print(f"{Fore.RED}{Style.BRIGHT}Sensitive Data Items: {Fore.YELLOW}{total_keys}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Sensitive Data Items: {Fore.WHITE}{total_keys}{Style.RESET_ALL}")

        # Check if host intelligence is enabled
        if self.host_intel.enabled:
            print(f"\n{Fore.CYAN}[*] Initiating multi-API intelligence gathering...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Querying: IP2Location.io | Host.io | IP-API.com{Style.RESET_ALL}\n")

            # Main domain intelligence
            print(f"{Fore.GREEN}{Style.BRIGHT}🎯 PRIMARY DOMAIN: {Fore.WHITE}{self.domain}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
            intel = self.host_intel.gather_intelligence(self.domain)
            self.host_intel.print_intelligence(self.domain, intel)

            # Subdomain intelligence (top 3)
            analyzed_count = 0
            max_intel_targets = 3

            for subdomain in list(self.found_subdomains)[:max_intel_targets]:
                if analyzed_count >= max_intel_targets:
                    break

                print_snake((analyzed_count + 1) % 4)
                print(f"\n{Fore.GREEN}{Style.BRIGHT}🎯 SUBDOMAIN: {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
                intel = self.host_intel.gather_intelligence(subdomain)
                self.host_intel.print_intelligence(subdomain, intel)
                analyzed_count += 1

                if analyzed_count < max_intel_targets:
                    time.sleep(1)

            if len(self.found_subdomains) > max_intel_targets:
                remaining = len(self.found_subdomains) - max_intel_targets
                print(f"\n{Fore.YELLOW}[*] {remaining} additional subdomains available for analysis{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] Host intelligence features disabled (no API keys configured){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Configure API keys in config.json to enable this feature{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")

        # ============================================================
        # SECTION 2: SUBDOMAIN ENUMERATION WITH ANALYSIS
        # ============================================================
        print(f"\n\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}")
        print("  _________    ___.        .___                    .__        ")
        print(" /   _____/__ _\_ |__    __| _/____   _____ _____  |__| ____  ")
        print(" \_____  \|  |  \ __ \  / __ |/  _ \ /     \\__  \ |  |/    \ ")
        print(" /        \  |  / \_\ \/ /_/ (  <_> )  Y Y  \/ __ \|  |   |  \\")
        print("/_______  /____/|___  /\____ |\____/|__|_|  (____  /__|___|  /")
        print("        \/          \/      \/            \/     \/        \/ ")
        print("   _____                .__               .__                 ")
        print("  /  _  \   ____ _____  |  | ___.__. _____|__| ______         ")
        print(" /  /_\  \ /    \\__  \ |  |<   |  |/  ___/  |/  ___/         ")
        print("/    |    \   |  \/ __ \|  |_\___  |\___ \|  |\___ \          ")
        print("\____|__  /___|  (____  /____/ ____/____  >__/____  >         ")
        print("        \/     \/     \/     \/         \/        \/          ")
        print(f"{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")

        print_snake(1)

        print(f"\n{Fore.WHITE}{Style.BRIGHT}DISCOVERED SUBDOMAINS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}\n")

        # Show each found subdomain with its analysis inline
        for subdomain in sorted(self.found_subdomains):
            # Always show the Found line
            print(f"{Fore.GREEN}[+] Found: {Fore.WHITE}{subdomain}{Style.RESET_ALL}")

            # If this subdomain was analyzed, show the stats underneath
            if subdomain in self.results:
                result = self.results[subdomain]
                has_data = (result['profile_ids'] or any(result['files'].values()) or
                           result['emails'] or any(result['api_keys'].values()))

                if has_data:
                    # Subdomain has data - show analysis
                    print(f"{Fore.GREEN}    [+] Analyzed: {Fore.WHITE}{subdomain}{Style.RESET_ALL}")

                    # Show quick stats
                    if result['profile_ids']:
                        print(f"{Fore.BLUE}        📋 Profile IDs: {Fore.WHITE}{len(result['profile_ids'])}{Style.RESET_ALL}")

                    file_count = sum(len(result['files'][cat]) for cat in result['files'])
                    if file_count > 0:
                        print(f"{Fore.MAGENTA}        📁 Files Found: {Fore.WHITE}{file_count}{Style.RESET_ALL}")
                        for cat, files in result['files'].items():
                            if files:
                                cat_name = cat.title()
                                print(f"{Fore.CYAN}            - {cat_name}: {Fore.WHITE}{len(files)}{Style.RESET_ALL}")

                    if any(result['api_keys'].values()):
                        sensitive_count = sum(len(result['api_keys'][cat]) for cat in result['api_keys'])
                        print(f"{Fore.RED}        🔑 Sensitive Data: {Fore.YELLOW}{sensitive_count} items{Style.RESET_ALL}")

                    if result['emails']:
                        print(f"{Fore.CYAN}        📧 Emails: {Fore.WHITE}{len(result['emails'])}{Style.RESET_ALL}")
                else:
                    # Subdomain was analyzed but has no data
                    print(f"{Fore.YELLOW}    [-] No data found{Style.RESET_ALL}")
            else:
                # Subdomain was not analyzed (not accessible or failed)
                print(f"{Fore.YELLOW}    [-] No data found{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")

        # ============================================================
        # SECTION 3: EXTRACTED CONTENT & LINKS
        # ============================================================
        print(f"\n\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{Style.BRIGHT}")
        print("    ______     __                  __           __")
        print("   / ____/  __/ /__________ ______/ /____  ____/ /")
        print("  / __/ | |/_/ __/ ___/ __ `/ ___/ __/ _ \/ __  / ")
        print(" / /____>  </ /_/ /  / /_/ / /__/ /_/  __/ /_/ /  ")
        print("/_____/_/|_|\__/_/   \__,_/\___/\__/\___/\__,_/   ")
        print("  / ____/___  ____  / /____  ____  / /_           ")
        print(" / /   / __ \/ __ \/ __/ _ \/ __ \/ __/           ")
        print("/ /___/ /_/ / / / / /_/  __/ / / / /_             ")
        print("\____/\____/_/ /_/\__/\___/_/ /_/\__/             ")
        print(f"{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")

        print_snake(2)

        # Print detailed findings for each subdomain
        self.print_detailed_findings()

    def print_detailed_findings(self):
        """Print organized extracted content by subdomain"""

        snake_index = 0
        for idx, (subdomain, result) in enumerate(self.results.items()):
            has_findings = (
                result['profile_ids'] or
                any(result['files'].values()) or
                any(result['api_keys'].values()) or
                result['emails']
            )

            if not has_findings:
                continue

            # Print snake between subdomains
            if idx > 0:
                print()
                print_snake(snake_index % 4)
            snake_index += 1

            # Subdomain header with color coding
            print(f"\n{Fore.BLUE}{'▓' * 70}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}{Style.BRIGHT}SUBDOMAIN ENUMERATION - {Fore.WHITE}{subdomain}{Style.RESET_ALL}")
            print(f"{Fore.BLUE}{'▓' * 70}{Style.RESET_ALL}")

            # Profile IDs
            if result['profile_ids']:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}  📋 PROFILE IDs ({len(result['profile_ids'])}){Style.RESET_ALL}")
                print(f"{Fore.CYAN}  {'─' * 66}{Style.RESET_ALL}")
                for pid in result['profile_ids'][:20]:
                    print(f"  {Fore.WHITE}• {pid}{Style.RESET_ALL}")
                if len(result['profile_ids']) > 20:
                    print(f"  {Fore.YELLOW}... and {len(result['profile_ids']) - 20} more{Style.RESET_ALL}")

            # Files by category
            has_files = any(result['files'].values())
            if has_files:
                print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  📁 DISCOVERED FILES{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}  {'─' * 66}{Style.RESET_ALL}")

            if result['files']['documents']:
                print(f"\n{Fore.YELLOW}    📄 Documents ({len(result['files']['documents'])}){Style.RESET_ALL}")
                for doc in result['files']['documents'][:10]:
                    print(f"      {Fore.WHITE}• {doc}{Style.RESET_ALL}")
                if len(result['files']['documents']) > 10:
                    print(f"      {Fore.YELLOW}... and {len(result['files']['documents']) - 10} more{Style.RESET_ALL}")

            if result['files']['images']:
                print(f"\n{Fore.CYAN}    🖼️  Images ({len(result['files']['images'])}){Style.RESET_ALL}")
                for img in result['files']['images'][:10]:
                    print(f"      {Fore.WHITE}• {img}{Style.RESET_ALL}")
                if len(result['files']['images']) > 10:
                    print(f"      {Fore.YELLOW}... and {len(result['files']['images']) - 10} more{Style.RESET_ALL}")

            if result['files']['archives']:
                print(f"\n{Fore.MAGENTA}    📦 Archives ({len(result['files']['archives'])}){Style.RESET_ALL}")
                for archive in result['files']['archives']:
                    print(f"      {Fore.WHITE}• {archive}{Style.RESET_ALL}")

            if result['files']['data']:
                print(f"\n{Fore.BLUE}    📊 Data Files ({len(result['files']['data'])}){Style.RESET_ALL}")
                for data in result['files']['data'][:8]:
                    print(f"      {Fore.WHITE}• {data}{Style.RESET_ALL}")
                if len(result['files']['data']) > 8:
                    print(f"      {Fore.YELLOW}... and {len(result['files']['data']) - 8} more{Style.RESET_ALL}")

            if result['files']['media']:
                print(f"\n{Fore.GREEN}    🎬 Media Files ({len(result['files']['media'])}){Style.RESET_ALL}")
                for media in result['files']['media'][:5]:
                    print(f"      {Fore.WHITE}• {media}{Style.RESET_ALL}")
                if len(result['files']['media']) > 5:
                    print(f"      {Fore.YELLOW}... and {len(result['files']['media']) - 5} more{Style.RESET_ALL}")

            if result['files']['other']:
                print(f"\n{Fore.WHITE}    📎 Other Files ({len(result['files']['other'])}){Style.RESET_ALL}")
                for other in result['files']['other'][:5]:
                    print(f"      {Fore.WHITE}• {other}{Style.RESET_ALL}")
                if len(result['files']['other']) > 5:
                    print(f"      {Fore.YELLOW}... and {len(result['files']['other']) - 5} more{Style.RESET_ALL}")

            # API Keys and Secrets
            if any(result['api_keys'].values()):
                print(f"\n{Fore.RED}{Style.BRIGHT}  🔑 SENSITIVE DATA DETECTED{Style.RESET_ALL}")
                print(f"{Fore.RED}  {'─' * 66}{Style.RESET_ALL}")

                if result['api_keys']['api_keys']:
                    print(f"\n{Fore.YELLOW}    🔐 API Keys ({len(result['api_keys']['api_keys'])}){Style.RESET_ALL}")
                    for key in result['api_keys']['api_keys']:
                        masked = key[:8] + '*' * (len(key) - 12) + key[-4:] if len(key) > 12 else key[:4] + '*' * (len(key) - 4)
                        print(f"      {Fore.RED}• {masked}{Style.RESET_ALL}")

                if result['api_keys']['tokens']:
                    print(f"\n{Fore.YELLOW}    🎫 Tokens ({len(result['api_keys']['tokens'])}){Style.RESET_ALL}")
                    for token in result['api_keys']['tokens']:
                        masked = token[:8] + '*' * (len(token) - 12) + token[-4:] if len(token) > 12 else token[:4] + '*' * (len(token) - 4)
                        print(f"      {Fore.RED}• {masked}{Style.RESET_ALL}")

                if result['api_keys']['secrets']:
                    print(f"\n{Fore.YELLOW}    🔒 Secrets ({len(result['api_keys']['secrets'])}){Style.RESET_ALL}")
                    for secret in result['api_keys']['secrets']:
                        masked = secret[:8] + '*' * (len(secret) - 12) + secret[-4:] if len(secret) > 12 else secret[:4] + '*' * (len(secret) - 4)
                        print(f"      {Fore.RED}• {masked}{Style.RESET_ALL}")

                if result['api_keys']['passwords']:
                    print(f"\n{Fore.YELLOW}    🔑 Passwords ({len(result['api_keys']['passwords'])}){Style.RESET_ALL}")
                    for pwd in result['api_keys']['passwords']:
                        print(f"      {Fore.RED}• {'*' * len(pwd)} (length: {len(pwd)}){Style.RESET_ALL}")

                if result['api_keys']['credentials']:
                    print(f"\n{Fore.YELLOW}    💳 Credentials ({len(result['api_keys']['credentials'])}){Style.RESET_ALL}")
                    for cred in result['api_keys']['credentials']:
                        masked = re.sub(r':[^:@]+@', ':***@', cred)
                        print(f"      {Fore.RED}• {masked}{Style.RESET_ALL}")

            # Emails
            if result['emails']:
                print(f"\n{Fore.CYAN}{Style.BRIGHT}  📧 EMAIL ADDRESSES ({len(result['emails'])}){Style.RESET_ALL}")
                print(f"{Fore.CYAN}  {'─' * 66}{Style.RESET_ALL}")
                for email in sorted(result['emails'])[:15]:
                    print(f"  {Fore.WHITE}• {email}{Style.RESET_ALL}")
                if len(result['emails']) > 15:
                    print(f"  {Fore.YELLOW}... and {len(result['emails']) - 15} more{Style.RESET_ALL}")

        # Close the extracted content section
        print(f"\n{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='Cabal Domain Viper - OSINT Subdomain Enumeration and HTML Extraction Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python CabalDomainViper.py -d example.com
  python CabalDomainViper.py -d example.com -w subdomains.txt -t 20
  python CabalDomainViper.py -d example.com -o results.json
        """
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Subdomain wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', default='viper_results.json', help='Output JSON file')
    parser.add_argument('--timeout', type=int, default=5, help='HTTP timeout in seconds (default: 5)')
    parser.add_argument('--config', default='config.json', help='Config file with API keys (default: config.json)')

    args = parser.parse_args()

    # Display animated ASCII art banner
    print(DOMAIN_VIPER_ART)
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}     OSINT Tool v2.0 - Subdomain Enumeration & Content Extraction{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")

    # Brief animation
    messages = [
        f"{Fore.GREEN}[*] Initializing Viper...",
        f"{Fore.GREEN}[*] Loading modules...",
        f"{Fore.GREEN}[*] Ready to strike!{Style.RESET_ALL}"
    ]

    for msg in messages:
        print(msg)
        time.sleep(0.3)

    print()

    # Load API keys
    api_keys = load_api_keys(args.config)

    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()

    viper = CabalDomainViper(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        api_keys=api_keys
    )

    # Enumerate subdomains
    viper.enumerate_subdomains()

    if viper.found_subdomains:
        # Analyze subdomains
        viper.analyze_all_subdomains()

        # Save results
        viper.save_results(args.output)

        # Print comprehensive report (includes host intelligence and extracted content)
        viper.print_summary()

        # Final completion message
        print_snake(0)
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[✓] Complete OSINT scan finished! Happy hunting! 🐍{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.RED}[!] No subdomains found. Exiting.{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == '__main__':
    main()
