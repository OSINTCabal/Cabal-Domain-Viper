# Cabal Domain Viper 🐍

**Advanced OSINT Subdomain Enumeration and Content Extraction Tool**

A powerful reconnaissance tool designed for licensed Private Investigators and security professionals. Combines subdomain enumeration with deep content extraction and threat intelligence gathering from multiple APIs.

## 🎯 Features

### Core Capabilities
- **Subdomain Enumeration**: Fast DNS-based subdomain discovery using built-in or custom wordlists
- **Content Extraction**: Deep HTML parsing to extract:
  - Profile IDs and user identifiers
  - Email addresses
  - Documents (PDF, Office files)
  - Images and media files
  - Archives and data files
  - API endpoints and URLs
- **Sensitive Data Detection**: Identifies exposed:
  - API keys (AWS, Google, GitHub, etc.)
  - Access tokens and Bearer tokens
  - Secrets and credentials
  - Database connection strings
  - Passwords in source code
- **Host Intelligence** (Optional): Integrates with IP2Location.io, Host.io, and IP-API.com for:
  - Geolocation data
  - Network information (ISP, ASN)
  - DNS records
  - Security flags (proxy, hosting, VPN)
  - Web infrastructure details

### Advanced Features
- **Multi-threaded Processing**: Concurrent subdomain checking and analysis
- **Smart Categorization**: Files organized by type (documents, images, archives, etc.)
- **Colorized Output**: Easy-to-read terminal interface with ASCII art
- **JSON Export**: Complete results saved for further analysis
- **Graceful Degradation**: Works with or without API keys configured

## 📋 Prerequisites

- Python 3.7 or higher
- Required Python packages:
  ```
  requests
  dnspython
  beautifulsoup4
  colorama
  ```

## 🔧 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/CabalDomainViper.git
cd CabalDomainViper
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure API keys (Optional but Recommended):**
```bash
cp config.json.example config.json
# Edit config.json with your API keys
```

## 🔑 API Configuration (Optional)

Host intelligence features require API keys. The tool works without them but provides limited intelligence.

### Required APIs for Full Functionality

#### 1. IP2Location.io
- **Purpose**: IP geolocation and threat intelligence
- **Sign up**: [https://www.ip2location.io/](https://www.ip2location.io/)
- **Free tier**: 30,000 queries/month
- **Setup**:
  1. Create account and get API key
  2. Add to `config.json` under `"ip2location"`

#### 2. Host.io
- **Purpose**: Domain intelligence, DNS records, web infrastructure
- **Sign up**: [https://host.io/](https://host.io/)
- **Free tier**: 1,000 queries/month
- **Setup**:
  1. Create account and get API token
  2. Add to `config.json` under `"hostio"`

#### 3. IP-API.com
- **Purpose**: Additional IP geolocation
- **No API key required** (45 requests/minute free)

### Configuration File

Create `config.json`:

```json
{
  "ip2location": "YOUR_IP2LOCATION_API_KEY",
  "hostio": "YOUR_HOSTIO_API_KEY"
}
```

**Note**: The tool will run without `config.json` but host intelligence features will be disabled.

## 🚀 Usage

### Basic Usage

**Enumerate subdomains with default wordlist:**
```bash
python3 CabalDomainViper.py -d example.com
```

**Use custom subdomain wordlist:**
```bash
python3 CabalDomainViper.py -d example.com -w /path/to/subdomains.txt
```

**Increase threading for faster scans:**
```bash
python3 CabalDomainViper.py -d example.com -t 20
```

**Custom output file:**
```bash
python3 CabalDomainViper.py -d example.com -o my_results.json
```

**Specify custom config file:**
```bash
python3 CabalDomainViper.py -d example.com --config /path/to/config.json
```

### Advanced Usage

**Full scan with all options:**
```bash
python3 CabalDomainViper.py \
  -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -t 50 \
  -o full_scan_results.json \
  --timeout 10 \
  --config my_config.json
```

### Command Line Arguments

```
Required:
  -d, --domain          Target domain (e.g., example.com)

Optional:
  -w, --wordlist        Path to subdomain wordlist file
  -t, --threads         Number of threads (default: 10)
  -o, --output          Output JSON file (default: viper_results.json)
  --timeout             HTTP timeout in seconds (default: 5)
  --config              Config file path (default: config.json)
```

## 📊 Output Format

### Terminal Output

The tool provides a comprehensive, color-coded report in three sections:

1. **Host Intelligence**: Geolocation, network info, DNS records, security flags
2. **Subdomain Enumeration**: All discovered subdomains with quick stats
3. **Extracted Content**: Detailed findings for each subdomain including:
   - Profile IDs
   - Categorized files
   - Sensitive data (masked)
   - Email addresses

### JSON Export

Results are saved in structured JSON format:

```json
{
  "subdomain.example.com": {
    "subdomain": "subdomain.example.com",
    "accessible": true,
    "profile_ids": ["user123", "profile456"],
    "emails": ["contact@example.com"],
    "files": {
      "documents": ["https://...file.pdf"],
      "images": ["https://...image.jpg"],
      "archives": ["https://...backup.zip"],
      "data": ["https://...data.json"],
      "media": ["https://...video.mp4"],
      "other": []
    },
    "api_keys": {
      "api_keys": ["AKIA..."],
      "tokens": ["ghp_..."],
      "secrets": [],
      "passwords": [],
      "credentials": []
    },
    "urls": ["https://..."]
  }
}
```

## 🔍 What Gets Extracted

### File Types Detected
- **Documents**: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, ODT, ODS, ODP
- **Images**: JPG, PNG, GIF, BMP, SVG, WEBP, ICO, TIFF
- **Archives**: ZIP, RAR, TAR, GZ, BZ2, 7Z, TGZ
- **Data**: JSON, XML, CSV, YAML, SQL, DB
- **Media**: MP4, AVI, MOV, MP3, WAV, FLAC, OGG

### Sensitive Data Patterns
- **API Keys**: AWS, Google, GitHub tokens
- **Access Tokens**: OAuth, Bearer tokens
- **Secrets**: Client secrets, app secrets
- **Passwords**: Hardcoded passwords in source
- **Credentials**: Database connection strings

### Profile Identifiers
- User IDs
- Profile IDs
- Account identifiers
- Custom ID patterns

## 🛡️ Legal & Ethical Use

**⚠️ CRITICAL LEGAL NOTICE**

This tool is designed **EXCLUSIVELY** for:
- ✅ Licensed Private Investigators with proper authorization
- ✅ Security researchers with written permission
- ✅ Penetration testers under valid contracts
- ✅ IT administrators testing their own infrastructure
- ✅ Bug bounty hunters within program scope

**PROHIBITED USES**:
- ❌ Unauthorized access to systems
- ❌ Stalking, harassment, or privacy violations
- ❌ Corporate espionage
- ❌ Any illegal activity
- ❌ Violating terms of service

### Legal Requirements

Users must:
1. Have explicit authorization for all targets
2. Comply with CFAA (Computer Fraud and Abuse Act) and local laws
3. Respect privacy rights and data protection regulations (GDPR, CCPA, etc.)
4. Follow responsible disclosure practices
5. Maintain chain of custody for evidence

**The authors assume NO liability for misuse. Users accept FULL responsibility for their actions.**

## 🛠️ Troubleshooting

### Common Issues

**"No subdomains found"**
- Target may have no subdomains with the wordlist used
- Try a larger wordlist (e.g., SecLists)
- Check if domain is valid and resolvable

**"Config file not found"**
- Create `config.json` from the example file
- Use `--config` to specify alternate location
- Tool will run without it (limited features)

**DNS Resolution Errors**
- Check internet connectivity
- Some networks block DNS lookups
- Try reducing thread count with `-t 5`

**SSL Certificate Warnings**
- Tool disables SSL verification by design
- Necessary for some OSINT investigations
- Warnings are suppressed automatically

**Rate Limiting**
- Reduce thread count: `-t 5`
- Increase timeout: `--timeout 10`
- Check API quota limits

### Performance Tips

1. **Faster Scans**: Increase threads (`-t 20` to `-t 50`)
2. **More Accurate**: Decrease threads and increase timeout
3. **Large Wordlists**: Use more threads but watch for rate limits
4. **API Limits**: Tool includes built-in delays to respect rate limits

## 📁 Project Structure

```
CabalDomainViper/
├── CabalDomainViper.py      # Main tool (subdomain enumeration version)
├── config.json.example       # API key template
├── config.json              # Your API keys (gitignored)
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── LICENSE                  # MIT License
├── .gitignore              # Git ignore rules
└── wordlists/              # Optional wordlist directory
    └── subdomains.txt
```

## 📦 Dependencies

The tool requires the following Python packages:

```
requests>=2.28.0
dnspython>=2.3.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
```

Install with: `pip install -r requirements.txt`

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional API integrations
- More extraction patterns
- Output format options (CSV, XML, HTML reports)
- Enhanced stealth features
- Better error handling
- Unit tests

## 🔄 Version History

### v2.0 (Current - Advanced OSINT)
- Subdomain enumeration with DNS resolution
- Deep HTML content extraction
- Sensitive data detection
- File categorization by type
- Profile ID extraction
- Email harvesting
- Multi-threaded processing
- Colorized terminal output
- JSON export functionality
- Optional host intelligence integration

### v1.0 (Basic)
- Simple IP/domain intelligence gathering
- Multi-API integration
- Basic reporting

## 🙏 Acknowledgments

- **IP2Location.io** - IP geolocation services
- **Host.io** - Domain intelligence platform  
- **IP-API.com** - Free IP geolocation API
- **SecLists** - Comprehensive wordlists for enumeration

## 📧 Support

- Open issues on GitHub for bugs or feature requests
- Check existing issues before creating new ones
- Provide detailed environment information

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

This tool is provided "as is" without warranty. Users are solely responsible for ensuring compliance with all applicable laws and regulations.

---

**Made for the OSINT community by licensed investigators.**

**Remember**: Always get proper authorization before conducting any investigation. With great power comes great responsibility. 🐍
