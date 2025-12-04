Cabal Domain Viper 🐍

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
