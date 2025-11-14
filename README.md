# IXXXI – hadixxity + SUPERECON Integration

```
    ································

    : _  _    _  _    _  _    _  _ :

    :(_)( )  ( )( )  ( )( )  ( )(_):

    :| |`\`\/'/'`\`\/'/'`\`\/'/'| |:

    :| |  >  <    >  <    >  <  | |:

    :| | /'/\`\  /'/\`\  /'/\`\ | |:

    :(_)(_)  (_)(_)  (_)(_)  (_)(_):

    ································
```

**IXXXI** is a tool that effectively, logically, coherently, and orderly integrates two powerful reconnaissance tools:

- **hadixxity**: Passive/OSINT reconnaissance (WHOIS, DNS, CT logs, ASN/BGP, Shodan)
- **SUPERECON**: Active web reconnaissance (web scanning, vulnerability analysis, bug bounty)

## 🎯 Workflow

IXXXI executes a 4-phase workflow:

1. **PHASE 1 - hadixxity**: Executes passive/OSINT reconnaissance
   - Corporate intelligence
   - WHOIS/RIR
   - DNS and email posture (DMARC/DKIM/SPF/BIMI)
   - Certificate Transparency logs (crt.sh)
   - ASN/BGP mapping
   - Cloud ranges (AWS)
   - Shodan (optional)
   - Subdomain consolidation

2. **PHASE 2 - Preparation**: Extracts hadixxity data and prepares it for SUPERECON
   - Discovered subdomains → SUPERECON sources
   - Resolved IPs
   - ASNs and prefixes

3. **PHASE 3 - SUPERECON**: Executes active web reconnaissance using hadixxity data
   - Additional subdomain discovery (optional)
   - DNS resolution (dnsx)
   - Web scanning (httpx, katana, urlfinder)
   - Vulnerability analysis (XSS, CORS, WAF, etc.)
   - Bug bounty tools (dalfox, arjun, logsensor, etc.)

4. **PHASE 4 - Consolidation**: Generates a unified summary of all results

## 📋 Requirements

- **Bash 5+**
- **All scripts included**: `ixxxi.sh`, `hadixxity.sh`, and `superecon.sh` are included in the same directory
- **Basic tools**: `curl`, `git`, `dig`, `whois` (usually pre-installed on Kali Linux)
- **Optional tools**: Various reconnaissance tools (subfinder, httpx, dnsx, etc.) - see tool-specific documentation
- **API keys** (optional but recommended): Shodan, ProjectDiscovery, VirusTotal, etc. (see `config.env.example`)

## 🚀 Installation

IXXXI is now a **fully integrated application** with all components included in a single directory.

### Quick Start

1. **Run the unified installation script:**
   ```bash
   cd ixxxi
   chmod +x install.sh
   ./install.sh
   ```

2. **Configure API keys:**
   ```bash
   # Edit the configuration file
   nano .ixxxi.env
   # or
   vim .ixxxi.env
   ```
   
   Add your API keys (see `config.env.example` for all available options):
   - **Shodan**: https://account.shodan.io/
   - **ProjectDiscovery**: https://cloud.projectdiscovery.io/
   - **VirusTotal**: https://www.virustotal.com/gui/join-us
   - **URLScan.io**: https://urlscan.io/user/signup
   - And more (see config file)

3. **Start using IXXXI:**
   ```bash
   ./ixxxi.sh -d target.com
   ```

### Manual Installation (if needed)

If you prefer to install components separately:

1. **Ensure all scripts are in the same directory:**
   ```bash
   ls ixxxi/
   # Should show: ixxxi.sh, hadixxity.sh, superecon.sh, install.sh
   ```

2. **Make scripts executable:**
   ```bash
   chmod +x ixxxi.sh hadixxity.sh superecon.sh install.sh
   ```

3. **Create configuration file:**
   ```bash
   cp config.env.example .ixxxi.env
   # Edit .ixxxi.env with your API keys
   ```

### Custom Script Locations

If `hadixxity.sh` or `superecon.sh` are in different locations, you can specify them:

```bash
export HADIXXITY_SCRIPT="/path/to/hadixxity.sh"
export SUPERECON_SCRIPT="/path/to/superecon.sh"
./ixxxi.sh -d target.com
```

The script will automatically search in common locations if not found in the same directory.

## 💻 Basic Usage

```bash
# Basic reconnaissance
./ixxxi.sh -d target.com

# With company name and advanced options
./ixxxi.sh -d target.com -n "Target Corp" -S -C --with-wafw00f --with-cors

# Passive reconnaissance only (don't touch the target)
./ixxxi.sh -d target.com --passive --full-subs

# With delays and random User-Agent
./ixxxi.sh -d target.com --random-ua --delay 1:5 --with-dalfox --with-file-hunt
```

## 📖 Main Options

### General Options

- `-d, --domain DOMAIN`: Target domain (required)
- `-n, --name NAME`: Company/program name
- `-i, --ip IP`: Optional seed IP
- `-a, --asn ASNS`: Seed ASNs (comma-separated)
- `-o, --outdir DIR`: Output directory (default: `recon-DOMAIN`)
- `-f, --config FILE`: Configuration file (default: `.hadixxity.env`)
- `-v, --verbose`: Verbose mode
- `-h, --help`: Show help

### hadixxity Options (Passive Reconnaissance)

- `-S, --shodan`: Enable Shodan module
- `-C, --cloud`: Enable AWS cloud helper
- `-X, --spiderfoot`: Generate SpiderFoot HX plan
- `-A, --apex-file FILE`: File with apex domains
- `-U, --user-agent UA`: Custom User-Agent
- `--random-ua`: Pick random User-Agent
- `--delay SEC`: Fixed delay between requests
- `--random-delay MIN:MAX`: Random delay between MIN and MAX seconds
- `--httpx-final`: Run httpx over consolidated subdomains

### SUPERECON Options (Active Reconnaissance)

- `--passive`: OSINT only (don't touch the target)
- `--full-subs`: Run all subdomain sources
- `--crt`: Enable crt.sh
- `--ctfr`: Enable ctfr
- `--with-gau`: Enable GAU (historical)
- `--with-subscraper`: Enable subscraper
- `--no-dnsx`: Disable dnsx
- `--no-httpx`: Disable httpx
- `--no-katana`: Disable katana
- `--no-urlfinder`: Disable urlfinder
- `--no-xss`: Disable XSS analysis
- `--with-arjun`: Parameter discovery
- `--with-dalfox`: Active XSS analysis
- `--with-cors`: CORS verification
- `--with-cf-hero`: Cloudflare origin discovery
- `--with-favicons`: Favicon fingerprinting
- `--with-wafw00f`: WAF detection
- `--with-403jump`: 403 bypass attempts
- `--with-fallparams`: Parameter harvesting
- `--with-cvemap`: CVE/technology hints
- `--with-js-inventory`: JS/SourceMaps inventory
- `--with-file-hunt`: Sensitive file search
- `--with-cariddi`: cariddi scan (secrets, endpoints)
- `--with-logsensor`: Login panel detection
- `--with-logsensor-sqli`: SQLi scan on login panels
- `--bbot-spider`: bbot with spider + email-enum presets
- `--bbot-web-basic`: bbot with web-basic presets
- `--bbot-web-thorough`: bbot with web-thorough presets
- `--wmap`: Metasploit wmap integration (stub)
- `--api`: Create/load API keys file

## 📁 Output Structure

```
recon-<domain>/
├── reports/              # Consolidated lists (hadixxity)
│   ├── subdomains.txt
│   ├── ips.txt
│   ├── asns.txt
│   └── ...
├── whois/                # WHOIS data (hadixxity)
├── dns/                  # DNS records (hadixxity)
├── ct/                   # Certificate Transparency (hadixxity)
├── asn/                  # ASN/BGP data (hadixxity)
├── shodan/               # Shodan results (hadixxity, if -S)
├── subdomains/           # Alive subdomains (SUPERECON)
├── scans/                # httpx scans (SUPERECON)
├── urls/                 # Discovered URLs (SUPERECON)
├── findings/             # Findings (SUPERECON)
│   ├── waf-detected-*.tsv
│   ├── xss-candidates-*.txt
│   ├── cors-*.txt
│   └── ...
├── sources/               # Subdomain sources (SUPERECON)
│   └── hadixxity-*.txt   # Subdomains from hadixxity
└── ixxxi-summary.txt     # Unified summary
```

## 🔑 API Keys Configuration

IXXXI uses the same configuration file as hadixxity (`.hadixxity.env`). Copy the example and configure your API keys:

```bash
cp config.env.example .hadixxity.env
# Edit .hadixxity.env with your API keys
```

Supported API keys:
- `SHODAN_API_KEY`: For Shodan module (`-S`)
- `PROJECTDISCOVERY_API_KEY`: For enhanced subfinder/httpx
- `SPIDERFOOT_URL` / `SPIDERFOOT_API_KEY`: For SpiderFoot HX (`-X`)
- And more (see `config.env.example`)

## 📊 Usage Examples

### Example 1: Complete Reconnaissance

```bash
./ixxxi.sh -d target.com -n "Target Corp" \
  -S -C \
  --full-subs \
  --with-wafw00f --with-cors --with-dalfox \
  --with-file-hunt --with-cariddi
```

### Example 2: Passive Only

```bash
./ixxxi.sh -d target.com --passive --full-subs
```

### Example 3: With Delays and Random UA

```bash
./ixxxi.sh -d target.com \
  --random-ua \
  --delay 1:5 \
  --with-wafw00f --with-403jump
```

### Example 4: Complete Bug Bounty

```bash
./ixxxi.sh -d target.com \
  -S \
  --full-subs \
  --with-wafw00f --with-cors --with-dalfox \
  --with-arjun --with-fallparams \
  --with-file-hunt --with-cariddi \
  --with-logsensor --with-logsensor-sqli \
  --with-cvemap
```

## 🔄 Data Flow

```
hadixxity (PHASE 1)
    ↓
[Subdomains, IPs, ASNs]
    ↓
Preparation (PHASE 2)
    ↓
[Subdomains → sources/ of SUPERECON]
    ↓
SUPERECON (PHASE 3)
    ↓
[Web scans, vulnerability analysis]
    ↓
Consolidation (PHASE 4)
    ↓
[Unified summary]
```

## ⚠️ Important Notes

1. **Authorization**: Run this script only against targets where you have explicit authorization.

2. **Script Paths**: By default, IXXXI looks for `hadixxity.sh` and `superecon.sh` in the same directory (integrated app). If not found, it searches in common locations. You can specify custom paths:
   ```bash
   export HADIXXITY_SCRIPT="/path/to/hadixxity.sh"
   export SUPERECON_SCRIPT="/path/to/superecon.sh"
   ```

3. **Passive Mode**: Use `--passive` if you only want OSINT without directly touching the target.

4. **Delays**: Use `--delay` or `--random-delay` to avoid rate limiting and simulate human activity.

## 🐛 Troubleshooting

### Scripts not found

```bash
# Check paths
echo $HADIXXITY_SCRIPT
echo $SUPERECON_SCRIPT

# Or specify absolute paths
export HADIXXITY_SCRIPT="/full/path/to/hadixxity.sh"
export SUPERECON_SCRIPT="/full/path/to/superecon.sh"
```

### Permissions

```bash
chmod +x ixxxi.sh
chmod +x ../hadixxity.sh
chmod +x ../superecon.sh
```

## 📝 Changelog

- **2025-11-14**: Initial version - hadixxity + SUPERECON integration

## 📜 License

MIT

## 👤 Author

Integration created to combine the best of hadixxity and SUPERECON in a unified workflow.

---

**Happy hunting! 🎯**
