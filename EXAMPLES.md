# IXXXI Usage Examples

## Example 1: Basic Reconnaissance

```bash
./ixxxi.sh -d example.com
```

This command executes:
- hadixxity with default configuration
- SUPERECON with default configuration
- Generates a unified summary

## Example 2: Complete Reconnaissance with Shodan

```bash
./ixxxi.sh -d target.com -n "Target Corp" \
  -S \
  --full-subs \
  --with-wafw00f --with-cors --with-dalfox
```

This command:
- Runs hadixxity with Shodan enabled (`-S`)
- Runs all subdomain sources (`--full-subs`)
- Detects WAFs (`--with-wafw00f`)
- Verifies CORS issues (`--with-cors`)
- Analyzes XSS vulnerabilities (`--with-dalfox`)

## Example 3: Passive Reconnaissance Only

```bash
./ixxxi.sh -d target.com --passive --full-subs
```

This command:
- Runs hadixxity (passive reconnaissance)
- Runs SUPERECON only in passive mode (doesn't touch the target)
- Useful for OSINT without direct interaction with the target

## Example 4: Complete Bug Bounty

```bash
./ixxxi.sh -d target.com \
  -S -C \
  --full-subs \
  --with-wafw00f --with-cors --with-dalfox \
  --with-arjun --with-fallparams \
  --with-file-hunt --with-cariddi \
  --with-logsensor --with-logsensor-sqli \
  --with-cvemap --with-js-inventory
```

This command executes a complete reconnaissance for bug bounty:
- Shodan and AWS cloud helpers
- All subdomain sources
- WAF, CORS, XSS detection
- Parameter discovery (arjun, fallparams)
- Sensitive file search
- Secrets and endpoints scanning (cariddi)
- Login panel and SQLi detection
- CVE and technology hints
- JS/SourceMaps inventory

## Example 5: With Delays and Random User-Agent

```bash
./ixxxi.sh -d target.com \
  --random-ua \
  --delay 1:5 \
  --with-wafw00f --with-403jump
```

This command:
- Uses random User-Agent to avoid detection
- Applies random delays between 1 and 5 seconds
- Detects WAFs
- Attempts 403 bypass

## Example 6: With Seed IP and ASNs

```bash
./ixxxi.sh -d target.com \
  -i 192.168.1.100 \
  -a "AS15169,AS16509" \
  -S
```

This command:
- Uses a seed IP for discovery
- Specifies manual ASNs
- Enables Shodan for additional searches

## Example 7: With Custom Apex File

```bash
./ixxxi.sh -d target.com \
  -A /path/to/apex-domains.txt \
  --httpx-final
```

This command:
- Uses a custom file with apex domains
- Runs final httpx over all consolidated subdomains

## Example 8: Verbose Mode for Debugging

```bash
./ixxxi.sh -d target.com -v \
  --with-wafw00f --with-cors
```

This command:
- Shows all executed commands (verbose mode)
- Useful for debugging and understanding what the script is doing

## Example 9: With BBOT (Advanced Reconnaissance)

```bash
./ixxxi.sh -d target.com \
  --bbot-web-thorough \
  --with-cariddi
```

This command:
- Runs BBOT with web-thorough presets (aggressive reconnaissance)
- Scans secrets and endpoints with cariddi

## Example 10: Web Vulnerability Analysis Only

```bash
./ixxxi.sh -d target.com \
  --no-dnsx \
  --with-wafw00f --with-cors --with-dalfox \
  --with-403jump --with-file-hunt
```

This command:
- Skips DNS resolution (`--no-dnsx`)
- Focuses on web analysis:
  - WAF detection
  - CORS verification
  - XSS analysis
  - 403 bypass
  - Sensitive file search

## Notes

- All examples assume you're in the directory where `ixxxi.sh` is located
- Make sure you have configured `.hadixxity.env` with your API keys if using `-S` or other options that require them
- Results are saved in `recon-<domain>/` by default
- Use `-o` to specify a custom output directory

