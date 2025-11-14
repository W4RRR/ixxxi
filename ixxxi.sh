#!/usr/bin/env bash
#
# ixxxi.sh – Effective integration of hadixxity + SUPERECON
#
# Workflow:
#   1) hadixxity: Passive/OSINT reconnaissance (WHOIS, DNS, CT, ASN, Shodan)
#   2) SUPERECON: Active web reconnaissance using hadixxity data
#
# Usage:
#   ./ixxxi.sh -d target.com -n "Target Corp" [options]
#
set -Eeuo pipefail

VERSION="2025-11-14"

# ---------- Colors ----------
C_RED="\033[31m"
C_GRN="\033[32m"
C_YEL="\033[33m"
C_BLU="\033[34m"
C_CYN="\033[36m"
C_MAG="\033[35m"
C_RST="\033[0m"

info(){  echo -e "${C_CYN}[INFO]${C_RST} $*"; }
ok(){    echo -e "${C_GRN}[OK]  ${C_RST} $*"; }
warn(){  echo -e "${C_YEL}[WARN]${C_RST} $*"; }
err(){   echo -e "${C_RED}[ERR] ${C_RST} $*"; }
die(){   err "$*"; exit 1; }

trap 'rc=$?; err "Execution stopped at line $LINENO running: $BASH_COMMAND (rc=$rc)"; exit $rc' ERR

# ---------- Banner ----------
show_banner() {
  echo -e "${C_MAG}"
  cat <<'EOF'
    ································

    : _  _    _  _    _  _    _  _ :

    :(_)( )  ( )( )  ( )( )  ( )(_):

    :| |`\`\/'/'`\`\/'/'`\`\/'/'| |:

    :| |  >  <    >  <    >  <  | |:

    :| | /'/\`\  /'/\`\  /'/\`\ | |:

    :(_)(_)  (_)(_)  (_)(_)  (_)(_):

    ································
    
    hadixxity + SUPERECON Integration
EOF
  echo -e "${C_RST}"
}

# ---------- Global variables ----------
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HADIXXITY_SCRIPT="${HADIXXITY_SCRIPT:-${SCRIPT_DIR}/../hadixxity.sh}"
SUPERECON_SCRIPT="${SUPERECON_SCRIPT:-${SCRIPT_DIR}/../superecon.sh}"

TARGET_DOMAIN=""
COMPANY_NAME=""
SEED_IP=""
ASNS=""
OUTDIR=""
CONFIG_FILE=""

# Flags hadixxity
USE_SHODAN=0
USE_CLOUD=0
USE_SPIDERFOOT=0
APEX_LIST_FILE=""
CUSTOM_USER_AGENT=""
USE_RANDOM_UA=0
DELAY_FIXED=""
DELAY_MIN=""
DELAY_MAX=""
RUN_FINAL_HTTPX=0

# Flags SUPERECON
PASSIVE_ONLY=0
FULL_SUBS=0
DO_CRT=0
DO_CTFR=0
DO_GAU=0
DO_SUBSCRAPER=0
DO_DNSX=1
DO_HTTPX=1
DO_KATANA=1
DO_URLFINDER=1
DO_XSS=1
DO_ARJUN=0
DO_DALFOX=0
DO_CORS=0
DO_CF_HERO=0
DO_FAVICONS=0
DO_WAFW00F=0
DO_403JUMP=0
DO_FALLPARAMS=0
DO_CVEMAP=0
DO_JS_INVENTORY=0
DO_FILE_HUNT=0
DO_CARIDDI=0
DO_LOGSENSOR=0
DO_LOGSENSOR_SQLI=0
DO_BBOT_SPIDER=0
DO_BBOT_WEB_BASIC=0
DO_BBOT_WEB_THOROUGH=0
DO_WMAP=0
DO_API=0
VERBOSE=0
GLOBAL_UA=""
RND_MIN=""
RND_MAX=""

# ---------- Usage ----------
usage() {
  cat <<EOF
ixxxi.sh v${VERSION} – hadixxity + SUPERECON Integration

Usage:
  $0 -d DOMAIN [options]

Main options:
  -d, --domain       Target domain (required)
  -n, --name         Company/program name
  -i, --ip           Optional seed IP
  -a, --asn          Seed ASNs (comma-separated)
  -o, --outdir       Output directory (default: recon-DOMAIN)

hadixxity options (passive reconnaissance):
  -S, --shodan       Enable Shodan module
  -C, --cloud        Enable AWS cloud helper
  -X, --spiderfoot   Generate SpiderFoot HX plan
  -A, --apex-file    File with apex domains for subfinder→httpx
  -U, --user-agent   Custom User-Agent
      --random-ua     Pick random User-Agent
      --delay SEC     Fixed delay between requests
      --random-delay MIN:MAX
                     Random delay between MIN and MAX seconds
      --httpx-final   Run httpx over consolidated subdomains

SUPERECON options (active reconnaissance):
  --passive          OSINT only (don't touch the target)
  --full-subs        Run all subdomain sources
  --crt              Enable crt.sh
  --ctfr             Enable ctfr
  --with-gau         Enable GAU (historical)
  --with-subscraper  Enable subscraper
  --no-dnsx          Disable dnsx
  --no-httpx         Disable httpx
  --no-katana        Disable katana
  --no-urlfinder     Disable urlfinder
  --no-xss           Disable XSS analysis
  --with-arjun       Parameter discovery
  --with-dalfox      Active XSS analysis
  --with-cors        CORS verification
  --with-cf-hero     Cloudflare origin discovery
  --with-favicons    Favicon fingerprinting
  --with-wafw00f     WAF detection
  --with-403jump     403 bypass attempts
  --with-fallparams  Parameter harvesting
  --with-cvemap      CVE/technology hints
  --with-js-inventory JS/SourceMaps inventory
  --with-file-hunt   Sensitive file search
  --with-cariddi     cariddi scan (secrets, endpoints)
  --with-logsensor   Login panel detection
  --with-logsensor-sqli SQLi scan on login panels
  --bbot-spider      bbot with spider + email-enum presets
  --bbot-web-basic   bbot with web-basic presets
  --bbot-web-thorough bbot with web-thorough presets
  --wmap             Metasploit wmap integration (stub)
  --api              Create/load API keys file

General options:
  -f, --config       Path to config file (default: .hadixxity.env)
  -v, --verbose      Verbose mode
  -h, --help         Show this help

Examples:
  $0 -d target.com
  $0 -d target.com -n "Target Corp" -S -C --with-wafw00f --with-cors
  $0 -d target.com --passive --full-subs
  $0 -d target.com --random-ua --delay 1:5 --with-dalfox --with-file-hunt

Legal:
  Run this script only against targets where you have explicit authorization.
EOF
}

# ---------- Helpers ----------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Command '$1' not found in \$PATH. Please install it first."
}

ensure_file() {
  local file="$1"
  [[ -f "$file" ]] || : > "$file"
}

# ---------- Check scripts ----------
check_scripts() {
  if [[ ! -f "${HADIXXITY_SCRIPT}" ]]; then
    die "hadixxity.sh script not found at: ${HADIXXITY_SCRIPT}"
  fi
  if [[ ! -x "${HADIXXITY_SCRIPT}" ]]; then
    warn "hadixxity.sh is not executable, attempting chmod +x..."
    chmod +x "${HADIXXITY_SCRIPT}" || die "Could not make hadixxity.sh executable"
  fi

  if [[ ! -f "${SUPERECON_SCRIPT}" ]]; then
    die "superecon.sh script not found at: ${SUPERECON_SCRIPT}"
  fi
  if [[ ! -x "${SUPERECON_SCRIPT}" ]]; then
    warn "superecon.sh is not executable, attempting chmod +x..."
    chmod +x "${SUPERECON_SCRIPT}" || die "Could not make superecon.sh executable"
  fi
}

# ---------- Phase 1: Run hadixxity ----------
run_hadixxity() {
  info "[PHASE 1] Running hadixxity (passive/OSINT reconnaissance)"
  
  local hadixxity_args=()
  [[ -n "${TARGET_DOMAIN}" ]] && hadixxity_args+=(-d "${TARGET_DOMAIN}")
  [[ -n "${COMPANY_NAME}" ]] && hadixxity_args+=(-n "${COMPANY_NAME}")
  [[ -n "${SEED_IP}" ]] && hadixxity_args+=(-i "${SEED_IP}")
  [[ -n "${ASNS}" ]] && hadixxity_args+=(-a "${ASNS}")
  [[ -n "${OUTDIR}" ]] && hadixxity_args+=(-o "${OUTDIR}")
  [[ -n "${CONFIG_FILE}" ]] && hadixxity_args+=(-f "${CONFIG_FILE}")
  [[ "${USE_SHODAN}" -eq 1 ]] && hadixxity_args+=(-S)
  [[ "${USE_CLOUD}" -eq 1 ]] && hadixxity_args+=(-C)
  [[ "${USE_SPIDERFOOT}" -eq 1 ]] && hadixxity_args+=(-X)
  [[ -n "${APEX_LIST_FILE}" ]] && hadixxity_args+=(-A "${APEX_LIST_FILE}")
  [[ -n "${CUSTOM_USER_AGENT}" ]] && hadixxity_args+=(-U "${CUSTOM_USER_AGENT}")
  [[ "${USE_RANDOM_UA}" -eq 1 ]] && hadixxity_args+=(--random-ua)
  [[ -n "${DELAY_FIXED}" ]] && hadixxity_args+=(--delay "${DELAY_FIXED}")
  [[ -n "${DELAY_MIN}" && -n "${DELAY_MAX}" ]] && hadixxity_args+=(--random-delay "${DELAY_MIN}:${DELAY_MAX}")
  [[ "${RUN_FINAL_HTTPX}" -eq 1 ]] && hadixxity_args+=(--httpx-final)

  if [[ "${VERBOSE}" -eq 1 ]]; then
    info "hadixxity command: ${HADIXXITY_SCRIPT} ${hadixxity_args[*]}"
  fi

  if ! "${HADIXXITY_SCRIPT}" "${hadixxity_args[@]}"; then
    warn "hadixxity.sh completed with errors, but continuing..."
  fi

  ok "[PHASE 1] hadixxity completed"
}

# ---------- Phase 2: Extract hadixxity data and prepare for SUPERECON ----------
prepare_superecon_input() {
  info "[PHASE 2] Preparing hadixxity data for SUPERECON"
  
  local hadixxity_reports="${OUTDIR}/reports"
  local superecon_sources="${OUTDIR}/sources"
  local superecon_subdomains="${OUTDIR}/subdomains"

  # Create SUPERECON directories if they don't exist
  mkdir -p "${superecon_sources}" "${superecon_subdomains}"

  # Copy consolidated subdomains from hadixxity to SUPERECON sources
  # SUPERECON's unify_subdomains function looks for specific files in sources/
  # We'll add hadixxity subdomains to a file that SUPERECON recognizes (crt-<domain>-domains.txt)
  local crt_dest="${superecon_sources}/crt-${TARGET_DOMAIN}-domains.txt"
  
  if [[ -f "${hadixxity_reports}/subdomains.txt" ]] && [[ -s "${hadixxity_reports}/subdomains.txt" ]]; then
    info "Copying hadixxity subdomains to SUPERECON sources"
    # SUPERECON looks for crt-<domain>-domains.txt in sources/
    # We'll create/append to this file so SUPERECON includes hadixxity subdomains in unification
    if [[ ! -f "${crt_dest}" ]]; then
      cp "${hadixxity_reports}/subdomains.txt" "${crt_dest}" || true
    else
      # Merge with existing crt file
      cat "${hadixxity_reports}/subdomains.txt" >> "${crt_dest}" 2>/dev/null || true
      sort -u "${crt_dest}" -o "${crt_dest}" || true
    fi
    local sub_count=$(wc -l < "${crt_dest}" 2>/dev/null || echo 0)
    ok "Subdomains added to sources (crt file): ${sub_count} subdomains"
  else
    warn "No consolidated subdomains found from hadixxity"
  fi

  # Also copy CT log subdomains if they exist (merge into the same crt file)
  if [[ -d "${OUTDIR}/ct" ]]; then
    for ct_file in "${OUTDIR}"/ct/*.subdomains.txt; do
      if [[ -f "${ct_file}" ]] && [[ -s "${ct_file}" ]]; then
        local basename_ct=$(basename "${ct_file}" .subdomains.txt)
        # If it's the same domain, merge into the main crt file
        if [[ "${basename_ct}" == "${TARGET_DOMAIN}" ]]; then
          if [[ -f "${crt_dest}" ]]; then
            cat "${ct_file}" >> "${crt_dest}" 2>/dev/null || true
            sort -u "${crt_dest}" -o "${crt_dest}" || true
          else
            cp "${ct_file}" "${crt_dest}" || true
          fi
        else
          # Different domain, create separate file
          local separate_crt="${superecon_sources}/crt-${basename_ct}-domains.txt"
          if [[ ! -f "${separate_crt}" ]]; then
            cp "${ct_file}" "${separate_crt}" || true
          else
            cat "${ct_file}" >> "${separate_crt}" 2>/dev/null || true
            sort -u "${separate_crt}" -o "${separate_crt}" || true
          fi
        fi
      fi
    done
  fi

  # Create unified subdomain file for SUPERECON
  # SUPERECON expects subdomains/subdomains-<domain>.txt and will use it if it exists
  # If SUPERECON runs its own unification, it will merge all sources including our hadixxity file
  local unified_subs="${superecon_subdomains}/subdomains-${TARGET_DOMAIN}.txt"
  
  # If file doesn't exist or is empty, create it with hadixxity data
  if [[ ! -s "${unified_subs}" ]]; then
    : > "${unified_subs}"
    
    # Add subdomains from hadixxity
    if [[ -f "${hadixxity_reports}/subdomains.txt" ]] && [[ -s "${hadixxity_reports}/subdomains.txt" ]]; then
      cat "${hadixxity_reports}/subdomains.txt" >> "${unified_subs}" 2>/dev/null || true
    fi
    
    # Add root domain if not present
    if ! grep -Fxq "${TARGET_DOMAIN}" "${unified_subs}" 2>/dev/null; then
      echo "${TARGET_DOMAIN}" >> "${unified_subs}"
    fi

    # Sort and remove duplicates
    if [[ -s "${unified_subs}" ]]; then
      sort -u "${unified_subs}" -o "${unified_subs}" || true
      local count=$(wc -l < "${unified_subs}" 2>/dev/null || echo 0)
      ok "Unified subdomains prepared: ${count} subdomains in ${unified_subs}"
    else
      warn "Could not prepare unified subdomains"
      echo "${TARGET_DOMAIN}" > "${unified_subs}"
    fi
  else
    # File already exists (maybe from a previous run), just log it
    local count=$(wc -l < "${unified_subs}" 2>/dev/null || echo 0)
    info "Unified subdomains file already exists: ${count} subdomains in ${unified_subs}"
  fi

  ok "[PHASE 2] Data prepared for SUPERECON"
}

# ---------- Phase 3: Run SUPERECON ----------
run_superecon() {
  info "[PHASE 3] Running SUPERECON (active web reconnaissance)"
  
  local superecon_args=()
  
  # Domain is already in output directory, but SUPERECON needs it as positional argument
  superecon_args+=("${TARGET_DOMAIN}")
  
  [[ -n "${OUTDIR}" ]] && superecon_args+=(--out "${OUTDIR}")
  [[ "${VERBOSE}" -eq 1 ]] && superecon_args+=(--verbose)
  # Map random UA: if USE_RANDOM_UA is set, pass --random-ua to SUPERECON
  [[ "${USE_RANDOM_UA}" -eq 1 ]] && superecon_args+=(--random-ua)
  # Map delays: use RND_MIN/RND_MAX if set, otherwise use DELAY_MIN/DELAY_MAX
  if [[ -n "${RND_MIN}" && -n "${RND_MAX}" ]]; then
    superecon_args+=(--delay "${RND_MIN}:${RND_MAX}")
  elif [[ -n "${DELAY_MIN}" && -n "${DELAY_MAX}" ]]; then
    superecon_args+=(--delay "${DELAY_MIN}:${DELAY_MAX}")
  fi
  [[ "${PASSIVE_ONLY}" -eq 1 ]] && superecon_args+=(--passive)
  [[ "${FULL_SUBS}" -eq 1 ]] && superecon_args+=(--full-subs)
  [[ "${DO_CRT}" -eq 1 ]] && superecon_args+=(--crt)
  [[ "${DO_CTFR}" -eq 1 ]] && superecon_args+=(--ctfr)
  [[ "${DO_GAU}" -eq 1 ]] && superecon_args+=(--with-gau)
  [[ "${DO_SUBSCRAPER}" -eq 1 ]] && superecon_args+=(--with-subscraper)
  [[ "${DO_DNSX}" -eq 0 ]] && superecon_args+=(--no-dnsx)
  [[ "${DO_HTTPX}" -eq 0 ]] && superecon_args+=(--no-httpx)
  [[ "${DO_KATANA}" -eq 0 ]] && superecon_args+=(--no-katana)
  [[ "${DO_URLFINDER}" -eq 0 ]] && superecon_args+=(--no-urlfinder)
  [[ "${DO_XSS}" -eq 0 ]] && superecon_args+=(--no-xss)
  [[ "${DO_ARJUN}" -eq 1 ]] && superecon_args+=(--with-arjun)
  [[ "${DO_DALFOX}" -eq 1 ]] && superecon_args+=(--with-dalfox)
  [[ "${DO_CORS}" -eq 1 ]] && superecon_args+=(--with-cors)
  [[ "${DO_CF_HERO}" -eq 1 ]] && superecon_args+=(--with-cf-hero)
  [[ "${DO_FAVICONS}" -eq 1 ]] && superecon_args+=(--with-favicons)
  [[ "${DO_WAFW00F}" -eq 1 ]] && superecon_args+=(--with-wafw00f)
  [[ "${DO_403JUMP}" -eq 1 ]] && superecon_args+=(--with-403jump)
  [[ "${DO_FALLPARAMS}" -eq 1 ]] && superecon_args+=(--with-fallparams)
  [[ "${DO_CVEMAP}" -eq 1 ]] && superecon_args+=(--with-cvemap)
  [[ "${DO_JS_INVENTORY}" -eq 1 ]] && superecon_args+=(--with-js-inventory)
  [[ "${DO_FILE_HUNT}" -eq 1 ]] && superecon_args+=(--with-file-hunt)
  [[ "${DO_CARIDDI}" -eq 1 ]] && superecon_args+=(--with-cariddi)
  [[ "${DO_LOGSENSOR}" -eq 1 ]] && superecon_args+=(--with-logsensor)
  [[ "${DO_LOGSENSOR_SQLI}" -eq 1 ]] && superecon_args+=(--with-logsensor-sqli)
  [[ "${DO_BBOT_SPIDER}" -eq 1 ]] && superecon_args+=(--bbot-spider)
  [[ "${DO_BBOT_WEB_BASIC}" -eq 1 ]] && superecon_args+=(--bbot-web-basic)
  [[ "${DO_BBOT_WEB_THOROUGH}" -eq 1 ]] && superecon_args+=(--bbot-web-thorough)
  [[ "${DO_WMAP}" -eq 1 ]] && superecon_args+=(--wmap)
  [[ "${DO_API}" -eq 1 ]] && superecon_args+=(--api)

  if [[ "${VERBOSE}" -eq 1 ]]; then
    info "SUPERECON command: ${SUPERECON_SCRIPT} ${superecon_args[*]}"
  fi

  if ! "${SUPERECON_SCRIPT}" "${superecon_args[@]}"; then
    warn "superecon.sh completed with errors, but continuing..."
  fi

  ok "[PHASE 3] SUPERECON completed"
}

# ---------- Phase 4: Consolidate results ----------
consolidate_results() {
  info "[PHASE 4] Consolidating final results"
  
  local summary_file="${OUTDIR}/ixxxi-summary.txt"
  {
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    IXXXI SUMMARY"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Target domain: ${TARGET_DOMAIN}"
    [[ -n "${COMPANY_NAME}" ]] && echo "Company: ${COMPANY_NAME}"
    echo "Output directory: ${OUTDIR}"
    echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    HADIXXITY RESULTS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    # Subdomains
    if [[ -f "${OUTDIR}/reports/subdomains.txt" ]]; then
      local sub_count=$(wc -l < "${OUTDIR}/reports/subdomains.txt" 2>/dev/null || echo 0)
      echo "Subdomains discovered: ${sub_count}"
      echo "  → ${OUTDIR}/reports/subdomains.txt"
    fi
    
    # IPs
    if [[ -f "${OUTDIR}/reports/ips.txt" ]]; then
      local ip_count=$(wc -l < "${OUTDIR}/reports/ips.txt" 2>/dev/null || echo 0)
      echo "Resolved IPs: ${ip_count}"
      echo "  → ${OUTDIR}/reports/ips.txt"
    fi
    
    # ASNs
    if [[ -f "${OUTDIR}/reports/asns.txt" ]]; then
      local asn_count=$(wc -l < "${OUTDIR}/reports/asns.txt" 2>/dev/null || echo 0)
      echo "ASNs discovered: ${asn_count}"
      echo "  → ${OUTDIR}/reports/asns.txt"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    SUPERECON RESULTS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    # Alive subdomains
    if [[ -f "${OUTDIR}/subdomains/subdomains-alive-${TARGET_DOMAIN}.txt" ]]; then
      local alive_count=$(wc -l < "${OUTDIR}/subdomains/subdomains-alive-${TARGET_DOMAIN}.txt" 2>/dev/null || echo 0)
      echo "Alive subdomains: ${alive_count}"
      echo "  → ${OUTDIR}/subdomains/subdomains-alive-${TARGET_DOMAIN}.txt"
    fi
    
    # URLs
    if [[ -f "${OUTDIR}/urls/all-urls-${TARGET_DOMAIN}.txt" ]]; then
      local url_count=$(wc -l < "${OUTDIR}/urls/all-urls-${TARGET_DOMAIN}.txt" 2>/dev/null || echo 0)
      echo "URLs discovered: ${url_count}"
      echo "  → ${OUTDIR}/urls/all-urls-${TARGET_DOMAIN}.txt"
    fi
    
    # WAF
    if [[ -f "${OUTDIR}/findings/waf-detected-${TARGET_DOMAIN}.tsv" ]]; then
      local waf_count=$(wc -l < "${OUTDIR}/findings/waf-detected-${TARGET_DOMAIN}.tsv" 2>/dev/null || echo 0)
      echo "WAFs detected: ${waf_count}"
      echo "  → ${OUTDIR}/findings/waf-detected-${TARGET_DOMAIN}.tsv"
    fi
    
    # XSS
    if [[ -f "${OUTDIR}/findings/xss-candidates-${TARGET_DOMAIN}.txt" ]]; then
      local xss_count=$(wc -l < "${OUTDIR}/findings/xss-candidates-${TARGET_DOMAIN}.txt" 2>/dev/null || echo 0)
      echo "XSS candidates: ${xss_count}"
      echo "  → ${OUTDIR}/findings/xss-candidates-${TARGET_DOMAIN}.txt"
    fi
    
    # CORS
    if [[ -f "${OUTDIR}/findings/cors-${TARGET_DOMAIN}.txt" ]]; then
      local cors_count=$(wc -l < "${OUTDIR}/findings/cors-${TARGET_DOMAIN}.txt" 2>/dev/null || echo 0)
      echo "CORS issues: ${cors_count}"
      echo "  → ${OUTDIR}/findings/cors-${TARGET_DOMAIN}.txt"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    DIRECTORY STRUCTURE"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Passive reconnaissance (hadixxity):"
    echo "  ${OUTDIR}/reports/     - Consolidated lists"
    echo "  ${OUTDIR}/whois/       - WHOIS data"
    echo "  ${OUTDIR}/dns/         - DNS records"
    echo "  ${OUTDIR}/ct/           - Certificate Transparency logs"
    echo "  ${OUTDIR}/asn/         - ASN/BGP data"
    echo "  ${OUTDIR}/shodan/      - Shodan results (if -S)"
    echo ""
    echo "Active reconnaissance (SUPERECON):"
    echo "  ${OUTDIR}/subdomains/  - Alive subdomains"
    echo "  ${OUTDIR}/scans/       - httpx scans"
    echo "  ${OUTDIR}/urls/        - Discovered URLs"
    echo "  ${OUTDIR}/findings/    - Findings (WAF, XSS, CORS, etc.)"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
  } > "${summary_file}"
  
  ok "[PHASE 4] Summary saved to: ${summary_file}"
  cat "${summary_file}"
}

# ---------- Argument parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      TARGET_DOMAIN="$2"; shift 2;;
    -n|--name)
      COMPANY_NAME="$2"; shift 2;;
    -i|--ip)
      SEED_IP="$2"; shift 2;;
    -a|--asn)
      ASNS="$2"; shift 2;;
    -o|--outdir)
      OUTDIR="$2"; shift 2;;
    -f|--config)
      CONFIG_FILE="$2"; shift 2;;
    -S|--shodan)
      USE_SHODAN=1; shift 1;;
    -C|--cloud)
      USE_CLOUD=1; shift 1;;
    -X|--spiderfoot)
      USE_SPIDERFOOT=1; shift 1;;
    -A|--apex-file)
      if [[ -z "${2:-}" || "${2:0:1}" == "-" ]]; then
        warn "Option $1 expects a file path. Ignoring manual apex list."
        shift 1
      else
        APEX_LIST_FILE="$2"; shift 2
      fi;;
    -U|--user-agent)
      CUSTOM_USER_AGENT="$2"; USE_RANDOM_UA=0; shift 2;;
    --random-ua)
      USE_RANDOM_UA=1; shift 1;;
    --delay)
      if [[ "$2" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        DELAY_FIXED="$2"; DELAY_MIN=""; DELAY_MAX=""; shift 2
      else
        die "Invalid value for --delay (use a positive number, decimals allowed)"
      fi;;
    --random-delay)
      range="$2"
      [[ "$range" == *:* ]] || die "Invalid format for --random-delay. Use MIN:MAX"
      RND_MIN="${range%%:*}"
      RND_MAX="${range##*:}"
      DELAY_MIN="${RND_MIN}"
      DELAY_MAX="${RND_MAX}"
      DELAY_FIXED=""
      shift 2;;
    --httpx-final)
      RUN_FINAL_HTTPX=1; shift 1;;
    --passive)
      PASSIVE_ONLY=1; shift 1;;
    --full-subs)
      FULL_SUBS=1; shift 1;;
    --crt)
      DO_CRT=1; shift 1;;
    --ctfr)
      DO_CTFR=1; shift 1;;
    --with-gau)
      DO_GAU=1; shift 1;;
    --with-subscraper)
      DO_SUBSCRAPER=1; shift 1;;
    --no-dnsx)
      DO_DNSX=0; shift 1;;
    --no-httpx)
      DO_HTTPX=0; shift 1;;
    --no-katana)
      DO_KATANA=0; shift 1;;
    --no-urlfinder)
      DO_URLFINDER=0; shift 1;;
    --no-xss)
      DO_XSS=0; shift 1;;
    --with-arjun)
      DO_ARJUN=1; shift 1;;
    --with-dalfox)
      DO_DALFOX=1; shift 1;;
    --with-cors)
      DO_CORS=1; shift 1;;
    --with-cf-hero)
      DO_CF_HERO=1; shift 1;;
    --with-favicons)
      DO_FAVICONS=1; shift 1;;
    --with-wafw00f)
      DO_WAFW00F=1; shift 1;;
    --with-403jump)
      DO_403JUMP=1; shift 1;;
    --with-fallparams)
      DO_FALLPARAMS=1; shift 1;;
    --with-cvemap)
      DO_CVEMAP=1; shift 1;;
    --with-js-inventory)
      DO_JS_INVENTORY=1; shift 1;;
    --with-file-hunt)
      DO_FILE_HUNT=1; shift 1;;
    --with-cariddi)
      DO_CARIDDI=1; shift 1;;
    --with-logsensor)
      DO_LOGSENSOR=1; shift 1;;
    --with-logsensor-sqli)
      DO_LOGSENSOR_SQLI=1; shift 1;;
    --bbot-spider)
      DO_BBOT_SPIDER=1; shift 1;;
    --bbot-web-basic)
      DO_BBOT_WEB_BASIC=1; shift 1;;
    --bbot-web-thorough)
      DO_BBOT_WEB_THOROUGH=1; shift 1;;
    --wmap)
      DO_WMAP=1; shift 1;;
    --api)
      DO_API=1; shift 1;;
    -v|--verbose)
      VERBOSE=1; shift 1;;
    -h|--help)
      usage; exit 0;;
    *)
      err "Unknown option: $1"
      usage
      exit 1;;
  esac
done

# ---------- Validation ----------
if [[ -z "${TARGET_DOMAIN}" ]]; then
  usage
  die "You must specify -d / --domain"
fi

[[ -z "${OUTDIR:-}" ]] && OUTDIR="recon-${TARGET_DOMAIN}"

# ---------- Main execution ----------
show_banner
info "Starting ixxxi.sh – hadixxity + SUPERECON Integration"
info "Target: ${TARGET_DOMAIN}"
info "Output: ${OUTDIR}"

check_scripts
need_cmd bash

run_hadixxity
prepare_superecon_input

if [[ "${PASSIVE_ONLY}" -eq 0 ]]; then
  run_superecon
else
  info "Passive mode enabled, skipping SUPERECON"
fi

consolidate_results

ok "ixxxi.sh completed successfully."
info "Review the summary at: ${OUTDIR}/ixxxi-summary.txt"

exit 0

