#!/usr/bin/env bash
#
# IXXXI Unified Installation Script
# Installs and configures hadixxity, SUPERECON, and ixxxi integration
#
set -Eeuo pipefail

VERSION="2025-11-14"
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
C_RED="\033[31m"
C_GRN="\033[32m"
C_YEL="\033[33m"
C_CYN="\033[36m"
C_MAG="\033[35m"
C_RST="\033[0m"

info(){  echo -e "${C_CYN}[INFO]${C_RST} $*"; }
ok(){    echo -e "${C_GRN}[OK]  ${C_RST} $*"; }
warn(){  echo -e "${C_YEL}[WARN]${C_RST} $*"; }
err(){   echo -e "${C_RED}[ERR] ${C_RST} $*"; }
die(){   err "$*"; exit 1; }

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
    
    IXXXI Unified Installation
EOF
  echo -e "${C_RST}"
}

ensure_package() {
  local pkg="$1"
  if command -v "$pkg" >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt >/dev/null 2>&1; then
    info "Installing ${pkg} with apt..."
    sudo apt update -y && sudo apt install -y "$pkg" || warn "Could not install ${pkg} automatically"
  elif command -v yum >/dev/null 2>&1; then
    info "Installing ${pkg} with yum..."
    sudo yum install -y "$pkg" || warn "Could not install ${pkg} automatically"
  else
    warn "Package manager not found. Please install ${pkg} manually."
  fi
}

find_script() {
  local script_name="$1"
  # Priority order: same dir > parent dir > common locations
  local search_paths=(
    "${WORKDIR}/${script_name}"
    "${WORKDIR}/../${script_name}"
    "${WORKDIR}/../../${script_name}"
    "${WORKDIR}/../../../${script_name}"
    "${HOME}/hadixxity/${script_name}"
    "${HOME}/SUPERECON/${script_name}"
    "${HOME}/software/pentest/hadixxity/${script_name}"
    "${HOME}/software/pentest/SUPERECON/${script_name}"
    "${HOME}/software/pentest/${script_name}"
    "/opt/hadixxity/${script_name}"
    "/opt/SUPERECON/${script_name}"
    "/usr/local/bin/${script_name}"
    "/usr/bin/${script_name}"
    "$(command -v "${script_name}" 2>/dev/null || true)"
  )
  
  for path in "${search_paths[@]}"; do
    if [[ -n "${path}" && -f "${path}" ]]; then
      echo "${path}"
      return 0
    fi
  done
  return 1
}

copy_script() {
  local source="$1"
  local dest="$2"
  local script_name=$(basename "$dest")
  
  if [[ -f "${source}" ]]; then
    info "Copying ${script_name} from ${source}..."
    cp "${source}" "${dest}" || die "Failed to copy ${script_name}"
    chmod +x "${dest}" || warn "Could not make ${script_name} executable"
    ok "${script_name} copied successfully"
    return 0
  fi
  return 1
}

download_script() {
  local script_name="$1"
  local dest="${WORKDIR}/${script_name}"
  local url=""
  
  # Define URLs for scripts (adjust these to your actual repository URLs)
  case "${script_name}" in
    hadixxity.sh)
      # If you have a GitHub repo or direct URL, add it here
      # url="https://raw.githubusercontent.com/yourusername/hadixxity/main/hadixxity.sh"
      warn "No download URL configured for hadixxity.sh"
      return 1
      ;;
    superecon.sh)
      # If you have a GitHub repo or direct URL, add it here
      # url="https://raw.githubusercontent.com/yourusername/SUPERECON/main/superecon.sh"
      warn "No download URL configured for superecon.sh"
      return 1
      ;;
    *)
      return 1
      ;;
  esac
  
  if [[ -n "${url}" ]]; then
    info "Downloading ${script_name} from ${url}..."
    if command -v curl >/dev/null 2>&1; then
      curl -sSL "${url}" -o "${dest}" || { err "Failed to download ${script_name}"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
      wget -q "${url}" -O "${dest}" || { err "Failed to download ${script_name}"; return 1; }
    else
      err "Neither curl nor wget found. Cannot download ${script_name}"
      return 1
    fi
    chmod +x "${dest}" || warn "Could not make ${script_name} executable"
    ok "${script_name} downloaded successfully"
    return 0
  fi
  return 1
}

install_script() {
  local script_name="$1"
  local dest="${WORKDIR}/${script_name}"
  
  # If script already exists in workdir, skip
  if [[ -f "${dest}" ]]; then
    ok "${script_name} already exists in ${WORKDIR}"
    return 0
  fi
  
  info "Installing ${script_name}..."
  
  # Priority 1: Check parent directory (where the original scripts likely are)
  local parent_dir=$(dirname "${WORKDIR}")
  local parent_script="${parent_dir}/${script_name}"
  if [[ -f "${parent_script}" ]]; then
    info "Found ${script_name} in parent directory, copying..."
    if copy_script "${parent_script}" "${dest}"; then
      return 0
    fi
  fi
  
  # Priority 2: Try to find and copy from common locations
  local found_path
  if found_path=$(find_script "${script_name}"); then
    if copy_script "${found_path}" "${dest}"; then
      return 0
    fi
  fi
  
  # Priority 3: Check if there's a sources/ directory with the scripts
  local sources_dir="${WORKDIR}/sources"
  if [[ -d "${sources_dir}" ]] && [[ -f "${sources_dir}/${script_name}" ]]; then
    info "Found ${script_name} in sources/ directory, copying..."
    if copy_script "${sources_dir}/${script_name}" "${dest}"; then
      return 0
    fi
  fi
  
  # Priority 4: Check parent directory sources/
  if [[ -d "${parent_dir}/sources" ]] && [[ -f "${parent_dir}/sources/${script_name}" ]]; then
    info "Found ${script_name} in parent sources/ directory, copying..."
    if copy_script "${parent_dir}/sources/${script_name}" "${dest}"; then
      return 0
    fi
  fi
  
  # Priority 5: If not found locally, try to download (if URL is configured)
  if download_script "${script_name}"; then
    return 0
  fi
  
  # If all else fails, provide helpful instructions
  err "${script_name} not found and cannot be installed automatically"
  echo
  warn "To install ${script_name}, you can:"
  warn "  1. Copy it manually:"
  warn "     cp /path/to/${script_name} ${WORKDIR}/"
  warn "  2. Place it in the parent directory:"
  warn "     cp /path/to/${script_name} ${parent_dir}/"
  warn "  3. Create a sources/ directory in ${WORKDIR} and place it there:"
  warn "     mkdir -p ${WORKDIR}/sources"
  warn "     cp /path/to/${script_name} ${WORKDIR}/sources/"
  warn "  4. If you have a GitHub repository, edit install.sh and add the download URL"
  warn "  5. If the scripts are in a different location, set environment variables:"
  if [[ "${script_name}" == "hadixxity.sh" ]]; then
    warn "     export HADIXXITY_SCRIPT=\"/path/to/${script_name}\""
  elif [[ "${script_name}" == "superecon.sh" ]]; then
    warn "     export SUPERECON_SCRIPT=\"/path/to/${script_name}\""
  fi
  echo
  return 1
}

check_scripts() {
  local missing=0
  
  # ixxxi.sh must exist
  [[ -f "${WORKDIR}/ixxxi.sh" ]] || { err "ixxxi.sh not found in ${WORKDIR}"; missing=1; }
  
  # Try to install hadixxity.sh if missing
  if [[ ! -f "${WORKDIR}/hadixxity.sh" ]]; then
    warn "hadixxity.sh not found in ${WORKDIR}"
    if ! install_script "hadixxity.sh"; then
      missing=1
    fi
  else
    ok "hadixxity.sh found"
  fi
  
  # Try to install superecon.sh if missing
  if [[ ! -f "${WORKDIR}/superecon.sh" ]]; then
    warn "superecon.sh not found in ${WORKDIR}"
    if ! install_script "superecon.sh"; then
      missing=1
    fi
  else
    ok "superecon.sh found"
  fi
  
  if [[ $missing -eq 1 ]]; then
    die "Required scripts are missing. Please install them manually or configure download URLs."
  fi
  
  ok "All required scripts are available"
}

setup_config() {
  local config_file="${WORKDIR}/.ixxxi.env"
  local example_file="${WORKDIR}/config.env.example"
  
  if [[ ! -f "${config_file}" ]]; then
    if [[ -f "${example_file}" ]]; then
      info "Creating configuration file from example..."
      cp "${example_file}" "${config_file}"
      ok "Configuration file created: ${config_file}"
      warn "Please edit ${config_file} and add your API keys"
    else
      warn "config.env.example not found. Creating minimal config file..."
      cat > "${config_file}" <<'EOF'
# IXXXI API Keys Configuration
# Add your API keys below

SHODAN_API_KEY=""
PROJECTDISCOVERY_API_KEY=""
SPIDERFOOT_URL=""
SPIDERFOOT_API_KEY=""
EOF
      ok "Minimal configuration file created: ${config_file}"
    fi
  else
    warn ".ixxxi.env already exists; not overwriting"
  fi
  
  # Also create .hadixxity.env symlink or copy for compatibility
  if [[ ! -f "${WORKDIR}/.hadixxity.env" ]]; then
    if [[ -f "${config_file}" ]]; then
      ln -sf ".ixxxi.env" "${WORKDIR}/.hadixxity.env" 2>/dev/null || \
      cp "${config_file}" "${WORKDIR}/.hadixxity.env" 2>/dev/null || true
    fi
  fi
}

make_executable() {
  info "Making scripts executable..."
  chmod +x "${WORKDIR}/ixxxi.sh" 2>/dev/null || warn "Could not make ixxxi.sh executable"
  chmod +x "${WORKDIR}/hadixxity.sh" 2>/dev/null || warn "Could not make hadixxity.sh executable"
  chmod +x "${WORKDIR}/superecon.sh" 2>/dev/null || warn "Could not make superecon.sh executable"
  chmod +x "${WORKDIR}/install.sh" 2>/dev/null || warn "Could not make install.sh executable"
  ok "Scripts are now executable"
}

normalize_line_endings() {
  info "Normalizing line endings (LF)..."
  if command -v dos2unix >/dev/null 2>&1; then
    for script in ixxxi.sh hadixxity.sh superecon.sh install.sh; do
      [[ -f "${WORKDIR}/${script}" ]] && dos2unix "${WORKDIR}/${script}" >/dev/null 2>&1 || true
    done
    [[ -f "${WORKDIR}/.ixxxi.env" ]] && dos2unix "${WORKDIR}/.ixxxi.env" >/dev/null 2>&1 || true
    ok "Line endings normalized"
  else
    warn "dos2unix not found. Line endings may be CRLF (Windows). Install dos2unix for best compatibility."
  fi
}

setup_sources() {
  # Create sources directory and copy original scripts if they exist in parent directory
  local sources_dir="${WORKDIR}/sources"
  local parent_dir=$(dirname "${WORKDIR}")
  
  # Create sources directory if it doesn't exist
  mkdir -p "${sources_dir}" 2>/dev/null || true
  
  # Copy scripts from parent directory to sources/ if they exist and sources/ versions don't
  for script in hadixxity.sh superecon.sh; do
    local parent_script="${parent_dir}/${script}"
    local source_script="${sources_dir}/${script}"
    
    if [[ -f "${parent_script}" ]] && [[ ! -f "${source_script}" ]]; then
      info "Copying ${script} to sources/ directory for future installations..."
      cp "${parent_script}" "${source_script}" 2>/dev/null || warn "Could not copy ${script} to sources/"
    fi
  done
  
  # Also copy bootstrap.sh if it exists (might be useful)
  if [[ -f "${parent_dir}/bootstrap.sh" ]] && [[ ! -f "${sources_dir}/bootstrap.sh" ]]; then
    info "Copying bootstrap.sh to sources/ directory..."
    cp "${parent_dir}/bootstrap.sh" "${sources_dir}/bootstrap.sh" 2>/dev/null || true
  fi
}

check_dependencies() {
  info "Checking basic dependencies..."
  local deps=("bash" "curl" "git")
  local missing_deps=()
  
  for dep in "${deps[@]}"; do
    if command -v "$dep" >/dev/null 2>&1; then
      ok "$dep found"
    else
      missing_deps+=("$dep")
      warn "$dep not found"
    fi
  done
  
  if [[ ${#missing_deps[@]} -gt 0 ]]; then
    warn "Missing dependencies: ${missing_deps[*]}"
    info "Attempting to install missing dependencies..."
    for dep in "${missing_deps[@]}"; do
      ensure_package "$dep"
    done
  fi
}

show_next_steps() {
  echo
  echo -e "${C_MAG}════════════════════════════════════════════════════════════════${C_RST}"
  echo -e "${C_MAG}                    INSTALLATION COMPLETE${C_RST}"
  echo -e "${C_MAG}════════════════════════════════════════════════════════════════${C_RST}"
  echo
  echo -e "${C_CYN}Next steps:${C_RST}"
  echo
  echo "1. Edit the configuration file:"
  echo "   ${C_YEL}nano ${WORKDIR}/.ixxxi.env${C_RST}"
  echo "   (or use your preferred editor)"
  echo
  echo "2. Add your API keys to the config file"
  echo "   - Shodan: https://account.shodan.io/"
  echo "   - ProjectDiscovery: https://cloud.projectdiscovery.io/"
  echo "   - Others: See config.env.example for links"
  echo
  echo "3. Run IXXXI:"
  echo "   ${C_YEL}./ixxxi.sh -d target.com${C_RST}"
  echo
  echo "4. For help:"
  echo "   ${C_YEL}./ixxxi.sh --help${C_RST}"
  echo
  echo -e "${C_MAG}════════════════════════════════════════════════════════════════${C_RST}"
  echo
}

main() {
  show_banner
  info "IXXXI Unified Installation (v${VERSION})"
  info "Working directory: ${WORKDIR}"
  echo
  
  # Setup sources directory first (copy scripts from parent if available)
  setup_sources
  
  check_scripts
  check_dependencies
  setup_config
  normalize_line_endings
  make_executable
  
  ok "Installation completed successfully!"
  show_next_steps
}

main "$@"

