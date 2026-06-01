#!/usr/bin/env bash
# =============================================================================
# setup_forensic_tools.sh
# Install all tools for Forensic Profiling Tool on Kali Linux 2026.x
# Includes: .NET 9, PowerShell, EZ Tools, Python libs, ewf-tools, regripper
#
# Compatible: bash 4+ / zsh 5+
# Usage: bash setup_forensic_tools.sh
#        zsh  setup_forensic_tools.sh
# =============================================================================

# ── Shell compat ──────────────────────────────────────────────────────────────
# pipefail works in both bash and zsh
if [ -n "$ZSH_VERSION" ]; then
    setopt errexit nounset pipefail 2>/dev/null || true
else
    set -uo pipefail
fi

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ── Config ────────────────────────────────────────────────────────────────────
DOTNET_DIR="$HOME/.dotnet"
DOTNET_BIN="$DOTNET_DIR/dotnet"
EZTOOLS_DIR="$HOME/EZTools"
EZTOOLS_NET9="$EZTOOLS_DIR/bin/net9"
PWSH_VERSION="7.5.4"

# ── Detect RC file (update both if both exist) ────────────────────────────────
RC_FILES=()
[[ -f "$HOME/.zshrc" ]]  && RC_FILES+=("$HOME/.zshrc")
[[ -f "$HOME/.bashrc" ]] && RC_FILES+=("$HOME/.bashrc")

# If neither exists yet, create one matching the running shell
if [[ ${#RC_FILES[@]} -eq 0 ]]; then
    if [ -n "${ZSH_VERSION:-}" ]; then
        touch "$HOME/.zshrc"
        RC_FILES+=("$HOME/.zshrc")
    else
        touch "$HOME/.bashrc"
        RC_FILES+=("$HOME/.bashrc")
    fi
fi

# ── Portable regex helper (no grep -P) ───────────────────────────────────────
# Usage: regex_extract <pattern_ERE> <string>
regex_extract() {
    echo "$2" | grep -oE "$1" | head -1
}

# =============================================================================
# BANNER
# =============================================================================
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║       Forensic Tools Setup — Kali Linux 2026        ║"
echo "  ║  .NET 9 + PowerShell + EZ Tools + Python libs       ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Shell     : ${YELLOW}${SHELL}${NC}"
echo -e "  RC files  : ${YELLOW}${RC_FILES[*]}${NC}"
echo ""

# =============================================================================
# STEP 1: APT packages
# =============================================================================
log_step "Step 1: Installing APT packages"

sudo apt update -qq

sudo apt install -y \
    ewf-tools \
    regripper \
    python3-evtx \
    python3-pylnk3 \
    liblnk-utils \
    sleuthkit \
    wget \
    curl

log_success "APT packages installed successfully"

# =============================================================================
# STEP 2: .NET 9 SDK
# =============================================================================
log_step "Step 2: Installing .NET 9 SDK"

if "$DOTNET_BIN" --version 2>/dev/null | grep -q "^9\."; then
    log_success ".NET 9 already installed: $("$DOTNET_BIN" --version)"
else
    log_info "Downloading dotnet-install.sh..."
    wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh
    chmod +x /tmp/dotnet-install.sh
    /tmp/dotnet-install.sh --channel 9.0 --install-dir "$DOTNET_DIR"
    rm /tmp/dotnet-install.sh
    export DOTNET_ROOT="$DOTNET_DIR"
    export PATH="$DOTNET_DIR:$DOTNET_DIR/tools:$PATH"
    log_success ".NET $("$DOTNET_BIN" --version) installed"
fi

export DOTNET_ROOT="$DOTNET_DIR"
export PATH="$DOTNET_DIR:$DOTNET_DIR/tools:$PATH"

# =============================================================================
# STEP 3: PowerShell
# =============================================================================
log_step "Step 3: Installing PowerShell $PWSH_VERSION"

# grep -oE instead of grep -oP for portability
CURRENT_PWSH=$(pwsh --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")

if [[ "$CURRENT_PWSH" == "$PWSH_VERSION" ]]; then
    log_success "PowerShell $PWSH_VERSION already installed"
else
    log_info "Downloading PowerShell $PWSH_VERSION..."
    wget -q "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell_${PWSH_VERSION}-1.deb_amd64.deb" \
        -O /tmp/pwsh.deb
    sudo dpkg -i /tmp/pwsh.deb > /dev/null 2>&1
    sudo apt install -f -y > /dev/null 2>&1  # fix any missing deps
    rm /tmp/pwsh.deb
    log_success "PowerShell $(pwsh --version) installed"
fi

# =============================================================================
# STEP 4: EZ Tools
# =============================================================================
log_step "Step 4: Downloading EZ Tools"

TOOL_COUNT=0
if [[ -d "$EZTOOLS_NET9" ]]; then
    TOOL_COUNT=$(find "$EZTOOLS_NET9" -maxdepth 2 -name "*.dll" 2>/dev/null | wc -l)
fi

if [[ "$TOOL_COUNT" -gt 10 ]]; then
    log_success "EZ Tools already installed ($TOOL_COUNT DLLs found)"
    log_info "Skipping download. Remove $EZTOOLS_NET9 to redownload."
else
    log_info "Downloading Get-ZimmermanTools.ps1..."
    mkdir -p "$EZTOOLS_DIR"
    wget -q "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" \
        -O "$EZTOOLS_DIR/Get-ZimmermanTools.ps1"

    log_info "Running Get-ZimmermanTools.ps1 (this may take a few minutes)..."
    pwsh "$EZTOOLS_DIR/Get-ZimmermanTools.ps1" -Dest "$EZTOOLS_DIR/bin" -NetVersion 9

    TOOL_COUNT=$(find "$EZTOOLS_NET9" -maxdepth 2 -name "*.dll" 2>/dev/null | wc -l)
    log_success "EZ Tools downloaded ($TOOL_COUNT DLLs)"
fi

# =============================================================================
# STEP 5: Sync RECmd Batch Files
# =============================================================================
log_step "Step 5: Syncing RECmd Batch Files"

RECMD_DLL=$(find "$EZTOOLS_NET9" -name "RECmd.dll" 2>/dev/null | head -1 || true)
if [[ -f "${RECMD_DLL:-}" ]]; then
    log_info "Syncing batch files from GitHub..."
    "$DOTNET_BIN" "$RECMD_DLL" --sync 2>/dev/null \
        && log_success "Batch files synced" \
        || log_warn "Sync failed (network issue?) — continuing"
else
    log_warn "RECmd.dll not found — skipping sync"
fi

# =============================================================================
# STEP 6: Write PATH + Aliases to RC file(s)
# =============================================================================
log_step "Step 6: Updating shell RC file(s)"

# Resolve DLL paths once
find_dll() { find "$EZTOOLS_NET9" -name "${1}.dll" 2>/dev/null | head -1 || true; }

RECMD=$(find_dll "RECmd")
PECMD=$(find_dll "PECmd")
LECMD=$(find_dll "LECmd")
JLECMD=$(find_dll "JLECmd")
SBECMD=$(find_dll "SBECmd")
EVTXECMD=$(find_dll "EvtxECmd")
AMCACHE=$(find_dll "AmcacheParser")
RBCMD=$(find_dll "RBCmd")
MFTECMD=$(find_dll "MFTECmd")
SQLEMD=$(find_dll "SQLECmd")
SRUMECMD=$(find_dll "SrumECmd")

# Build the config block as a variable (written once, applied to each RC file)
build_config_block() {
    printf '\n# ── Forensic Tools Setup ──────────────────────────────────────────────────────\n'
    printf 'export DOTNET_ROOT="$HOME/.dotnet"\n'
    printf 'export PATH="$HOME/.dotnet:$HOME/.dotnet/tools:$PATH"\n'
    printf 'export EZ_NET9="%s"\n' "$EZTOOLS_NET9"
    printf '\n# EZ Tools aliases\n'

    write_alias() {
        local aname="$1" dll="$2"
        if [[ -n "$dll" && -f "$dll" ]]; then
            # Quote dotnet path and DLL path; works in both bash and zsh
            printf "alias %s='%s' '%s'\n" "$aname" "$DOTNET_BIN" "$dll"
        else
            printf '# %s: DLL not found\n' "$aname"
        fi
    }

    write_alias "RECmd"         "$RECMD"
    write_alias "PECmd"         "$PECMD"
    write_alias "LECmd"         "$LECMD"
    write_alias "JLECmd"        "$JLECMD"
    write_alias "SBECmd"        "$SBECMD"
    write_alias "EvtxECmd"      "$EVTXECMD"
    write_alias "AmcacheParser" "$AMCACHE"
    write_alias "RBCmd"         "$RBCMD"
    write_alias "MFTECmd"       "$MFTECMD"
    write_alias "SQLECmd"       "$SQLEMD"
    write_alias "SrumECmd"      "$SRUMECMD"

    printf '# ── End Forensic Tools ────────────────────────────────────────────────────────\n'
}

BLOCK=$(build_config_block)

for RC in "${RC_FILES[@]}"; do
    # Remove old block if present
    if grep -q "# ── Forensic Tools Setup" "$RC" 2>/dev/null; then
        log_warn "Old config found in $RC — removing and rewriting"
        # Use a temp file for in-place edit (works on both Linux and macOS)
        TMPRC=$(mktemp)
        awk '/# ── Forensic Tools Setup/{skip=1} /# ── End Forensic Tools/{skip=0; next} !skip' \
            "$RC" > "$TMPRC" && mv "$TMPRC" "$RC"
    fi
    echo "$BLOCK" >> "$RC"
    log_success "Aliases written to $RC"
done

# =============================================================================
# STEP 7: Verify everything
# =============================================================================
log_step "Step 7: Verification"

ERRORS=0

check_cmd() {
    local label="$1"
    # shift past label so remaining args are the command to eval
    shift
    if eval "$@" &>/dev/null; then
        log_success "$label"
    else
        log_warn "$label — FAILED"
        ERRORS=$((ERRORS + 1))
    fi
}

check_dll() {
    local label="$1" dll="${2:-}"
    if [[ -n "$dll" && -f "$dll" ]]; then
        log_success "$label → $(basename "$(dirname "$dll")")/$(basename "$dll")"
    else
        log_warn "$label — not found"
        ERRORS=$((ERRORS + 1))
    fi
}

echo ""
log_info "System tools:"
check_cmd "dotnet 9.x"      '"$DOTNET_BIN" --version | grep -q "^9\."'
check_cmd "pwsh"             'pwsh --version'
check_cmd "ewfmount"         'command -v ewfmount'
check_cmd "mmls (sleuthkit)" 'command -v mmls'
check_cmd "regripper"        'command -v regripper'
check_cmd "python3"          'python3 --version'
check_cmd "python3-evtx"     'python3 -c "import Evtx"'
check_cmd "python3-pylnk3"   'python3 -c "import pylnk3"'

echo ""
log_info "EZ Tools DLLs:"
check_dll "RECmd"          "$RECMD"
check_dll "PECmd"          "$PECMD"
check_dll "LECmd"          "$LECMD"
check_dll "JLECmd"         "$JLECMD"
check_dll "SBECmd"         "$SBECMD"
check_dll "EvtxECmd"       "$EVTXECMD"
check_dll "AmcacheParser"  "$AMCACHE"
check_dll "RBCmd"          "$RBCMD"
check_dll "MFTECmd"        "$MFTECMD"
check_dll "SQLECmd"        "$SQLEMD"

KROLL=$(find "$EZTOOLS_NET9" -name "Kroll_Batch.reb" 2>/dev/null | head -1 || true)
check_dll "Kroll_Batch.reb" "$KROLL"

# =============================================================================
# DONE
# =============================================================================
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
if [[ $ERRORS -eq 0 ]]; then
    echo "  ║   ✓  Setup complete — everything OK!                ║"
else
    printf "  ║   ✗  Setup complete with %-2d warning(s)             ║\n" "$ERRORS"
fi
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  RC files updated  :  ${YELLOW}${RC_FILES[*]}${NC}"
echo ""
echo -e "  Reload shell       :"
for RC in "${RC_FILES[@]}"; do
    echo -e "    ${GREEN}source $RC${NC}"
done
echo ""
echo -e "  Quick test         :"
echo -e "  ${GREEN}RECmd --version${NC}"
echo -e "  ${GREEN}PECmd --version${NC}"
echo -e "  ${GREEN}EvtxECmd --version${NC}"
echo ""
