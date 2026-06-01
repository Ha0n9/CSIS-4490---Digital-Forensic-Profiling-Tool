#!/usr/bin/env bash
# =============================================================================
# extract_artifacts.sh
# Parse all raw forensic artifacts → JSON using pure Python parsers
# (No EZ Tools required)
#
# Usage:
#   bash extract_artifacts.sh -m <mount_point> -o <output_dir>
# =============================================================================

if [ -n "${ZSH_VERSION:-}" ]; then
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
log_error()   { echo -e "${RED}[✗]${NC} $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}━━━ $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

usage() {
    echo -e "
${BOLD}Usage:${NC}
  bash $(basename "$0") -m <mount_point> -o <output_dir>

${BOLD}Options:${NC}
  -m  Mount point of the Windows image (required)
  -o  Output directory (required) — must contain raw/ from mount_and_extract.sh
  -h  Show this help
"
    exit 0
}

MOUNT=""
OUTPUT=""
while getopts "m:o:h" opt; do
    case $opt in
        m) MOUNT="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$MOUNT" || -z "$OUTPUT" ]]; then
    log_error "Missing required arguments!"; usage
fi

[[ ! -d "$MOUNT" ]] && { log_error "Mount point not found: $MOUNT"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSERS_DIR="$SCRIPT_DIR/parsers"
RAW="$OUTPUT/raw"
JSON_DIR="$OUTPUT/json"
LOG_FILE="$OUTPUT/extraction.log"

mkdir -p "$JSON_DIR"

# ── EZ Tools (optional — used if available) ───────────────────────────────────
DOTNET="$HOME/.dotnet/dotnet"
EZ="$HOME/EZTools/bin/net9"
PECMD=$(find "$EZ"    -name "PECmd.dll"      2>/dev/null | head -1 || true)
LECMD=$(find "$EZ"    -name "LECmd.dll"      2>/dev/null | head -1 || true)
JLECMD=$(find "$EZ"   -name "JLECmd.dll"     2>/dev/null | head -1 || true)
RBCMD=$(find "$EZ"    -name "RBCmd.dll"      2>/dev/null | head -1 || true)
EVTXECMD=$(find "$EZ" -name "EvtxECmd.dll"   2>/dev/null | head -1 || true)
RECMD=$(find "$EZ"    -name "RECmd.dll"      2>/dev/null | head -1 || true)
KROLL=$(find "$EZ"    -name "Kroll_Batch.reb" 2>/dev/null | head -1 || true)

HAS_EZ=false
[[ -f "${DOTNET}" && -n "${PECMD}" ]] && HAS_EZ=true

TOTAL_OK=0
TOTAL_WARN=0

run_ez() {
    local label="$1" dll="$2"; shift 2
    [[ -z "$dll" || ! -f "$dll" ]] && return 1
    log_info "  EZ Tools: $label..."
    "$DOTNET" "$dll" "$@" 2>/dev/null \
        && log_success "  $label OK" \
        || log_warn "  $label returned non-zero (continuing)"
}

run_parser() {
    local label="$1" script="$2"; shift 2
    local path="$PARSERS_DIR/$script"
    [[ ! -f "$path" ]] && { log_warn "  Parser not found: $script"; TOTAL_WARN=$((TOTAL_WARN+1)); return 1; }
    log_info "  Python parser: $script"
    if python3 "$path" "$@"; then
        TOTAL_OK=$((TOTAL_OK+1))
    else
        log_warn "  $script returned non-zero"
        TOTAL_WARN=$((TOTAL_WARN+1))
    fi
}

# =============================================================================
# BANNER
# =============================================================================
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║       Windows Forensic Artifact Parser              ║"
echo "  ║       Python-native (no EZ Tools required)          ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Mount   : ${YELLOW}$MOUNT${NC}"
echo -e "  Raw dir : ${YELLOW}$RAW${NC}"
echo -e "  JSON dir: ${YELLOW}$JSON_DIR${NC}"
echo -e "  EZ Tools: $([ "$HAS_EZ" = true ] && echo "${GREEN}available (will use as supplement)${NC}" || echo "${YELLOW}not found (Python-only mode)${NC}")"
echo ""

# ── Detect Windows version from extracted hive structure ──────────────────────
WIN_VER="unknown"
USERS_DIR=""
if [[ -d "$MOUNT/Documents and Settings" ]]; then
    WIN_VER="xp"; USERS_DIR="$MOUNT/Documents and Settings"
elif [[ -d "$MOUNT/Users" ]]; then
    WIN_VER="modern"; USERS_DIR="$MOUNT/Users"
fi
export WIN_VER MOUNT OUTPUT RAW JSON_DIR USERS_DIR

# =============================================================================
# STEP 1: User Accounts
# =============================================================================
log_step "Step 1: User Accounts"

# Supplement with RECmd if available
if [[ "$HAS_EZ" == true && -f "$RAW/hives/system/SAM" && -n "$RECMD" && -n "$KROLL" ]]; then
    run_ez "RECmd SAM" "$RECMD" \
        -f "$RAW/hives/system/SAM" \
        --bn "$KROLL" \
        --csv "$JSON_DIR" --csvf user_accounts_ez --nl
fi

run_parser "user_accounts" "parse_user_accounts.py" \
    --raw-dir "$RAW" \
    --output  "$JSON_DIR/user_accounts.json"

# =============================================================================
# STEP 2: Application Activity (Prefetch)
# =============================================================================
log_step "Step 2: Application Activity — Prefetch"

# EZ Tools supplement
if [[ "$HAS_EZ" == true && -n "$PECMD" ]]; then
    run_ez "PECmd" "$PECMD" \
        -d "$RAW/prefetch" --csv "$JSON_DIR" --csvf app_prefetch_ez -q
fi

run_parser "application_activity" "parse_application_activity.py" \
    --raw-dir "$RAW" \
    --output  "$JSON_DIR/application_activity.json"

# =============================================================================
# STEP 3: Event Logs + Network Activity
# =============================================================================
log_step "Step 3: Event Logs + Network Activity"

EVTX_DIR=""

# auto-detect EVTX location (VERY IMPORTANT FIX)
if [[ -d "$RAW/event_logs" ]]; then
    EVTX_DIR="$RAW/event_logs"
elif [[ -d "$MOUNT/Windows/System32/winevt/Logs" ]]; then
    EVTX_DIR="$MOUNT/Windows/System32/winevt/Logs"
elif [[ -d "$RAW/windows_logs" ]]; then
    EVTX_DIR="$RAW/windows_logs"
fi

if [[ -z "$EVTX_DIR" ]]; then
    log_warn "EVTX directory not found — skipping event parsing"
else

    log_info "  EVTX source: $EVTX_DIR"

    # optional EZ Tools (keep but don't rely on it)
    if [[ "$HAS_EZ" == true && -n "$EVTXECMD" ]]; then
        run_ez "EvtxECmd" "$EVTXECMD" \
            -d "$EVTX_DIR" \
            --csv "$JSON_DIR" \
            --csvf event_logs_ez -q
    fi

    # FORCE REAL PARSER (IMPORTANT FIX)
    run_parser "event_logs" "parse_event_logs.py" \
        --mount "$MOUNT" \
        --output "$JSON_DIR/event_logs.json" \
        --network "$JSON_DIR/network_activity.json"
fi

# =============================================================================
# STEP 4: Browser History
# =============================================================================
log_step "Step 4: Browser History"

run_parser "browser_history" "parse_browser_history.py" \
    --raw-dir "$RAW/browser" \
    --output  "$JSON_DIR/browser_history.json"

# =============================================================================
# STEP 5: Document & Folder Access
# =============================================================================
log_step "Step 5: Document & Folder Access — LNK + Jump Lists"

if [[ "$HAS_EZ" == true ]]; then
    [[ -n "$LECMD" ]]  && \
        run_ez "LECmd" "$LECMD" -d "$RAW/lnk_files" --csv "$JSON_DIR" --csvf lnk_ez -q
    [[ -n "$JLECMD" ]] && \
        run_ez "JLECmd" "$JLECMD" -d "$RAW/jump_lists" --csv "$JSON_DIR" --csvf jl_ez -q
fi

run_parser "document_folder_access" "parse_document_folder_access.py" \
    --raw-dir "$RAW" \
    --output  "$JSON_DIR/document_folder_access.json"

# =============================================================================
# STEP 6: Deleted Files
# =============================================================================
log_step "Step 6: Deleted Files — Recycle Bin"

if [[ "$HAS_EZ" == true && -n "$RBCMD" && "$WIN_VER" != "xp" ]]; then
    run_ez "RBCmd" "$RBCMD" \
        -d "$RAW/recycle_bin" --csv "$JSON_DIR" --csvf deleted_ez
fi

run_parser "deleted_files" "parse_deleted_files.py" \
    --raw-dir "$RAW" \
    --output  "$JSON_DIR/deleted_files.json" \
    --win-ver "$WIN_VER"

# =============================================================================
# DONE
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║              Parsing Complete!                       ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Parsers OK   : ${GREEN}$TOTAL_OK${NC}"
echo -e "  Warnings     : ${YELLOW}$TOTAL_WARN${NC}"
echo ""
echo -e "  JSON artifacts:"
find "$JSON_DIR" -name "*.json" 2>/dev/null | sort | while read -r f; do
    SIZE=$(du -h "$f" | cut -f1)
    COUNT=$(python3 -c "import json,sys; d=json.load(open('$f')); print(d.get('count','?'))" 2>/dev/null || echo "?")
    printf "  ${GREEN}✓${NC} %-45s %s  (%s records)\n" "$(basename "$f")" "$SIZE" "$COUNT"
done
echo ""
echo -e "  Log  : ${YELLOW}$LOG_FILE${NC}"
echo ""
