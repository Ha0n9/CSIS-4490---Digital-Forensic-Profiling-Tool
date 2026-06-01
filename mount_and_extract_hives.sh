#!/usr/bin/env bash
# =============================================================================
# mount_and_extract.sh
# Mount E01 image and extract ALL forensic artifacts:
#   - User Accounts      (SAM, NTUSER.DAT, UsrClass.dat)
#   - Application Activity (Prefetch)
#   - Browser History    (Chrome, Edge, Brave, Firefox, IE)
#   - Document & Folder Access (LNK files, Jump Lists)
#   - Deleted Files      ($Recycle.Bin / RECYCLER INFO2)
#   - Event Logs         (.evtx / .evt)
#   - Network Activity   (hosts, network hives, DNS cache artifacts)
#
# Supports: Windows XP, Vista, 7, 8, 10, 11
#
# Usage:
#   bash mount_and_extract.sh -e /path/to/image.E01 -o /path/to/output
#   bash mount_and_extract.sh -e /path/to/image.E01 -o /path/to/output -k
#   bash mount_and_extract.sh -e /path/to/image.E01 -o /path/to/output -v
# =============================================================================

# ── Shell compat ──────────────────────────────────────────────────────────────
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

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    echo -e "
${BOLD}Usage:${NC}
  bash $(basename "$0") -e <image.E01> -o <output_dir> [options]

${BOLD}Options:${NC}
  -e  Path to E01 image file (required)
  -o  Output directory for extracted artifacts (required)
  -k  Keep image mounted after extraction (optional)
  -v  Skip ewfverify step (optional)
  -h  Show this help

${BOLD}Examples:${NC}
  bash $(basename "$0") -e /cases/suspect.E01 -o /cases/output
  bash $(basename "$0") -e /cases/suspect.E01 -o /cases/output -k
  bash $(basename "$0") -e /cases/suspect.E01 -o /cases/output -v
"
    exit 0
}

# ── Parse arguments ───────────────────────────────────────────────────────────
E01_FILE=""
OUTPUT_DIR=""
KEEP_MOUNTED=false
SKIP_VERIFY=false

while getopts "e:o:khv" opt; do
    case $opt in
        e) E01_FILE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        k) KEEP_MOUNTED=true ;;
        v) SKIP_VERIFY=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$E01_FILE" || -z "$OUTPUT_DIR" ]]; then
    log_error "Missing required arguments!"
    usage
fi

# ── Mount points (unique per PID) ─────────────────────────────────────────────
EWF_MOUNT="/mnt/ewf_$$"
IMG_MOUNT="/mnt/img_$$"

# ── Cleanup on exit ───────────────────────────────────────────────────────────
LOOP_DEV=""  # initialise here so cleanup always has it in scope

cleanup() {
    [[ -n "${LOOP_DEV:-}" ]] && sudo losetup -d "$LOOP_DEV" 2>/dev/null || true

    if [[ "$KEEP_MOUNTED" == false ]]; then
        log_info "Unmounting and cleaning up..."
        sudo umount "$IMG_MOUNT" 2>/dev/null || true
        sudo umount "$EWF_MOUNT" 2>/dev/null || true
        sudo rmdir  "$IMG_MOUNT" 2>/dev/null || true
        sudo rmdir  "$EWF_MOUNT" 2>/dev/null || true
        log_success "Cleanup done"
    else
        echo ""
        log_warn "Image left mounted (-k flag):"
        log_info  "  EWF  : $EWF_MOUNT"
        log_info  "  Image: $IMG_MOUNT"
        log_info  "To unmount manually:"
        log_info  "  sudo umount $IMG_MOUNT && sudo umount $EWF_MOUNT"
    fi
}
trap cleanup EXIT

# ── Counters and log ──────────────────────────────────────────────────────────
TOTAL_EXTRACTED=0
TOTAL_FAILED=0
LOG_FILE="$OUTPUT_DIR/extraction.log"

# ── Helper: copy a single file, log it ───────────────────────────────────────
cp_artifact() {
    local src="$1" dest="$2" label="$3"
    [[ ! -f "$src" ]] && return 1
    mkdir -p "$(dirname "$dest")"
    sudo cp "$src" "$dest" 2>/dev/null || return 1
    sudo chmod 644 "$dest" 2>/dev/null || true
    local size; size=$(du -h "$dest" 2>/dev/null | cut -f1)
    log_success "  [$label] $(basename "$dest") ($size)"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $label | $src" >> "$LOG_FILE"
    TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + 1))
    return 0
}

# ── Helper: copy a directory tree ────────────────────────────────────────────
cp_dir() {
    local src="$1" dest="$2" label="$3"
    [[ ! -d "$src" ]] && return 1
    mkdir -p "$dest"
    sudo cp -r "$src/." "$dest/" 2>/dev/null || true
    local count; count=$(find "$dest" -type f 2>/dev/null | wc -l)
    log_success "  [$label] $count files → $(basename "$dest")"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $label | $src → $dest" >> "$LOG_FILE"
    TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + count))
    return 0
}

# ── Skip list for user profiles ───────────────────────────────────────────────
is_system_user() {
    case "$1" in
        "All Users"|"Default User"|"Default"|"Public"|"LocalService"|"NetworkService"|"systemprofile") return 0 ;;
    esac
    return 1
}

# =============================================================================
# BANNER
# =============================================================================
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║     E01 Mount & Full Forensic Artifact Extractor    ║"
echo "  ║     Supports: Windows XP / Vista / 7 / 8 / 10 / 11 ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  E01 Image : ${YELLOW}$E01_FILE${NC}"
echo -e "  Output    : ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "  Time      : $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

mkdir -p "$OUTPUT_DIR"

# =============================================================================
# STEP 1: Check dependencies
# =============================================================================
log_step "Step 1: Checking dependencies"

MISSING=0
for cmd in ewfverify ewfmount ewfinfo mmls sudo python3; do
    if command -v "$cmd" &>/dev/null; then
        log_success "$cmd"
    else
        log_error "$cmd — not found"
        MISSING=$((MISSING + 1))
    fi
done

if [[ $MISSING -gt 0 ]]; then
    log_error "$MISSING dependencies missing. Run: bash setup_forensic_tools.sh"
    exit 1
fi

# =============================================================================
# STEP 2: Verify E01 integrity (MODIFIED ONLY HERE)
# =============================================================================
log_step "Step 2: Verifying E01 image integrity"

[[ ! -f "$E01_FILE" ]] && { log_error "E01 not found: $E01_FILE"; exit 1; }

IMAGE_SIZE=$(du -h "$E01_FILE" | cut -f1)
log_info "File: $E01_FILE ($IMAGE_SIZE)"

if [[ "$SKIP_VERIFY" == true ]]; then
    log_warn "Skipping ewfverify (-v enabled)"
else
    log_info "Running ewfverify (this may take a while)..."

    VERIFY_OUTPUT=$(ewfverify "$E01_FILE" 2>&1)
    if [[ $? -eq 0 ]]; then
        log_success "Image integrity verified OK"
        echo "$VERIFY_OUTPUT" | grep -iE "MD5|SHA1|SHA-1" | while read -r line; do
            log_info "  $line"
        done
    else
        log_warn "ewfverify non-zero — image may have no stored hash or is incomplete"
        log_warn "Continuing anyway"
    fi
fi

log_info "Image metadata:"
ewfinfo "$E01_FILE" 2>/dev/null \
    | grep -iE "case|evidence|examiner|acquisition|media|sectors|bytes" || true

# =============================================================================
# STEP 3: Mount E01
# =============================================================================
log_step "Step 3: Mounting E01 image"

sudo mkdir -p "$EWF_MOUNT" "$IMG_MOUNT"
sudo ewfmount "$E01_FILE" "$EWF_MOUNT"
log_success "ewfmount OK → $EWF_MOUNT"

EWF_DEVICE="$EWF_MOUNT/ewf1"
[[ ! -e "$EWF_DEVICE" ]] && { log_error "ewf1 not found in $EWF_MOUNT"; exit 1; }

# =============================================================================
# STEP 4: Detect partition + mount Windows filesystem
# =============================================================================
log_step "Step 4: Detecting partition layout"

MMLS_OUTPUT=$(sudo mmls "$EWF_DEVICE" 2>/dev/null || true)
[[ -z "$MMLS_OUTPUT" ]] && MMLS_OUTPUT=$(sudo fdisk -l "$EWF_DEVICE" 2>/dev/null || true)
echo "$MMLS_OUTPUT"

WINDOWS_OFFSET=""
WINDOWS_SIZE=0
while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[A-Z] ]] && continue
    echo "$line" | grep -qE "Meta|Unallocated|\-\-\-\-\-" && continue
    OFFSET=$(echo "$line" | awk '{print $3}' | tr -d '[:space:]')
    LENGTH=$(echo "$line" | awk '{print $4}' | tr -d '[:space:]')
    DESC=$(echo "$line"   | awk '{for(i=6;i<=NF;i++) printf $i" "}' | tr '[:upper:]' '[:lower:]')
    [[ -z "$LENGTH" || "$LENGTH" == "0000000000" ]] && continue
    if echo "$DESC" | grep -qiE "ntfs|basic data|windows"; then
        LEN_DEC=$(echo "$LENGTH" | sed 's/^0*//' | tr -d '[:space:]')
        LEN_DEC=${LEN_DEC:-0}
        if [[ "$LEN_DEC" -gt "$WINDOWS_SIZE" ]]; then
            WINDOWS_SIZE=$LEN_DEC
            WINDOWS_OFFSET="$OFFSET"
            log_info "Candidate: offset=$OFFSET size=$LENGTH ($DESC)"
        fi
    fi
done <<< "$MMLS_OUTPUT"
[[ -n "$WINDOWS_OFFSET" ]] && log_success "Selected largest Windows partition at offset $WINDOWS_OFFSET"

log_step "Step 5: Mounting Windows partition"

MOUNT_SUCCESS=false
MOUNT_METHOD=""

# ── Setup loopback device ─────────────────────────────────────────────────────
setup_loop() {
    local offset_bytes="$1"
    # Release any previous loop device
    [[ -n "$LOOP_DEV" ]] && sudo losetup -d "$LOOP_DEV" 2>/dev/null || true
    LOOP_DEV=$(sudo losetup --find --show --read-only \
        --offset "$offset_bytes" "$EWF_DEVICE" 2>/dev/null || true)
    [[ -n "$LOOP_DEV" ]]
}

try_mount() {
    local offset_bytes="$1" label="$2"
    local err

    # ── Attempt 1: ntfs-3g (best for NTFS — handles Win10/11 metadata) ────────
    if command -v ntfs-3g &>/dev/null; then
        err=$(sudo ntfs-3g -o ro,noatime,offset="$offset_bytes" \
            "$EWF_DEVICE" "$IMG_MOUNT" 2>&1) \
            && { log_success "Mounted via ntfs-3g ($label)"; MOUNT_METHOD="ntfs-3g"; MOUNT_SUCCESS=true; return 0; }
        log_info "    ntfs-3g with offset: ${err##*$'\n'}"

        # ntfs-3g also accepts loopback device (needed on some kernels)
        if setup_loop "$offset_bytes"; then
            err=$(sudo ntfs-3g -o ro,noatime "$LOOP_DEV" "$IMG_MOUNT" 2>&1) \
                && { log_success "Mounted via ntfs-3g + loop ($label)"; MOUNT_METHOD="ntfs-3g-loop"; MOUNT_SUCCESS=true; return 0; }
            log_info "    ntfs-3g + loop: ${err##*$'\n'}"
        fi
    fi

    # ── Attempt 2: kernel mount -t ntfs (read-only, no metadata writes) ───────
    err=$(sudo mount -t ntfs -o ro,noatime,offset="$offset_bytes" \
        "$EWF_DEVICE" "$IMG_MOUNT" 2>&1) \
        && { log_success "Mounted via kernel ntfs ($label)"; MOUNT_METHOD="kernel-ntfs"; MOUNT_SUCCESS=true; return 0; }
    log_info "    kernel ntfs: ${err##*$'\n'}"

    # ── Attempt 3: generic mount (auto-detect fs type) ────────────────────────
    err=$(sudo mount -o ro,noatime,offset="$offset_bytes" \
        "$EWF_DEVICE" "$IMG_MOUNT" 2>&1) \
        && { log_success "Mounted via auto-detect ($label)"; MOUNT_METHOD="auto"; MOUNT_SUCCESS=true; return 0; }
    log_info "    auto-detect: ${err##*$'\n'}"

    # ── Attempt 4: via loopback + auto-detect ─────────────────────────────────
    if setup_loop "$offset_bytes"; then
        err=$(sudo mount -o ro,noatime "$LOOP_DEV" "$IMG_MOUNT" 2>&1) \
            && { log_success "Mounted via loop ($label)"; MOUNT_METHOD="loop"; MOUNT_SUCCESS=true; return 0; }
        log_info "    loop auto: ${err##*$'\n'}"
    fi

    return 1
}

# ── Try auto-detected offset first ───────────────────────────────────────────
if [[ -n "$WINDOWS_OFFSET" ]]; then
    # Strip leading zeros to force decimal interpretation (avoid octal errors)
    _offset_dec=$(echo "$WINDOWS_OFFSET" | sed 's/^0*//')
    _offset_dec=${_offset_dec:-0}
    OFFSET_BYTES=$(( _offset_dec * 512 ))
    log_info "Trying auto-detected offset: $_offset_dec sectors ($OFFSET_BYTES bytes)..."
    try_mount "$OFFSET_BYTES" "offset=$_offset_dec" || true
fi

# ── Fallback: common offsets ─────────────────────────────────────────────────
if [[ "$MOUNT_SUCCESS" == false ]]; then
    log_warn "Auto-detect failed — trying common offsets..."
    for FALLBACK_OFFSET in 2048 63 206848 1026048; do
        [[ "$FALLBACK_OFFSET" == "$WINDOWS_OFFSET" ]] && continue  # already tried
        log_info "Trying offset $FALLBACK_OFFSET sectors..."
        try_mount $(( FALLBACK_OFFSET * 512 )) "offset=$FALLBACK_OFFSET" && break || true
    done
fi

# ── Last resort: no offset ───────────────────────────────────────────────────
if [[ "$MOUNT_SUCCESS" == false ]]; then
    log_warn "All partition offsets failed — trying direct mount (no offset)..."
    sudo mount -o ro,noatime "$EWF_DEVICE" "$IMG_MOUNT" 2>/dev/null \
        && { log_success "Direct mount succeeded"; MOUNT_METHOD="direct"; MOUNT_SUCCESS=true; } || true
fi

if [[ "$MOUNT_SUCCESS" == false ]]; then
    log_error "All mount attempts failed."
    log_error ""
    log_error "Manual steps to diagnose:"
    log_error "  sudo mmls $EWF_DEVICE"
    log_error "  sudo fsstat -o <sector_offset> $EWF_DEVICE"
    log_error "  sudo ntfs-3g -o ro,offset=<offset_bytes> $EWF_DEVICE $IMG_MOUNT"
    log_error ""
    log_error "Install ntfs-3g if missing:"
    log_error "  sudo apt install ntfs-3g"
    exit 1
fi

log_info "Mount method : $MOUNT_METHOD"

log_info "Filesystem root:"
ls "$IMG_MOUNT" 2>/dev/null || true

# =============================================================================
# STEP 6: Detect Windows version
# =============================================================================
log_step "Step 6: Detecting Windows version"

WIN_VER="unknown"
WIN_ROOT=""
USERS_DIR=""

for d in "$IMG_MOUNT/Windows" "$IMG_MOUNT/WINDOWS" "$IMG_MOUNT/windows"; do
    [[ -d "$d" ]] && WIN_ROOT="$d" && break
done

# ── Detect Windows version ────────────────────────────────────────────────────
# Priority: Users/ (modern) wins over "Documents and Settings"
# because Win10 creates "Documents and Settings" as an NTFS junction point
# that appears as a real directory when mounted — check Users first.
#
# Distinguish real XP "Documents and Settings" from Win10 junction:
#   - Real XP dir: contains actual user subdirs with NTUSER.DAT
#   - Win10 junction: empty or only contains redirects, no NTUSER.DAT inside

_has_users_dir=false
_has_dos_real=false   # real XP "Documents and Settings" (not a junction)

[[ -d "$IMG_MOUNT/Users" ]] && _has_users_dir=true

if [[ -d "$IMG_MOUNT/Documents and Settings" ]]; then
    # Check if it contains any real user profile (NTUSER.DAT)
    # A junction point on Win10 will be empty or inaccessible when mounted read-only
    _dos_user_count=$(find "$IMG_MOUNT/Documents and Settings" \
        -maxdepth 2 -iname "NTUSER.DAT" 2>/dev/null | wc -l)
    [[ "$_dos_user_count" -gt 0 ]] && _has_dos_real=true
fi

if [[ "$_has_users_dir" == true ]]; then
    # Modern Windows (Vista/7/8/10/11) — Users/ is the real profile store
    WIN_VER="modern"
    USERS_DIR="$IMG_MOUNT/Users"
    # Narrow down version using WinSxS (Vista+) and absence of WinSxS (rare)
    if find "${WIN_ROOT:-$IMG_MOUNT}" -maxdepth 2 \
            -type d -iname "WinSxS" 2>/dev/null | grep -q .; then
        log_success "Detected: Windows Vista / 7 / 8 / 10 / 11 (modern)"
    else
        log_success "Detected: Windows (modern, version unclear)"
    fi
elif [[ "$_has_dos_real" == true ]]; then
    # Real XP — "Documents and Settings" contains actual NTUSER.DAT files
    WIN_VER="xp"
    USERS_DIR="$IMG_MOUNT/Documents and Settings"
    log_success "Detected: Windows XP"
else
    log_warn "Could not detect Windows version from directory structure"
    log_warn "  Users/: $_has_users_dir  |  D&S real: $_has_dos_real"
fi

log_info "Windows root : ${WIN_ROOT:-NOT FOUND}"
log_info "Users dir    : ${USERS_DIR:-NOT FOUND}"

# Export for subshells
export WIN_VER IMG_MOUNT WIN_ROOT USERS_DIR OUTPUT_DIR

# =============================================================================
# OUTPUT DIRECTORY STRUCTURE
# =============================================================================
RAW="$OUTPUT_DIR/raw"

mkdir -p \
    "$RAW/hives/system" \
    "$RAW/hives/users" \
    "$RAW/prefetch" \
    "$RAW/event_logs" \
    "$RAW/recycle_bin" \
    "$RAW/browser/ie" \
    "$RAW/browser/firefox" \
    "$RAW/browser/chrome" \
    "$RAW/lnk_files" \
    "$RAW/jump_lists" \
    "$RAW/network"

# =============================================================================
# STEP 7: USER ACCOUNTS — Registry hives
# =============================================================================
log_step "Step 7: User Accounts — Registry Hives"

log_info "Extracting system hives..."
for LABEL in SAM SYSTEM SOFTWARE SECURITY; do
    MATCH=$(find "$IMG_MOUNT" -maxdepth 8 -type f \
        -iname "$LABEL" -path "*/config/*" \
        ! -ipath "*/repair/*" ! -ipath "*/RegBack/*" \
        2>/dev/null | head -1 || true)
    if [[ -n "$MATCH" ]]; then
        cp_artifact "$MATCH" "$RAW/hives/system/$LABEL" "HIVE/$LABEL"
        # Transaction logs
        for ext in .LOG .LOG1 .LOG2; do
            [[ -f "${MATCH}${ext}" ]] && \
                sudo cp "${MATCH}${ext}" "$RAW/hives/system/${LABEL}${ext}" 2>/dev/null || true
        done
    else
        log_warn "  $LABEL — not found"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
done

if [[ -n "$USERS_DIR" ]]; then
    log_info "Extracting user hives..."
    while IFS= read -r -d '' USER_DIR; do
        USERNAME=$(basename "$USER_DIR")
        is_system_user "$USERNAME" && continue

        USER_HIVE_DIR="$RAW/hives/users/$USERNAME"
        mkdir -p "$USER_HIVE_DIR"
        FOUND=0

        # NTUSER.DAT
        for f in "$USER_DIR/NTUSER.DAT" "$USER_DIR/ntuser.dat"; do
            if cp_artifact "$f" "$USER_HIVE_DIR/NTUSER.DAT" "HIVE/$USERNAME"; then
                for ext in .LOG .LOG1 .LOG2; do
                    [[ -f "${f}${ext}" ]] && \
                        sudo cp "${f}${ext}" "$USER_HIVE_DIR/NTUSER.DAT${ext}" 2>/dev/null || true
                done
                FOUND=$((FOUND + 1)); break
            fi
        done

        # UsrClass.dat
        for usrclass in \
            "$USER_DIR/AppData/Local/Microsoft/Windows/UsrClass.dat" \
            "$USER_DIR/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat"; do
            if cp_artifact "$usrclass" "$USER_HIVE_DIR/UsrClass.dat" "HIVE/$USERNAME"; then
                FOUND=$((FOUND + 1)); break
            fi
        done

        [[ $FOUND -eq 0 ]] && rmdir "$USER_HIVE_DIR" 2>/dev/null || true
    done < <(find "$USERS_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
fi

# =============================================================================
# STEP 8: APPLICATION ACTIVITY — Prefetch
# =============================================================================
log_step "Step 8: Application Activity — Prefetch"

PREFETCH_SRC=$(find "$IMG_MOUNT" -maxdepth 4 -type d -iname "Prefetch" 2>/dev/null | head -1 || true)

if [[ -n "$PREFETCH_SRC" ]]; then
    PF_COUNT=$(find "$PREFETCH_SRC" -iname "*.pf" 2>/dev/null | wc -l)
    log_info "Found $PF_COUNT .pf files in $PREFETCH_SRC"
    find "$PREFETCH_SRC" -iname "*.pf" 2>/dev/null | while read -r pf; do
        sudo cp "$pf" "$RAW/prefetch/" 2>/dev/null || true
    done
    TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + PF_COUNT))
    log_success "  $PF_COUNT prefetch files → $RAW/prefetch"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | PREFETCH | $PF_COUNT files from $PREFETCH_SRC" >> "$LOG_FILE"
else
    log_warn "Prefetch directory not found (may be disabled or WinXP pre-SP3)"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

# =============================================================================
# STEP 9: EVENT LOGS + NETWORK ACTIVITY
# =============================================================================
log_step "Step 9: Event Logs + Network Activity"

# ── Re-derive WIN_ROOT if Step 6 missed it (case-insensitive) ────────────────
if [[ -z "$WIN_ROOT" ]]; then
    WIN_ROOT=$(find "$IMG_MOUNT" -maxdepth 1 -type d -iname "windows" \
        2>/dev/null | head -1 || true)
    [[ -n "$WIN_ROOT" ]] && log_info "WIN_ROOT re-derived: $WIN_ROOT"
fi

if [[ "$WIN_VER" == "xp" ]]; then
    # XP: AppEvent.Evt / SecEvent.Evt / SysEvent.Evt in system32\config
    # Find the config dir case-insensitively under WIN_ROOT, or scan whole image
    EVT_SRC=$(find "${WIN_ROOT:-$IMG_MOUNT}" -maxdepth 3 -type d \
        -iname "config" -path "*/system32/*" 2>/dev/null | head -1 || true)

    # Fallback: locate any .Evt file and use its directory
    if [[ -z "$EVT_SRC" ]]; then
        EVT_SRC=$(find "$IMG_MOUNT" -maxdepth 8 \
            \( -iname "AppEvent.Evt" -o -iname "SecEvent.Evt" -o -iname "SysEvent.Evt" \) \
            2>/dev/null | head -1 | xargs -r dirname || true)
    fi

    if [[ -n "$EVT_SRC" ]]; then
        EVT_COUNT=0
        while IFS= read -r -d '' f; do
            cp "$f" "$RAW/event_logs/" 2>/dev/null || true
            EVT_COUNT=$((EVT_COUNT + 1))
        done < <(find "$EVT_SRC" -maxdepth 1 -iname "*.evt" -print0 2>/dev/null)
        TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + EVT_COUNT))
        log_success "  $EVT_COUNT .evt files (XP) ← $EVT_SRC"
        echo "$(date '+%Y-%m-%d %H:%M:%S') | EVENT_LOGS | $EVT_COUNT XP .evt" >> "$LOG_FILE"
    else
        log_warn "XP event log dir not found"
        log_warn "  Searched: ${WIN_ROOT:-$IMG_MOUNT}/*/system32/config and full image scan"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi

else
    # Win10/11: .evtx files in %SystemRoot%\System32\winevt\Logs\
    # Try 3 strategies in order:

    # 1. find winevt/Logs directory anywhere in image (most reliable)
    EVTX_SRC=$(find "$IMG_MOUNT" -maxdepth 8 -type d \
        -iname "Logs" -path "*/winevt/*" 2>/dev/null | head -1 || true)

    # 2. locate Security.evtx and use its parent
    if [[ -z "$EVTX_SRC" ]]; then
        EVTX_SRC=$(find "$IMG_MOUNT" -maxdepth 10 \
            -iname "Security.evtx" 2>/dev/null \
            | head -1 | xargs -r dirname || true)
    fi

    # 3. construct path from WIN_ROOT with both case variants
    if [[ -z "$EVTX_SRC" && -n "$WIN_ROOT" ]]; then
        for _cand in \
            "$WIN_ROOT/System32/winevt/Logs" \
            "$WIN_ROOT/system32/winevt/Logs" \
            "$WIN_ROOT/system32/winevt/logs"; do
            [[ -d "$_cand" ]] && { EVTX_SRC="$_cand"; break; }
        done
    fi

    if [[ -n "$EVTX_SRC" ]]; then
        EVTX_COUNT=$(find "$EVTX_SRC" -maxdepth 1 -iname "*.evtx" 2>/dev/null | wc -l)
        find "$EVTX_SRC" -maxdepth 1 -iname "*.evtx" 2>/dev/null \
            -exec cp {} "$RAW/event_logs/" \;
        TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + EVTX_COUNT))
        log_success "  $EVTX_COUNT .evtx files ← $EVTX_SRC"
        echo "$(date '+%Y-%m-%d %H:%M:%S') | EVENT_LOGS | $EVTX_COUNT .evtx" >> "$LOG_FILE"

        # Network-relevant logs → also in network/ for easy triage
        for _ename in \
            "Security" \
            "System" \
            "Microsoft-Windows-NetworkProfile%4Operational" \
            "Microsoft-Windows-WLAN-AutoConfig%4Operational" \
            "Microsoft-Windows-Dhcp-Client%4Admin" \
            "Microsoft-Windows-DNS-Client%4Operational" \
            "Microsoft-Windows-TerminalServices-RDPClient%4Operational" \
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational"; do
            _src=$(find "$EVTX_SRC" -maxdepth 1 \
                -iname "${_ename}.evtx" 2>/dev/null | head -1 || true)
            [[ -f "$_src" ]] && cp "$_src" "$RAW/network/" 2>/dev/null || true
        done
        log_success "  Network-relevant logs → $RAW/network"
    else
        log_warn "EVTX directory not found after 3 search strategies"
        log_warn "  WIN_ROOT=${WIN_ROOT:-NOT FOUND}"
        log_warn "  Try manually: find $IMG_MOUNT -iname '*.evtx' 2>/dev/null | head -5"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
fi

# ── Network config files (hosts, lmhosts) ────────────────────────────────────
if [[ -n "$WIN_ROOT" ]]; then
    for _f in \
        "$WIN_ROOT/System32/drivers/etc/hosts" \
        "$WIN_ROOT/system32/drivers/etc/hosts" \
        "$WIN_ROOT/System32/drivers/etc/networks" \
        "$WIN_ROOT/system32/drivers/etc/networks" \
        "$WIN_ROOT/System32/drivers/etc/lmhosts.sam" \
        "$WIN_ROOT/system32/drivers/etc/lmhosts.sam"; do
        [[ -f "$_f" ]] && \
            cp_artifact "$_f" "$RAW/network/$(basename "$_f")" \
                "NETWORK/$(basename "$_f")" || true
    done
fi

# =============================================================================
# STEP 10: BROWSER HISTORY
# =============================================================================
log_step "Step 10: Browser History"

if [[ -n "$USERS_DIR" ]]; then
    IE_COUNT=0; FF_COUNT=0; CR_COUNT=0

    while IFS= read -r -d '' USER_DIR; do
        USERNAME=$(basename "$USER_DIR")
        is_system_user "$USERNAME" && continue

        # ── Internet Explorer — index.dat ──────────────────────────────────
        while IFS= read -r -d '' idat; do
            PARENT=$(basename "$(dirname "$idat")")
            GPARENT=$(basename "$(dirname "$(dirname "$idat")")")
            DEST="$RAW/browser/ie/${USERNAME}_${GPARENT}_${PARENT}_index.dat"
            sudo cp "$idat" "$DEST" 2>/dev/null || true
            IE_COUNT=$((IE_COUNT + 1))
        done < <(find "$USER_DIR" -iname "index.dat" -print0 2>/dev/null)

        # ── Firefox — places.sqlite + extras ──────────────────────────────
        while IFS= read -r -d '' pdb; do
            PROFILE=$(basename "$(dirname "$pdb")")
            BASE="$RAW/browser/firefox/${USERNAME}_${PROFILE}"
            sudo cp "$pdb" "${BASE}_places.sqlite" 2>/dev/null || true
            for extra in cookies.sqlite downloads.sqlite formhistory.sqlite; do
                SRC="$(dirname "$pdb")/$extra"
                [[ -f "$SRC" ]] && sudo cp "$SRC" "${BASE}_${extra}" 2>/dev/null || true
            done
            FF_COUNT=$((FF_COUNT + 1))
        done < <(find "$USER_DIR" -iname "places.sqlite" -print0 2>/dev/null)

        # ── Chrome / Edge / Brave ─────────────────────────────────────────
        for browser_path in "Google/Chrome" "Microsoft/Edge" "BraveSoftware/Brave-Browser"; do
            BNAME=$(echo "$browser_path" | cut -d'/' -f2)
            for user_data in \
                "$USER_DIR/AppData/Local/$browser_path/User Data" \
                "$USER_DIR/Local Settings/Application Data/$browser_path/User Data"; do
                [[ ! -d "$user_data" ]] && continue
                while IFS= read -r -d '' hist; do
                    PROFILE=$(basename "$(dirname "$hist")")
                    BASE="$RAW/browser/chrome/${USERNAME}_${BNAME}_${PROFILE}"
                    sudo cp "$hist" "${BASE}_History" 2>/dev/null || true
                    for extra in Cookies "Login Data" "Web Data"; do
                        SRC="$(dirname "$hist")/$extra"
                        SAFE_NAME=$(echo "$extra" | tr ' ' '_')
                        [[ -f "$SRC" ]] && sudo cp "$SRC" "${BASE}_${SAFE_NAME}" 2>/dev/null || true
                    done
                    CR_COUNT=$((CR_COUNT + 1))
                done < <(find "$user_data" -name "History" ! -path "*/Cache/*" -print0 2>/dev/null)
            done
        done

    done < <(find "$USERS_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

    TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + IE_COUNT + FF_COUNT + CR_COUNT))
    log_success "  IE: $IE_COUNT files | Firefox: $FF_COUNT | Chrome/Edge/Brave: $CR_COUNT"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | BROWSER | IE=$IE_COUNT FF=$FF_COUNT Chrome=$CR_COUNT" >> "$LOG_FILE"
fi

# =============================================================================
# STEP 11: DOCUMENT & FOLDER ACCESS — LNK + Jump Lists
# =============================================================================
log_step "Step 11: Document & Folder Access — LNK + Jump Lists"

if [[ -n "$USERS_DIR" ]]; then
    LNK_COUNT=0; JL_COUNT=0

    while IFS= read -r -d '' USER_DIR; do
        USERNAME=$(basename "$USER_DIR")
        is_system_user "$USERNAME" && continue

        USER_LNK="$RAW/lnk_files/$USERNAME"
        USER_JL="$RAW/jump_lists/$USERNAME"
        mkdir -p "$USER_LNK" "$USER_JL"

        # LNK files from Recent
        for recent in \
            "$USER_DIR/Recent" \
            "$USER_DIR/AppData/Roaming/Microsoft/Windows/Recent"; do
            [[ ! -d "$recent" ]] && continue
            while IFS= read -r -d '' f; do
                sudo cp "$f" "$USER_LNK/" 2>/dev/null || true
                LNK_COUNT=$((LNK_COUNT + 1))
            done < <(find "$recent" -maxdepth 1 -iname "*.lnk" -print0 2>/dev/null)
        done

        # Jump Lists (AutomaticDestinations + CustomDestinations)
        for jl_dir in \
            "$USER_DIR/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations" \
            "$USER_DIR/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations"; do
            [[ ! -d "$jl_dir" ]] && continue
            while IFS= read -r -d '' f; do
                sudo cp "$f" "$USER_JL/" 2>/dev/null || true
                JL_COUNT=$((JL_COUNT + 1))
            done < <(find "$jl_dir" -type f -print0 2>/dev/null)
        done

    done < <(find "$USERS_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

    TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + LNK_COUNT + JL_COUNT))
    log_success "  LNK: $LNK_COUNT | Jump Lists: $JL_COUNT"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | LNK/JL | LNK=$LNK_COUNT JL=$JL_COUNT" >> "$LOG_FILE"
fi

# =============================================================================
# STEP 12: DELETED FILES — Recycle Bin
# =============================================================================
log_step "Step 12: Deleted Files — Recycle Bin"

RECYCLE_SRC=$(find "$IMG_MOUNT" -maxdepth 2 -type d \
    \( -iname "RECYCLER" -o -iname "\$Recycle.Bin" \) 2>/dev/null | head -1 || true)

if [[ -n "$RECYCLE_SRC" ]]; then
    sudo cp -r "$RECYCLE_SRC/." "$RAW/recycle_bin/" 2>/dev/null || true
    RB_COUNT=$(find "$RAW/recycle_bin" -type f 2>/dev/null | wc -l)
    TOTAL_EXTRACTED=$((TOTAL_EXTRACTED + RB_COUNT))
    log_success "  $RB_COUNT files from $(basename "$RECYCLE_SRC")"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | RECYCLE_BIN | $RB_COUNT files from $RECYCLE_SRC" >> "$LOG_FILE"
else
    log_warn "Recycle Bin not found (\$Recycle.Bin / RECYCLER)"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
fi

# =============================================================================
# STEP 13: Generate report
# =============================================================================
log_step "Step 13: Generating extraction report"

REPORT_FILE="$OUTPUT_DIR/extraction_report.txt"

{
    echo "================================================================================"
    echo "  FORENSIC ARTIFACT EXTRACTION REPORT"
    echo "================================================================================"
    echo "  Date           : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  E01 Image      : $E01_FILE"
    echo "  Image Size     : $IMAGE_SIZE"
    echo "  Windows Ver    : $WIN_VER"
    echo "  Output Dir     : $RAW"
    echo "  Total Extracted: $TOTAL_EXTRACTED files"
    echo "  Failed/Missing : $TOTAL_FAILED"
    echo "================================================================================"
    echo ""
    echo "  ARTIFACT SUMMARY:"
    echo ""
    for section in \
        "hives/system:Registry System Hives" \
        "hives/users:Registry User Hives" \
        "prefetch:Prefetch (.pf)" \
        "event_logs:Event Logs (.evtx/.evt)" \
        "network:Network Artifacts" \
        "browser/ie:IE Browser History" \
        "browser/firefox:Firefox Browser History" \
        "browser/chrome:Chrome/Edge/Brave History" \
        "lnk_files:LNK Files" \
        "jump_lists:Jump Lists" \
        "recycle_bin:Recycle Bin"; do
        DIR="${section%%:*}"
        LABEL="${section##*:}"
        COUNT=$(find "$RAW/$DIR" -type f 2>/dev/null | wc -l)
        printf "  %-40s %d files\n" "$LABEL" "$COUNT"
    done
    echo ""
    echo "  ALL EXTRACTED FILES:"
    find "$RAW" -type f 2>/dev/null | sort | while read -r f; do
        SIZE=$(du -h "$f" | cut -f1)
        printf "  %-60s %s\n" "${f#$OUTPUT_DIR/}" "$SIZE"
    done
    echo ""
    echo "  NEXT STEPS:"
    echo "  1. Parse with EZ Tools:"
    echo "     PECmd    -d $RAW/prefetch     --csv <output>"
    echo "     EvtxECmd -d $RAW/event_logs   --csv <output>"
    echo "     LECmd    -d $RAW/lnk_files    --csv <output>"
    echo "     JLECmd   -d $RAW/jump_lists   --csv <output>"
    echo "     RBCmd    -d $RAW/recycle_bin  --csv <output>"
    echo "     RECmd    -f $RAW/hives/system/SAM --bn ~/EZTools/bin/net9/RECmd/BatchExamples/Kroll_Batch.reb --csv <output>"
    echo "  2. Run extract_artifacts.sh -m $IMG_MOUNT -o <output>"
    echo "================================================================================"
} | tee "$REPORT_FILE"

# =============================================================================
# DONE
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║              Extraction Complete!                    ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Extracted  : ${GREEN}$TOTAL_EXTRACTED files${NC}"
echo -e "  Failed     : ${YELLOW}$TOTAL_FAILED${NC}"
echo -e "  Report     : ${YELLOW}$REPORT_FILE${NC}"
echo -e "  Log        : ${YELLOW}$LOG_FILE${NC}"
echo ""
