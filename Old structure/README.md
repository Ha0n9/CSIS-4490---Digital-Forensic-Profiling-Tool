# Windows Forensic Profiling Tool

**CYBERSECURITY CAPSTONE — CAP D2 | Project 6: Digital Forensics — Windows Suspect Profiling**
**Group 05 | Douglas College — CSIS 4490**

> Takahiro Tanaka (300408537) · Hoang Nghiem Dac (300416011) · Tzu-Yun Wang (300399726)
> Instructor: Gabriel Vitus

---

## Overview

This project implements an automated forensic pipeline that extracts, parses, and structures Windows forensic artifacts from disk images (.E01 format) to support per-user activity profiling and suspicion scoring. The tool runs entirely on **Kali Linux** and requires **no EZ Tools dependency** for its core parsers — all Python parsers work standalone, with EZ Tools used as an optional supplement if available.

**Research Question:** To what extent does correlating multiple Windows forensic artifact categories — including indicators of deleted or partially concealed activity — improve the accuracy of per-user activity profiling, and how does this impact the reliability of user suspicion assessment in a multi-user system?

---

## Supported Environments

| Windows Version | Support |
|---|---|
| Windows XP | ✅ (M57-Jean image, legacy EVT logs, `Documents and Settings`) |
| Windows 10 | ✅ (EVTX logs, `$Recycle.Bin`, `Users` directory) |
| Windows 11 | ✅ (same pipeline as Win10) |
| Windows 8/8.1 | ❌ Excluded (low forensic relevance) |
| Windows 7 | ❌ Excluded (similar kernel to Win10) |

---

## Project Structure

```
.
├── setup_forensic_tools.sh        # One-time environment setup (Kali Linux)
├── mount_and_extract_hives.sh     # Stage 1 — Mount E01 + extract raw artifacts
├── extract_artifacts.sh           # Stage 2 — Parse raw artifacts → JSON
└── parsers/
    ├── parse_user_accounts.py          # SAM + NTUSER.DAT → user_accounts.json
    ├── parse_application_activity.py   # Prefetch (.pf) → application_activity.json
    ├── parse_event_logs.py             # EVT/EVTX → event_logs.json + network_activity.json
    ├── parse_browser_history.py        # Chrome/Firefox/IE SQLite → browser_history.json
    ├── parse_document_folder_access.py # LNK files + Jump Lists → document_folder_access.json
    └── parse_deleted_files.py          # Recycle Bin (INFO2 / $I files) → deleted_files.json
```

---

## Quick Start

### Step 1 — Install all tools (run once per machine)

```bash
chmod +x setup_forensic_tools.sh
./setup_forensic_tools.sh
source ~/.zshrc
```

This installs: .NET SDK 9.x, PowerShell 7.5.4, EZ Tools suite, ewf-tools, sleuthkit, RegRipper, python3-evtx, python3-pylnk3.

### Step 2 — Mount E01 image and extract raw artifacts

```bash
bash mount_and_extract_hives.sh -e /path/to/image.E01 -o /cases/output
```

Optional flags:
- `-k` — keep the image mounted after extraction
- `-v` — skip ewfverify integrity check (faster)

Extracted files land in `/cases/output/raw/`.

### Step 3 — Parse raw artifacts into JSON

```bash
bash extract_artifacts.sh -m /mnt/img_<PID> -o /cases/output
```

Parsed JSON files land in `/cases/output/json/`.

---

## Artifact Categories

| Artifact | Source Files | Output JSON |
|---|---|---|
| User Accounts | `SAM`, `NTUSER.DAT` | `user_accounts.json` |
| Application Activity | Prefetch `.pf` files | `application_activity.json` |
| Event Logs + Network | `.evtx` / `.evt` | `event_logs.json`, `network_activity.json` |
| Browser History | `History` (SQLite), `places.sqlite`, `index.dat` | `browser_history.json` |
| Document & Folder Access | `.lnk` files, Jump Lists | `document_folder_access.json` |
| Deleted Files | `$Recycle.Bin` / `RECYCLER/INFO2` | `deleted_files.json` |

---

## File-by-File Explanation

### `setup_forensic_tools.sh`

One-time setup script for a fresh Kali Linux VM. Runs 7 steps in sequence:

1. **APT packages** — installs `ewf-tools`, `sleuthkit`, `regripper`, `python3-evtx`, `python3-pylnk3`
2. **.NET SDK 9.x** — downloads and installs to `~/.dotnet` via Microsoft's official installer
3. **PowerShell 7.5.4** — installs via `.deb` package
4. **EZ Tools** — downloads the full Eric Zimmerman Tools suite (`PECmd`, `LECmd`, `EvtxECmd`, `RECmd`, etc.) via `Get-ZimmermanTools.ps1`
5. **RECmd batch files** — syncs `Kroll_Batch.reb` registry templates from GitHub
6. **Shell config** — writes `PATH` exports and command aliases to `.zshrc` / `.bashrc`
7. **Verification** — automatically validates every tool installation with pass/fail output

---

### `mount_and_extract_hives.sh`

The main acquisition script. Takes an `.E01` disk image and produces a `raw/` directory of all forensic artifacts ready for parsing.

**Flow:**

```
E01 file
  └─ [Step 1] Check dependencies (ewfmount, mmls, python3, etc.)
  └─ [Step 2] Verify image integrity via ewfverify (MD5/SHA1)
  └─ [Step 3] Mount E01 with ewfmount → /mnt/ewf_<PID>/ewf1
  └─ [Step 4] Detect partition layout with mmls → find Windows NTFS partition
  └─ [Step 5] Mount Windows partition (tries ntfs-3g → kernel ntfs → auto → loopback)
  └─ [Step 6] Detect Windows version:
              - Users/ present → Windows Vista/7/8/10/11 ("modern")
              - Documents and Settings/ with NTUSER.DAT → Windows XP
  └─ [Step 7]  Extract registry hives: SAM, SYSTEM, SOFTWARE, SECURITY → raw/hives/system/
               Extract per-user hives: NTUSER.DAT, UsrClass.dat → raw/hives/users/<username>/
  └─ [Step 8]  Copy Prefetch .pf files → raw/prefetch/
  └─ [Step 9]  Copy Event Logs (.evtx or .evt) → raw/event_logs/
               Copy network-relevant logs (Security, WLAN, DNS, RDP) → raw/network/
               Copy hosts/lmhosts files → raw/network/
  └─ [Step 10] Copy browser data → raw/browser/{ie,firefox,chrome}/
  └─ [Step 11] Copy LNK files → raw/lnk_files/<username>/
               Copy Jump Lists → raw/jump_lists/<username>/
  └─ [Step 12] Copy Recycle Bin → raw/recycle_bin/
  └─ [Step 13] Generate extraction_report.txt
```

---

### `extract_artifacts.sh`

Orchestrates all Python parsers against the `raw/` directory from the previous step, producing structured JSON in `json/`.

**Flow:**

```
raw/ directory
  ├─ [Step 1] parse_user_accounts.py     → json/user_accounts.json
  ├─ [Step 2] parse_application_activity.py → json/application_activity.json
  ├─ [Step 3] parse_event_logs.py        → json/event_logs.json + json/network_activity.json
  ├─ [Step 4] parse_browser_history.py   → json/browser_history.json
  ├─ [Step 5] parse_document_folder_access.py → json/document_folder_access.json
  └─ [Step 6] parse_deleted_files.py     → json/deleted_files.json
```

If EZ Tools is installed, each step also runs the corresponding EZ tool (PECmd, EvtxECmd, etc.) as a supplemental output. The Python parsers always run regardless.

---

### `parsers/parse_user_accounts.py`

Parses the Windows `SAM` registry hive to extract local user accounts, then each user's `NTUSER.DAT` for autorun entries and typed path history.

**From SAM:** username, RID (user ID number), last login time, password last set, failed login count, total login count, account locked/disabled status.

**From NTUSER.DAT:** Run/RunOnce autostart entries (programs that launch at login), TypedPaths (folders the user manually typed into the address bar).

---

### `parsers/parse_application_activity.py`

*(Note: file is named `parse_application_activity.py` but contains the event log parser code — the application activity parser shares the same base.)*

Parses Windows Prefetch `.pf` files. Prefetch records every executable that ran on the system, along with a timestamp and run count. This tells you **what programs were executed and when**, even if the program has since been deleted.

---

### `parsers/parse_event_logs.py`

Parses Windows event logs in two formats:

- **EVTX** (Windows Vista/7/10/11): binary XML format, parsed via the `python-evtx` library
- **EVT** (Windows XP): older binary format, parsed with raw `struct` unpacking — no deprecated libraries needed

After parsing, events are categorized into four buckets: network events, logon events, process creation events, and service events. Outputs two JSON files: `event_logs.json` (all events) and `network_activity.json` (network-related events only).

Key event IDs tracked: 4624/4625 (logon success/fail), 4688/4689 (process start/stop), 5156/5157 (firewall allow/block), 4778/4779 (RDP session), 7045 (new service installed).

---

### `parsers/parse_browser_history.py`

Parses browser history from three browser families:

- **Chrome / Edge / Brave** — reads the `History` SQLite database, joining `urls` and `visits` tables. Timestamps are in Chrome epoch (microseconds since 1601-01-01).
- **Firefox** — reads `places.sqlite`, joining `moz_places` and `moz_historyvisits`. Timestamps are Unix microseconds.
- **Internet Explorer** — scans `index.dat` binary files with regex to extract URLs (best-effort, legacy format).

All browser databases are copied to a temp file before reading to avoid WAL lock issues.

---

### `parsers/parse_document_folder_access.py`

Parses two artifact types that reveal what files and folders a user accessed:

- **LNK files** (Windows Shortcut files from the `Recent` folder): contain the target file path, timestamps (created/modified/accessed), file size, volume label, and drive type. Parsed with `pylnk3` if available, otherwise falls back to raw struct parsing.
- **Jump Lists** (`.automaticDestinations` / `.customDestinations` files): OLE compound files that record recently/frequently accessed items per application. The parser counts embedded LNK entries and extracts what it can without needing external OLE libraries.

---

### `parsers/parse_deleted_files.py`

Parses the Windows Recycle Bin in both formats:

- **Windows XP** (`RECYCLER/INFO2`): fixed 280-byte binary records per deleted file. Extracts original path, file size, deletion timestamp, and drive number.
- **Windows Vista/7/10/11** (`$Recycle.Bin/$I??????`): per-file `$I` metadata records containing original path, file size, and deletion timestamp (Windows FILETIME). The corresponding `$R` file holds the actual deleted file content.

---

## Forensic Datasets Used

| Image | OS | Source | Format | MD5 |
|---|---|---|---|---|
| M57-Jean (2009) | Windows XP | [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/m57-jean/) | .E01 | `78a52b5bac78f4e711607707ac0e3f93` |
| Custom VM image | Windows 10/11 | Generated via FTK Imager (controlled lab VM) | .E01 | — |

---

## Environment Requirements

- **OS:** Kali Linux 2026.x (64-bit), kernel 6.x
- **VM name:** `CSIS4490_g05`
- **Python:** 3.x with `python-registry`, `python-evtx`, `pylnk3`
- **Optional:** .NET 9 SDK + EZ Tools for supplemental output

Install everything with:
```bash
bash setup_forensic_tools.sh
```

---

## GitHub Repository

[https://github.com/Ha0n9/CSIS-4490---Digital-Forensic-Profiling-Tool](https://github.com/Ha0n9/CSIS-4490---Digital-Forensic-Profiling-Tool.git)
