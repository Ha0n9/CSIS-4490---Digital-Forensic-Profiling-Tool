# Forensic Profiler

**CYBERSECURITY CAPSTONE — CAP D2 | Project 6: Digital Forensics — Windows Suspect Profiling**
**Group 05 | Douglas College — CSIS 4490**

> Takahiro Tanaka (300408537) · Hoang Nghiem Dac (300416011) · Tzu-Yun Wang (300399726)
> Instructor: Gabriel Vitus

---

## Overview

Forensic Profiler is a four-stage pipeline that turns a raw Windows `.E01` disk image into a per-user suspicion report: it mounts the image, extracts and parses artifacts into structured JSON, correlates that JSON across every user account on the system, and renders a self-contained HTML report ranking each account by risk. It runs entirely on **Kali Linux** and requires **no EZ Tools dependency** for its core parsers — every Python parser works standalone, with EZ Tools used only as an optional supplement when available.

`forensic-profiler/` is the current, actively developed implementation of the pipeline — everything described in this README lives there. An earlier iteration of the project — separate acquisition/parsing shell scripts and experimental scoring logic, with no single entry point and no reporting stage — is preserved under `Old structure/` at the repository root for reference; it is no longer maintained.

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
├── README.md
├── Old structure/                  # Archived pre-unification scripts, kept for reference only
│   ├── parsers/                        # Earlier, standalone versions of the Stage 2 parsers
│   ├── experimental_correlation_and_scoring_logics/   # v1-v11 iterative scoring scripts (see EXP logs)
│   └── *.sh                            # Earlier, standalone mount/extract scripts
└── forensic-profiler/               # The unified pipeline — run everything from here
    ├── full_forensic_profiler.py       # Unified entry point — runs all 4 stages (+ --setup)
    ├── setup_forensic_tools.sh         # One-time environment setup (Kali Linux)
    ├── requirements.txt                 # Python dependencies (pip install -r requirements.txt)
    ├── mount_and_extract_hives.sh       # Stage 1 — Mount E01 + extract raw artifacts
    ├── extract_artifacts.sh             # Stage 2 — Parse raw artifacts → JSON
    ├── parsers/
    │   ├── parse_user_accounts.py          # SAM + NTUSER.DAT → user_accounts.json
    │   ├── parse_application_activity.py   # Prefetch (.pf) → application_activity.json
    │   ├── parse_event_logs.py             # EVT/EVTX → event_logs.json + network_activity.json
    │   ├── parse_browser_history.py        # Chrome/Firefox/IE SQLite → browser_history.json
    │   ├── parse_document_folder_access.py # LNK files + Jump Lists → document_folder_access.json
    │   └── parse_deleted_files.py          # Recycle Bin (INFO2 / $I files) → deleted_files.json
    ├── correlation/
    │   ├── engine.py                   # Stage 3 — merges JSON artifacts per user, scores risk
    │   └── narrative.py                # Turns one scored user record into a plain-language narrative
    ├── reporting/
    │   └── html_report.py              # Stage 4 — generates forensic_report.html
    └── <CaseName>/output/               # Per-case output — raw/, json/, reports/ (see Quick Start)
```

---

## Quick Start

### Step 1 — Install all tools (run once per machine)

```bash
cd forensic-profiler
chmod +x setup_forensic_tools.sh
sudo ./setup_forensic_tools.sh
source ~/.zshrc
pip install -r requirements.txt
```
PLEASE !!! - use sudo when run ./setup_forensic_tools.sh to ensure all tools are well install

`setup_forensic_tools.sh` installs: .NET SDK 9.x, PowerShell 7.5.4, EZ Tools suite, ewf-tools, sleuthkit, RegRipper. `requirements.txt` covers the pure-Python dependencies the parsers actually import: `evtx`/`python-evtx` (event log parsing) and `python-registry` (SAM/NTUSER.DAT parsing) — every other artifact (Prefetch, LNK/Jump Lists, Recycle Bin, browser history, HTML reporting) is parsed with the standard library only, no extra package needed.

Instead of running `setup_forensic_tools.sh` by hand, you can also do it through the entry point:

```bash
sudo python3 full_forensic_profiler.py --setup
```

This runs the same install script and exits — it doesn't touch an image or output directory. `full_forensic_profiler.py` also does a cheap, read-only check of the required tooling (`ewfmount`, `mmls`, .NET, `python-registry`, `evtx`) before every pipeline run and warns (without blocking) if anything looks missing.

### Step 2 — Run the full pipeline

```bash
sudo python3 full_forensic_profiler.py -e /path/to/image.E01 -o /cases/output
```

This runs all four stages back to back and produces `/cases/output/reports/forensic_report.html`. `sudo` is required end-to-end — mounting the E01 (`ewfmount`/`losetup`) and reading the NTFS filesystem/registry hives (`ntfs-3g`) both need root, so files under `output/` end up root-owned.

Optional flags:
- `-k, --keep-mounted` — keep the image mounted after extraction (useful for manual follow-up)
- `-v, --skip-verify` — skip the `ewfverify` integrity check (faster, but skips corruption detection — see [Troubleshooting](#troubleshooting))
- `--skip-extract` — reuse an existing `raw/` instead of remounting the image
- `--skip-parse` — reuse an existing `json/` instead of re-parsing
- `--skip-correlate` / `--skip-report` — stop before scoring / before generating the HTML report

Re-running just the scoring and report after changing correlation logic, without remounting or re-parsing:

```bash
sudo python3 full_forensic_profiler.py -e image.E01 -o /cases/output --skip-extract --skip-parse
```

### Running the acquisition/parsing stages individually

The two acquisition/parsing stages also work standalone, if you only need raw artifacts or JSON without scoring:

```bash
# Stage 1 — mount E01 and extract raw artifacts
bash mount_and_extract_hives.sh -e /path/to/image.E01 -o /cases/output
```

Optional flags: `-k` (keep mounted), `-v` (skip ewfverify). Extracted files land in `/cases/output/raw/`.

```bash
# Stage 2 — parse raw artifacts into JSON
bash extract_artifacts.sh -o /cases/output
```

Parsed JSON files land in `/cases/output/json/`. (`-m /mnt/img_<PID>` is only needed as a fallback if `extraction_report.txt` is missing — normally the parser reads the Windows version straight from that report.)

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

*(All paths below are relative to `forensic-profiler/`.)*

### `full_forensic_profiler.py`

Unified entry point. Orchestrates the other four stages in order — extraction, parsing, correlation, reporting — each as a step that can be individually skipped (`--skip-extract`, `--skip-parse`, `--skip-correlate`, `--skip-report`) so any stage can be re-run in isolation once its inputs already exist on disk. Reads `extraction_report.txt` between stages to recover the detected Windows version and mount point without re-touching the image.

`--setup` runs `setup_forensic_tools.sh` and exits, without needing `--image`/`--output`. On every normal pipeline run, `check_tool_availability()` does a cheap, read-only check for `ewfmount`, `mmls`, the .NET SDK, and the `python-registry`/`evtx` Python packages, and prints a warning (not a hard failure) if any are missing, pointing at `--setup`.

### `setup_forensic_tools.sh`

One-time setup script for a fresh Kali Linux VM. Runs 7 steps in sequence:

1. **APT packages** — installs `ewf-tools`, `sleuthkit`, `regripper`, `python3-evtx`, `python3-pylnk3`, `ntfs-3g`
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
  └─ [Step 5] Mount Windows partition — tries, in order: auto-detected offset,
              common MBR/GPT offsets, and finally offset 0 (logical/single-volume
              acquisitions with no partition table). Each offset tries ntfs-3g +
              loop device first, then kernel mount, then kernel offset mount.
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

If EZ Tools is installed, each step also runs the corresponding EZ tool (LECmd, EvtxECmd, RBCmd, etc.) as a supplemental output. The Python parsers always run regardless.

---

### `parsers/parse_user_accounts.py`

Parses the Windows `SAM` registry hive to extract local user accounts, then each user's `NTUSER.DAT` for autorun entries and typed path history.

**From SAM:** username, RID (user ID number), last login time, password last set, failed login count, total login count, account locked/disabled status.

**From NTUSER.DAT:** Run/RunOnce autostart entries (programs that launch at login), TypedPaths (folders the user manually typed into the address bar).

---

### `parsers/parse_application_activity.py`

Parses Windows Prefetch `.pf` files across every on-disk format Windows has used — v17 (XP), v23 (Vista/7), v26 (Win8), v30/v31 (Win10, MAM-compressed). Prefetch records every executable that ran on the system, along with a timestamp and run count — this tells you **what programs were executed and when**, even if the program has since been deleted. It also extracts Section C (the file-path string table) from each `.pf` file to recover the full path the executable ran from, which is what lets the correlation stage attribute a given run to a specific user account.

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

All browser databases are copied to a temp file before reading, along with their `-wal`/`-shm` WAL-mode sidecar files if present, so recent visits sitting only in the WAL (not yet checkpointed into the main database) aren't silently missed.

---

### `parsers/parse_document_folder_access.py`

Parses two artifact types that reveal what files and folders a user accessed:

- **LNK files** (Windows Shortcut files from the `Recent` folder): contain the target file path, timestamps (created/modified/accessed), file size, volume label, and drive type. Parsed with a hand-rolled `struct`-based parser rather than `pylnk3` — `pylnk3` has known failures on Windows 10 LNK files ("This is not a valid drive"), so this parser never depends on it.
- **Jump Lists** (`.automaticDestinations` / `.customDestinations` files): OLE compound files that record recently/frequently accessed items per application. The parser counts embedded LNK entries and extracts what it can without needing external OLE libraries.

---

### `parsers/parse_deleted_files.py`

Parses the Windows Recycle Bin in both formats:

- **Windows XP** (`RECYCLER/INFO2`): fixed 280-byte binary records per deleted file. Extracts original path, file size, deletion timestamp, and drive number.
- **Windows Vista/7/10/11** (`$Recycle.Bin/$I??????`): per-file `$I` metadata records containing original path, file size, and deletion timestamp (Windows FILETIME). The corresponding `$R` file holds the actual deleted file content.

---

### `correlation/engine.py`

Stage 3. Loads every JSON artifact produced by Stage 2 and builds one risk profile per OS account.

**Scoring.** Each of seven evidence categories contributes a weighted score, independently capped so that no single high-volume category (e.g. thousands of browser-history rows) can dominate the total:

| Category | Weight | Cap |
|---|---|---|
| Deleted files | 4 | 40 |
| Event log anomalies (failed logons, cleared logs, privilege escalation, …) | 4 | 60 |
| Application activity (recon/remote-access/execution/deletion/credential tools) | 3 | 30 |
| Network activity (internal/external/suspicious-destination tiers, incl. flagged domains surfaced from browser history) | 3 | 45 |
| Sensitive document access | 2 | 30 |
| User account flags (e.g. excessive failed logins) | 1 | 5 |
| Flagged browser history (anonymization/exfil/paste/hacking sites) | 0.5 | 20 |

The capped category scores are summed and scaled against a **fixed** ceiling — not the highest score seen in the current run — via a logarithmic transform, so the same evidence always produces the same score regardless of who else is in the same image, and scores stay comparable across different forensic images. A bonus is then added for cross-artifact temporal patterns: a file accessed and then deleted in quick succession, an application run followed by network activity, a burst of activity followed by a long silence, rapid repeated actions, or several independent artifact types active within the same short window — each pattern independently capped.

**Attribution.** A record is attributed to a user account via a resolvable path (`Users\<name>` / `Documents and Settings\<name>`) first, falling back to SID resolution — the account's RID, cross-referenced against `user_accounts.json` — when the path alone doesn't identify a user. Prefetch execution evidence poses a harder case, since a large share of Prefetch records point at system-wide installation paths carrying no per-user information at all; for that category specifically, a third fallback consults a per-user index built from each account's own UserAssist registry history (a ROT13-encoded record of GUI-launched programs stored in each user's own `NTUSER.DAT`), and attributes an execution to a specific account only when exactly one account's UserAssist history references that executable's basename — a tie between two or more candidate accounts is left unattributed rather than guessed at. Prefetch activity that still can't be attributed by any of these three mechanisms is retained as case-wide "shared pool" evidence but is **not** split across every account: doing so would give every account, including `Guest`/`HelpAssistant`/service accounts, a non-evidentiary score floor just for existing in the same image.

**Risk classification.** An account is first checked against a real-evidence gate: if every one of its seven category metrics is exactly zero, it is `LOW` immediately, regardless of what the score would otherwise evaluate to. Accounts that pass this gate are classified `HIGH` only when the final score reaches at least 18, evidence spans at least two independent categories, and at least one of those categories is drawn from a five-category "strong evidence" subset (deleted files, event anomalies, document access, application activity, network activity) — browser history and account flags corroborate but are never sufficient on their own. `MEDIUM` applies when the score reaches at least 6 or evidence spans at least two categories without meeting the `HIGH` score threshold; everything else is `LOW`. Every threshold is absolute, not computed relative to the other accounts present on the same image — percentile ranking guarantees someone is always "top 20%" even in an image with no real suspects. Every label carries a short `risk_rationale` string quoting the exact score, diversity count, and strong-category count that produced it.

**Security-log visibility.** Security-channel event auditing is disabled by default on Windows XP, so an unmodified XP image commonly has zero usable security-log evidence regardless of what the account actually did. `correlation_results.json`'s `summary.security_log_coverage` flags this explicitly (`status: "NO_VISIBILITY"` vs. `"OBSERVED"`, plus the raw event count) so a low event-anomaly score can be read correctly — as an absence of visibility, not a clean audit trail. This flag is report-only and never feeds back into scoring.

**Privileged-logon handling.** Event ID 4672 (and its legacy Windows XP equivalent, 576 — "an account was granted elevated privileges at logon") fires on every administrator-equivalent logon regardless of whether anything suspicious followed it, so it is excluded from independent scoring entirely. It can only contribute to an account's score through the timeline-correlation bonus above, and only when it falls within 30 minutes of some other, independently real piece of evidence for the same account. A privileged logon with no nearby corroborating evidence contributes nothing at all — this correction replaced an earlier version of the model that scored 4672 directly and, as a result, had ranked an uninvolved administrator account above the true suspect on the Adam case.

Domain/URL flagging (anonymization sites, exfil sites, paste sites, hacking tools) matches the hostname against a boundary-safe suffix check — `host == domain` or `host.endswith("." + domain)` — never a bare substring scan, which produces false positives from coincidental substrings unrelated to the actual domain (e.g. an ad-tracking token that happens to contain "i2p"). The same boundary check tiers network destinations into internal/external/suspicious. Suspicious-executable matching is an exact lookup of the cleaned filename against a table of known names, not a substring scan, so an unrelated binary that merely contains a keyword isn't mistaken for the real tool.

**Threats & anomalies.** Two additional read-only passes run over the scored results, feeding the HTML report's "Threats Detected" and "Anomalies" sections: `build_threats()` aggregates each rankable user's evidence into indicator-based threats (known-suspicious executable execution, contact with a flagged network/browser destination, anti-forensics/persistence events like log clearing or service installs), and `build_anomalies()` aggregates the timeline patterns and account-flag evidence already computed above. Neither pass touches scoring — they only re-describe evidence that's already been scored.

---

### `correlation/narrative.py`

Takes one already-scored user record (one entry of `user_correlations`) and turns it into an investigator-oriented narrative: a phased evidence chain with a time range and confidence rating per phase, a plain-language summary, and analyst notes on what to verify manually next. Deliberately offline and deterministic — it only reads fields already attached to the record by `engine.py` (never re-reads raw artifact JSON, never re-scores, no network calls, no LLM), so the narrative is reproducible and never disagrees with the score or risk label that produced it. Rendered in the report's "Investigation Narrative" section.

---

### `reporting/html_report.py`

Stage 4. Renders `forensic_report.html` — fully self-contained, no external assets. Sections:

- **Executive Summary** — artifact counts across the whole case.
- **Threats / Anomalies** — populated from `correlation/engine.py`'s `build_threats()`/`build_anomalies()` passes described above; not empty once there's scored evidence to describe.
- **User Activity Analysis** — one row per account: event/network/document/browser counts, risk score, risk label.
- **Investigation Timelines** — one expandable block per ranked account (`HIGH`/`MEDIUM` expanded by default) containing a **score breakdown** table (count + score contribution per category), a **chronological activity timeline** merging every timestamped piece of evidence attributed to that account (deletions, event anomalies, network connections, flagged browser visits, suspicious application runs, sensitive document access) in the order it happened, and — if the case has any — a separate **"System-Wide Activity (unattributed)"** block listing the shared-pool Prefetch executions that couldn't be tied to any specific account. The unattributed block is shown for investigator context only; it's identical across every account's card and is never counted toward that account's score.
- **Investigation Narrative** — one expandable block per ranked account rendering `correlation/narrative.py`'s phased evidence chain, summary, and analyst notes.

The engine's per-account `risk_rationale` string (the plain-language justification for `HIGH`/`MEDIUM`/`LOW`) is present in `correlation_results.json` but not yet surfaced anywhere in the HTML report — a known gap, not a missing computation.

---

## Forensic Datasets Used

| Image | OS | Source | Format | MD5 |
|---|---|---|---|---|
| M57-Jean (2009) | Windows XP | [Digital Corpora — M57-Jean](https://digitalcorpora.org/corpora/scenarios/m57-jean/) | .E01 | `78a52b5bac78f4e711607707ac0e3f93` |
| Lone Wolf Scenario (2018) | Windows 10 Education | [Digital Corpora — 2018 Lone Wolf Scenario](https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/) | .E01 | `7af48fa65519e84246b1729e5b68f140` |
| Adam Case | Windows 11 Education | Self-built controlled VM, FTK Imager acquisition (multi-segment E01) | .E01 | `5ca059eb0c86a2df28c3170ea27f83f5` |

> Always run `ewfverify` (or check `ewfinfo`'s `Is corrupted:` field) on a new image before relying on it — see [Troubleshooting](#troubleshooting).

---

## Environment Requirements

- **OS:** Kali Linux 2026.x (64-bit), kernel 6.x
- **VM name:** `CSIS4490_g05`
- **Python:** 3.x with `python-registry`, `python-evtx`/`evtx` (see `requirements.txt`) — everything else is standard library
- **Optional:** .NET 9 SDK + EZ Tools for supplemental output

Install everything with:
```bash
bash setup_forensic_tools.sh
pip install -r requirements.txt
```

---

## Troubleshooting

**Mount fails / "All mount attempts failed"**
`mount_and_extract_hives.sh` auto-detects the partition offset via `mmls`, falls back to a list of common MBR/GPT offsets, and finally tries offset `0` (for logical/single-volume acquisitions with no partition table at all) before giving up. If it still fails, read the *full* error text it prints for each attempt — a repeated `NTFS signature is missing` at every offset usually means the image itself is incomplete or corrupted, not a mounting bug. Confirm with:
```bash
ewfinfo /path/to/image.E01   # check "Is corrupted:" and total segment size vs. reported media size
```

**Report shows every non-primary account at exactly 0.0 / LOW**
This is expected, not a bug: an account's score comes only from evidence directly attributable to it, so accounts with no attributable evidence — only shared/unattributed activity — correctly score 0.0. Check `summary.unattributed_app_activity_weighted` in `correlation_results.json` to see the pooled, case-wide amount that was deliberately excluded from every individual score. If an account you *expect* to have real evidence still shows 0.0, check that its `evidence.*` arrays in the same file are non-empty — an empty result there means attribution failed (see `_resolve_user()` and its SID fallback in `correlation/engine.py`), not that the scoring is wrong.

**`sudo: a password is required` when re-running report generation only**
Output directories are root-owned from the mount/extract stage (mounting E01 images and reading NTFS/registry hives both require root). Re-run correlation/report generation with `sudo` too, or `chown` the output directory to your user once extraction is done.

---

## GitHub Repository

<https://github.com/Ha0n9/CSIS-4490---Digital-Forensic-Profiling-Tool>

This is that repository. `forensic-profiler/` is the actively developed pipeline described throughout this README; `Old structure/` holds the earlier, pre-unification scripts kept for reference only — see the commit history for the migration between the two.
