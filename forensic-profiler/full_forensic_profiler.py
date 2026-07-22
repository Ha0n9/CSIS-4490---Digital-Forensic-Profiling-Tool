#!/usr/bin/env python3
"""
forensic_profiler.py — Unified Entry Point
============================================
Orchestrates the complete forensic pipeline by calling existing scripts:

  Stage 1 : mount_and_extract_hives.sh   (mount E01 + extract raw artifacts)
  Stage 2 : extract_artifacts.sh         (parse raw → JSON)
  Stage 3 : correlation/engine.py        (correlate artifacts)
  Stage 4 : reporting/html_report.py     (generate HTML report)

Usage:
    python3 full_forensic_profiler.py --image /cases/suspect.E01 --output /cases/output/
    python3 full_forensic_profiler.py --image /cases/suspect.E01 --output /cases/output/ --skip-extract
    python3 full_forensic_profiler.py --image /cases/suspect.E01 --output /cases/output/ --skip-parse
    python3 full_forensic_profiler.py --image /cases/suspect.E01 --output /cases/output/ --keep-mounted
"""

import argparse
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple

# ── Colors ────────────────────────────────────────────────────────────────────
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m'

def log_info(msg):    print(f"{BLUE}[*]{NC} {msg}")
def log_success(msg): print(f"{GREEN}[✓]{NC} {msg}")
def log_warn(msg):    print(f"{YELLOW}[!]{NC} {msg}")
def log_error(msg):   print(f"{RED}[✗]{NC} {msg}")
def log_step(msg):    print(f"\n{CYAN}{BOLD}━━━ {msg} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")

# ── Setup logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('profiler')

# ── Constants ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.absolute()
PARSERS_DIR = PROJECT_ROOT / 'parsers'
CORRELATION_DIR = PROJECT_ROOT / 'correlation'
REPORTING_DIR = PROJECT_ROOT / 'reporting'

# Add to Python path for imports
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(CORRELATION_DIR))
sys.path.insert(0, str(REPORTING_DIR))


def run_setup(project_root: Path) -> int:
    """
    Run setup_forensic_tools.sh, streaming its output directly to the
    terminal (no capture_output) so the install's sudo password prompt and
    multi-minute download progress behave exactly as they would running the
    script by hand. Returns the script's exit code.
    """
    script_path = project_root / 'setup_forensic_tools.sh'
    if not script_path.exists():
        log_error(f"Setup script not found: {script_path}")
        return 1
    log_step("Installing / Verifying Forensic Tooling")
    result = subprocess.run(["bash", str(script_path)])
    return result.returncode


def check_tool_availability() -> List[str]:
    """
    Cheap, read-only check for the tooling extraction/parsing depend on
    (ewf-tools, sleuthkit, .NET 9 for the EZ Tools, and the Python parser
    packages). Returns human-readable descriptions of what's missing —
    never installs or modifies anything itself; that's setup_forensic_tools.sh's
    job, run explicitly via --setup.
    """
    missing = []
    if not shutil.which("ewfmount"):
        missing.append("ewfmount (ewf-tools)")
    if not shutil.which("mmls"):
        missing.append("mmls (sleuthkit)")
    if not (Path.home() / ".dotnet" / "dotnet").exists():
        missing.append(".NET 9 SDK (~/.dotnet) — needed for EZ Tools")
    for module, label in (("Registry", "python-registry"), ("evtx", "evtx")):
        try:
            __import__(module)
        except ImportError:
            missing.append(f"{label} (Python package)")
    return missing


class ForensicProfiler:
    """Orchestrates the forensic pipeline by calling existing scripts/modules"""
    
    def __init__(
        self,
        image_path: str,
        output_dir: str,
        keep_mounted: bool = False,
        skip_verify: bool = False
    ):
        self.image_path = Path(image_path)
        self.output_dir = Path(output_dir)
        self.keep_mounted = keep_mounted
        self.skip_verify = skip_verify
        
        # Output subdirectories
        self.raw_dir = self.output_dir / 'raw'
        self.json_dir = self.output_dir / 'json'
        self.report_dir = self.output_dir / 'reports'
        
        # Create directories
        for d in [self.output_dir, self.raw_dir, self.json_dir, self.report_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # State
        self.mount_point = None
        self.win_version = None
        self.extraction_report = None
        
        log_info(f"Output directory: {self.output_dir}")
    
    def _run_script(self, script_name: str, args: List[str]) -> Tuple[bool, str]:
        """Run a bash script and capture output"""
        script_path = PROJECT_ROOT / script_name
        if not script_path.exists():
            log_error(f"Script not found: {script_path}")
            return False, "Script not found"
        
        cmd = ["bash", str(script_path)] + args
        log_info(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Print stdout in real-time (for user feedback)
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        print(line)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                log_error(f"Script failed with code {result.returncode}")
                if result.stderr:
                    log_error(f"Error: {result.stderr[:500]}")
                return False, result.stderr
                
        except Exception as e:
            log_error(f"Failed to run script: {e}")
            return False, str(e)
    
    def _read_extraction_report(self) -> Optional[Dict]:
        """Read Windows version and mount point from extraction report"""
        report_file = self.output_dir / 'extraction_report.txt'
        if not report_file.exists():
            return None
        
        report_data = {}
        try:
            with open(report_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        key = key.strip().lower().replace(' ', '_')
                        value = value.strip()
                        
                        if key == 'windows_ver':
                            report_data['windows_version'] = value
                        elif key == 'mount_method':
                            report_data['mount_method'] = value
                        elif key == 'total_extracted':
                            report_data['total_extracted'] = value.replace('files', '').strip()
                        elif key == 'failed/missing':
                            report_data['failed_missing'] = value
                        elif key == 'e01_image':
                            report_data['e01_image'] = value
                        elif key == 'output_dir':
                            report_data['output_dir'] = value
            return report_data
        except Exception as e:
            log_warn(f"Failed to parse extraction report: {e}")
            return None
    
    def step1_extract(self) -> bool:
        """Step 1: Mount E01 and extract raw artifacts"""
        log_step("Step 1: Mount and Extract Raw Artifacts")
        
        # Check if raw artifacts already exist
        if self.raw_dir.exists() and any(self.raw_dir.iterdir()):
            log_warn(f"Raw artifacts already exist in {self.raw_dir}")
            self.extraction_report = self._read_extraction_report()
            if self.extraction_report:
                self.win_version = self.extraction_report.get('windows_version', 'unknown')
                log_info(f"Windows version from report: {self.win_version}")
            return True
        
        # Validate image exists
        if not self.image_path.exists():
            log_error(f"Image not found: {self.image_path}")
            return False
        
        args = [
            "-e", str(self.image_path),
            "-o", str(self.output_dir)
        ]
        if self.keep_mounted:
            args.append("-k")
        if self.skip_verify:
            args.append("-v")
        
        success, _ = self._run_script("mount_and_extract_hives.sh", args)
        
        if success:
            # Read extraction report
            self.extraction_report = self._read_extraction_report()
            if self.extraction_report:
                self.win_version = self.extraction_report.get('windows_version', 'unknown')
                log_info(f"Windows version: {self.win_version}")
            
            log_success("Extraction complete")
            return True
        
        return False
    
    def step2_parse(self) -> bool:
        """Step 2: Parse raw artifacts to JSON"""
        log_step("Step 2: Parse Raw Artifacts to JSON")
        
        if not self.raw_dir.exists() or not any(self.raw_dir.iterdir()):
            log_error("No raw artifacts found. Run extraction first or use --skip-extract")
            return False
        
        if self.json_dir.exists() and any(self.json_dir.glob("*.json")):
            log_warn(f"JSON artifacts already exist in {self.json_dir}")
            return True
        
        # Try to find mount point from extraction report
        mount_point = None
        report_file = self.output_dir / 'extraction_report.txt'
        if report_file.exists():
            with open(report_file, 'r') as f:
                content = f.read()
                import re
                match = re.search(r'-m\s+(\S+)', content)
                if match:
                    mount_point = match.group(1)
                    log_info(f"Found mount point from report: {mount_point}")
        
        # If not found, try to find any img_* directory in /mnt
        if not mount_point:
            import subprocess
            result = subprocess.run(
                ["sudo", "find", "/mnt", "-maxdepth", "1", "-name", "img_*", "-type", "d"],
                capture_output=True, text=True
            )
            if result.stdout.strip():
                mount_point = result.stdout.strip().split('\n')[0]
                log_info(f"Found mount point in /mnt: {mount_point}")
        
        # Build args - mount point is now optional
        args = ["-o", str(self.output_dir)]
        if mount_point and Path(mount_point).exists():
            args.extend(["-m", mount_point])
        else:
            log_warn("No mount point found, parsing without -m flag")
        
        success, _ = self._run_script("extract_artifacts.sh", args)
        
        if success:
            log_success("Parsing complete")
            return True
        
        return False
    
    def step3_correlate(self) -> bool:
        """Step 3: Correlate artifacts"""
        log_step("Step 3: Correlate Artifacts")
        
        # Check if JSON exists
        if not self.json_dir.exists():
            log_error("No JSON artifacts found. Run parsing first or use --skip-parse")
            return False
        
        try:
            from correlation.engine import CorrelationEngine
            
            engine = CorrelationEngine(
                json_dir=str(self.json_dir),
                output_dir=str(self.report_dir)
            )
            
            results = engine.run()
            
            # Save summary
            summary_file = self.report_dir / "correlation_summary.json"
            with open(summary_file, "w") as f:
                json.dump(results, f, indent=2, default=str)
            
            log_success(f"Correlation complete: {len(results.get('user_correlations', []))} users analyzed")
            return True
            
        except ImportError as e:
            log_error(f"Failed to import correlation engine: {e}")
            log_info("Make sure correlation/__init__.py and correlation/engine.py exist")
            return False
        except Exception as e:
            log_error(f"Correlation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def step4_report(self) -> bool:
        """Step 4: Generate HTML report"""
        log_step("Step 4: Generate Report")
        
        try:
            from reporting.html_report import HTMLReporter
            
            reporter = HTMLReporter(
                json_dir=str(self.json_dir),
                correlated_dir=str(self.report_dir),
                output_dir=str(self.report_dir)
            )
            
            report_path = reporter.generate()
            
            log_success(f"Report generated: {report_path}")
            return True
            
        except ImportError as e:
            log_error(f"Failed to import reporting module: {e}")
            log_info("Make sure reporting/__init__.py and reporting/html_report.py exist")
            return False
        except Exception as e:
            log_error(f"Report generation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run(self) -> bool:
        """Run the full pipeline"""
        log_info("\n" + "=" * 60)
        log_info("Starting Forensic Profiler")
        log_info(f"Image: {self.image_path}")
        log_info("=" * 60)
        
        steps = [
            ("Extraction", self.step1_extract),
            ("Parsing", self.step2_parse),
            ("Correlation", self.step3_correlate),
            ("Reporting", self.step4_report),
        ]
        
        for step_name, step_func in steps:
            if not step_func():
                log_error(f"Pipeline failed at: {step_name}")
                return False
        
        # Summary
        log_info("\n" + "=" * 60)
        log_success("Forensic Profiling Complete!")
        log_info("=" * 60)
        log_info(f"  Output     : {self.output_dir}")
        log_info(f"  Raw        : {self.raw_dir}")
        log_info(f"  JSON       : {self.json_dir}")
        log_info(f"  Reports    : {self.report_dir}")
        log_info("=" * 60)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Forensic Profiler - Unified Entry Point",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline
  python3 full_forensic_profiler.py -e /cases/suspect.E01 -o ./output

  # Skip extraction (use existing raw artifacts)
  python3 full_forensic_profiler.py -e /cases/suspect.E01 -o ./output --skip-extract

  # Skip parsing (use existing JSON)
  python3 full_forensic_profiler.py -e /cases/suspect.E01 -o ./output --skip-parse

  # Keep image mounted
  python3 full_forensic_profiler.py -e /cases/suspect.E01 -o ./output --keep-mounted

  # Install/verify required forensic tooling (EZ Tools, ewf-tools, .NET, etc.)
  # instead of running setup_forensic_tools.sh by hand
  python3 full_forensic_profiler.py --setup
        """
    )

    parser.add_argument(
        "-e", "--image",
        help="Path to E01 image file (not required with --setup)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output directory for all artifacts (not required with --setup)"
    )

    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run setup_forensic_tools.sh to install/verify required tooling, then exit"
    )

    parser.add_argument(
        "-k", "--keep-mounted",
        action="store_true",
        help="Keep image mounted after extraction"
    )
    
    parser.add_argument(
        "-v", "--skip-verify",
        action="store_true",
        help="Skip E01 verification (ewfverify)"
    )
    
    parser.add_argument(
        "--skip-extract",
        action="store_true",
        help="Skip extraction (use existing raw artifacts)"
    )
    
    parser.add_argument(
        "--skip-parse",
        action="store_true",
        help="Skip parsing (use existing JSON artifacts)"
    )
    
    parser.add_argument(
        "--skip-correlate",
        action="store_true",
        help="Skip correlation"
    )
    
    parser.add_argument(
        "--skip-report",
        action="store_true",
        help="Skip report generation"
    )
    
    args = parser.parse_args()

    # --setup runs the tooling installer and exits; it doesn't need an image
    # or output dir, and shouldn't be combined with a pipeline run in the
    # same invocation (sudo apt/dpkg installs are a separate, explicit action).
    if args.setup:
        sys.exit(run_setup(PROJECT_ROOT))

    if not args.image or not args.output:
        parser.error("--image and --output are required (unless using --setup)")

    # Validate inputs
    if not args.skip_extract and not Path(args.image).exists():
        log_error(f"Image file not found: {args.image}")
        sys.exit(1)

    # Warn (don't block) if tooling extraction/parsing depend on looks
    # incomplete — run with --setup first to install it.
    if not (args.skip_extract and args.skip_parse):
        missing = check_tool_availability()
        if missing:
            log_warn("Some tooling required for extraction/parsing appears to be missing:")
            for item in missing:
                log_warn(f"    - {item}")
            log_warn("Run 'python3 full_forensic_profiler.py --setup' to install it, or continue if you know it's already set up elsewhere.")

    # Create profiler
    profiler = ForensicProfiler(
        image_path=args.image,
        output_dir=args.output,
        keep_mounted=args.keep_mounted,
        skip_verify=args.skip_verify
    )

    # Run pipeline with skips
    if args.skip_extract and args.skip_parse and args.skip_correlate and args.skip_report:
        log_warn("All steps skipped! Nothing to do.")
        sys.exit(0)

    try:
        # Step 1: Extract (unless skipped)
        if not args.skip_extract:
            if not profiler.step1_extract():
                sys.exit(1)
        
        # Step 2: Parse (unless skipped)
        if not args.skip_parse:
            if not profiler.step2_parse():
                sys.exit(1)
        
        # Step 3: Correlate (unless skipped)
        if not args.skip_correlate:
            if not profiler.step3_correlate():
                sys.exit(1)
        
        # Step 4: Report (unless skipped)
        if not args.skip_report:
            if not profiler.step4_report():
                sys.exit(1)
        
        # Success
        log_success("\nPipeline completed successfully!")
        log_info(f"  Output: {profiler.output_dir}")
        log_info(f"  Report: {profiler.report_dir}/forensic_report.html")
        sys.exit(0)
        
    except KeyboardInterrupt:
        log_warn("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
