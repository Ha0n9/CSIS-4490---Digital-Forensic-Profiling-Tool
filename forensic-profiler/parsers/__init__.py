#!/usr/bin/env python3
"""
Parsers Package - All forensic artifact parsers

Each module in this package is designed to run standalone (`python3
parsers/parse_X.py --raw-dir ... --output ...`, as extract_artifacts.sh
invokes them) and does not define a module-level function named after
itself, so this package intentionally does not re-export one. Import the
specific function you need directly, e.g.
`from parsers.parse_deleted_files import parse_info2`.
"""
