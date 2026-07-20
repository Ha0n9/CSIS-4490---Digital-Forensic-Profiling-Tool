#!/usr/bin/env python3
"""
Parsers Package - All forensic artifact parsers
"""

from .parse_browser_history import parse_browser_history
from .parse_event_logs import parse_event_logs
from .parse_application_activity import parse_application_activity
from .parse_user_accounts import parse_user_accounts
from .parse_document_folder_access import parse_document_folder_access
from .parse_deleted_files import parse_deleted_files

__all__ = [
    'parse_browser_history',
    'parse_event_logs',
    'parse_application_activity',
    'parse_user_accounts',
    'parse_document_folder_access',
    'parse_deleted_files'
]
