#!/usr/bin/env python3
"""
Correlation Rules - Detection rules for suspicious activity
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta


class CorrelationRules:
    """Detection rules for forensic artifacts"""
    
    def __init__(self):
        # Suspicious event IDs (Windows Security Events)
        self.suspicious_events = {
            4624: "Successful logon",
            4625: "Failed logon",
            4634: "Logoff",
            4648: "Logon with explicit credentials",
            4672: "Special privileges assigned",
            4688: "Process creation",
            4720: "User created",
            4728: "User added to group",
            4732: "Group membership",
            4768: "Kerberos TGT requested",
            4776: "Domain authentication",
            7045: "Service installed"
        }
        
        # Suspicious event patterns
        self.suspicious_patterns = {
            "failed_logins": {"threshold": 5, "window_hours": 1},
            "off_hours_logins": {"start_hour": 2, "end_hour": 4},
            "service_installations": {"threshold": 3, "window_hours": 24}
        }
    
    def is_suspicious_event(self, event: Dict) -> bool:
        """Check if an event is suspicious"""
        event_id = event.get("event_id")
        return event_id in self.suspicious_events
    
    def is_suspicious_connection(self, connection: Dict) -> bool:
        """Check if a network connection is suspicious"""
        dest = connection.get("destination", "").lower()
        if not dest:
            return False
        
        # Check for TOR/Onion
        if "tor" in dest or "onion" in dest:
            return True
        
        # Check for known malicious domains (simplified)
        suspicious_domains = ["malware", "ransomware", "phishing"]
        for domain in suspicious_domains:
            if domain in dest:
                return True
        
        return False
    
    def is_sensitive_file(self, file_info: Dict) -> bool:
        """Check if file access is sensitive"""
        path = file_info.get("target_path", "").lower()
        if not path:
            return False
        
        sensitive_patterns = [
            ".sam", ".ntuser.dat", ".system", ".security", ".software",
            ".pwd", ".key", ".pem", ".pfx", ".enc", ".crypt"
        ]
        
        return any(pattern in path for pattern in sensitive_patterns)
    
    def detect_failed_login_anomaly(self, events: List[Dict]) -> bool:
        """Detect excessive failed logins within time window"""
        failed_logins = []
        threshold = self.suspicious_patterns["failed_logins"]["threshold"]
        window = self.suspicious_patterns["failed_logins"]["window_hours"]
        
        for event in events:
            if event.get("event_id") == 4625:  # Failed logon
                timestamp = event.get("timestamp")
                if timestamp:
                    failed_logins.append(timestamp)
        
        if len(failed_logins) >= threshold:
            # Check if they occurred within the time window
            try:
                times = [datetime.fromisoformat(ts) for ts in failed_logins if ts]
                if times:
                    earliest = min(times)
                    latest = max(times)
                    delta = (latest - earliest).total_seconds() / 3600
                    if delta <= window:
                        return True
            except:
                pass
        
        return False
    
    def detect_off_hours_activity(self, events: List[Dict]) -> int:
        """Count events occurring during off-hours (2-4 AM)"""
        count = 0
        start_hour = self.suspicious_patterns["off_hours_logins"]["start_hour"]
        end_hour = self.suspicious_patterns["off_hours_logins"]["end_hour"]
        
        for event in events:
            timestamp = event.get("timestamp")
            if timestamp:
                try:
                    dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
                    hour = dt.hour
                    if start_hour <= hour <= end_hour:
                        count += 1
                except:
                    pass
        
        return count


class ThreatIntel:
    """Threat intelligence integration (simplified)"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.known_hashes = set()
    
    def load_from_file(self, filepath: str):
        """Load threat intel from file"""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '.' in line and ':' not in line:
                            self.malicious_domains.add(line.lower())
                        elif ':' in line:
                            self.malicious_ips.add(line)
        except:
            pass
    
    def check_ip(self, ip: str) -> bool:
        """Check if IP is malicious"""
        return ip in self.malicious_ips
    
    def check_domain(self, domain: str) -> bool:
        """Check if domain is malicious"""
        return domain.lower() in self.malicious_domains
    
    def check_hash(self, hash_val: str) -> bool:
        """Check if hash is known malicious"""
        return hash_val in self.known_hashes
