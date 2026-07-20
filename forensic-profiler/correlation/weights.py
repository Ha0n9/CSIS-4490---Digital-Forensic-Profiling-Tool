#!/usr/bin/env python3
"""
Correlation Weights - Scoring weights for suspicious activities
"""

from dataclasses import dataclass


@dataclass
class ScoreWeights:
    """Scoring weights for correlation engine"""
    
    # Event weights
    SUSPICIOUS_EVENT: int = 10
    CRITICAL_EVENT: int = 25
    SYSTEM_EVENT: int = 5
    
    # Network weights
    SUSPICIOUS_NETWORK: int = 15
    TOR_CONNECTION: int = 30
    MALICIOUS_IP: int = 40
    
    # File weights
    SENSITIVE_FILE: int = 10
    SYSTEM_FILE: int = 5
    DELETED_FILE: int = 8
    
    # User weights
    PRIVILEGED_USER: int = 5
    ADMIN_USER: int = 10
    
    # Pattern weights
    OFF_HOURS_ACTIVITY: int = 15
    FAILED_LOGIN_BRUTE_FORCE: int = 25
    RAPID_SERVICE_INSTALL: int = 20
    
    # Thresholds
    LOW_RISK_THRESHOLD: int = 20
    MEDIUM_RISK_THRESHOLD: int = 50
    HIGH_RISK_THRESHOLD: int = 80
    
    def calculate_user_score(
        self,
        events: list,
        network_connections: list,
        file_accesses: list,
        rules #CorrelationRules
    ) -> int:
        """Calculate risk score for a user"""
        score = 0
        
        # Check events
        for event in events:
            if rules.is_suspicious_event(event):
                score += self.SUSPICIOUS_EVENT
                
                # Critical events get extra weight
                if event.get("event_id") in [4672, 4720, 7045]:
                    score += self.CRITICAL_EVENT
        
        # Check network connections
        for conn in network_connections:
            if rules.is_suspicious_connection(conn):
                score += self.SUSPICIOUS_NETWORK
        
        # Check file accesses
        for file in file_accesses:
            if rules.is_sensitive_file(file):
                score += self.SENSITIVE_FILE
        
        # Check patterns
        if rules.detect_off_hours_activity(events) > 5:
            score += self.OFF_HOURS_ACTIVITY
        
        if rules.detect_failed_login_anomaly(events):
            score += self.FAILED_LOGIN_BRUTE_FORCE
        
        return min(100, score)
