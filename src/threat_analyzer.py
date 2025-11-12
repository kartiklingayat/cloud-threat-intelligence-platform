import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any
import re

class ThreatAnalyzer:
    def __init__(self):
        self.threat_intelligence = self.load_threat_intelligence()
        self.suspicious_patterns = self.load_suspicious_patterns()
    
    def load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence data"""
        return {
            'known_malicious_ips': ['192.168.1.100', '10.0.0.50'],  # Example data
            'suspicious_user_agents': ['nmap', 'sqlmap', 'metasploit'],
            'high_risk_regions': ['us-east-1', 'eu-west-1'],  # Regions with unusual activity
            'critical_operations': [
                'CreateUser', 'DeleteUser', 'ModifySecurityGroup',
                'CreateAccessKey', 'DeleteLogGroup', 'StopLogging'
            ]
        }
    
    def load_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """Define suspicious activity patterns"""
        return [
            {
                'name': 'privilege_escalation',
                'patterns': [
                    'CreateUser.*CreateAccessKey',
                    'AttachUserPolicy.*AdministratorAccess'
                ],
                'severity': 'HIGH'
            },
            {
                'name': 'data_exfiltration',
                'patterns': [
                    'GetObject.*CopyObject',
                    'ListBuckets.*GetObject'
                ],
                'severity': 'HIGH'
            },
            {
                'name': 'persistence',
                'patterns': [
                    'CreateTrail.*StopLogging',
                    'CreateAlarm.*DeleteAlarm'
                ],
                'severity': 'MEDIUM'
            }
        ]
    
    def analyze_events(self, events: pd.DataFrame) -> Dict[str, Any]:
        """Comprehensive threat analysis"""
        if events.empty:
            return {'threats_detected': 0, 'analysis': []}
        
        threats = []
        
        # Analyze each event for threats
        for _, event in events.iterrows():
            event_threats = self.analyze_single_event(event)
            threats.extend(event_threats)
        
        # Pattern-based analysis
        pattern_threats = self.analyze_behavioral_patterns(events)
        threats.extend(pattern_threats)
        
        # Reverse engineering analysis
        reverse_engineering_threats = self.reverse_engineer_suspicious_activity(events)
        threats.extend(reverse_engineering_threats)
        
        # Calculate threat metrics
        high_severity = len([t for t in threats if t['severity'] == 'HIGH'])
        medium_severity = len([t for t in threats if t['severity'] == 'MEDIUM'])
        
        return {
            'threats_detected': len(threats),
            'high_severity_threats': high_severity,
            'medium_severity_threats': medium_severity,
            'threats': threats,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
    
    def analyze_single_event(self, event: pd.Series) -> List[Dict[str, Any]]:
        """Analyze single event for potential threats"""
        threats = []
        
        # Check for known malicious IPs
        if event.get('source_ip') in self.threat_intelligence['known_malicious_ips']:
            threats.append({
                'threat_type': 'known_malicious_ip',
                'severity': 'HIGH',
                'description': f"Activity from known malicious IP: {event['source_ip']}",
                'event_details': event.to_dict(),
                'confidence': 0.95
            })
        
        # Check for suspicious user agents
        user_agent = str(event.get('user_agent', '')).lower()
        for suspicious_ua in self.threat_intelligence['suspicious_user_agents']:
            if suspicious_ua in user_agent:
                threats.append({
                    'threat_type': 'suspicious_user_agent',
                    'severity': 'MEDIUM',
                    'description': f"Suspicious user agent detected: {suspicious_ua}",
                    'event_details': event.to_dict(),
                    'confidence': 0.75
                })
        
        # Check for critical operations
        event_name = event.get('event_name', '')
        if event_name in self.threat_intelligence['critical_operations']:
            threats.append({
                'threat_type': 'critical_operation',
                'severity': 'HIGH',
                'description': f"Critical security operation detected: {event_name}",
                'event_details': event.to_dict(),
                'confidence': 0.85
            })
        
        return threats
    
    def analyze_behavioral_patterns(self, events: pd.DataFrame) -> List[Dict[str, Any]]:
        """Analyze sequences of events for suspicious patterns"""
        threats = []
        
        # Group events by user
        for user in events['user_identity'].unique():
            user_events = events[events['user_identity'] == user].sort_values('timestamp')
            event_sequence = ' '.join(user_events['event_name'].tolist())
            
            for pattern in self.suspicious_patterns:
                for regex_pattern in pattern['patterns']:
                    if re.search(regex_pattern, event_sequence):
                        threats.append({
                            'threat_type': pattern['name'],
                            'severity': pattern['severity'],
                            'description': f"Suspicious pattern detected: {pattern['name']}",
                            'user': user,
                            'event_sequence': event_sequence,
                            'confidence': 0.80
                        })
        
        return threats
    
    def reverse_engineer_suspicious_activity(self, events: pd.DataFrame) -> List[Dict[str, Any]]:
        """Reverse engineer and investigate suspicious activities"""
        threats = []
        
        # Analyze failed authentication attempts
        failed_auth = events[events['error_code'].notna()]
        if len(failed_auth) > 10:  # Threshold for brute force detection
            threats.append({
                'threat_type': 'possible_brute_force',
                'severity': 'HIGH',
                'description': f"Multiple failed authentication attempts: {len(failed_auth)}",
                'affected_users': failed_auth['user_identity'].nunique(),
                'confidence': 0.90
            })
        
        # Analyze unusual time patterns
        night_events = events[events['hour'].between(0, 5)]  # Midnight to 5 AM
        if len(night_events) > 5:
            threats.append({
                'threat_type': 'unusual_time_activity',
                'severity': 'MEDIUM',
                'description': f"Unusual activity during off-hours: {len(night_events)} events",
                'confidence': 0.70
            })
        
        # Analyze geographic anomalies
        unique_regions = events['region'].nunique()
        if unique_regions > 3:
            threats.append({
                'threat_type': 'geographic_anomaly',
                'severity': 'MEDIUM',
                'description': f"Activity from multiple regions: {unique_regions}",
                'confidence': 0.65
            })
        
        return threats
    
    def generate_threat_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive threat report"""
        report = [
            "🔍 CLOUD THREAT INTELLIGENCE REPORT",
            "=" * 50,
            f"Generated: {analysis_results['analysis_timestamp']}",
            f"Total Threats Detected: {analysis_results['threats_detected']}",
            f"High Severity: {analysis_results['high_severity_threats']}",
            f"Medium Severity: {analysis_results['medium_severity_threats']}",
            "",
            "📋 DETAILED THREAT ANALYSIS:",
            ""
        ]
        
        for i, threat in enumerate(analysis_results['threats'], 1):
            report.extend([
                f"{i}. {threat['threat_type'].upper()}",
                f"   Severity: {threat['severity']}",
                f"   Description: {threat['description']}",
                f"   Confidence: {threat['confidence']:.0%}",
                ""
            ])
        
        return "\n".join(report)

class RealTimeThreatMonitor:
    def __init__(self, threat_analyzer: ThreatAnalyzer):
        self.threat_analyzer = threat_analyzer
        self.threat_history = []
    
    def monitor_events(self, events: pd.DataFrame) -> Dict[str, Any]:
        """Monitor events in real-time for threats"""
        analysis = self.threat_analyzer.analyze_events(events)
        
        # Store in history
        self.threat_history.append({
            'timestamp': datetime.utcnow(),
            'analysis': analysis
        })
        
        # Keep only last 1000 analyses
        if len(self.threat_history) > 1000:
            self.threat_history = self.threat_history[-1000:]
        
        return analysis
    
    def get_threat_metrics(self) -> Dict[str, Any]:
        """Get threat detection metrics"""
        if not self.threat_history:
            return {}
        
        total_threats = sum(item['analysis']['threats_detected'] for item in self.threat_history)
        high_severity = sum(item['analysis']['high_severity_threats'] for item in self.threat_history)
        
        return {
            'total_threats_detected': total_threats,
            'high_severity_threats': high_severity,
            'monitoring_duration_hours': len(self.threat_history),
            'average_threats_per_hour': total_threats / max(1, len(self.threat_history))
        }
