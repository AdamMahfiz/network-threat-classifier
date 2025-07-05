"""
Enhanced Data Processing Module with Better Feature Engineering
"""

import pandas as pd
import numpy as np
import re
from typing import List
import hashlib

class DataProcessor:
    """Enhanced data preprocessing and feature extraction"""
    
    def __init__(self):
        # Define threat patterns with weights
        self.threat_patterns = {
            'high_threat': {
                'patterns': ['attack', 'malware', 'ddos', 'injection', 'exploit', 'breach', 'intrusion', 'ransomware', 'trojan', 'virus'],
                'weight': 2.0
            },
            'medium_threat': {
                'patterns': ['fail', 'error', 'scan', 'blocked', 'denied', 'unauthorized', 'suspicious', 'anomaly', 'brute'],
                'weight': 1.5
            },
            'security_events': {
                'patterns': ['login', 'admin', 'root', 'ssh', 'password', 'authentication', 'privilege'],
                'weight': 1.0
            },
            'network_events': {
                'patterns': ['connection', 'port', 'firewall', 'proxy', 'vpn', 'tunnel'],
                'weight': 0.5
            }
        }
        
        # Critical ports that indicate higher threat
        self.critical_ports = {
            '22': 2.0,    # SSH
            '23': 2.0,    # Telnet
            '3389': 2.0,  # RDP
            '1433': 1.5,  # SQL Server
            '3306': 1.5,  # MySQL
            '5432': 1.5,  # PostgreSQL
            '21': 1.0,    # FTP
            '25': 1.0,    # SMTP
            '53': 0.8,    # DNS
            '80': 0.3,    # HTTP (normal)
            '443': 0.3    # HTTPS (normal)
        }
    
    def process_logs(self, logs: List[str]) -> np.ndarray:
        """Process raw log entries with enhanced features"""
        features = []
        for log in logs:
            feature_vector = self._extract_enhanced_features(log.strip())
            features.append(feature_vector)
        return np.array(features)
    
    def process_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        """Process pandas DataFrame"""
        return df.select_dtypes(include=[np.number]).fillna(0).values
    
    def _extract_enhanced_features(self, log: str) -> List[float]:
        """Extract enhanced features from a single log entry"""
        features = []
        log_lower = log.lower()
        
        # 1. Log complexity score
        complexity = len(set(log)) / len(log) if log else 0
        features.append(complexity * 10)
        
        # 2-5. Threat pattern matching with weights
        for category, config in self.threat_patterns.items():
            score = 0
            for pattern in config['patterns']:
                if pattern in log_lower:
                    score += config['weight']
            features.append(score)
        
        # 6. Failed authentication score
        auth_fail_score = 0
        if re.search(r'(fail|error|invalid|incorrect).*(login|auth|password)', log_lower):
            auth_fail_score = 8.0
        elif 'failed' in log_lower and any(word in log_lower for word in ['login', 'auth', 'password']):
            auth_fail_score = 6.0
        features.append(auth_fail_score)
        
        # 7. Attack signature detection
        attack_signatures = [
            r'(ddos|dos)\s+attack',
            r'port\s+scan',
            r'brute\s+force',
            r'sql\s+injection',
            r'buffer\s+overflow',
            r'malware\s+(detected|found)',
            r'virus\s+(detected|found)'
        ]
        attack_score = 0
        for signature in attack_signatures:
            if re.search(signature, log_lower):
                attack_score += 3.0
        features.append(attack_score)
        
        # 8. IP address analysis
        ip_addresses = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
        ip_score = 0
        for ip in ip_addresses:
            # Check for private vs public IPs
            if ip.startswith(('192.168.', '10.', '172.')):
                ip_score += 0.3
            else:
                ip_score += 0.8
        features.append(ip_score)
        
        # 9. Port analysis with weighted scoring
        port_score = 0
        for port, weight in self.critical_ports.items():
            if f'port {port}' in log_lower or f':{port}' in log:
                port_score += weight
        features.append(port_score)
        
        # 10. Time-based anomaly detection
        time_anomaly = 0
        if re.search(r'(timeout|delay|slow|hang)', log_lower):
            time_anomaly = 4.0
        elif re.search(r'(quick|fast|rapid|burst)', log_lower):
            time_anomaly = 2.0
        features.append(time_anomaly)
        
        # 11. User privilege analysis
        privilege_score = 0
        high_priv_users = ['admin', 'administrator', 'root', 'system', 'service']
        for user in high_priv_users:
            if user in log_lower:
                privilege_score += 3.0
        features.append(privilege_score)
        
        # 12. Network protocol analysis
        protocol_score = 0
        protocols = {
            'ssh': 3.0, 'telnet': 4.0, 'ftp': 2.0, 'smtp': 2.0,
            'http': 0.5, 'https': 0.5, 'dns': 1.0
        }
        for protocol, weight in protocols.items():
            if protocol in log_lower:
                protocol_score += weight
        features.append(protocol_score)
        
        # 13. Frequency indicators
        frequency_score = 0
        frequency_words = ['multiple', 'repeated', 'continuous', 'burst', 'flood']
        for word in frequency_words:
            if word in log_lower:
                frequency_score += 3.0
        features.append(frequency_score)
        
        # 14. Security action response
        security_response = 0
        response_actions = ['blocked', 'denied', 'rejected', 'dropped', 'quarantined', 'isolated']
        for action in response_actions:
            if action in log_lower:
                security_response += 1.0
        features.append(security_response)
        
        # 15. Data exfiltration indicators
        exfiltration_score = 0
        exfil_keywords = ['download', 'upload', 'transfer', 'copy', 'export', 'backup']
        for keyword in exfil_keywords:
            if keyword in log_lower:
                exfiltration_score += 0.5
        features.append(exfiltration_score)
        
        # 16. Normal activity indicators (negative weight - increased effect)
        normal_score = 0
        normal_indicators = ['successful', 'normal', 'routine', 'scheduled', 'maintenance', 'regular', 'standard', 'completed', 'established']
        for indicator in normal_indicators:
            if indicator in log_lower:
                normal_score -= 4.0
        features.append(normal_score)
        
        # 17. Log source credibility
        source_score = 0
        if any(source in log_lower for source in ['firewall', 'ids', 'ips', 'antivirus']):
            source_score = 2.0  # More credible sources
        features.append(source_score)
        
        # 18. Severity keywords
        severity_score = 0
        severity_keywords = {
            'critical': 5.0, 'high': 4.0, 'medium': 2.0, 'low': 1.0,
            'warning': 2.0, 'alert': 3.0, 'emergency': 5.0
        }
        for keyword, weight in severity_keywords.items():
            if keyword in log_lower:
                severity_score += weight
        features.append(severity_score)
        
        # 19. Geolocation indicators
        geo_score = 0
        suspicious_countries = ['china', 'russia', 'north korea', 'iran']
        for country in suspicious_countries:
            if country in log_lower:
                geo_score += 4.0
        features.append(geo_score)
        
        # 20. Log entropy (randomness indicator)
        entropy = self._calculate_entropy(log)
        features.append(entropy * 5)
        
        return features[:20]
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
