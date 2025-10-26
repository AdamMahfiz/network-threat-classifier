"""
Threat Detection Settings Module

This module contains configurable settings for threat detection thresholds,
escalation rules, and monitoring parameters.
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ThreatThresholds:
    """Configurable threat detection thresholds"""
    
    # Packet rate thresholds (packets per second)
    low_threat_pps: int = 3000
    medium_threat_pps: int = 10000
    high_threat_pps: int = 50000
    
    # Port scan detection thresholds
    port_scan_medium: int = 25
    port_scan_high: int = 50
    
    # ICMP flood detection thresholds
    icmp_flood_medium: int = 75
    icmp_flood_high: int = 100
    
    # Protocol anomaly thresholds
    icmp_ratio_threshold: float = 0.9
    icmp_packet_minimum: int = 50


@dataclass
class EscalationRules:
    """Threat escalation rules and timing"""
    
    # Time thresholds for escalation
    sustained_threshold_seconds: float = 3.0
    burst_window_seconds: float = 60.0
    
    # Burst detection parameters
    min_bursts_for_escalation: int = 3
    burst_threshold_multiplier: float = 0.8  # 80% of threshold to count as burst
    
    # Escalation cooldown (prevent rapid escalations)
    escalation_cooldown_seconds: float = 10.0


class ThreatTracker:
    """Tracks threat levels and handles escalation logic"""
    
    def __init__(self, thresholds: ThreatThresholds, rules: EscalationRules):
        self.thresholds = thresholds
        self.rules = rules
        
        # Tracking data
        self.packet_rate_history: List[Dict] = []
        self.threat_level_history: List[Dict] = []
        self.last_escalation_time: float = 0
        self.burst_events: List[Dict] = []
        
    def evaluate_threat_level(self, packets_per_second: float) -> str:
        """Evaluate base threat level based on packet rate"""
        current_time = time.time()
        
        # Determine base threat level
        if packets_per_second >= self.thresholds.high_threat_pps:
            base_level = 'high'
        elif packets_per_second >= self.thresholds.medium_threat_pps:
            base_level = 'medium'
        elif packets_per_second >= self.thresholds.low_threat_pps:
            base_level = 'low'
        else:
            base_level = 'normal'
        
        # Record packet rate
        self.packet_rate_history.append({
            'time': current_time,
            'pps': packets_per_second,
            'base_level': base_level
        })
        
        # Clean old history (keep last 5 minutes)
        cutoff_time = current_time - 300
        self.packet_rate_history = [
            entry for entry in self.packet_rate_history 
            if entry['time'] > cutoff_time
        ]
        
        # Check for escalation conditions
        escalated_level = self._check_escalation(base_level, current_time)
        
        # Record final threat level
        self.threat_level_history.append({
            'time': current_time,
            'base_level': base_level,
            'final_level': escalated_level,
            'pps': packets_per_second
        })
        
        return escalated_level
    
    def _check_escalation(self, base_level: str, current_time: float) -> str:
        """Check if threat level should be escalated based on rules"""
        
        # Check cooldown period
        if current_time - self.last_escalation_time < self.rules.escalation_cooldown_seconds:
            return base_level
        
        # Check for sustained high traffic
        sustained_escalation = self._check_sustained_threat(current_time)
        
        # Check for burst patterns
        burst_escalation = self._check_burst_pattern(current_time)
        
        # Apply escalation
        final_level = base_level
        
        if sustained_escalation or burst_escalation:
            final_level = self._escalate_level(base_level)
            self.last_escalation_time = current_time
            
            # Log escalation reason
            reason = []
            if sustained_escalation:
                reason.append("sustained_traffic")
            if burst_escalation:
                reason.append("burst_pattern")
            
            print(f"🔺 Threat escalated from {base_level} to {final_level} due to: {', '.join(reason)}")
        
        return final_level
    
    def _check_sustained_threat(self, current_time: float) -> bool:
        """Check if traffic has been above threshold for sustained period"""
        
        # Look back for sustained threshold period
        lookback_time = current_time - self.rules.sustained_threshold_seconds
        
        # Get recent entries within the sustained period
        recent_entries = [
            entry for entry in self.packet_rate_history
            if entry['time'] >= lookback_time and entry['base_level'] != 'normal'
        ]
        
        # Check if we have consistent threat level for the entire period
        if len(recent_entries) >= 3:  # At least 3 data points
            # Check if all recent entries are above low threat threshold
            all_above_threshold = all(
                entry['pps'] >= self.thresholds.low_threat_pps 
                for entry in recent_entries
            )
            
            return all_above_threshold
        
        return False
    
    def _check_burst_pattern(self, current_time: float) -> bool:
        """Check for repeated bursts within the burst window"""
        
        # Look back for burst window
        lookback_time = current_time - self.rules.burst_window_seconds
        
        # Find burst events (traffic above 80% of low threshold)
        burst_threshold = self.thresholds.low_threat_pps * self.rules.burst_threshold_multiplier
        
        recent_bursts = []
        for entry in self.packet_rate_history:
            if (entry['time'] >= lookback_time and 
                entry['pps'] >= burst_threshold):
                recent_bursts.append(entry)
        
        # Group bursts (events within 5 seconds are considered same burst)
        burst_groups = []
        current_group = []
        
        for burst in sorted(recent_bursts, key=lambda x: x['time']):
            if (not current_group or 
                burst['time'] - current_group[-1]['time'] <= 5):
                current_group.append(burst)
            else:
                if current_group:
                    burst_groups.append(current_group)
                current_group = [burst]
        
        if current_group:
            burst_groups.append(current_group)
        
        # Check if we have enough burst groups
        return len(burst_groups) >= self.rules.min_bursts_for_escalation
    
    def _escalate_level(self, current_level: str) -> str:
        """Escalate threat level by one step"""
        escalation_map = {
            'normal': 'low',
            'low': 'medium',
            'medium': 'high',
            'high': 'high'  # Can't escalate beyond high
        }
        return escalation_map.get(current_level, current_level)
    
    def get_statistics(self) -> Dict:
        """Get current threat tracking statistics"""
        current_time = time.time()
        
        # Recent activity (last 5 minutes)
        recent_time = current_time - 300
        recent_history = [
            entry for entry in self.packet_rate_history
            if entry['time'] > recent_time
        ]
        
        if not recent_history:
            return {
                'avg_pps': 0,
                'max_pps': 0,
                'threat_events': 0,
                'escalations': 0
            }
        
        avg_pps = sum(entry['pps'] for entry in recent_history) / len(recent_history)
        max_pps = max(entry['pps'] for entry in recent_history)
        
        threat_events = len([
            entry for entry in recent_history
            if entry['base_level'] != 'normal'
        ])
        
        escalations = len([
            entry for entry in self.threat_level_history
            if (entry['time'] > recent_time and 
                entry['final_level'] != entry['base_level'])
        ])
        
        return {
            'avg_pps': round(avg_pps, 1),
            'max_pps': round(max_pps, 1),
            'threat_events': threat_events,
            'escalations': escalations
        }


# Default configuration instances
DEFAULT_THRESHOLDS = ThreatThresholds()
DEFAULT_ESCALATION_RULES = EscalationRules()

# Global threat tracker instance
threat_tracker = ThreatTracker(DEFAULT_THRESHOLDS, DEFAULT_ESCALATION_RULES)


def get_threat_tracker() -> ThreatTracker:
    """Get the global threat tracker instance"""
    return threat_tracker


def update_thresholds(new_thresholds: ThreatThresholds):
    """Update the global threat thresholds"""
    global threat_tracker
    threat_tracker.thresholds = new_thresholds


def update_escalation_rules(new_rules: EscalationRules):
    """Update the global escalation rules"""
    global threat_tracker
    threat_tracker.rules = new_rules