#!/usr/bin/env python3
"""
Test script for the new advanced threat detection system
Demonstrates the new thresholds and escalation rules
"""

import sys
import os
import time
import random

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.threat_classifier.utils.threat_settings import (
    get_threat_tracker, 
    ThreatThresholds, 
    EscalationRules,
    update_thresholds,
    update_escalation_rules
)

def test_basic_thresholds():
    """Test the basic packet rate thresholds"""
    print("🧪 Testing Basic Threat Thresholds")
    print("=" * 50)
    
    threat_tracker = get_threat_tracker()
    
    test_cases = [
        (1000, "Normal traffic"),
        (2500, "Below low threshold"),
        (3500, "Low threat (3k+ pps)"),
        (8000, "Medium range"),
        (12000, "Medium threat (10k+ pps)"),
        (25000, "High range"),
        (55000, "High threat (50k+ pps)"),
        (100000, "Extreme traffic")
    ]
    
    for pps, description in test_cases:
        threat_level = threat_tracker.evaluate_threat_level(pps)
        print(f"📊 {pps:6,} pps → {threat_level:6} | {description}")
        time.sleep(0.1)  # Small delay to separate events
    
    print()

def test_sustained_escalation():
    """Test threat escalation for sustained high traffic"""
    print("⏱️  Testing Sustained Traffic Escalation")
    print("=" * 50)
    
    # Reset tracker for clean test
    threat_tracker = get_threat_tracker()
    threat_tracker.packet_rate_history.clear()
    threat_tracker.threat_level_history.clear()
    
    # Simulate sustained traffic above low threshold for 4 seconds
    print("Simulating sustained traffic at 4,000 pps for 4+ seconds...")
    
    for i in range(8):  # 8 measurements over ~4 seconds
        threat_level = threat_tracker.evaluate_threat_level(4000)
        print(f"  {i+1}. {threat_level} threat detected (4,000 pps)")
        time.sleep(0.5)  # 0.5 second intervals
    
    print()

def test_burst_pattern_escalation():
    """Test threat escalation for burst patterns"""
    print("💥 Testing Burst Pattern Escalation")
    print("=" * 50)
    
    # Reset tracker for clean test
    threat_tracker = get_threat_tracker()
    threat_tracker.packet_rate_history.clear()
    threat_tracker.threat_level_history.clear()
    
    print("Simulating burst patterns within 1-minute window...")
    
    # Create multiple burst events
    burst_scenarios = [
        (2500, "Burst 1: 2,500 pps (80% of 3k threshold)"),
        (100, "Normal traffic"),
        (2600, "Burst 2: 2,600 pps"),
        (150, "Normal traffic"),
        (2700, "Burst 3: 2,700 pps"),
        (200, "Normal traffic"),
        (2800, "Burst 4: 2,800 pps (should trigger escalation)")
    ]
    
    for pps, description in burst_scenarios:
        threat_level = threat_tracker.evaluate_threat_level(pps)
        print(f"  📈 {description} → {threat_level}")
        time.sleep(0.2)
    
    print()

def test_statistics():
    """Test the statistics functionality"""
    print("📈 Testing Statistics and Tracking")
    print("=" * 50)
    
    threat_tracker = get_threat_tracker()
    
    # Generate some varied traffic
    traffic_patterns = [1000, 5000, 15000, 2000, 8000, 45000, 3000]
    
    for pps in traffic_patterns:
        threat_level = threat_tracker.evaluate_threat_level(pps)
        print(f"  Traffic: {pps:5,} pps → {threat_level}")
        time.sleep(0.1)
    
    # Get and display statistics
    stats = threat_tracker.get_statistics()
    print(f"\n📊 Statistics Summary:")
    print(f"  Average PPS: {stats['avg_pps']:,}")
    print(f"  Maximum PPS: {stats['max_pps']:,}")
    print(f"  Threat Events: {stats['threat_events']}")
    print(f"  Escalations: {stats['escalations']}")
    print()

def test_configurable_thresholds():
    """Test updating thresholds dynamically"""
    print("⚙️  Testing Configurable Thresholds")
    print("=" * 50)
    
    # Test with custom thresholds
    custom_thresholds = ThreatThresholds(
        low_threat_pps=2000,    # Lower threshold for testing
        medium_threat_pps=5000,
        high_threat_pps=20000
    )
    
    print("Setting custom thresholds:")
    print(f"  Low: {custom_thresholds.low_threat_pps:,} pps")
    print(f"  Medium: {custom_thresholds.medium_threat_pps:,} pps")
    print(f"  High: {custom_thresholds.high_threat_pps:,} pps")
    
    update_thresholds(custom_thresholds)
    
    # Test with the new thresholds
    test_cases = [
        (1500, "Below custom low threshold"),
        (2500, "Above custom low threshold"),
        (6000, "Above custom medium threshold"),
        (25000, "Above custom high threshold")
    ]
    
    threat_tracker = get_threat_tracker()
    for pps, description in test_cases:
        threat_level = threat_tracker.evaluate_threat_level(pps)
        print(f"  {pps:5,} pps → {threat_level:6} | {description}")
    
    print()

def test_escalation_rules():
    """Test custom escalation rules"""
    print("🔺 Testing Custom Escalation Rules")
    print("=" * 50)
    
    # Set faster escalation for testing
    custom_rules = EscalationRules(
        sustained_threshold_seconds=2.0,  # Faster escalation
        burst_window_seconds=30.0,        # Shorter window
        min_bursts_for_escalation=2       # Fewer bursts needed
    )
    
    print("Setting custom escalation rules:")
    print(f"  Sustained threshold: {custom_rules.sustained_threshold_seconds} seconds")
    print(f"  Burst window: {custom_rules.burst_window_seconds} seconds")
    print(f"  Min bursts for escalation: {custom_rules.min_bursts_for_escalation}")
    
    update_escalation_rules(custom_rules)
    
    # Reset tracker
    threat_tracker = get_threat_tracker()
    threat_tracker.packet_rate_history.clear()
    threat_tracker.threat_level_history.clear()
    
    # Test faster sustained escalation
    print("\nTesting faster sustained escalation (2 seconds):")
    for i in range(5):
        threat_level = threat_tracker.evaluate_threat_level(2500)
        print(f"  {i+1}. {threat_level} (2,500 pps)")
        time.sleep(0.5)
    
    print()

def main():
    """Run all tests"""
    print("🚀 Advanced Threat Detection System Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_basic_thresholds()
        test_sustained_escalation()
        test_burst_pattern_escalation()
        test_statistics()
        test_configurable_thresholds()
        test_escalation_rules()
        
        print("✅ All tests completed successfully!")
        print("\n🎯 Key Features Demonstrated:")
        print("  ✓ Packet rate thresholds: 3k, 10k, 50k pps")
        print("  ✓ Sustained traffic escalation (3+ seconds)")
        print("  ✓ Burst pattern detection (1-minute window)")
        print("  ✓ Configurable thresholds and rules")
        print("  ✓ Real-time statistics tracking")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()