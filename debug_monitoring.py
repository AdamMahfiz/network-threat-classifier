#!/usr/bin/env python3
"""
Debug script to test the live monitoring issue
"""

import requests
import time
import threading
from scapy.all import sniff
import socketio

def test_packet_capture_immediate():
    """Test immediate packet capture (like the current implementation)"""
    print("🔍 Testing current implementation (60-second timeout)...")
    
    count = 0
    def count_packet(pkt):
        nonlocal count
        count += 1
        if count <= 5:
            print(f"  Packet {count} captured")
    
    print("⏱️  Starting 10-second capture (simulating current app behavior)...")
    start_time = time.time()
    
    # This simulates the current app.py implementation
    sniff(timeout=10, prn=count_packet, store=0)  # Using 10 seconds instead of 60 for testing
    
    end_time = time.time()
    elapsed = end_time - start_time
    
    print(f"📊 Results after {elapsed:.1f} seconds:")
    print(f"   Total packets: {count}")
    print(f"   Packets/minute: {count * (60/elapsed):.1f}")
    
    return count

def test_socket_io_events():
    """Test if Socket.IO events are being emitted"""
    print("\n🔌 Testing Socket.IO events...")
    
    try:
        sio = socketio.SimpleClient()
        sio.connect('http://localhost:5000')
        print("✅ Connected to Socket.IO server")
        
        events_received = []
        
        # Listen for traffic updates
        @sio.event
        def traffic_update(data):
            events_received.append(('traffic_update', data))
            print(f"📊 Received traffic_update: {data}")
        
        @sio.event
        def monitoring_status(data):
            events_received.append(('monitoring_status', data))
            print(f"📡 Received monitoring_status: {data}")
        
        # Start monitoring via API
        print("🚀 Starting monitoring via API...")
        response = requests.post('http://localhost:5000/monitor', 
                               data={'action': 'start'}, 
                               allow_redirects=False)
        print(f"   Start response: {response.status_code}")
        
        # Wait for events
        print("⏳ Waiting 15 seconds for events...")
        time.sleep(15)
        
        # Stop monitoring
        print("🛑 Stopping monitoring...")
        response = requests.post('http://localhost:5000/monitor', 
                               data={'action': 'stop'}, 
                               allow_redirects=False)
        print(f"   Stop response: {response.status_code}")
        
        sio.disconnect()
        
        print(f"\n📨 Total events received: {len(events_received)}")
        for event_type, data in events_received:
            print(f"   {event_type}: {data}")
        
        return len(events_received) > 0
        
    except Exception as e:
        print(f"❌ Socket.IO test error: {e}")
        return False

def analyze_monitoring_issue():
    """Analyze why monitoring shows all zeros"""
    print("\n🔍 ANALYZING MONITORING ISSUE")
    print("=" * 50)
    
    print("\n📋 Current Implementation Analysis:")
    print("1. monitor_traffic() uses sniff(timeout=60, ...)")
    print("2. This means it waits 60 FULL SECONDS before emitting data")
    print("3. During those 60 seconds, the UI shows zeros")
    print("4. Only after 60 seconds, you'll see the packet count")
    
    print("\n⚠️  PROBLEM IDENTIFIED:")
    print("   The 60-second timeout is too long for real-time monitoring!")
    print("   Users expect to see updates every few seconds, not every minute.")
    
    print("\n💡 SOLUTION:")
    print("   Change timeout from 60 seconds to 5-10 seconds for better UX")
    print("   This will provide more frequent updates while still being efficient")

def main():
    print("🐛 LIVE MONITORING DEBUG ANALYSIS")
    print("=" * 60)
    
    # Test 1: Packet capture
    print("\n📋 TEST 1: Packet Capture")
    packet_count = test_packet_capture_immediate()
    
    # Test 2: Socket.IO events
    print("\n📋 TEST 2: Socket.IO Events")
    events_working = test_socket_io_events()
    
    # Analysis
    analyze_monitoring_issue()
    
    print("\n" + "=" * 60)
    print("🎯 DIAGNOSIS SUMMARY")
    print("=" * 60)
    
    if packet_count > 0:
        print("✅ Packet capture: WORKING")
    else:
        print("❌ Packet capture: NOT WORKING")
    
    if events_working:
        print("✅ Socket.IO events: WORKING")
    else:
        print("❌ Socket.IO events: NOT WORKING")
    
    print("\n🔧 ROOT CAUSE:")
    print("   The 60-second timeout in monitor_traffic() is causing the issue.")
    print("   The system IS working, but updates are too infrequent!")
    
    print("\n📝 RECOMMENDED FIX:")
    print("   Change 'sniff(timeout=60, ...)' to 'sniff(timeout=5, ...)'")
    print("   This will provide updates every 5 seconds instead of every minute.")
    
    print("\n🏁 Debug completed!")

if __name__ == "__main__":
    main()