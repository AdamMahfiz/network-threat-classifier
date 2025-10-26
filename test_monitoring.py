#!/usr/bin/env python3
"""
Test script to verify live monitoring functionality
"""

import requests
import time
import threading
from scapy.all import sniff, IP, TCP
import socket

def generate_network_activity():
    """Generate some network activity to test monitoring"""
    print("Generating network activity...")
    
    # Make some HTTP requests to generate traffic
    try:
        for i in range(5):
            response = requests.get('http://httpbin.org/get', timeout=5)
            print(f"Request {i+1}: Status {response.status_code}")
            time.sleep(1)
    except Exception as e:
        print(f"HTTP request error: {e}")
    
    # Create some local socket connections
    try:
        for i in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                sock.connect(('127.0.0.1', 5000))  # Connect to our Flask app
                sock.close()
                print(f"Local connection {i+1}: Success")
            except:
                print(f"Local connection {i+1}: Failed (expected)")
            time.sleep(0.5)
    except Exception as e:
        print(f"Socket error: {e}")

def test_packet_capture():
    """Test packet capture functionality"""
    print("\nTesting packet capture for 10 seconds...")
    
    packet_count = 0
    
    def count_packet(pkt):
        nonlocal packet_count
        packet_count += 1
        if packet_count <= 5:  # Show first 5 packets
            if IP in pkt:
                print(f"Packet {packet_count}: {pkt[IP].src} -> {pkt[IP].dst}")
    
    try:
        # Start packet capture in background
        capture_thread = threading.Thread(
            target=lambda: sniff(timeout=10, prn=count_packet, store=0)
        )
        capture_thread.start()
        
        # Generate activity while capturing
        time.sleep(2)
        activity_thread = threading.Thread(target=generate_network_activity)
        activity_thread.start()
        
        # Wait for both to complete
        capture_thread.join()
        activity_thread.join()
        
        print(f"\nTotal packets captured: {packet_count}")
        
        if packet_count > 0:
            print("✅ Packet capture is working!")
            return True
        else:
            print("⚠️  No packets captured - this might indicate an issue")
            return False
            
    except Exception as e:
        print(f"❌ Packet capture error: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Testing Live Monitoring Functionality")
    print("=" * 50)
    
    # Test packet capture
    capture_works = test_packet_capture()
    
    print("\n" + "=" * 50)
    if capture_works:
        print("✅ Live monitoring should work properly!")
        print("\n📋 Next steps:")
        print("1. Go to http://localhost:5000/monitor")
        print("2. Click 'Start Monitoring'")
        print("3. Generate some network activity")
        print("4. Watch the real-time chart update")
    else:
        print("❌ Live monitoring may have issues")
        print("\n🔧 Troubleshooting:")
        print("1. Run as administrator (Windows)")
        print("2. Check firewall settings")
        print("3. Ensure network adapter is accessible")
    
    print("\n🏁 Test completed!")