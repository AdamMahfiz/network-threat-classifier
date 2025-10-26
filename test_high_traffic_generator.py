#!/usr/bin/env python3
"""
High Traffic Generator for Testing Threat Detection

This script generates high-volume network traffic to test the live monitoring
system's threat detection capabilities and trigger alert notifications.

Usage:
    python test_high_traffic_generator.py [mode]
    
Modes:
    - low: Generate 4,000 pps (Low threat)
    - medium: Generate 15,000 pps (Medium threat) 
    - high: Generate 60,000 pps (High threat)
    - escalation: Test sustained traffic escalation
    - burst: Test burst pattern detection
    - extreme: Generate 100,000+ pps (Extreme threat)
"""

import socket
import threading
import time
import sys
import random
from concurrent.futures import ThreadPoolExecutor
import argparse

class HighTrafficGenerator:
    def __init__(self):
        self.running = False
        self.packet_count = 0
        self.start_time = None
        
    def generate_packet_data(self, size=64):
        """Generate random packet data"""
        return b'X' * size + bytes([random.randint(0, 255) for _ in range(32)])
    
    def send_udp_packets(self, target_host='127.0.0.1', target_port=12345, packets_per_thread=1000):
        """Send UDP packets from a single thread"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            
            for _ in range(packets_per_thread):
                if not self.running:
                    break
                    
                try:
                    data = self.generate_packet_data()
                    sock.sendto(data, (target_host, target_port))
                    self.packet_count += 1
                except:
                    pass  # Ignore send errors
                    
        except Exception as e:
            print(f"Thread error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
    
    def generate_traffic(self, target_pps, duration=30, num_threads=50):
        """Generate traffic at specified packets per second"""
        print(f"🚀 Starting traffic generation:")
        print(f"   Target: {target_pps:,} packets/second")
        print(f"   Duration: {duration} seconds")
        print(f"   Threads: {num_threads}")
        print(f"   Expected total: {target_pps * duration:,} packets")
        print()
        
        self.running = True
        self.packet_count = 0
        self.start_time = time.time()
        
        # Calculate packets per thread per second
        packets_per_thread_per_sec = target_pps // num_threads
        packets_per_batch = max(1, packets_per_thread_per_sec // 10)  # 10 batches per second
        
        def worker():
            while self.running:
                batch_start = time.time()
                self.send_udp_packets(packets_per_thread=packets_per_batch)
                
                # Control timing to achieve target rate
                elapsed = time.time() - batch_start
                sleep_time = max(0, 0.1 - elapsed)  # 10 batches per second
                if sleep_time > 0:
                    time.sleep(sleep_time)
        
        # Start worker threads
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker) for _ in range(num_threads)]
            
            # Monitor progress
            try:
                for i in range(duration):
                    time.sleep(1)
                    current_pps = self.packet_count / (time.time() - self.start_time)
                    print(f"⏱️  {i+1:2d}s | {self.packet_count:8,} packets | {current_pps:8,.0f} pps")
                    
            except KeyboardInterrupt:
                print("\n🛑 Stopping traffic generation...")
            
            # Stop all threads
            self.running = False
            
            # Wait for threads to finish
            for future in futures:
                try:
                    future.result(timeout=2)
                except:
                    pass
        
        # Final statistics
        total_time = time.time() - self.start_time
        final_pps = self.packet_count / total_time
        
        print(f"\n📊 Final Statistics:")
        print(f"   Total packets: {self.packet_count:,}")
        print(f"   Total time: {total_time:.1f} seconds")
        print(f"   Average PPS: {final_pps:,.0f}")
        print(f"   Target achieved: {(final_pps/target_pps)*100:.1f}%")

def test_low_threat():
    """Generate low threat traffic (4,000 pps)"""
    print("🟡 LOW THREAT TEST - 4,000 pps")
    print("=" * 50)
    generator = HighTrafficGenerator()
    generator.generate_traffic(target_pps=4000, duration=20, num_threads=20)

def test_medium_threat():
    """Generate medium threat traffic (15,000 pps)"""
    print("🟠 MEDIUM THREAT TEST - 15,000 pps")
    print("=" * 50)
    generator = HighTrafficGenerator()
    generator.generate_traffic(target_pps=15000, duration=20, num_threads=30)

def test_high_threat():
    """Generate high threat traffic (60,000 pps)"""
    print("🔴 HIGH THREAT TEST - 60,000 pps")
    print("=" * 50)
    generator = HighTrafficGenerator()
    generator.generate_traffic(target_pps=60000, duration=15, num_threads=50)

def test_escalation():
    """Test sustained traffic escalation"""
    print("⏱️  ESCALATION TEST - Sustained 4,000 pps")
    print("=" * 50)
    print("This will trigger escalation after 3+ seconds of sustained traffic")
    generator = HighTrafficGenerator()
    generator.generate_traffic(target_pps=4000, duration=10, num_threads=20)

def test_burst_patterns():
    """Test burst pattern detection"""
    print("💥 BURST PATTERN TEST")
    print("=" * 50)
    print("Generating multiple traffic bursts within 1-minute window...")
    
    generator = HighTrafficGenerator()
    
    # Generate 4 bursts with normal traffic in between
    bursts = [
        (3000, 3, "Burst 1"),
        (500, 2, "Normal"),
        (3200, 3, "Burst 2"), 
        (400, 2, "Normal"),
        (3400, 3, "Burst 3"),
        (300, 2, "Normal"),
        (3600, 4, "Burst 4 - Should trigger escalation")
    ]
    
    for pps, duration, description in bursts:
        print(f"\n{description}: {pps} pps for {duration}s")
        generator.generate_traffic(target_pps=pps, duration=duration, num_threads=15)
        time.sleep(1)  # Brief pause between bursts

def test_extreme_threat():
    """Generate extreme threat traffic (100,000+ pps)"""
    print("💀 EXTREME THREAT TEST - 100,000+ pps")
    print("=" * 50)
    print("⚠️  WARNING: This will generate very high network traffic!")
    
    confirm = input("Continue? (y/N): ").lower().strip()
    if confirm != 'y':
        print("Test cancelled.")
        return
        
    generator = HighTrafficGenerator()
    generator.generate_traffic(target_pps=100000, duration=10, num_threads=100)

def main():
    parser = argparse.ArgumentParser(description='High Traffic Generator for Threat Detection Testing')
    parser.add_argument('mode', nargs='?', default='medium', 
                       choices=['low', 'medium', 'high', 'escalation', 'burst', 'extreme'],
                       help='Traffic generation mode (default: medium)')
    
    args = parser.parse_args()
    
    print("🌐 High Traffic Generator for Threat Detection Testing")
    print("=" * 60)
    print("⚠️  Make sure the monitoring system is running at http://localhost:5000/monitor")
    print("⚠️  This will generate network traffic to test threat detection")
    print()
    
    mode_functions = {
        'low': test_low_threat,
        'medium': test_medium_threat,
        'high': test_high_threat,
        'escalation': test_escalation,
        'burst': test_burst_patterns,
        'extreme': test_extreme_threat
    }
    
    try:
        mode_functions[args.mode]()
        print(f"\n✅ {args.mode.upper()} threat test completed!")
        print("🔍 Check the monitoring page for threat alerts and notifications")
        
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()