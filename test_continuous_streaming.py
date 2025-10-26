#!/usr/bin/env python3
"""
Continuous Streaming Test Script
Tests the enhanced monitoring system for stability and continuous data streaming.
"""

import socketio
import time
import threading
import json
from datetime import datetime
import statistics

class StreamingTester:
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_delay=1,
            reconnection_delay_max=5,
            reconnection_attempts=10,
            logger=False,
            engineio_logger=False
        )
        
        # Statistics
        self.stats = {
            'connections': 0,
            'disconnections': 0,
            'reconnections': 0,
            'messages_received': 0,
            'traffic_updates': 0,
            'monitoring_status_updates': 0,
            'live_alerts': 0,
            'connection_errors': 0,
            'start_time': None,
            'last_message_time': None,
            'message_intervals': [],
            'uptime_periods': []
        }
        
        self.is_running = False
        self.last_connect_time = None
        
        self.setup_event_handlers()
    
    def setup_event_handlers(self):
        """Setup Socket.IO event handlers"""
        
        @self.sio.event
        def connect():
            self.stats['connections'] += 1
            self.last_connect_time = time.time()
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"[{current_time}] ✅ Connected (Total connections: {self.stats['connections']})")
        
        @self.sio.event
        def disconnect():
            self.stats['disconnections'] += 1
            if self.last_connect_time:
                uptime = time.time() - self.last_connect_time
                self.stats['uptime_periods'].append(uptime)
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"[{current_time}] ❌ Disconnected (Total disconnections: {self.stats['disconnections']})")
        
        @self.sio.event
        def connect_error(data):
            self.stats['connection_errors'] += 1
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"[{current_time}] 🔴 Connection error: {data}")
        
        @self.sio.on('reconnect')
        def on_reconnect():
            self.stats['reconnections'] += 1
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"[{current_time}] 🔄 Reconnected (Total reconnections: {self.stats['reconnections']})")
        
        @self.sio.on('traffic_update')
        def on_traffic_update(data):
            self.stats['traffic_updates'] += 1
            self.stats['messages_received'] += 1
            self._record_message_time()
            
            if self.stats['traffic_updates'] % 10 == 0:  # Log every 10th update
                current_time = datetime.now().strftime('%H:%M:%S')
                packets = data.get('packets_processed', 'N/A')
                print(f"[{current_time}] 📈 Traffic update #{self.stats['traffic_updates']} - Packets: {packets}")
        
        @self.sio.on('monitoring_status')
        def on_monitoring_status(data):
            self.stats['monitoring_status_updates'] += 1
            self.stats['messages_received'] += 1
            self._record_message_time()
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"[{current_time}] 📊 Monitoring status: {data.get('status', 'Unknown')}")
        
        @self.sio.on('live_alert')
        def on_live_alert(data):
            self.stats['live_alerts'] += 1
            self.stats['messages_received'] += 1
            self._record_message_time()
            current_time = datetime.now().strftime('%H:%M:%S')
            threat_type = data.get('threat_type', 'Unknown')
            print(f"[{current_time}] 🚨 Live alert: {threat_type}")
    
    def _record_message_time(self):
        """Record message timing for interval analysis"""
        current_time = time.time()
        if self.stats['last_message_time']:
            interval = current_time - self.stats['last_message_time']
            self.stats['message_intervals'].append(interval)
            # Keep only last 100 intervals to prevent memory growth
            if len(self.stats['message_intervals']) > 100:
                self.stats['message_intervals'] = self.stats['message_intervals'][-100:]
        self.stats['last_message_time'] = current_time
    
    def connect(self):
        """Connect to the server"""
        try:
            print(f"Connecting to {self.server_url}...")
            self.sio.connect(self.server_url)
            self.stats['start_time'] = time.time()
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.sio.connected:
            self.sio.disconnect()
    
    def start_monitoring(self):
        """Start the monitoring test"""
        self.is_running = True
        print("🚀 Starting continuous streaming test...")
        print("Press Ctrl+C to stop the test\n")
        
        # Start statistics reporting thread
        stats_thread = threading.Thread(target=self._report_stats_periodically)
        stats_thread.daemon = True
        stats_thread.start()
        
        try:
            while self.is_running:
                if not self.sio.connected:
                    print("Connection lost, attempting to reconnect...")
                    time.sleep(1)
                else:
                    time.sleep(0.1)  # Small sleep to prevent busy waiting
        except KeyboardInterrupt:
            print("\n🛑 Test interrupted by user")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop the monitoring test"""
        self.is_running = False
        self.disconnect()
        self._print_final_report()
    
    def _report_stats_periodically(self):
        """Report statistics every 30 seconds"""
        while self.is_running:
            time.sleep(30)
            if self.is_running:
                self._print_stats_summary()
    
    def _print_stats_summary(self):
        """Print current statistics summary"""
        current_time = datetime.now().strftime('%H:%M:%S')
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print(f"\n[{current_time}] === STATS SUMMARY ===")
        print(f"Uptime: {uptime:.1f}s | Connected: {self.sio.connected}")
        print(f"Messages: {self.stats['messages_received']} | Traffic Updates: {self.stats['traffic_updates']}")
        print(f"Connections: {self.stats['connections']} | Disconnections: {self.stats['disconnections']}")
        print(f"Reconnections: {self.stats['reconnections']} | Errors: {self.stats['connection_errors']}")
        
        if self.stats['message_intervals']:
            avg_interval = statistics.mean(self.stats['message_intervals'])
            print(f"Avg Message Interval: {avg_interval:.2f}s")
        print("=" * 40 + "\n")
    
    def _print_final_report(self):
        """Print final test report"""
        total_time = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print("\n" + "=" * 50)
        print("🏁 FINAL TEST REPORT")
        print("=" * 50)
        print(f"Total Test Duration: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
        print(f"Total Messages Received: {self.stats['messages_received']}")
        print(f"Traffic Updates: {self.stats['traffic_updates']}")
        print(f"Monitoring Status Updates: {self.stats['monitoring_status_updates']}")
        print(f"Live Alerts: {self.stats['live_alerts']}")
        print(f"Total Connections: {self.stats['connections']}")
        print(f"Total Disconnections: {self.stats['disconnections']}")
        print(f"Total Reconnections: {self.stats['reconnections']}")
        print(f"Connection Errors: {self.stats['connection_errors']}")
        
        if self.stats['uptime_periods']:
            avg_uptime = statistics.mean(self.stats['uptime_periods'])
            total_uptime = sum(self.stats['uptime_periods'])
            uptime_percentage = (total_uptime / total_time * 100) if total_time > 0 else 0
            print(f"Average Connection Uptime: {avg_uptime:.1f}s")
            print(f"Total Uptime: {total_uptime:.1f}s ({uptime_percentage:.1f}%)")
        
        if self.stats['message_intervals']:
            avg_interval = statistics.mean(self.stats['message_intervals'])
            min_interval = min(self.stats['message_intervals'])
            max_interval = max(self.stats['message_intervals'])
            print(f"Message Intervals - Avg: {avg_interval:.2f}s, Min: {min_interval:.2f}s, Max: {max_interval:.2f}s")
        
        # Calculate reliability metrics
        if self.stats['connections'] > 0:
            reliability = ((self.stats['connections'] - self.stats['connection_errors']) / self.stats['connections']) * 100
            print(f"Connection Reliability: {reliability:.1f}%")
        
        if total_time > 0:
            message_rate = self.stats['messages_received'] / total_time
            print(f"Average Message Rate: {message_rate:.2f} messages/second")
        
        print("=" * 50)

def main():
    """Main function to run the continuous streaming test"""
    tester = StreamingTester()
    
    if tester.connect():
        tester.start_monitoring()
    else:
        print("Failed to establish initial connection")

if __name__ == "__main__":
    main()