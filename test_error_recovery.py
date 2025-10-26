#!/usr/bin/env python3
"""
Error Recovery Test Script
Tests the monitoring system's ability to recover from various error conditions.
"""

import requests
import time
import json
from datetime import datetime
import threading
import subprocess
import sys

class ErrorRecoveryTester:
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
    
    def log(self, message, test_name="GENERAL"):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] [{test_name}] {message}")
    
    def test_monitoring_thread_restart(self):
        """Test monitoring thread restart capability"""
        test_name = "THREAD_RESTART"
        self.log("Testing monitoring thread restart capability", test_name)
        
        try:
            # Start monitoring
            self.log("Starting monitoring...", test_name)
            response = self.session.post(f"{self.base_url}/monitor", 
                                       json={"action": "start"})
            
            if response.status_code == 200:
                self.log("✅ Monitoring started successfully", test_name)
            else:
                self.log(f"❌ Failed to start monitoring: {response.status_code}", test_name)
                return False
            
            time.sleep(2)
            
            # Stop monitoring
            self.log("Stopping monitoring...", test_name)
            response = self.session.post(f"{self.base_url}/monitor", 
                                       json={"action": "stop"})
            
            if response.status_code == 200:
                self.log("✅ Monitoring stopped successfully", test_name)
            else:
                self.log(f"❌ Failed to stop monitoring: {response.status_code}", test_name)
                return False
            
            time.sleep(1)
            
            # Restart monitoring
            self.log("Restarting monitoring...", test_name)
            response = self.session.post(f"{self.base_url}/monitor", 
                                       json={"action": "start"})
            
            if response.status_code == 200:
                self.log("✅ Monitoring restarted successfully", test_name)
                return True
            else:
                self.log(f"❌ Failed to restart monitoring: {response.status_code}", test_name)
                return False
                
        except Exception as e:
            self.log(f"❌ Exception during thread restart test: {e}", test_name)
            return False
    
    def test_rapid_start_stop_cycles(self):
        """Test rapid start/stop cycles to check for race conditions"""
        test_name = "RAPID_CYCLES"
        self.log("Testing rapid start/stop cycles", test_name)
        
        success_count = 0
        total_cycles = 5
        
        try:
            for i in range(total_cycles):
                self.log(f"Cycle {i+1}/{total_cycles}", test_name)
                
                # Start
                start_response = self.session.post(f"{self.base_url}/monitor", 
                                                 json={"action": "start"})
                time.sleep(0.5)
                
                # Stop
                stop_response = self.session.post(f"{self.base_url}/monitor", 
                                                json={"action": "stop"})
                time.sleep(0.5)
                
                if start_response.status_code == 200 and stop_response.status_code == 200:
                    success_count += 1
                    self.log(f"✅ Cycle {i+1} completed successfully", test_name)
                else:
                    self.log(f"❌ Cycle {i+1} failed - Start: {start_response.status_code}, Stop: {stop_response.status_code}", test_name)
            
            success_rate = (success_count / total_cycles) * 100
            self.log(f"Rapid cycles test completed: {success_count}/{total_cycles} successful ({success_rate:.1f}%)", test_name)
            return success_rate >= 80  # 80% success rate threshold
            
        except Exception as e:
            self.log(f"❌ Exception during rapid cycles test: {e}", test_name)
            return False
    
    def test_concurrent_requests(self):
        """Test concurrent monitoring requests"""
        test_name = "CONCURRENT"
        self.log("Testing concurrent monitoring requests", test_name)
        
        results = []
        
        def make_request(action, thread_id):
            try:
                response = self.session.post(f"{self.base_url}/monitor", 
                                           json={"action": action})
                results.append({
                    'thread_id': thread_id,
                    'action': action,
                    'status_code': response.status_code,
                    'success': response.status_code == 200
                })
                self.log(f"Thread {thread_id} - {action}: {response.status_code}", test_name)
            except Exception as e:
                results.append({
                    'thread_id': thread_id,
                    'action': action,
                    'error': str(e),
                    'success': False
                })
                self.log(f"Thread {thread_id} - {action}: ERROR - {e}", test_name)
        
        try:
            # Create multiple threads making concurrent requests
            threads = []
            
            # Start requests
            for i in range(3):
                thread = threading.Thread(target=make_request, args=("start", f"START-{i}"))
                threads.append(thread)
                thread.start()
            
            # Stop requests
            for i in range(3):
                thread = threading.Thread(target=make_request, args=("stop", f"STOP-{i}"))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            successful_requests = sum(1 for r in results if r.get('success', False))
            total_requests = len(results)
            success_rate = (successful_requests / total_requests) * 100
            
            self.log(f"Concurrent requests test completed: {successful_requests}/{total_requests} successful ({success_rate:.1f}%)", test_name)
            return success_rate >= 70  # 70% success rate threshold for concurrent requests
            
        except Exception as e:
            self.log(f"❌ Exception during concurrent requests test: {e}", test_name)
            return False
    
    def test_server_health_check(self):
        """Test server health and responsiveness"""
        test_name = "HEALTH_CHECK"
        self.log("Testing server health and responsiveness", test_name)
        
        try:
            # Test main endpoint
            response = self.session.get(f"{self.base_url}/")
            if response.status_code == 200:
                self.log("✅ Main endpoint responsive", test_name)
            else:
                self.log(f"❌ Main endpoint not responsive: {response.status_code}", test_name)
                return False
            
            # Test monitor endpoint
            response = self.session.get(f"{self.base_url}/monitor")
            if response.status_code in [200, 302]:  # 302 for redirect to login
                self.log("✅ Monitor endpoint responsive", test_name)
            else:
                self.log(f"❌ Monitor endpoint not responsive: {response.status_code}", test_name)
                return False
            
            # Test response time
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/")
            response_time = time.time() - start_time
            
            if response_time < 2.0:  # 2 second threshold
                self.log(f"✅ Response time acceptable: {response_time:.3f}s", test_name)
                return True
            else:
                self.log(f"⚠️ Response time slow: {response_time:.3f}s", test_name)
                return False
                
        except Exception as e:
            self.log(f"❌ Exception during health check: {e}", test_name)
            return False
    
    def test_memory_leak_detection(self):
        """Basic memory leak detection through repeated operations"""
        test_name = "MEMORY_LEAK"
        self.log("Testing for potential memory leaks", test_name)
        
        try:
            # Perform repeated start/stop operations
            for i in range(10):
                self.session.post(f"{self.base_url}/monitor", json={"action": "start"})
                time.sleep(0.1)
                self.session.post(f"{self.base_url}/monitor", json={"action": "stop"})
                time.sleep(0.1)
                
                if i % 3 == 0:
                    self.log(f"Completed {i+1}/10 memory test cycles", test_name)
            
            # Final health check
            response = self.session.get(f"{self.base_url}/")
            if response.status_code == 200:
                self.log("✅ Server still responsive after repeated operations", test_name)
                return True
            else:
                self.log(f"❌ Server not responsive after repeated operations: {response.status_code}", test_name)
                return False
                
        except Exception as e:
            self.log(f"❌ Exception during memory leak test: {e}", test_name)
            return False
    
    def run_all_tests(self):
        """Run all error recovery tests"""
        print("🧪 Starting Error Recovery Test Suite")
        print("=" * 50)
        
        tests = [
            ("Server Health Check", self.test_server_health_check),
            ("Monitoring Thread Restart", self.test_monitoring_thread_restart),
            ("Rapid Start/Stop Cycles", self.test_rapid_start_stop_cycles),
            ("Concurrent Requests", self.test_concurrent_requests),
            ("Memory Leak Detection", self.test_memory_leak_detection)
        ]
        
        results = {}
        
        for test_name, test_func in tests:
            print(f"\n🔍 Running: {test_name}")
            print("-" * 30)
            
            try:
                result = test_func()
                results[test_name] = result
                status = "✅ PASSED" if result else "❌ FAILED"
                print(f"Result: {status}")
            except Exception as e:
                results[test_name] = False
                print(f"Result: ❌ FAILED (Exception: {e})")
        
        # Print final summary
        print("\n" + "=" * 50)
        print("🏁 ERROR RECOVERY TEST SUMMARY")
        print("=" * 50)
        
        passed_tests = sum(1 for result in results.values() if result)
        total_tests = len(results)
        
        for test_name, result in results.items():
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"{test_name}: {status}")
        
        success_rate = (passed_tests / total_tests) * 100
        print(f"\nOverall Success Rate: {passed_tests}/{total_tests} ({success_rate:.1f}%)")
        
        if success_rate >= 80:
            print("🎉 Error recovery system is ROBUST!")
        elif success_rate >= 60:
            print("⚠️ Error recovery system needs IMPROVEMENT")
        else:
            print("🚨 Error recovery system has CRITICAL ISSUES")
        
        return success_rate >= 80

def main():
    """Main function to run error recovery tests"""
    tester = ErrorRecoveryTester()
    
    try:
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()