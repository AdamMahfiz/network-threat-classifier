#!/usr/bin/env python3
"""
Test script to generate sample alerts for the dashboard
"""
import requests
import time
import json

def trigger_test_alert():
    """Send a test alert to the server"""
    try:
        # This endpoint will emit a test alert
        response = requests.post('http://localhost:5000/api/test-alert', 
                               json={'message': 'Test alert from script'})
        if response.status_code == 200:
            print("✅ Test alert sent successfully")
        else:
            print(f"❌ Failed to send alert: {response.status_code}")
    except Exception as e:
        print(f"❌ Error sending alert: {e}")

if __name__ == "__main__":
    print("🧪 Sending test alert...")
    trigger_test_alert()