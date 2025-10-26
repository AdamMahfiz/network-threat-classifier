# High Traffic Generator - Usage Instructions

## 🚀 Quick Start

The `test_high_traffic_generator.py` file has been created to generate high-volume network traffic that will trigger threat alerts in your live monitoring system.

## 📋 Prerequisites

1. **Make sure the monitoring system is running:**
   ```bash
   python app.py
   ```
   
2. **Open the monitoring page in your browser:**
   ```
   http://localhost:5000/monitor
   ```

## 🎯 Available Test Modes

### 1. Medium Threat Test (Default)
```bash
python test_high_traffic_generator.py medium
```
- **Target:** 15,000 packets/second
- **Duration:** 20 seconds
- **Expected Result:** Medium threat alerts

### 2. Low Threat Test
```bash
python test_high_traffic_generator.py low
```
- **Target:** 4,000 packets/second
- **Duration:** 20 seconds
- **Expected Result:** Low threat alerts

### 3. High Threat Test
```bash
python test_high_traffic_generator.py high
```
- **Target:** 60,000 packets/second
- **Duration:** 15 seconds
- **Expected Result:** High threat alerts

### 4. Escalation Test
```bash
python test_high_traffic_generator.py escalation
```
- **Target:** 4,000 packets/second (sustained)
- **Duration:** 10 seconds
- **Expected Result:** Threat escalation after 3+ seconds

### 5. Burst Pattern Test
```bash
python test_high_traffic_generator.py burst
```
- **Pattern:** Multiple traffic bursts within 1-minute window
- **Expected Result:** Burst pattern escalation alerts

### 6. Extreme Threat Test
```bash
python test_high_traffic_generator.py extreme
```
- **Target:** 100,000+ packets/second
- **Duration:** 10 seconds
- **Expected Result:** Extreme threat alerts
- **⚠️ Warning:** Generates very high network traffic

## 📊 What to Expect

### On the Monitoring Page:
1. **Real-time Traffic Updates:** You'll see packet counts and PPS increase dramatically
2. **Threat Level Changes:** The threat level indicator will change from "normal" to "low", "medium", or "high"
3. **Alert Notifications:** Red alert banners will appear with threat details
4. **Statistics Updates:** Counters for alerts, traffic, and heartbeats will increment

### Alert Examples:
- **Medium Threat:** "Medium threat detected: 15,000.0 pps"
- **High Threat:** "High threat detected: 60,000.0 pps (avg: 45,000 pps)"
- **Escalation:** "Threat escalated due to sustained/burst patterns"

## 🔍 Testing Steps

1. **Start the monitoring system** and open the monitoring page
2. **Run a test mode** (start with `medium` for best results)
3. **Watch the monitoring page** for real-time alerts and notifications
4. **Check the statistics** to see threat detection working
5. **Try different modes** to test various threat levels

## 📈 Threat Detection Thresholds

Based on the advanced threat detection system:
- **Low Threat:** 3,000+ packets/second
- **Medium Threat:** 10,000+ packets/second  
- **High Threat:** 50,000+ packets/second
- **Escalation:** Sustained traffic for 3+ seconds OR 3+ bursts within 1 minute

## 🛠️ Troubleshooting

### If No Alerts Appear:
1. Verify the monitoring system is running and active
2. Check that you're on the correct monitoring page
3. Ensure the advanced threat detection is enabled
4. Try the `high` or `extreme` modes for more obvious results

### If Traffic Generation Fails:
1. Check your network permissions
2. Try reducing the number of threads
3. Ensure no firewall is blocking UDP traffic

## ✅ Success Indicators

You'll know the test is working when you see:
- ✅ Packet counts increasing rapidly on the monitoring page
- ✅ Threat level changing from "normal" to higher levels
- ✅ Red alert notifications appearing
- ✅ Statistics counters incrementing
- ✅ Real-time updates showing high PPS values

## 🎉 Example Output

When running `python test_high_traffic_generator.py medium`, you should see:
```
🟠 MEDIUM THREAT TEST - 15,000 pps
==================================================
🚀 Starting traffic generation:
   Target: 15,000 packets/second
   Duration: 20 seconds
   
⏱️   1s |   15,863 packets |   15,423 pps
⏱️   2s |   30,557 packets |   15,057 pps
...

✅ MEDIUM threat test completed!
🔍 Check the monitoring page for threat alerts and notifications
```

And on the monitoring page, you should see medium threat alerts and notifications appearing in real-time!