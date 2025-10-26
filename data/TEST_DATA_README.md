# Test Data Files

This directory contains simple test data files in NSL-KDD format for testing the network threat classifier.

## Files

### test_data.txt
A comprehensive test dataset with 20 samples covering various attack types and normal traffic:
- **Normal traffic**: HTTP, FTP, SMTP, Finger, POP3 connections
- **Attack types**: 
  - neptune (DoS attack)
  - buffer_overflow (U2R attack)
  - warezclient (R2L attack)
  - smurf (DoS attack)
  - portsweep (Probe attack)
  - guess_passwd (R2L attack)
  - satan (Probe attack)
  - ftp_write (R2L attack)

### simple_test.txt
A minimal test dataset with 5 samples for quick testing:
- 1 normal HTTP connection
- 1 neptune DoS attack
- 1 smurf DoS attack
- 1 portsweep probe attack
- 1 guess_passwd R2L attack

## NSL-KDD Format

Each line contains 42 features (41 network features + 1 difficulty level):
1. Duration
2. Protocol type (tcp, udp, icmp)
3. Service (http, ftp, telnet, etc.)
4. Flag (SF, S0, REJ, etc.)
5-41. Various network connection features
42. Attack type (normal, neptune, smurf, etc.)
43. Difficulty level (1-21)

## Usage

These files can be used to:
- Test the classifier with known attack patterns
- Validate preprocessing pipelines
- Debug model performance on specific attack types
- Quick functionality testing without loading large datasets

## Attack Type Categories

- **DoS (Denial of Service)**: neptune, smurf
- **Probe**: portsweep, satan
- **R2L (Remote to Local)**: warezclient, guess_passwd, ftp_write
- **U2R (User to Root)**: buffer_overflow
- **Normal**: legitimate network traffic