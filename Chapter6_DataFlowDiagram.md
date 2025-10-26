# Chapter 6: Data Flow Diagram (DFD)

## Network Threat Classification System - Data Flow Analysis

### Overview
This document presents the Data Flow Diagram (DFD) for the Network Threat Classification System, illustrating how data moves through different processes, data stores, and external entities.

---

## Context Diagram (Level 0 DFD)

```
┌─────────────────┐    Log Data/Files     ┌─────────────────────────────┐
│                 │ ──────────────────────>│                             │
│      User       │                        │   Network Threat           │
│   (Admin/User)  │<──────────────────────│  Classification System     │
│                 │   Analysis Results     │                             │
└─────────────────┘                        └─────────────────────────────┘
                                                         │
                                                         │ Threat Alerts
                                                         │ System Logs
                                                         ▼
                                           ┌─────────────────────────────┐
                                           │     Security Operations     │
                                           │        Center (SOC)         │
                                           └─────────────────────────────┘
```

**External Entities:**
- **User/Admin**: Provides log data and receives analysis results
- **Security Operations Center**: Receives threat alerts and system logs

---

## Level 1 DFD - System Overview

```
┌─────────────┐
│    User     │
└──────┬──────┘
       │ 1. Login Credentials
       │ 2. Log Files/Text
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    NETWORK THREAT CLASSIFICATION SYSTEM                 │
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────┐ │
│  │     1.0     │    │     2.0     │    │     3.0     │    │   4.0    │ │
│  │ Authenticate│    │   Process   │    │  Classify   │    │ Generate │ │
│  │    User     │    │    Logs     │    │  Threats    │    │ Reports  │ │
│  └─────────────┘    └─────────────┘    └─────────────┘    └──────────┘ │
│         │                   │                   │                │      │
│         ▼                   ▼                   ▼                ▼      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────┐ │
│  │   D1: User  │    │ D2: Session │    │ D3: Threat  │    │D4: Audit │ │
│  │  Database   │    │    Data     │    │   Events    │    │   Logs   │ │
│  └─────────────┘    └─────────────┘    └─────────────┘    └──────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
       │
       ▼ 3. Analysis Results
┌─────────────┐
│    User     │
└─────────────┘
```

---

## Level 2 DFD - Detailed Process Breakdown

### Process 1.0: User Authentication

```
┌─────────────┐
│    User     │
└──────┬──────┘
       │ Username/Password
       │ 2FA Token
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    1.0 AUTHENTICATE USER                   │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │   1.1    │    │   1.2    │    │   1.3    │             │
│  │ Validate │    │ Verify   │    │ Create   │             │
│  │Credentials│    │   2FA    │    │ Session  │             │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘             │
│       │               │               │                   │
│       ▼               ▼               ▼                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │ D1.1: Users │ │D1.2: Roles  │ │D1.3:Sessions│         │
│  │  Database   │ │  Database   │ │  Database   │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
       │ Session Token
       ▼
┌─────────────┐
│    User     │
└─────────────┘
```

### Process 2.0: Log Processing

```
┌─────────────┐
│    User     │
└──────┬──────┘
       │ Raw Log Data
       │ File Upload
       ▼
┌─────────────────────────────────────────────────────────────┐
│                   2.0 PROCESS LOGS                         │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │   2.1    │    │   2.2    │    │   2.3    │             │
│  │ Validate │    │ Extract  │    │  Store   │             │
│  │   Input  │    │ Features │    │   Data   │             │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘             │
│       │               │               │                   │
│       ▼               ▼               ▼                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │D2.1: Upload │ │D2.2: Feature│ │D2.3: Log    │         │
│  │   Buffer    │ │   Vectors   │ │  Entries    │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
       │ Processed Features
       ▼
┌─────────────────┐
│ 3.0 Classify    │
│    Threats      │
└─────────────────┘
```

### Process 3.0: Threat Classification

```
┌─────────────────┐
│ 2.0 Process     │
│    Logs         │
└────────┬────────┘
         │ Feature Vectors
         ▼
┌─────────────────────────────────────────────────────────────┐
│                 3.0 CLASSIFY THREATS                       │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │   3.1    │    │   3.2    │    │   3.3    │             │
│  │   Load   │    │ Predict  │    │  Store   │             │
│  │   Model  │    │ Threat   │    │ Results  │             │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘             │
│       │               │               │                   │
│       ▼               ▼               ▼                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │D3.1: ML     │ │D3.2: Threat │ │D3.3: Analysis│        │
│  │   Models    │ │Predictions  │ │  Sessions   │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
       │ Threat Classifications
       ▼
┌─────────────────┐
│ 4.0 Generate    │
│    Reports      │
└─────────────────┘
```

### Process 4.0: Report Generation

```
┌─────────────────┐
│ 3.0 Classify    │
│    Threats      │
└────────┬────────┘
         │ Classification Results
         ▼
┌─────────────────────────────────────────────────────────────┐
│                4.0 GENERATE REPORTS                        │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │   4.1    │    │   4.2    │    │   4.3    │             │
│  │Aggregate │    │ Create   │    │ Deliver  │             │
│  │  Data    │    │ Visuals  │    │ Results  │             │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘             │
│       │               │               │                   │
│       ▼               ▼               ▼                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │D4.1: Report │ │D4.2: Charts │ │D4.3: Audit  │         │
│  │    Data     │ │    Data     │ │    Logs     │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
       │ Reports & Alerts
       ▼
┌─────────────┐
│    User     │
│     SOC     │
└─────────────┘
```

---

## Data Stores Description

### D1: User Management Data Stores
- **D1.1: Users Database**: User accounts, credentials, 2FA secrets
- **D1.2: Roles Database**: User roles and permissions
- **D1.3: Sessions Database**: Active user sessions and tokens

### D2: Processing Data Stores
- **D2.1: Upload Buffer**: Temporary storage for uploaded files
- **D2.2: Feature Vectors**: Extracted features from log data
- **D2.3: Log Entries**: Processed and stored log entries

### D3: Analysis Data Stores
- **D3.1: ML Models**: Trained machine learning models
- **D3.2: Threat Predictions**: Classification results and confidence scores
- **D3.3: Analysis Sessions**: Session metadata and results

### D4: Reporting Data Stores
- **D4.1: Report Data**: Aggregated analysis results
- **D4.2: Charts Data**: Visualization data for dashboards
- **D4.3: Audit Logs**: System activity and security events

---

## Data Flow Specifications

### Input Data Flows
1. **User Credentials**: Username, password, 2FA token
2. **Log Files**: CSV, TXT, LOG format files
3. **Log Text**: Direct text input via web interface
4. **Configuration**: System settings and parameters

### Processing Data Flows
1. **Session Tokens**: Authentication and authorization data
2. **Feature Vectors**: Numerical representations of log data
3. **Predictions**: ML model output with confidence scores
4. **Aggregated Data**: Summarized analysis results

### Output Data Flows
1. **Analysis Results**: Threat classifications and details
2. **Visual Reports**: Charts, graphs, and dashboards
3. **Audit Trails**: Security events and system logs
4. **Alerts**: High-priority threat notifications

---

## Real-time Data Flows

### Live Monitoring Process
```
┌─────────────────┐
│ Network Traffic │
└────────┬────────┘
         │ Packet Data
         ▼
┌─────────────────────────────────────────────────────────────┐
│              REAL-TIME MONITORING                           │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │ Capture  │    │ Analyze  │    │ Alert    │             │
│  │ Packets  │    │ Traffic  │    │ Users    │             │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘             │
│       │               │               │                   │
│       ▼               ▼               ▼                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │ Packet      │ │ Traffic     │ │ Alert       │         │
│  │ Buffer      │ │ Metrics     │ │ Queue       │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
         │ Real-time Alerts
         ▼
┌─────────────────┐
│   Dashboard     │
│   WebSocket     │
└─────────────────┘
```

---

## Data Flow Security Considerations

### Secure Data Transmission
- **HTTPS**: All web traffic encrypted
- **Session Management**: Secure token-based authentication
- **Input Validation**: Sanitization of all user inputs
- **Access Control**: Role-based data access restrictions

### Data Integrity
- **Database Transactions**: ACID compliance for data consistency
- **Backup Procedures**: Regular data backups and recovery
- **Audit Logging**: Complete trail of data modifications
- **Error Handling**: Graceful failure and recovery mechanisms

---

*This Data Flow Diagram provides a comprehensive view of how data moves through the Network Threat Classification System, supporting system analysis, optimization, and maintenance activities.*