# Chapter 6: System Architecture Diagram

## Network Threat Classification System - System Architecture

### Overview
This document presents the comprehensive system architecture for the Network Threat Classification System, illustrating the interaction between presentation layer, application layer, data layer, and external components.

---

## High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    NETWORK THREAT CLASSIFICATION SYSTEM                                    │
│                                           SYSTEM ARCHITECTURE                                               │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                    PRESENTATION LAYER                                              │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │  │
│  │  │   Web Browser   │  │   Dashboard     │  │   Admin Panel   │  │   Mobile View   │             │  │
│  │  │                 │  │   Interface     │  │                 │  │                 │             │  │
│  │  │ • HTML5/CSS3    │  │ • Real-time     │  │ • User Mgmt     │  │ • Responsive    │             │  │
│  │  │ • JavaScript    │  │ • Charts/Graphs │  │ • System Config │  │ • Touch UI      │             │  │
│  │  │ • Bootstrap     │  │ • Threat Alerts │  │ • Audit Logs    │  │                 │             │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘             │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                    │                                                        │
│                                                    │ HTTPS/WebSocket                                       │
│                                                    ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                    APPLICATION LAYER                                              │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                              WEB APPLICATION TIER                                         │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │  │  │
│  │  │  │   Flask App     │  │   Authentication│  │   API Gateway   │  │   WebSocket     │     │  │  │
│  │  │  │   (app.py)      │  │   Manager       │  │                 │  │   Handler       │     │  │  │
│  │  │  │                 │  │                 │  │ • REST APIs     │  │                 │     │  │  │
│  │  │  │ • Route Mgmt    │  │ • Login/2FA     │  │ • Rate Limiting │  │ • Real-time     │     │  │  │
│  │  │  │ • Template Eng  │  │ • Session Mgmt  │  │ • CORS Handling │  │ • Live Updates  │     │  │  │
│  │  │  │ • Error Handling│  │ • RBAC          │  │ • Input Valid   │  │ • Event Stream  │     │  │  │
│  │  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘     │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                                    │                                                │  │
│  │                                                    ▼                                                │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                              BUSINESS LOGIC TIER                                         │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │  │  │
│  │  │  │   Threat        │  │   Data          │  │   Analysis      │  │   Report        │     │  │  │
│  │  │  │   Classifier    │  │   Processor     │  │   Engine        │  │   Generator     │     │  │  │
│  │  │  │                 │  │                 │  │                 │  │                 │     │  │  │
│  │  │  │ • ML Model      │  │ • Log Parsing   │  │ • Session Mgmt  │  │ • PDF Export    │     │  │  │
│  │  │  │ • Random Forest │  │ • Data Clean    │  │ • Threat Scoring│  │ • Chart Gen     │     │  │  │
│  │  │  │ • Feature Ext   │  │ • Normalization │  │ • Pattern Recog │  │ • Data Export   │     │  │  │
│  │  │  │ • Model Training│  │ • Validation    │  │ • Alert Trigger │  │ • Scheduling    │     │  │  │
│  │  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘     │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                                    │                                                │  │
│  │                                                    ▼                                                │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                              INTEGRATION TIER                                            │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │  │  │
│  │  │  │   Database      │  │   File System   │  │   Cache Layer   │  │   Message       │     │  │  │
│  │  │  │   Connector     │  │   Manager       │  │                 │  │   Queue         │     │  │  │
│  │  │  │                 │  │                 │  │ • Redis Cache   │  │                 │     │  │  │
│  │  │  │ • SQLAlchemy    │  │ • Log Storage   │  │ • Session Store │  │ • Task Queue    │     │  │  │
│  │  │  │ • Connection    │  │ • Model Storage │  │ • Query Cache   │  │ • Async Process │     │  │  │
│  │  │  │   Pooling       │  │ • Temp Files    │  │ • Result Cache  │  │ • Background    │     │  │  │
│  │  │  │ • Transaction  │  │ • Upload Mgmt   │  │                 │  │   Jobs          │     │  │  │
│  │  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘     │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                    │                                                        │
│                                                    ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                      DATA LAYER                                                   │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                              DATABASE MANAGEMENT                                         │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │  │  │
│  │  │  │   PostgreSQL    │  │   Database      │  │   Backup &      │  │   Migration     │     │  │  │
│  │  │  │   Database      │  │   Schema        │  │   Recovery      │  │   Manager       │     │  │  │
│  │  │  │                 │  │                 │  │                 │  │                 │     │  │  │
│  │  │  │ • ACID Comply   │  │ • User Tables   │  │ • Auto Backup   │  │ • Schema Update │     │  │  │
│  │  │  │ • SSL Connect   │  │ • Log Tables    │  │ • Point Recovery│  │ • Data Migration│     │  │  │
│  │  │  │ • Connection    │  │ • Session Tables│  │ • Disaster Rec  │  │ • Version Ctrl  │     │  │  │
│  │  │  │   Pooling       │  │ • Audit Tables  │  │                 │  │                 │     │  │  │
│  │  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘     │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                                    │                                                │  │
│  │                                                    ▼                                                │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                              FILE STORAGE                                                │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │  │  │
│  │  │  │   Log Files     │  │   ML Models     │  │   Reports       │  │   Configuration │     │  │  │
│  │  │  │   Storage       │  │   Storage       │  │   Storage       │  │   Files         │     │  │  │
│  │  │  │                 │  │                 │  │                 │  │                 │     │  │  │
│  │  │  │ • Raw Logs      │  │ • Trained Models│  │ • PDF Reports   │  │ • App Config    │     │  │  │
│  │  │  │ • Processed     │  │ • Model Versions│  │ • CSV Exports   │  │ • Security Keys │     │  │  │
│  │  │  │ • Archived      │  │ • Training Data │  │ • Chart Images  │  │ • Environment   │     │  │  │
│  │  │  │ • Compressed    │  │ • Feature Sets  │  │ • Audit Reports │  │   Variables     │     │  │  │
│  │  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘     │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                    │                                                        │
│                                                    ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                   EXTERNAL INTERFACES                                             │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │  │
│  │  │   Log Sources   │  │   Threat Intel  │  │   Notification  │  │   Monitoring    │             │  │
│  │  │                 │  │   Feeds         │  │   Services      │  │   Systems       │             │  │
│  │  │ • Network Logs  │  │                 │  │                 │  │                 │             │  │
│  │  │ • System Logs   │  │ • CVE Database  │  │ • Email Alerts  │  │ • Health Checks │             │  │
│  │  │ • Application   │  │ • IOC Feeds     │  │ • SMS Alerts    │  │ • Performance   │             │  │
│  │  │   Logs          │  │ • Signature DB  │  │ • Slack/Teams   │  │   Metrics       │             │  │
│  │  │ • Security Logs │  │                 │  │ • Webhooks      │  │ • Log Aggreg    │             │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘             │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture Details

### Flask Application Core

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FLASK APPLICATION CORE                           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        APPLICATION STRUCTURE                       │   │
│  │                                                                     │   │
│  │  app.py (Main Application)                                         │   │
│  │  ├── Flask App Initialization                                       │   │
│  │  ├── Database Configuration                                         │   │
│  │  ├── Authentication Setup                                           │   │
│  │  ├── Route Registration                                             │   │
│  │  └── Error Handling                                                 │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐    ┌─────────────────┐                       │   │
│  │  │   Routes        │    │   Templates     │                       │   │
│  │  │                 │    │                 │                       │   │
│  │  │ • /dashboard    │    │ • index.html    │                       │   │
│  │  │ • /login        │    │ • login.html    │                       │   │
│  │  │ • /upload       │    │ • upload.html   │                       │   │
│  │  │ • /api/*        │    │ • admin.html    │                       │   │
│  │  │ • /admin        │    │ • profile.html  │                       │   │
│  │  └─────────────────┘    └─────────────────┘                       │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐    ┌─────────────────┐                       │   │
│  │  │   Static Files  │    │   Configuration │                       │   │
│  │  │                 │    │                 │                       │   │
│  │  │ • CSS Styles    │    │ • Environment   │                       │   │
│  │  │ • JavaScript    │    │   Variables     │                       │   │
│  │  │ • Images        │    │ • Security Keys │                       │   │
│  │  │ • Fonts         │    │ • Database URLs │                       │   │
│  │  └─────────────────┘    └─────────────────┘                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Machine Learning Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MACHINE LEARNING ARCHITECTURE                       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        THREAT CLASSIFIER                           │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │   Input Data    │                                               │   │
│  │  │                 │                                               │   │
│  │  │ • Network Logs  │                                               │   │
│  │  │ • System Events │                                               │   │
│  │  │ • Raw Features  │                                               │   │
│  │  └─────────┬───────┘                                               │   │
│  │            │                                                       │   │
│  │            ▼                                                       │   │
│  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │                 DATA PREPROCESSING                         │  │   │
│  │  │                                                             │  │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │   │
│  │  │  │   Data      │  │   Feature   │  │   Data      │        │  │   │
│  │  │  │ Cleaning    │  │ Extraction  │  │Normalization│        │  │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘        │  │   │
│  │  └─────────────────────┬───────────────────────────────────────┘  │   │
│  │                        │                                          │   │
│  │                        ▼                                          │   │
│  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │                 RANDOM FOREST MODEL                       │  │   │
│  │  │                                                             │  │   │
│  │  │  Model Configuration:                                      │  │   │
│  │  │  • n_estimators: 100                                       │  │   │
│  │  │  • max_depth: 10                                           │  │   │
│  │  │  • min_samples_split: 2                                    │  │   │
│  │  │  • min_samples_leaf: 1                                     │  │   │
│  │  │  • random_state: 42                                        │  │   │
│  │  │                                                             │  │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │   │
│  │  │  │   Training  │  │ Validation  │  │   Testing   │        │  │   │
│  │  │  │    Phase    │  │    Phase    │  │    Phase    │        │  │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘        │  │   │
│  │  └─────────────────────┬───────────────────────────────────────┘  │   │
│  │                        │                                          │   │
│  │                        ▼                                          │   │
│  │  ┌─────────────────────────────────────────────────────────────┐  │   │
│  │  │                 THREAT CLASSIFICATION                     │  │   │
│  │  │                                                             │  │   │
│  │  │  Output Classes:                                           │  │   │
│  │  │  • Low Threat (0.0 - 0.33)                                 │  │   │
│  │  │  • Medium Threat (0.34 - 0.66)                             │  │   │
│  │  │  • High Threat (0.67 - 1.0)                                │  │   │
│  │  │                                                             │  │   │
│  │  │  Confidence Score: 0.0 - 1.0                               │  │   │
│  │  │  Feature Importance: Available                             │  │   │
│  │  └─────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Database Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATABASE ARCHITECTURE                            │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        POSTGRESQL DATABASE                         │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐    ┌─────────────────┐                       │   │
│  │  │   Connection    │    │   Transaction   │                       │   │
│  │  │   Management    │    │   Management    │                       │   │
│  │  │                 │    │                 │                       │   │
│  │  │ • Pool Size: 20 │    │ • ACID Comply   │                       │   │
│  │  │ • SSL Enabled   │    │ • Rollback      │                       │   │
│  │  │ • Timeout: 30s  │    │ • Commit        │                       │   │
│  │  └─────────────────┘    └─────────────────┘                       │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                    TABLE STRUCTURE                         │   │   │
│  │  │                                                             │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │   │   │
│  │  │  │    users    │  │    roles    │  │ user_roles  │        │   │   │
│  │  │  │             │  │             │  │             │        │   │   │
│  │  │  │ • id (PK)   │  │ • id (PK)   │  │ • user_id   │        │   │   │
│  │  │  │ • username  │  │ • name      │  │ • role_id   │        │   │   │
│  │  │  │ • email     │  │ • desc      │  │             │        │   │   │
│  │  │  │ • password  │  │             │  │             │        │   │   │
│  │  │  │ • 2fa_secret│  │             │  │             │        │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘        │   │   │
│  │  │                                                             │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │   │   │
│  │  │  │analysis_    │  │ log_entries │  │threat_events│        │   │   │
│  │  │  │sessions     │  │             │  │             │        │   │   │
│  │  │  │             │  │ • id (PK)   │  │ • id (PK)   │        │   │   │
│  │  │  │ • id (PK)   │  │ • session_id│  │ • session_id│        │   │   │
│  │  │  │ • user_id   │  │ • log_data  │  │ • event_type│        │   │   │
│  │  │  │ • filename  │  │ • threat_lvl│  │ • details   │        │   │   │
│  │  │  │ • status    │  │ • confidence│  │ • timestamp │        │   │   │
│  │  │  │ • threat_   │  │ • timestamp │  │             │        │   │   │
│  │  │  │   distrib   │  │             │  │             │        │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘        │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                    RELATIONSHIPS                           │   │   │
│  │  │                                                             │   │   │
│  │  │  users ←──→ user_roles ←──→ roles                         │   │   │
│  │  │    │                                                       │   │   │
│  │  │    └──→ analysis_sessions                                  │   │   │
│  │  │              │                                             │   │   │
│  │  │              ├──→ log_entries                             │   │   │
│  │  │              └──→ threat_events                           │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## API Architecture

### RESTful API Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API ARCHITECTURE                              │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        API ENDPOINTS                               │   │
│  │                                                                     │   │
│  │  Authentication APIs:                                              │   │
│  │  ├── POST /api/auth/login                                           │   │
│  │  ├── POST /api/auth/logout                                          │   │
│  │  ├── POST /api/auth/verify-2fa                                      │   │
│  │  └── GET  /api/auth/status                                          │   │
│  │                                                                     │   │
│  │  Analysis APIs:                                                     │   │
│  │  ├── POST /api/upload                                               │   │
│  │  ├── GET  /api/analysis/{session_id}                                │   │
│  │  ├── GET  /api/analysis/{session_id}/results                        │   │
│  │  └── DELETE /api/analysis/{session_id}                              │   │
│  │                                                                     │   │
│  │  Dashboard APIs:                                                    │   │
│  │  ├── GET  /api/dashboard/stats                                      │   │
│  │  ├── GET  /api/dashboard/threats                                    │   │
│  │  ├── GET  /api/dashboard/trends                                     │   │
│  │  └── GET  /api/dashboard/alerts                                     │   │
│  │                                                                     │   │
│  │  Admin APIs:                                                        │   │
│  │  ├── GET  /api/admin/users                                          │   │
│  │  ├── POST /api/admin/users                                          │   │
│  │  ├── PUT  /api/admin/users/{user_id}                                │   │
│  │  ├── DELETE /api/admin/users/{user_id}                              │   │
│  │  └── GET  /api/admin/audit-logs                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        API MIDDLEWARE                              │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   Rate Limiting │  │   CORS Handler  │  │   Input Valid   │   │   │
│  │  │                 │  │                 │  │                 │   │   │
│  │  │ • 100 req/min   │  │ • Origin Check  │  │ • Schema Valid  │   │   │
│  │  │ • IP-based      │  │ • Method Allow  │  │ • Sanitization  │   │   │
│  │  │ • User-based    │  │ • Header Allow  │  │ • Type Check    │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   Auth Check    │  │   Error Handler │  │   Response      │   │   │
│  │  │                 │  │                 │  │   Formatter     │   │   │
│  │  │ • Token Valid   │  │ • Exception     │  │                 │   │   │
│  │  │ • Permission    │  │   Handling      │  │ • JSON Format   │   │   │
│  │  │   Check         │  │ • Error Logging │  │ • Status Codes  │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Real-time Communication Architecture

### WebSocket Implementation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WEBSOCKET ARCHITECTURE                              │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        CLIENT SIDE                                 │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐                                               │   │
│  │  │   JavaScript    │                                               │   │
│  │  │   WebSocket     │                                               │   │
│  │  │   Client        │                                               │   │
│  │  │                 │                                               │   │
│  │  │ • Connection    │                                               │   │
│  │  │   Management    │                                               │   │
│  │  │ • Event Handlers│                                               │   │
│  │  │ • Reconnection  │                                               │   │
│  │  │ • Heartbeat     │                                               │   │
│  │  └─────────┬───────┘                                               │   │
│  └────────────┼───────────────────────────────────────────────────────┘   │
│               │ WebSocket Connection                                        │
│               ▼                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        SERVER SIDE                                 │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐    ┌─────────────────┐                       │   │
│  │  │   Flask-        │    │   Event         │                       │   │
│  │  │   SocketIO      │    │   Handlers      │                       │   │
│  │  │                 │    │                 │                       │   │
│  │  │ • Connection    │    │ • analysis_     │                       │   │
│  │  │   Management    │    │   complete      │                       │   │
│  │  │ • Room Support  │    │ • threat_alert  │                       │   │
│  │  │ • Broadcasting  │    │ • progress_     │                       │   │
│  │  │ • Authentication│    │   update        │                       │   │
│  │  └─────────────────┘    └─────────────────┘                       │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                    EVENT FLOW                              │   │   │
│  │  │                                                             │   │   │
│  │  │  Client Connect ──→ Authentication ──→ Join Room           │   │   │
│  │  │       │                    │               │               │   │   │
│  │  │       ▼                    ▼               ▼               │   │   │
│  │  │  Analysis Start ──→ Progress Updates ──→ Results Broadcast │   │   │
│  │  │       │                    │               │               │   │   │
│  │  │       ▼                    ▼               ▼               │   │   │
│  │  │  Threat Detection ──→ Alert Generation ──→ Real-time UI   │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture Integration

### Security Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SECURITY INTEGRATION                              │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        NETWORK SECURITY                            │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   HTTPS/TLS     │  │   Firewall      │  │   Load Balancer │   │   │
│  │  │                 │  │   Rules         │  │                 │   │   │
│  │  │ • TLS 1.3       │  │                 │  │ • SSL Term      │   │   │
│  │  │ • Certificate   │  │ • Port 443 Only │  │ • Health Check  │   │   │
│  │  │   Management    │  │ • IP Whitelist  │  │ • Failover      │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        APPLICATION SECURITY                       │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   Authentication│  │   Authorization │  │   Session Mgmt  │   │   │
│  │  │                 │  │                 │  │                 │   │   │
│  │  │ • 2FA Required  │  │ • RBAC Model    │  │ • 30min Timeout │   │   │
│  │  │ • TOTP Tokens   │  │ • Role Check    │  │ • Secure Cookies│   │   │
│  │  │ • Strong Pwd    │  │ • Resource Perm │  │ • Token Rotation│   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        DATA SECURITY                               │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   Encryption    │  │   Input Valid   │  │   Audit Logging │   │   │
│  │  │                 │  │                 │  │                 │   │   │
│  │  │ • Password Hash │  │ • SQL Injection │  │ • All Actions   │   │   │
│  │  │ • Data at Rest  │  │   Prevention    │  │ • Tamper Proof  │   │   │
│  │  │ • Data Transit  │  │ • XSS Protection│  │ • Retention     │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Deployment Architecture

### Production Environment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DEPLOYMENT ARCHITECTURE                           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        INFRASTRUCTURE LAYER                        │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   Web Server    │  │   App Server    │  │   Database      │   │   │
│  │  │   (Nginx)       │  │   (Gunicorn)    │  │   Server        │   │   │
│  │  │                 │  │                 │  │   (PostgreSQL)  │   │   │
│  │  │ • Reverse Proxy │  │ • WSGI Server   │  │                 │   │   │
│  │  │ • SSL Term      │  │ • Multi-Process │  │ • Master-Slave  │   │   │
│  │  │ • Static Files  │  │ • Load Balance  │  │ • Replication   │   │   │
│  │  │ • Compression   │  │ • Health Check  │  │ • Backup        │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   Cache Layer   │  │   Message Queue │  │   File Storage  │   │   │
│  │  │   (Redis)       │  │   (Celery)      │  │   (NFS/S3)      │   │   │
│  │  │                 │  │                 │  │                 │   │   │
│  │  │ • Session Store │  │ • Async Tasks   │  │ • Log Files     │   │   │
│  │  │ • Query Cache   │  │ • Background    │  │ • ML Models     │   │   │
│  │  │ • Result Cache  │  │   Jobs          │  │ • Reports       │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        MONITORING & LOGGING                        │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │   │
│  │  │   Application   │  │   System        │  │   Security      │   │   │
│  │  │   Monitoring    │  │   Monitoring    │  │   Monitoring    │   │   │
│  │  │                 │  │                 │  │                 │   │   │
│  │  │ • Performance   │  │ • CPU/Memory    │  │ • Failed Logins │   │   │
│  │  │ • Error Rates   │  │ • Disk Space    │  │ • Intrusion Det │   │   │
│  │  │ • Response Time │  │ • Network I/O   │  │ • Audit Trails  │   │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack Summary

| Layer | Technology | Purpose | Version |
|-------|------------|---------|----------|
| **Frontend** | HTML5/CSS3/JavaScript | User Interface | Latest |
| | Bootstrap | UI Framework | 5.x |
| | Chart.js | Data Visualization | 3.x |
| **Backend** | Python | Programming Language | 3.8+ |
| | Flask | Web Framework | 2.x |
| | SQLAlchemy | ORM | 1.4+ |
| | Flask-Login | Authentication | 0.6+ |
| | PyOTP | 2FA Implementation | 2.6+ |
| **Machine Learning** | scikit-learn | ML Framework | 1.0+ |
| | pandas | Data Processing | 1.3+ |
| | numpy | Numerical Computing | 1.21+ |
| **Database** | PostgreSQL | Primary Database | 13+ |
| | Redis | Cache & Sessions | 6+ |
| **Security** | Werkzeug | Password Hashing | 2.0+ |
| | HTTPS/TLS | Transport Security | 1.3 |
| **Deployment** | Gunicorn | WSGI Server | 20+ |
| | Nginx | Web Server | 1.18+ |
| | Docker | Containerization | 20+ |

---

*This System Architecture provides a comprehensive view of the Network Threat Classification System's technical implementation, showing how all components work together to deliver secure, scalable, and efficient threat detection capabilities.*