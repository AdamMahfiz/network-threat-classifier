# Chapter 6: Security Framework Diagram

## Network Threat Classification System - Security Architecture

### Overview
This document presents the comprehensive security framework for the Network Threat Classification System, illustrating authentication mechanisms, authorization controls, data protection measures, and security monitoring capabilities.

---

## Security Framework Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    NETWORK THREAT CLASSIFICATION SYSTEM                                    │
│                                           SECURITY FRAMEWORK                                                │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                      AVAILABILITY                                                  │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  ☁️ Cloud Hosting                    💾 Backups                                              │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • High availability infrastructure   • Automated daily backups                            │  │  │
│  │  │  • Load balancing capabilities        • Point-in-time recovery                             │  │  │
│  │  │  • Auto-scaling resources             • Encrypted backup storage                           │  │  │
│  │  │  • 99.9% uptime SLA                   • Disaster recovery procedures                        │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              AUTHENTICATION & AUTHORIZATION                                        │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  💻 User Login                       👥 Role-Based Access Control                           │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Username/password authentication   • Admin role - full system access                    │  │  │
│  │  │  • Account lockout protection         • User role - limited access                         │  │  │
│  │  │  • Password complexity requirements   • Permission-based route protection                  │  │  │
│  │  │  • Secure session management          • Function-level authorization                       │  │  │
│  │  │                                                                                             │  │  │
│  │  │  🔐 Session Management                 👤 User Permission                                    │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Flask-Login integration            • File upload and analysis                           │  │  │
│  │  │  • Secure HTTP-only cookies           • Report generation                                   │  │  │
│  │  │  • 30-minute session timeout          • Profile management                                  │  │  │
│  │  │  • Session regeneration on login      • View own analysis results                          │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                      ACCOUNTABILITY                                                │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  📊 Activity Logging                  📈 System Monitoring                                   │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • User login/logout events           • Real-time system metrics                           │  │  │
│  │  │  • File upload activities             • Performance monitoring                              │  │  │
│  │  │  • Administrative actions             • Resource usage tracking                            │  │  │
│  │  │  • Failed authentication attempts     • Error rate monitoring                              │  │  │
│  │  │                                                                                             │  │  │
│  │  │  📋 Audit Trails                                                                            │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Comprehensive event logging        • Tamper-proof log storage                          │  │  │
│  │  │  • Centralized log management         • Log rotation and archival                          │  │  │
│  │  │  • Security incident tracking         • Compliance reporting                               │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                      CONFIDENTIALITY                                              │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  🔒 Encryption                        📧 Email Communication                                  │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • TLS 1.2+ for data in transit      • Secure email notifications                          │  │  │
│  │  │  • Database encryption at rest        • Encrypted report delivery                           │  │  │
│  │  │  • TOTP secret encryption             • PGP encryption for sensitive data                   │  │  │
│  │  │  • Bcrypt password hashing            • Secure communication channels                       │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                        INTEGRITY                                                   │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  🗄️ Database Integrity                ✅ Data Validation                                       │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • ACID transaction compliance        • Input sanitization                                   │  │  │
│  │  │  • Foreign key constraints            • File type validation                                 │  │  │
│  │  │  • Data consistency checks            • Content validation                                   │  │  │
│  │  │  • Backup integrity verification      • Schema validation                                    │  │  │
│  │  │                                                                                             │  │  │
│  │  │  🔐 Password Hashing                                                                          │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Bcrypt with salt (cost factor 12) • Secure password reset tokens                        │  │  │
│  │  │  • Password history prevention        • Time-limited reset tokens                           │  │  │
│  │  │  • Strong password requirements       • Single-use token validation                         │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                         USER                                                       │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  👨‍💼 Administrator                      👤 Users                                                │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Full system administration         • Standard user operations                            │  │  │
│  │  │  • User management capabilities        • File upload and analysis                           │  │  │
│  │  │  • System configuration access        • Report generation                                   │  │  │
│  │  │  • Audit log monitoring               • Profile management                                  │  │  │
│  │  │  • Database health oversight          • View personal analysis results                      │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                        TARGET                                                      │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  🎯 Targets                                                                                  │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Network log files and data streams                                                      │  │  │
│  │  │  • Machine learning models and algorithms                                                   │  │  │
│  │  │  • User credentials and authentication data                                                 │  │  │
│  │  │  • System configuration and settings                                                       │  │  │
│  │  │  • Analysis results and reports                                                             │  │  │
│  │  │  • Database integrity and availability                                                      │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                   SECURITY TRAINING                                                │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  📚 Awareness Content                  🔍 Detection Tool                                      │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Security best practices training   • Threat detection algorithms                        │  │  │
│  │  │  • Password security guidelines       • Anomaly detection systems                          │  │  │
│  │  │  • Phishing awareness programs        • Real-time monitoring tools                         │  │  │
│  │  │  • Incident response procedures       • Machine learning threat analysis                   │  │  │
│  │  │  • Data handling protocols            • Automated alert systems                            │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                    PRISAD PROGRAM                                                  │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                                                                             │  │  │
│  │  │  📧 Secures → Logs → 🔒 Protects → ✉️ Ensures → Provides                                    │  │  │
│  │  │                                                                                             │  │  │
│  │  │  The PRISAD (Privacy, Reliability, Integrity, Security, Availability, Data Protection)     │  │  │
│  │  │  program ensures comprehensive security coverage across all system components:              │  │  │
│  │  │                                                                                             │  │  │
│  │  │  • Privacy: User data protection and confidentiality                                       │  │  │
│  │  │  • Reliability: System uptime and consistent performance                                    │  │  │
│  │  │  • Integrity: Data accuracy and system consistency                                          │  │  │
│  │  │  • Security: Threat protection and access control                                           │  │  │
│  │  │  • Availability: Service accessibility and disaster recovery                               │  │  │
│  │  │  • Data Protection: Encryption and secure data handling                                     │  │  │
│  │  │                                                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Authentication Architecture

### Multi-Factor Authentication Flow

```
┌─────────────┐
│    User     │
└──────┬──────┘
       │ 1. Login Request
       ▼
┌─────────────────────────────────────────────────────────────┐
│                AUTHENTICATION PROCESS                      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              STEP 1: CREDENTIAL VALIDATION          │  │
│  │                                                      │  │
│  │  Username/Email ──┐                                 │  │
│  │                   │    ┌─────────────────────────┐   │  │
│  │  Password ────────┼───>│   AuthManager.login()   │   │  │
│  │                   │    │                         │   │  │
│  │  User Agent ──────┘    │ • Hash verification     │   │  │
│  │                        │ • Account status check │   │  │
│  │                        │ • Rate limiting        │   │  │
│  │                        └─────────┬───────────────┘   │  │
│  └────────────────────────────────────┼───────────────────┘  │
│                                       │                      │
│                                       ▼                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              STEP 2: 2FA VERIFICATION               │  │
│  │                                                      │  │
│  │  ┌─────────────┐    ┌─────────────┐                 │  │
│  │  │ Check 2FA   │    │   Generate  │                 │  │
│  │  │  Status     │    │  QR Code    │                 │  │
│  │  └─────┬───────┘    └─────┬───────┘                 │  │
│  │        │                  │                         │  │
│  │        ▼                  ▼                         │  │
│  │  ┌─────────────┐    ┌─────────────┐                 │  │
│  │  │ TOTP Token  │    │  Setup 2FA  │                 │  │
│  │  │Verification │    │   Process   │                 │  │
│  │  └─────┬───────┘    └─────────────┘                 │  │
│  │        │                                            │  │
│  │        ▼                                            │  │
│  │  ┌─────────────────────────────────────────────┐   │  │
│  │  │         PyOTP.verify(token, secret)         │   │  │
│  │  └─────────────────┬───────────────────────────┘   │  │
│  └────────────────────┼───────────────────────────────┘  │
│                       │                                  │
│                       ▼                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              STEP 3: SESSION CREATION               │  │
│  │                                                      │  │
│  │  ┌─────────────────────────────────────────────┐   │  │
│  │  │           Flask-Login Session              │   │  │
│  │  │                                             │   │  │
│  │  │ • Generate session token (UUID)            │   │  │
│  │  │ • Set session timeout (30 minutes)         │   │  │
│  │  │ • Store user context                       │   │  │
│  │  │ • Log authentication event                 │   │  │
│  │  └─────────────────┬───────────────────────────┘   │  │
│  └────────────────────┼───────────────────────────────┘  │
└───────────────────────┼─────────────────────────────────┘
                        │ Authenticated Session
                        ▼
                ┌─────────────┐
                │ Dashboard   │
                │   Access    │
                └─────────────┘
```

### 2FA Implementation Details

```
┌─────────────────────────────────────────────────────────────┐
│                    2FA SETUP PROCESS                       │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │    User     │    │   System    │    │Authenticator│    │
│  │  Profile    │    │  Generates  │    │     App     │    │
│  │  Settings   │    │   Secret    │    │  (Google,   │    │
│  └──────┬──────┘    └──────┬──────┘    │ Microsoft)  │    │
│         │                  │           └──────┬──────┘    │
│         │ 1. Enable 2FA    │                  │           │
│         ├─────────────────>│                  │           │
│         │                  │ 2. Generate      │           │
│         │                  │    TOTP Secret   │           │
│         │                  │                  │           │
│         │ 3. QR Code       │                  │           │
│         │<─────────────────┤                  │           │
│         │                  │                  │           │
│         │ 4. Scan QR Code  │                  │           │
│         ├─────────────────────────────────────>│           │
│         │                  │                  │           │
│         │ 5. Enter Token   │                  │           │
│         ├─────────────────>│                  │           │
│         │                  │ 6. Verify Token  │           │
│         │                  │                  │           │
│         │ 7. 2FA Enabled   │                  │           │
│         │<─────────────────┤                  │           │
└─────────────────────────────────────────────────────────────┘

**TOTP Algorithm**: Time-based One-Time Password (RFC 6238)
**Secret Length**: 32 characters (Base32 encoded)
**Time Window**: 30 seconds
**Tolerance**: ±1 time window for clock drift
```

---

## Authorization Framework

### Role-Based Access Control (RBAC)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          RBAC ARCHITECTURE                                 │
│                                                                             │
│  ┌─────────────────┐                    ┌─────────────────┐               │
│  │     USERS       │                    │     ROLES       │               │
│  │                 │                    │                 │               │
│  │ ┌─────────────┐ │  Many-to-Many     │ ┌─────────────┐ │               │
│  │ │   User 1    │ │ ◄────────────────► │ │    Admin    │ │               │
│  │ │   User 2    │ │                    │ │    User     │ │               │
│  │ │   User 3    │ │                    │ │   Analyst   │ │               │
│  │ └─────────────┘ │                    │ └─────────────┘ │               │
│  └─────────────────┘                    └─────────────────┘               │
│           │                                       │                        │
│           │                                       │                        │
│           ▼                                       ▼                        │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                      PERMISSIONS MATRIX                            │  │
│  │                                                                     │  │
│  │  Resource/Action    │  Admin  │  User   │ Analyst │               │  │
│  │  ──────────────────────────────────────────────────               │  │
│  │  Dashboard View     │   ✓     │    ✓    │    ✓    │               │  │
│  │  Upload Logs        │   ✓     │    ✓    │    ✓    │               │  │
│  │  View Analysis      │   ✓     │    ✓    │    ✓    │               │  │
│  │  User Management    │   ✓     │    ✗    │    ✗    │               │  │
│  │  System Settings    │   ✓     │    ✗    │    ✗    │               │  │
│  │  Audit Logs         │   ✓     │    ✗    │    ✓    │               │  │
│  │  DB Health          │   ✓     │    ✗    │    ✓    │               │  │
│  │  Live Monitoring    │   ✓     │    ✓    │    ✓    │               │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Access Control Implementation

```
┌─────────────────────────────────────────────────────────────┐
│                 ACCESS CONTROL FLOW                        │
│                                                             │
│  ┌─────────────┐                                           │
│  │   Request   │                                           │
│  │   Arrives   │                                           │
│  └──────┬──────┘                                           │
│         │                                                  │
│         ▼                                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │            SESSION VALIDATION                      │  │
│  │                                                     │  │
│  │  ┌─────────────┐    ┌─────────────┐               │  │
│  │  │   Check     │    │   Verify    │               │  │
│  │  │  Session    │    │  Timeout    │               │  │
│  │  │   Token     │    │ (30 mins)   │               │  │
│  │  └─────┬───────┘    └─────┬───────┘               │  │
│  │        │                  │                       │  │
│  │        ▼                  ▼                       │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │        @login_required decorator           │  │  │
│  │  └─────────────┬───────────────────────────────┘  │  │
│  └────────────────┼───────────────────────────────────┘  │
│                   │                                      │
│                   ▼                                      │
│  ┌─────────────────────────────────────────────────────┐  │
│  │            ROLE AUTHORIZATION                      │  │
│  │                                                     │  │
│  │  ┌─────────────┐    ┌─────────────┐               │  │
│  │  │   Load      │    │   Check     │               │  │
│  │  │   User      │    │   Role      │               │  │
│  │  │   Roles     │    │Permissions  │               │  │
│  │  └─────┬───────┘    └─────┬───────┘               │  │
│  │        │                  │                       │  │
│  │        ▼                  ▼                       │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │      current_user.has_role(role_name)      │  │  │
│  │  └─────────────┬───────────────────────────────┘  │  │
│  └────────────────┼───────────────────────────────────┘  │
│                   │                                      │
│                   ▼                                      │
│         ┌─────────────────┐                              │
│         │   AUTHORIZED    │                              │
│         │    ACCESS       │                              │
│         └─────────────────┘                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Protection Framework

### Password Security

```
┌─────────────────────────────────────────────────────────────┐
│                  PASSWORD SECURITY LAYER                   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              PASSWORD HASHING                      │   │
│  │                                                     │   │
│  │  Plain Text Password                               │   │
│  │         │                                          │   │
│  │         ▼                                          │   │
│  │  ┌─────────────────────────────────────────────┐  │   │
│  │  │         Werkzeug Security                   │  │   │
│  │  │                                             │  │   │
│  │  │  Algorithm: PBKDF2-SHA256                   │  │   │
│  │  │  Salt: Random 16-byte salt                  │  │   │
│  │  │  Iterations: 260,000 (default)             │  │   │
│  │  │  Key Length: 32 bytes                       │  │   │
│  │  └─────────────────┬───────────────────────────┘  │   │
│  │                    │                              │   │
│  │                    ▼                              │   │
│  │  Hashed Password (stored in database)             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              PASSWORD VALIDATION                   │   │
│  │                                                     │   │
│  │  Input Password                                    │   │
│  │         │                                          │   │
│  │         ▼                                          │   │
│  │  ┌─────────────────────────────────────────────┐  │   │
│  │  │      check_password_hash()                  │  │   │
│  │  │                                             │  │   │
│  │  │  • Extract salt from stored hash           │  │   │
│  │  │  • Apply same hashing algorithm            │  │   │
│  │  │  • Compare with stored hash                │  │   │
│  │  │  • Constant-time comparison                │  │   │
│  │  └─────────────────┬───────────────────────────┘  │   │
│  │                    │                              │   │
│  │                    ▼                              │   │
│  │  Authentication Result (True/False)               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Database Security

```
┌─────────────────────────────────────────────────────────────┐
│                   DATABASE SECURITY                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              CONNECTION SECURITY                   │   │
│  │                                                     │   │
│  │  ┌─────────────┐    ┌─────────────┐               │   │
│  │  │ SSL/TLS     │    │ Connection  │               │   │
│  │  │ Encryption  │    │   Pooling   │               │   │
│  │  └─────────────┘    └─────────────┘               │   │
│  │                                                     │   │
│  │  ┌─────────────┐    ┌─────────────┐               │   │
│  │  │ Credential  │    │   Timeout   │               │   │
│  │  │ Management  │    │ Management  │               │   │
│  │  └─────────────┘    └─────────────┘               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              DATA PROTECTION                       │   │
│  │                                                     │   │
│  │  ┌─────────────┐    ┌─────────────┐               │   │
│  │  │   Input     │    │ SQL Injection│              │   │
│  │  │ Validation  │    │ Prevention   │               │   │
│  │  └─────────────┘    └─────────────┘               │   │
│  │                                                     │   │
│  │  ┌─────────────┐    ┌─────────────┐               │   │
│  │  │ Parameterized│   │ Transaction │               │   │
│  │  │   Queries    │   │   Control   │               │   │
│  │  └─────────────┘    └─────────────┘               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Monitoring & Audit

### Audit Trail System

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AUDIT TRAIL SYSTEM                               │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      SECURITY EVENTS LOGGING                       │   │
│  │                                                                     │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │   │
│  │  │   Login     │  │   Logout    │  │   Failed    │  │  Session  │ │   │
│  │  │  Events     │  │   Events    │  │   Attempts  │  │  Timeout  │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │   │
│  │                                                                     │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │   │
│  │  │   2FA       │  │   Role      │  │   Data      │  │  System   │ │   │
│  │  │  Events     │  │  Changes    │  │   Access    │  │  Events   │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      AUDIT LOG STRUCTURE                           │   │
│  │                                                                     │   │
│  │  {                                                                  │   │
│  │    "timestamp": "2024-01-15T10:30:00Z",                          │   │
│  │    "event_type": "login_success",                                 │   │
│  │    "user_id": 123,                                                 │   │
│  │    "username": "admin",                                           │   │
│  │    "ip_address": "192.168.1.100",                                │   │
│  │    "user_agent": "Mozilla/5.0...",                               │   │
│  │    "session_id": "uuid-string",                                   │   │
│  │    "details": {                                                    │   │
│  │      "2fa_used": true,                                             │   │
│  │      "login_method": "web_interface"                              │   │
│  │    }                                                                │   │
│  │  }                                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Monitoring Dashboard

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURITY MONITORING DASHBOARD                       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      REAL-TIME ALERTS                              │   │
│  │                                                                     │   │
│  │  🔴 Multiple Failed Login Attempts                                 │   │
│  │  🟡 Unusual Login Time (Outside Business Hours)                   │   │
│  │  🟠 New Device/Location Login                                      │   │
│  │  🔴 Privilege Escalation Attempt                                   │   │
│  │  🟡 Session Timeout Exceeded                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      SECURITY METRICS                              │   │
│  │                                                                     │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │   │
│  │  │ Active      │  │ Failed      │  │ 2FA         │                │   │
│  │  │ Sessions    │  │ Logins      │  │ Adoption    │                │   │
│  │  │    15       │  │    3        │  │   85%       │                │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                │   │
│  │                                                                     │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │   │
│  │  │ Threat      │  │ System      │  │ Database    │                │   │
│  │  │ Events      │  │ Health      │  │ Health      │                │   │
│  │  │   127       │  │   Good      │  │   Good      │                │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Session Management Security

### Session Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                  SESSION LIFECYCLE                         │
│                                                             │
│  ┌─────────────┐                                           │
│  │   Login     │                                           │
│  │ Successful  │                                           │
│  └──────┬──────┘                                           │
│         │                                                  │
│         ▼                                                  │
│  ┌─────────────────────────────────────────────────────┐  │
│  │            SESSION CREATION                        │  │
│  │                                                     │  │
│  │  • Generate UUID session token                     │  │
│  │  • Set creation timestamp                          │  │
│  │  • Set expiration (30 minutes)                     │  │
│  │  • Store user context                              │  │
│  │  • Set secure cookie flags                         │  │
│  └─────────────────┬───────────────────────────────────┘  │
│                    │                                      │
│                    ▼                                      │
│  ┌─────────────────────────────────────────────────────┐  │
│  │            SESSION VALIDATION                      │  │
│  │                                                     │  │
│  │  On each request:                                  │  │
│  │  • Check session token exists                      │  │
│  │  • Verify token validity                           │  │
│  │  • Check expiration time                           │  │
│  │  • Update last activity                            │  │
│  │  • Extend session if valid                         │  │
│  └─────────────────┬───────────────────────────────────┘  │
│                    │                                      │
│                    ▼                                      │
│  ┌─────────────────────────────────────────────────────┐  │
│  │            SESSION TERMINATION                     │  │
│  │                                                     │  │
│  │  Triggers:                                         │  │
│  │  • Manual logout                                   │  │
│  │  • Timeout (30 minutes inactivity)                │  │
│  │  • Security violation                              │  │
│  │  • System shutdown                                 │  │
│  │                                                     │  │
│  │  Actions:                                          │  │
│  │  • Clear session data                              │  │
│  │  • Invalidate cookies                              │  │
│  │  • Log termination event                           │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Configuration

### Environment Security

```
┌─────────────────────────────────────────────────────────────┐
│                SECURITY CONFIGURATION                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              ENVIRONMENT VARIABLES                 │   │
│  │                                                     │   │
│  │  SECRET_KEY=<cryptographically-secure-key>        │   │
│  │  DATABASE_URL=<encrypted-connection-string>        │   │
│  │  FLASK_ENV=production                              │   │
│  │  SESSION_TIMEOUT=1800  # 30 minutes               │   │
│  │  MAX_LOGIN_ATTEMPTS=5                              │   │
│  │  LOCKOUT_DURATION=900  # 15 minutes               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              SECURITY HEADERS                      │   │
│  │                                                     │   │
│  │  Content-Security-Policy: default-src 'self'      │   │
│  │  X-Frame-Options: DENY                             │   │
│  │  X-Content-Type-Options: nosniff                   │   │
│  │  Strict-Transport-Security: max-age=31536000       │   │
│  │  X-XSS-Protection: 1; mode=block                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              COOKIE SECURITY                       │   │
│  │                                                     │   │
│  │  HttpOnly: true                                    │   │
│  │  Secure: true (HTTPS only)                         │   │
│  │  SameSite: Strict                                  │   │
│  │  Path: /                                           │   │
│  │  Domain: <application-domain>                      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Compliance & Standards

### Security Framework Compliance

| Security Standard | Implementation | Status |
|-------------------|----------------|--------|
| **OWASP Top 10** | |
| A01: Broken Access Control | RBAC + Session Management | ✅ Implemented |
| A02: Cryptographic Failures | HTTPS + Password Hashing | ✅ Implemented |
| A03: Injection | Parameterized Queries | ✅ Implemented |
| A04: Insecure Design | Security by Design | ✅ Implemented |
| A05: Security Misconfiguration | Secure Defaults | ✅ Implemented |
| A06: Vulnerable Components | Dependency Management | ✅ Implemented |
| A07: Authentication Failures | 2FA + Strong Passwords | ✅ Implemented |
| A08: Software Integrity | Code Signing + Validation | 🟡 Partial |
| A09: Logging Failures | Comprehensive Audit Logs | ✅ Implemented |
| A10: Server-Side Request Forgery | Input Validation | ✅ Implemented |

### Security Testing

```
┌─────────────────────────────────────────────────────────────┐
│                  SECURITY TESTING MATRIX                   │
│                                                             │
│  Test Type              │ Frequency │ Coverage              │
│  ──────────────────────────────────────────────────────────│
│  Authentication Tests   │ Daily     │ Login/2FA/Session     │
│  Authorization Tests    │ Weekly    │ RBAC/Permissions      │
│  Input Validation       │ Daily     │ All User Inputs       │
│  SQL Injection          │ Weekly    │ Database Queries      │
│  XSS Prevention         │ Weekly    │ Output Encoding       │
│  Session Security       │ Daily     │ Token Management      │
│  Password Security      │ Monthly   │ Hashing/Policies      │
│  Audit Log Integrity    │ Daily     │ Log Completeness      │
└─────────────────────────────────────────────────────────────┘
```

---

*This Security Framework provides comprehensive protection for the Network Threat Classification System, ensuring data confidentiality, integrity, and availability while maintaining compliance with industry security standards.*