# Chapter 6: Data Dictionary

## Network Threat Classification System - Database Schema Documentation

### Overview
This data dictionary provides comprehensive documentation of all database tables, fields, data types, constraints, and relationships within the Network Threat Classification System.

---

## 1. Users Table

**Table Name:** `users`
**Purpose:** Stores user account information and authentication data

| Field Name | Data Type | Constraints | Description |
|------------|-----------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Unique user identifier |
| username | STRING(80) | UNIQUE, NOT NULL | User login name |
| email | STRING(120) | UNIQUE, NOT NULL | User email address |
| password_hash | STRING(255) | NOT NULL | Hashed password using Werkzeug security |
| totp_secret | STRING(32) | NULLABLE | TOTP secret for 2FA authentication |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Account creation timestamp |
| last_login | DATETIME | NULLABLE | Last successful login timestamp |
| is_active | BOOLEAN | DEFAULT TRUE | Account status flag |

**Relationships:**
- Many-to-Many with `roles` table through `user_roles` association table
- One-to-Many with `analysis_sessions` table

---

## 2. Roles Table

**Table Name:** `roles`
**Purpose:** Defines user roles and permissions within the system

| Field Name | Data Type | Constraints | Description |
|------------|-----------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Unique role identifier |
| name | STRING(64) | UNIQUE, NOT NULL | Role name (e.g., 'admin', 'user') |
| description | STRING(255) | NULLABLE | Role description |

**Relationships:**
- Many-to-Many with `users` table through `user_roles` association table

---

## 3. User Roles Association Table

**Table Name:** `user_roles`
**Purpose:** Junction table for many-to-many relationship between users and roles

| Field Name | Data Type | Constraints | Description |
|------------|-----------|-------------|-------------|
| user_id | INTEGER | PRIMARY KEY, FOREIGN KEY | References users.id |
| role_id | INTEGER | PRIMARY KEY, FOREIGN KEY | References roles.id |

**Relationships:**
- Foreign Key to `users.id`
- Foreign Key to `roles.id`

---

## 4. Analysis Sessions Table

**Table Name:** `analysis_sessions`
**Purpose:** Tracks threat analysis sessions and their results

| Field Name | Data Type | Constraints | Description |
|------------|-----------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Unique session identifier |
| session_id | STRING(36) | UNIQUE, NOT NULL | UUID for session tracking |
| user_id | INTEGER | FOREIGN KEY, NOT NULL | References users.id |
| filename | STRING(255) | NULLABLE | Original filename if uploaded |
| total_logs | INTEGER | DEFAULT 0 | Total number of logs processed |
| threat_distribution | JSON | NULLABLE | Threat level counts {"Low": n, "Medium": n, "High": n} |
| created_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Session creation timestamp |
| completed_at | DATETIME | NULLABLE | Session completion timestamp |
| status | STRING(20) | DEFAULT 'pending' | Session status (pending, processing, completed, failed) |

**Relationships:**
- Many-to-One with `users` table (user_id)
- One-to-Many with `log_entries` table
- One-to-Many with `threat_events` table

---

## 5. Log Entries Table

**Table Name:** `log_entries`
**Purpose:** Stores individual log entries and their classification results

| Field Name | Data Type | Constraints | Description |
|------------|-----------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Unique log entry identifier |
| session_id | INTEGER | FOREIGN KEY, NOT NULL | References analysis_sessions.id |
| original_text | TEXT | NOT NULL | Original log text content |
| threat_level | STRING(10) | NOT NULL | Classified threat level (Low, Medium, High) |
| confidence_score | FLOAT | NOT NULL | ML model confidence (0.0 to 1.0) |
| features_extracted | JSON | NULLABLE | Feature vector used for classification |
| processed_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Processing timestamp |

**Relationships:**
- Many-to-One with `analysis_sessions` table (session_id)

---

## 6. Threat Events Table

**Table Name:** `threat_events`
**Purpose:** Logs significant threat events and security incidents

| Field Name | Data Type | Constraints | Description |
|------------|-----------|-------------|-------------|
| id | INTEGER | PRIMARY KEY, AUTO_INCREMENT | Unique event identifier |
| session_id | INTEGER | FOREIGN KEY, NOT NULL | References analysis_sessions.id |
| event_type | STRING(50) | NOT NULL | Type of threat event |
| severity | STRING(10) | NOT NULL | Event severity (Low, Medium, High, Critical) |
| source_ip | STRING(45) | NULLABLE | Source IP address if available |
| target_ip | STRING(45) | NULLABLE | Target IP address if available |
| port | INTEGER | NULLABLE | Network port involved |
| protocol | STRING(10) | NULLABLE | Network protocol (TCP, UDP, etc.) |
| details | JSON | NULLABLE | Additional event details |
| detected_at | DATETIME | DEFAULT CURRENT_TIMESTAMP | Event detection timestamp |

**Relationships:**
- Many-to-One with `analysis_sessions` table (session_id)

---

## Database Relationships Summary

### Entity Relationship Diagram (ERD) Description:

1. **Users ↔ Roles (Many-to-Many)**
   - Junction table: `user_roles`
   - Allows users to have multiple roles
   - Supports role-based access control (RBAC)

2. **Users → Analysis Sessions (One-to-Many)**
   - Each user can create multiple analysis sessions
   - Sessions track user activity and analysis history

3. **Analysis Sessions → Log Entries (One-to-Many)**
   - Each session contains multiple log entries
   - Maintains session-based grouping of logs

4. **Analysis Sessions → Threat Events (One-to-Many)**
   - Each session can generate multiple threat events
   - Links events to their originating analysis

---

## Data Types and Constraints

### Primary Data Types Used:
- **INTEGER**: Numeric identifiers and counts
- **STRING(n)**: Variable-length text with maximum length
- **TEXT**: Large text content (log entries)
- **DATETIME**: Timestamp fields with timezone support
- **FLOAT**: Decimal numbers (confidence scores)
- **JSON**: Structured data (threat distribution, features, details)
- **BOOLEAN**: True/false flags

### Key Constraints:
- **PRIMARY KEY**: Unique row identifier
- **FOREIGN KEY**: Referential integrity between tables
- **UNIQUE**: Ensures no duplicate values
- **NOT NULL**: Required fields
- **DEFAULT**: Automatic value assignment

---

## Indexes and Performance

### Recommended Indexes:
1. `users.username` - Fast login lookups
2. `users.email` - Email-based operations
3. `analysis_sessions.session_id` - Session tracking
4. `analysis_sessions.user_id` - User session history
5. `log_entries.session_id` - Session-based log retrieval
6. `threat_events.session_id` - Event correlation
7. `threat_events.detected_at` - Time-based queries

### Performance Considerations:
- JSON fields enable flexible schema evolution
- Proper indexing supports efficient queries
- Foreign key constraints maintain data integrity
- Timestamp fields enable audit trails and analytics

---

## Security Considerations

### Data Protection:
- **Password Storage**: Uses Werkzeug password hashing (PBKDF2)
- **2FA Secrets**: TOTP secrets stored securely
- **Session Management**: UUID-based session tracking
- **Audit Trail**: Comprehensive logging of user actions

### Access Control:
- Role-based permissions through `user_roles` table
- User activity tracking via `analysis_sessions`
- Threat event logging for security monitoring

---

*This data dictionary serves as the foundation for understanding the Network Threat Classification System's data architecture and supports system maintenance, development, and security auditing activities.*