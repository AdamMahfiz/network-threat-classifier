# Chapter 6: Entity Relationship Diagram (ERD)

## Network Threat Classification System - Database ERD

### Overview
This document presents the Entity Relationship Diagram (ERD) for the Network Threat Classification System database, illustrating the relationships between entities and their attributes.

---

## Database ERD

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    NETWORK THREAT CLASSIFICATION SYSTEM                                    │
│                                         ENTITY RELATIONSHIP DIAGRAM                                        │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                      CORE ENTITIES                                                 │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                    USERS                                                   │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │  │  │
│  │  │  │                              USER ENTITY                                          │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Attributes:                                                                       │   │  │  │
│  │  │  │  • id (PK) - INTEGER, AUTO_INCREMENT, NOT NULL                                    │   │  │  │
│  │  │  │  • username - VARCHAR(80), UNIQUE, NOT NULL                                       │   │  │  │
│  │  │  │  • email - VARCHAR(120), UNIQUE, NOT NULL                                         │   │  │  │
│  │  │  │  • password_hash - VARCHAR(255), NOT NULL                                         │   │  │  │
│  │  │  │  • role_id (FK) - INTEGER, NOT NULL                                               │   │  │  │
│  │  │  │  • totp_secret - VARCHAR(32), NULLABLE                                            │   │  │  │
│  │  │  │  • is_2fa_enabled - BOOLEAN, DEFAULT FALSE                                        │   │  │  │
│  │  │  │  • created_at - TIMESTAMP, DEFAULT CURRENT_TIMESTAMP                              │   │  │  │
│  │  │  │  • updated_at - TIMESTAMP, DEFAULT CURRENT_TIMESTAMP ON UPDATE                    │   │  │  │
│  │  │  │  • last_login - TIMESTAMP, NULLABLE                                               │   │  │  │
│  │  │  │  • is_active - BOOLEAN, DEFAULT TRUE                                              │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Constraints:                                                                      │   │  │  │
│  │  │  │  • PRIMARY KEY (id)                                                                │   │  │  │
│  │  │  │  • UNIQUE INDEX (username)                                                         │   │  │  │
│  │  │  │  • UNIQUE INDEX (email)                                                            │   │  │  │
│  │  │  │  • FOREIGN KEY (role_id) REFERENCES roles(id)                                     │   │  │  │
│  │  │  │  • CHECK (email LIKE '%@%')                                                        │   │  │  │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────┘   │  │  │
│  │  │                                                │                                              │  │  │
│  │  │                                                │ (1:N)                                        │  │  │
│  │  │                                                ▼                                              │  │  │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │  │  │
│  │  │  │                            ANALYSIS SESSIONS                                     │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Attributes:                                                                       │   │  │  │
│  │  │  │  • id (PK) - INTEGER, AUTO_INCREMENT, NOT NULL                                    │   │  │  │
│  │  │  │  • user_id (FK) - INTEGER, NOT NULL                                               │   │  │  │
│  │  │  │  • filename - VARCHAR(255), NOT NULL                                              │   │  │  │
│  │  │  │  • file_size - BIGINT, NOT NULL                                                   │   │  │  │
│  │  │  │  • upload_time - TIMESTAMP, DEFAULT CURRENT_TIMESTAMP                             │   │  │  │
│  │  │  │  • processing_start - TIMESTAMP, NULLABLE                                         │   │  │  │
│  │  │  │  • processing_end - TIMESTAMP, NULLABLE                                           │   │  │  │
│  │  │  │  • status - ENUM('pending', 'processing', 'completed', 'failed')                 │   │  │  │
│  │  │  │  • total_logs - INTEGER, DEFAULT 0                                                │   │  │  │
│  │  │  │  • threat_distribution - JSON, NULLABLE                                           │   │  │  │
│  │  │  │  • error_message - TEXT, NULLABLE                                                 │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Constraints:                                                                      │   │  │  │
│  │  │  │  • PRIMARY KEY (id)                                                                │   │  │  │
│  │  │  │  • FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE                   │   │  │  │
│  │  │  │  • INDEX (user_id, upload_time)                                                    │   │  │  │
│  │  │  │  • CHECK (file_size > 0)                                                           │   │  │  │
│  │  │  │  • CHECK (total_logs >= 0)                                                         │   │  │  │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                                │                                                    │  │
│  │                                                │ (1:N)                                              │  │
│  │                                                ▼                                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                    LOG ENTRIES                                           │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │  │  │
│  │  │  │                              LOG ENTRY ENTITY                                    │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Attributes:                                                                       │   │  │  │
│  │  │  │  • id (PK) - INTEGER, AUTO_INCREMENT, NOT NULL                                    │   │  │  │
│  │  │  │  • session_id (FK) - INTEGER, NOT NULL                                            │   │  │  │
│  │  │  │  • raw_log_data - TEXT, NOT NULL                                                   │   │  │  │
│  │  │  │  • threat_level - ENUM('Low', 'Medium', 'High'), NOT NULL                         │   │  │  │
│  │  │  │  • confidence_score - DECIMAL(5,4), NOT NULL                                       │   │  │  │
│  │  │  │  • processed_at - TIMESTAMP, DEFAULT CURRENT_TIMESTAMP                             │   │  │  │
│  │  │  │  • features - JSON, NULLABLE                                                       │   │  │  │
│  │  │  │  • source_ip - VARCHAR(45), NULLABLE                                               │   │  │  │
│  │  │  │  • destination_ip - VARCHAR(45), NULLABLE                                          │   │  │  │
│  │  │  │  • protocol - VARCHAR(20), NULLABLE                                                │   │  │  │
│  │  │  │  • port - INTEGER, NULLABLE                                                        │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Constraints:                                                                      │   │  │  │
│  │  │  │  • PRIMARY KEY (id)                                                                │   │  │  │
│  │  │  │  • FOREIGN KEY (session_id) REFERENCES analysis_sessions(id) ON DELETE CASCADE    │   │  │  │
│  │  │  │  • INDEX (session_id, threat_level)                                                │   │  │  │
│  │  │  │  • INDEX (processed_at)                                                             │   │  │  │
│  │  │  │  • CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0)                    │   │  │  │
│  │  │  │  • CHECK (port >= 0 AND port <= 65535)                                             │   │  │  │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  │                                                │                                                    │  │
│  │                                                │ (1:N)                                              │  │
│  │                                                ▼                                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                   THREAT EVENTS                                           │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │  │  │
│  │  │  │                            THREAT EVENT ENTITY                                   │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Attributes:                                                                       │   │  │  │
│  │  │  │  • id (PK) - INTEGER, AUTO_INCREMENT, NOT NULL                                    │   │  │  │
│  │  │  │  • session_id (FK) - INTEGER, NOT NULL                                            │   │  │  │
│  │  │  │  • log_entry_id (FK) - INTEGER, NULLABLE                                          │   │  │  │
│  │  │  │  • event_type - VARCHAR(50), NOT NULL                                              │   │  │  │
│  │  │  │  • severity - ENUM('Low', 'Medium', 'High', 'Critical'), NOT NULL                 │   │  │  │
│  │  │  │  • description - TEXT, NOT NULL                                                    │   │  │  │
│  │  │  │  • event_details - JSON, NULLABLE                                                 │   │  │  │
│  │  │  │  • created_at - TIMESTAMP, DEFAULT CURRENT_TIMESTAMP                              │   │  │  │
│  │  │  │  • resolved_at - TIMESTAMP, NULLABLE                                               │   │  │  │
│  │  │  │  • is_resolved - BOOLEAN, DEFAULT FALSE                                            │   │  │  │
│  │  │  │  • assigned_to - INTEGER, NULLABLE                                                │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Constraints:                                                                      │   │  │  │
│  │  │  │  • PRIMARY KEY (id)                                                                │   │  │  │
│  │  │  │  • FOREIGN KEY (session_id) REFERENCES analysis_sessions(id) ON DELETE CASCADE    │   │  │  │
│  │  │  │  • FOREIGN KEY (log_entry_id) REFERENCES log_entries(id) ON DELETE SET NULL       │   │  │  │
│  │  │  │  • FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL              │   │  │  │
│  │  │  │  • INDEX (session_id, severity)                                                    │   │  │  │
│  │  │  │  • INDEX (created_at)                                                               │   │  │  │
│  │  │  │  • INDEX (event_type)                                                               │   │  │  │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                    SUPPORTING ENTITIES                                             │  │
│  │                                                                                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────┐  │  │
│  │  │                                      ROLES                                                 │  │  │
│  │  │                                                                                             │  │  │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │  │  │
│  │  │  │                               ROLE ENTITY                                         │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Attributes:                                                                       │   │  │  │
│  │  │  │  • id (PK) - INTEGER, AUTO_INCREMENT, NOT NULL                                    │   │  │  │
│  │  │  │  • name - VARCHAR(50), UNIQUE, NOT NULL                                           │   │  │  │
│  │  │  │  • description - TEXT, NULLABLE                                                   │   │  │  │
│  │  │  │  • permissions - JSON, NULLABLE                                                   │   │  │  │
│  │  │  │  • created_at - TIMESTAMP, DEFAULT CURRENT_TIMESTAMP                              │   │  │  │
│  │  │  │  • is_active - BOOLEAN, DEFAULT TRUE                                              │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Constraints:                                                                      │   │  │  │
│  │  │  │  • PRIMARY KEY (id)                                                                │   │  │  │
│  │  │  │  • UNIQUE INDEX (name)                                                             │   │  │  │
│  │  │  │                                                                                     │   │  │  │
│  │  │  │  Default Roles:                                                                    │   │  │  │
│  │  │  │  • admin (id: 1) - Full system access                                             │   │  │  │
│  │  │  │  • user (id: 2) - Standard user access                                            │   │  │  │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────┘   │  │  │
│  │  └─────────────────────────────────────────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Relationship Details

### Primary Relationships

#### 1. Users ↔ Roles (Many-to-One)
```
USERS ||--o{ ROLES
  │           │
  │           └── role_id (FK)
  └── id (PK)

Relationship Type: Many-to-One
Cardinality: N:1
Constraints:
  • Each user must have exactly one role
  • Each role can be assigned to multiple users
  • Foreign key constraint with referential integrity
  • Default role assignment for new users
```

#### 2. Users ↔ Analysis Sessions (One-to-Many)
```
USERS ||--o{ ANALYSIS_SESSIONS
  │              │
  │              └── user_id (FK)
  └── id (PK)

Relationship Type: One-to-Many
Cardinality: 1:N
Constraints:
  • Each user can have multiple analysis sessions
  • Each session belongs to exactly one user
  • Cascade delete: removing user deletes all sessions
  • Index on (user_id, upload_time) for performance
```

#### 3. Analysis Sessions ↔ Log Entries (One-to-Many)
```
ANALYSIS_SESSIONS ||--o{ LOG_ENTRIES
        │                    │
        │                    └── session_id (FK)
        └── id (PK)

Relationship Type: One-to-Many
Cardinality: 1:N
Constraints:
  • Each session can contain multiple log entries
  • Each log entry belongs to exactly one session
  • Cascade delete: removing session deletes all log entries
  • Index on (session_id, threat_level) for filtering
```

#### 4. Analysis Sessions ↔ Threat Events (One-to-Many)
```
ANALYSIS_SESSIONS ||--o{ THREAT_EVENTS
        │                     │
        │                     └── session_id (FK)
        └── id (PK)

Relationship Type: One-to-Many
Cardinality: 1:N
Constraints:
  • Each session can generate multiple threat events
  • Each threat event belongs to exactly one session
  • Cascade delete: removing session deletes all threat events
  • Index on (session_id, severity) for prioritization
```

#### 5. Log Entries ↔ Threat Events (One-to-Many, Optional)
```
LOG_ENTRIES ||--o{ THREAT_EVENTS
     │                │
     │                └── log_entry_id (FK, NULLABLE)
     └── id (PK)

Relationship Type: One-to-Many (Optional)
Cardinality: 1:N (Optional)
Constraints:
  • Each log entry can trigger multiple threat events
  • Each threat event may reference one specific log entry
  • Set NULL on delete: removing log entry sets reference to NULL
  • Optional relationship for system-generated events
```

#### 6. Users ↔ Threat Events (One-to-Many, Assignment)
```
USERS ||--o{ THREAT_EVENTS
  │              │
  │              └── assigned_to (FK, NULLABLE)
  └── id (PK)

Relationship Type: One-to-Many (Optional)
Cardinality: 1:N (Optional)
Constraints:
  • Each user can be assigned multiple threat events
  • Each threat event may be assigned to one user
  • Set NULL on delete: removing user unassigns events
  • Optional assignment for event management
```

---

## Entity Attributes Summary

### Data Types Used

| Data Type | Usage | Examples |
|-----------|-------|----------|
| **INTEGER** | Primary keys, foreign keys, counters | id, user_id, total_logs |
| **VARCHAR(n)** | Text fields with length limits | username(80), email(120), filename(255) |
| **TEXT** | Large text content | raw_log_data, description, error_message |
| **TIMESTAMP** | Date and time tracking | created_at, updated_at, processed_at |
| **BOOLEAN** | True/false flags | is_2fa_enabled, is_active, is_resolved |
| **DECIMAL(5,4)** | Precision numbers | confidence_score (0.0000-1.0000) |
| **ENUM** | Predefined value sets | threat_level, status, severity |
| **JSON** | Structured data storage | threat_distribution, features, permissions |
| **BIGINT** | Large numbers | file_size (bytes) |

### Indexing Strategy

```sql
-- Performance Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_sessions_user_time ON analysis_sessions(user_id, upload_time);
CREATE INDEX idx_logs_session_threat ON log_entries(session_id, threat_level);
CREATE INDEX idx_logs_processed_at ON log_entries(processed_at);
CREATE INDEX idx_events_session_severity ON threat_events(session_id, severity);
CREATE INDEX idx_events_created_at ON threat_events(created_at);
CREATE INDEX idx_events_type ON threat_events(event_type);

-- Composite Indexes for Common Queries
CREATE INDEX idx_logs_session_confidence ON log_entries(session_id, confidence_score DESC);
CREATE INDEX idx_events_unresolved ON threat_events(is_resolved, severity, created_at);
```

### Constraints Summary

#### Referential Integrity
- **CASCADE DELETE**: Users → Sessions → Log Entries/Threat Events
- **SET NULL**: Log Entries → Threat Events (optional reference)
- **RESTRICT**: Roles → Users (prevent role deletion if users exist)

#### Data Validation
- **Email Format**: CHECK constraint for valid email format
- **Confidence Score**: Range validation (0.0 - 1.0)
- **Port Numbers**: Range validation (0 - 65535)
- **File Size**: Positive values only
- **Unique Constraints**: Username, email, role names

#### Business Rules
- **Default Values**: Timestamps, boolean flags, status enums
- **Required Fields**: Core identification and classification data
- **Optional Fields**: Extended metadata and assignment information

---

## Database Normalization

### Normalization Level: 3NF (Third Normal Form)

#### 1NF Compliance
- ✅ All attributes contain atomic values
- ✅ No repeating groups or arrays in columns
- ✅ Each row is unique with primary key

#### 2NF Compliance
- ✅ All non-key attributes fully depend on primary key
- ✅ No partial dependencies on composite keys
- ✅ Proper foreign key relationships

#### 3NF Compliance
- ✅ No transitive dependencies
- ✅ All non-key attributes depend only on primary key
- ✅ Separate entities for roles, users, sessions, logs, events

### Denormalization Considerations

#### JSON Fields (Controlled Denormalization)
- **threat_distribution**: Aggregated statistics for performance
- **features**: ML feature vectors for analysis
- **event_details**: Flexible event metadata
- **permissions**: Role-based access control data

#### Benefits
- Reduced JOIN operations for common queries
- Flexible schema for evolving requirements
- Improved read performance for dashboard queries

#### Trade-offs
- Slightly increased storage requirements
- JSON field queries less efficient than normalized columns
- Requires application-level validation for JSON structure

---

*This ERD provides a comprehensive view of the database structure for the Network Threat Classification System, showing all entities, relationships, constraints, and design decisions that support the system's functionality and performance requirements.*