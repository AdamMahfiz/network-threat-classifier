# Database Configuration

This application uses SQLite as its database system for simplicity and ease of deployment.

## SQLite Database

The application uses SQLite, a lightweight, file-based database that requires no separate server installation.

### Features:
- **Self-contained** - No external database server required
- **Zero-configuration** - Works out of the box
- **Portable** - Database is stored in a single file
- **Reliable** - ACID compliant with excellent data integrity

### Using SQLite

The database is automatically created when you first run the application. No additional setup is required.

#### Configuration

Set the database path in your `.env` file:

```bash
# SQLite database path (relative to project root)
SQLITE_DATABASE_PATH=data/threat_classifier.db
```

If not specified, the default path `data/threat_classifier.db` will be used.

### Database Schema

The application automatically creates the following tables:

1. **users** - User authentication and profile information
2. **analysis_sessions** - File upload and analysis session tracking
3. **log_entries** - Individual log entries from uploaded files
4. **threat_events** - Detected threats and their classifications

### Database Operations

#### Initialization
```python
from src.threat_classifier.database.init_db import init_database
init_database()
```

#### Getting a Session
```python
from src.threat_classifier.database.connection import db
session = db.get_session()
```

#### Health Check
```python
health_info = db.get_database_info()
```

### Data Storage

#### SQLite
Data is stored in the SQLite database file as configured in `SQLITE_DATABASE_PATH`.

### Backup and Recovery

#### SQLite Backup
```bash
# Simple file copy
cp data/threat_classifier.db data/threat_classifier_backup.db

# Or using SQLite command
sqlite3 data/threat_classifier.db ".backup data/threat_classifier_backup.db"
```

#### Recovery
```bash
# Restore from backup
cp data/threat_classifier_backup.db data/threat_classifier.db
```

### Performance Considerations

SQLite is suitable for:
- Development and testing
- Small to medium-scale deployments
- Single-server applications
- Applications with moderate concurrent users

### Database Comparison

| Feature | SQLite |
|---------|---------|
| Setup Complexity | None |
| Scalability | Medium |
| Concurrent Users | Good |
| Backup | File Copy |
| Maintenance | Minimal |

### Troubleshooting

#### Database Locked Error
If you encounter "database is locked" errors:
1. Ensure no other processes are accessing the database
2. Check file permissions
3. Restart the application

#### File Not Found
If the database file is missing:
1. Check the `SQLITE_DATABASE_PATH` configuration
2. Ensure the directory exists and is writable
3. The application will create the database automatically on first run

#### Performance Issues
For better performance:
1. Ensure the database file is on a fast storage device
2. Consider using WAL mode for better concurrent access
3. Regular VACUUM operations for maintenance

### Migration Notes

This application has been configured to use SQLite exclusively for simplified deployment and maintenance. All database operations are optimized for SQLite's capabilities and limitations.

## Viewing Database Content

### 1. Command-Line Database Viewer
Run the included database viewer script:
```bash
python view_database.py
```

**Features**:
- Display all table contents
- Show table statistics
- Export data to CSV files
- Works with both PostgreSQL and SQLite

### 2. External SQLite Browser Tools

When using SQLite (fallback mode), you can use these external tools:

#### DB Browser for SQLite (Recommended)
- **Download**: https://sqlitebrowser.org/
- **Features**: GUI interface, query editor, data visualization
- **Usage**: Open `data/threat_classifier.db` file

#### SQLite Studio
- **Download**: https://sqlitestudio.pl/
- **Features**: Advanced SQL editor, data export/import
- **Usage**: Connect to `data/threat_classifier.db`

#### SQLiteExpert
- **Download**: http://www.sqliteexpert.com/
- **Features**: Professional SQLite manager
- **Usage**: Open database file `data/threat_classifier.db`

#### Command Line SQLite
Built into most systems:
```bash
# Open SQLite database
sqlite3 data/threat_classifier.db

# Common commands:
.tables                    # List all tables
.schema table_name        # Show table structure
SELECT * FROM users;      # Query data
.quit                     # Exit
```

#### Online SQLite Viewers
- **SQLite Viewer**: https://sqliteviewer.app/
- **DB Fiddle**: https://www.db-fiddle.com/
- Upload your `data/threat_classifier.db` file

## Database Location

### PostgreSQL
Data is stored on your PostgreSQL server as configured in `DATABASE_URL`.

### SQLite
- **Database file**: `data/threat_classifier.db`
- **Location**: Project root directory
- **Backup**: Simply copy the `.db` file

## Troubleshooting

### PostgreSQL Connection Issues
1. Check `DATABASE_URL` format
2. Verify network connectivity
3. Confirm database credentials
4. Check firewall settings

**The application will automatically fall back to SQLite if PostgreSQL fails.**

### SQLite Issues
1. Check file permissions in `data/` directory
2. Ensure sufficient disk space
3. Verify SQLite installation

### Database Migration
To switch between databases:
1. Update `DATABASE_URL` in `.env`
2. Restart the application
3. Database tables are created automatically

## Feature Comparison

| Feature | PostgreSQL | SQLite |
|---------|------------|--------|
| Concurrent Users | ✅ Excellent | ⚠️ Limited |
| Performance | ✅ High | ✅ Good |
| Setup Complexity | ⚠️ Moderate | ✅ Zero config |
| Backup | ⚠️ Complex | ✅ File copy |
| Production Ready | ✅ Yes | ⚠️ Small scale |
| ACID Compliance | ✅ Full | ✅ Full |
| Network Required | ✅ Yes | ❌ No |

## Security Notes

- Custom queries can be executed using external SQLite browser tools
- Sensitive data is properly handled in both database types
- SQLite file should be secured with appropriate file permissions