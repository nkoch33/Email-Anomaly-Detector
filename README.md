# Email Anomaly Detector - Connection Architecture

## Overview
3-tier web application with authentication:
- **Frontend**: HTML/JavaScript (Browser)
- **Backend**: C++ with Crow framework (Port 8080)
- **Database**: MySQL (Port 3306)

## Technology Stack
- **Web Framework**: Crow (C++ header-only web framework)
- **Database**: MySQL with C++ connector
- **Security**: OpenSSL for password hashing
- **Authentication**: Session-based with secure cookies

## Connection Flow
```
Browser -> Frontend HTML/JS -> Backend C++ -> MySQL Database
```

## Frontend to Backend
- **Files**: `Frontend/login.html`, `Frontend/dashboard.html`
- **API**: JavaScript `SecureAPI` class
- **URL**: `http://localhost:8080/api`
- **Auth**: Session cookies

## Backend to Database
- **File**: `Backend/main.cpp`
- **Class**: `SecureDatabaseManager`
- **Database**: `Email_Anomaly_Detector`
- **Credentials**: From `config.env`

## Database Schema
- **File**: `Database/Email_Anomaly.sql`
- **Tables**: `users`, `sessions`
- **Test Users**: `testuser/testpass`, `testuser2/password123`

## Key Functions

### Backend (main.cpp)
**AuthManager Class:**
- `generateSecureToken()` - Creates 64-char session token
- `createSession(user_id)` - Creates new user session
- `validateSession(token)` - Checks if session is valid
- `getUserIdFromToken(token)` - Gets user ID from token

**SecureDatabaseManager Class:**
- `connect()` - Establishes MySQL connection
- `testConnection()` - Tests database connectivity
- `validateUser(username, password)` - Authenticates user
- `getUserId(username)` - Gets user ID from username

**Security Functions:**
- `generateSalt()` - Creates random salt for passwords
- `hashPassword(password, salt)` - SHA-256 password hashing
- `verifyPassword(password, hash, salt)` - Verifies password

### Frontend (JavaScript)
**SecureAPI Class:**
- `makeRequest(endpoint, options)` - Generic HTTP handler
- `login(username, password)` - User authentication
- `testConnection()` - Backend connectivity test
- `getProtectedData()` - Access protected resources
- `logout()` - Session termination

## API Endpoints
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/login` | POST | User login |
| `/api/logout` | POST | User logout |
| `/api/protected` | GET | Protected data |
| `/api/test-db` | GET | Database test |

## Quick Start
1. **Setup Database**: Run `Email_Anomaly.sql` in MySQL
2. **Start Backend**: Compile and run `main.cpp`
3. **Test**: Open `test_connections.html` in browser

## File Structure
```
Email-Anomaly-Detector-main/
├── Backend/main.cpp           # C++ server
├── Frontend/                  # HTML pages
├── Database/Email_Anomaly.sql # Database schema
├── config.env                 # Configuration
└── test_connections.html      # Testing tool
```
