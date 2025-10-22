#include "crow.h"
#include <mysql/mysql.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <ctime>
#include <random>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstdlib>
#include <openssl/sha.h>
#include <openssl/rand.h>

// =====================================
// STRUCTURES AND CLASSES
// =====================================

// Session structure
struct UserSession {
    std::string session_token;
    int user_id;
    std::time_t expires_at;
    bool is_valid;
};

// Authentication manager class
class AuthManager {
private:
    std::map<std::string, UserSession> active_sessions;
    std::mutex session_mutex;

public:
    std::string generateSecureToken() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::stringstream ss;
        for (int i = 0; i < 64; ++i) {
            ss << std::hex << dis(gen);
        }
        return ss.str();
    }
    
    std::string createSession(int user_id) {
        std::lock_guard<std::mutex> lock(session_mutex);
        
        std::string token = generateSecureToken();
        UserSession session;
        session.session_token = token;
        session.user_id = user_id;
        session.expires_at = std::time(nullptr) + 3600;
        session.is_valid = true;
        
        active_sessions[token] = session;
        return token;
    }
    
    bool validateSession(const std::string& token) {
        std::lock_guard<std::mutex> lock(session_mutex);
        
        auto it = active_sessions.find(token);
        if (it != active_sessions.end()) {
            if (it->second.expires_at > std::time(nullptr)) {
                return true;
            } else {
                active_sessions.erase(it);
            }
        }
        return false;
    }
    
    int getUserIdFromToken(const std::string& token) {
        std::lock_guard<std::mutex> lock(session_mutex);
        
        auto it = active_sessions.find(token);
        if (it != active_sessions.end() && it->second.is_valid) {
            return it->second.user_id;
        }
        return -1;
    }
};

// Database manager class with actual MySQL connection
class SecureDatabaseManager {
private:
    MYSQL* connection;
    std::mutex db_mutex;
    std::string host, username, password, database;
    bool is_connected;

public:
    SecureDatabaseManager() {
        connection = nullptr;
        is_connected = false;
        
        // Secure database configuration using environment variables
        host = std::getenv("DB_HOST") ? std::getenv("DB_HOST") : "localhost";
        database = std::getenv("DB_NAME") ? std::getenv("DB_NAME") : "login_system";
        username = std::getenv("DB_USERNAME") ? std::getenv("DB_USERNAME") : "root";
        password = std::getenv("DB_PASSWORD") ? std::getenv("DB_PASSWORD") : "";
        
        // Security check: warn if using default credentials
        if (username == "root" && password.empty()) {
            std::cerr << "WARNING: Using default database credentials. Set DB_USERNAME and DB_PASSWORD environment variables for security." << std::endl;
        }
    }
    
    ~SecureDatabaseManager() {
        if (connection) {
            mysql_close(connection);
        }
    }
    
    bool connect() {
        std::lock_guard<std::mutex> lock(db_mutex);
        
        // Set the  MySQL connection
        connection = mysql_init(nullptr);
        if (!connection) {
            std::cerr << "Database initialization failed" << std::endl;
            return false;
        }
        
        // Connect to database
        connection = mysql_real_connect(connection, host.c_str(), username.c_str(), 
                                      password.c_str(), database.c_str(), 3306, 
                                      nullptr, 0);
        
        if (!connection) {
            std::cerr << "Database connection failed" << std::endl;
            is_connected = false;
            return false;
        }
        
        std::cout << "Database connection established successfully" << std::endl;
        is_connected = true;
        return true;
    }
    
    bool testConnection() {
        std::lock_guard<std::mutex> lock(db_mutex);
        
        if (!is_connected || !connection) {
            return false;
        }
        
        // Use this for our proof of connection
        const char* query = "SELECT 1";
        if (mysql_query(connection, query)) {
            std::cerr << "Database test query failed" << std::endl;
            return false;
        }
        
        MYSQL_RES* result = mysql_store_result(connection);
        if (result) {
            mysql_free_result(result);
            return true;
        }
        
        return false;
    }
    
    // Validate user credentials against database using prepared statements
    bool validateUser(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(db_mutex);
        
        if (!is_connected || !connection) {
            return false;
        }
        
        // Use actual database query with prepared statements (need help with this)
        std::string query = "SELECT password_hash, salt FROM users WHERE username = ?";
        MYSQL_STMT* stmt = mysql_stmt_init(connection);
        if (!stmt) return false;
        
        if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
            mysql_stmt_close(stmt);
            return false;
        }
        
        MYSQL_BIND bind[1];
        memset(bind, 0, sizeof(bind));
        
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(username.c_str());
        bind[0].buffer_length = username.length();
        
        if (mysql_stmt_bind_param(stmt, bind)) {
            mysql_stmt_close(stmt);
            return false;
        }
        
        if (mysql_stmt_execute(stmt)) {
            mysql_stmt_close(stmt);
            return false;
        }
        
        // Process results and validate password hash
        MYSQL_BIND result_bind[2];
        memset(result_bind, 0, sizeof(result_bind));
        
        char password_hash[65] = {0};
        char salt[33] = {0};
        unsigned long hash_len = 0;
        unsigned long salt_len = 0;
        
        result_bind[0].buffer_type = MYSQL_TYPE_STRING;
        result_bind[0].buffer = password_hash;
        result_bind[0].buffer_length = sizeof(password_hash) - 1;
        result_bind[0].length = &hash_len;
        
        result_bind[1].buffer_type = MYSQL_TYPE_STRING;
        result_bind[1].buffer = salt;
        result_bind[1].buffer_length = sizeof(salt) - 1;
        result_bind[1].length = &salt_len;
        
        if (mysql_stmt_bind_result(stmt, result_bind)) {
            mysql_stmt_close(stmt);
            return false;
        }
        
        bool user_found = false;
        if (mysql_stmt_fetch(stmt) == 0) {
            user_found = true;
            
            // Null terminate the strings
            password_hash[hash_len] = '\0';
            salt[salt_len] = '\0';
            
            // Verify password
            std::string computed_hash = hashPassword(password, std::string(salt));
            user_found = (computed_hash == std::string(password_hash));
        }
        
        mysql_stmt_close(stmt);
        return user_found;
    }
    
    // Get user ID from database
    int getUserId(const std::string& username) {
        std::lock_guard<std::mutex> lock(db_mutex);
        
        if (!is_connected || !connection) {
            return -1;
        }
        
        // Use actual database query (another place needed for help)
        std::string query = "SELECT user_id FROM users WHERE username = ?";
        MYSQL_STMT* stmt = mysql_stmt_init(connection);
        if (!stmt) return -1;
        
        if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
            mysql_stmt_close(stmt);
            return -1;
        }
        
        MYSQL_BIND bind[1];
        memset(bind, 0, sizeof(bind));
        
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(username.c_str());
        bind[0].buffer_length = username.length();
        
        if (mysql_stmt_bind_param(stmt, bind)) {
            mysql_stmt_close(stmt);
            return -1;
        }
        
        if (mysql_stmt_execute(stmt)) {
            mysql_stmt_close(stmt);
            return -1;
        }
        
        // Process results
        MYSQL_BIND result_bind[1];
        memset(result_bind, 0, sizeof(result_bind));
        
        int user_id = -1;
        result_bind[0].buffer_type = MYSQL_TYPE_LONG;
        result_bind[0].buffer = &user_id;
        
        if (mysql_stmt_bind_result(stmt, result_bind)) {
            mysql_stmt_close(stmt);
            return -1;
        }
        
        if (mysql_stmt_fetch(stmt) == 0) {
            mysql_stmt_close(stmt);
            return user_id;
        }
        
        mysql_stmt_close(stmt);
        return -1;
    }
};

// ==============================
// SECURITY HELPER FUNCTIONS
// ==============================

// Generate cryptographically secure salt
std::string generateSalt() {
    unsigned char salt[16];
    if (RAND_bytes(salt, 16) != 1) {
        throw std::runtime_error("Failed to generate secure salt");
    }
    
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }
    return ss.str();
}

// Hash password with salt using SHA-256
std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string salted_password = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salted_password.c_str(), salted_password.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Verify password against stored hash
bool verifyPassword(const std::string& password, const std::string& stored_hash, const std::string& salt) {
    std::string computed_hash = hashPassword(password, salt);
    return computed_hash == stored_hash;
}

// ================================
// HELPER FUNCTIONS
// ================================

// Cookie helper functions
std::string extractCookieValue(const crow::request& req, const std::string& cookie_name) {
    auto cookie_header = req.get_header_value("Cookie");
    if (cookie_header.empty()) {
        return "";
    }
    
    std::stringstream ss(cookie_header);
    std::string cookie;
    
    while (std::getline(ss, cookie, ';')) {
        cookie.erase(0, cookie.find_first_not_of(" \t"));
        
        if (cookie.find(cookie_name + "=") == 0) {
            return cookie.substr(cookie_name.length() + 1);
        }
    }
    return "";
}

void setSecureCookie(crow::response& res, const std::string& name, const std::string& value) {
    std::string cookie = name + "=" + value + 
                        "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600";
    res.add_header("Set-Cookie", cookie);
}

// ======================================
// GLOBAL INSTANCES 
// ======================================

// Global instances
SecureDatabaseManager db_manager;
AuthManager auth_manager;

// =======================================
// MAIN FUNCTION
// =======================================
int main() {
    crow::SimpleApp app;

    // Database connection
    if (!db_manager.connect()){
        std::cerr << "Failed to connect to database." << std::endl;
        return 1;
    }

    // ====================================
    // MIDDLEWARE SECTION
    // ====================================
    app.use([&](const crow::request& req, crow::response& res, std::function<void()> next) {
        // CORS headers for development
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.add_header("Access-Control-Allow-Credentials", "true");
        
        // Security headers
        res.add_header("X-Content-Type-Options", "nosniff");
        res.add_header("X-Frame-Options", "DENY");
        res.add_header("X-XSS-Protection", "1; mode=block");
        res.add_header("Strict-Transport-Security", "max-age=31536000");
        next();
    });

    // =========================================
    // ROUTES SECTION
    // =========================================
    
    // Basic routes
    CROW_ROUTE(app, "/")
    ([]() {
        return "Secure Email Anomaly Detection Server is running!";
    });

    // Authentication routes
    CROW_ROUTE(app, "/api/login").methods("POST"_method)([&](const crow::request& req) {
        try {
            auto json_data = crow::json::load(req.body);
            std::string username = json_data["username"].s();
            std::string password = json_data["password"].s();
            
            // Validate credentials against database
            if (db_manager.validateUser(username, password)) {
                int user_id = db_manager.getUserId(username);
                std::string session_token = auth_manager.createSession(user_id);
                
                crow::response res;
                setSecureCookie(res, "session_token", session_token);
                res.code = 200;
                res.body = crow::json::wvalue{{"status", "success", "message", "Login successful"}}.dump();
                res.add_header("Content-Type", "application/json");
                
                return res;
            } else {
                return crow::response(401, crow::json::wvalue{{"error", "Invalid credentials"}}.dump());
            }
        } catch (...) {
            return crow::response(400, crow::json::wvalue{{"error", "Invalid request format"}}.dump());
        }
    });

    CROW_ROUTE(app, "/api/logout").methods("POST"_method)([](const crow::request& req) {
        crow::response res;
        res.add_header("Set-Cookie", "session_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
        res.code = 200;
        res.body = crow::json::wvalue{{"status", "success", "message", "Logged out"}}.dump();
        res.add_header("Content-Type", "application/json");
        
        return res;
    });

    // Protected routes
    CROW_ROUTE(app, "/api/protected").methods("GET"_method)([](const crow::request& req) {
        std::string session_token = extractCookieValue(req, "session_token");
        
        if (session_token.empty() || !auth_manager.validateSession(session_token)) {
            return crow::response(401, crow::json::wvalue{{"error", "Unauthorized"}}.dump());
        }
        
        int user_id = auth_manager.getUserIdFromToken(session_token);
        return crow::json::wvalue{{"message", "This is protected data", "user_id", user_id}};
    });

    // API routes
    CROW_ROUTE(app, "/api/test-db")([&]() {
        if (db_manager.testConnection()) {
            return crow::json::wvalue{{"status", "database_connected"}};
        } else {
            return crow::response(500, "Database connection failed");
        }
    });

    CROW_ROUTE(app, "/api/scan-email").methods("POST"_method)([](const crow::request& req){
        return crow::json::wvalue{{"status", "email_scanner_ready"}};
    });

    // =============================================================================
    // SERVER STARTUP
    // =============================================================================
    app.port(8080).run();
    return 0; 
}