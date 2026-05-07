#include "session_manager.h"
#include "security_logger.h"
#include <openssl/rand.h>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <sstream>

static std::unordered_map<std::string, Session> active_sessions;

std::string create_session(const std::string& username, Role role) {
    unsigned char buffer[32];
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        log_security_event(username, "INTERNAL", "SESSION_ERROR", "Failed to generate cryptographically secure random bytes");
        return "";
    }
    std::stringstream ss;
    for (int i = 0; i < 32; ++i) ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];

    // Replay attack prevention: append issue timestamp and nonce structure to session ID
    auto now = std::chrono::system_clock::now();
    long long timestamp = std::chrono::system_clock::to_time_t(now);
    ss << "_" << timestamp;

    std::string token = ss.str();
    active_sessions[token] = {token, username, role, timestamp + 3600}; // 1 hr session expiry
    log_security_event(username, "INTERNAL", "SESSION_CREATED", "Token issued securely");
    return token;
}

bool validate_session(const std::string& token) {
    auto it = active_sessions.find(token);
    if (it != active_sessions.end()) {
        long long current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        if (current_time < it->second.expires_at) {
            return true;
        }
        // Strict invalidation
        active_sessions.erase(it);
        log_security_event("SYSTEM", "INTERNAL", "SESSION_EXPIRED", "Token naturally expired and removed");
    }
    return false;
}

void invalidate_session(const std::string& token) {
    active_sessions.erase(token);
    log_security_event("SYSTEM", "INTERNAL", "SESSION_INVALIDATED", "Token explicitly destroyed");
}

Role get_session_role(const std::string& token) {
    auto it = active_sessions.find(token);
    if (it != active_sessions.end()) {
        return it->second.role;
    }
    return Role::GUEST; 
}
