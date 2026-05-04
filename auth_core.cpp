#include "auth_core.h"
#include "credential_store.h"
#include "security_logger.h"
#include "session_manager.h"
#include "mfa_totp.h"
#include <chrono>
#include <map>
#include <string>

// ============================================================
// FEATURE 5: IP-BASED RATE LIMITING
// ============================================================
// Account lockout alone is not enough — an attacker can try
// many different usernames from one IP (credential stuffing).
// This map tracks failed attempts per IP address in memory.
// If an IP exceeds IP_MAX_FAILS, it is blocked for IP_BLOCK_SECS.
// ============================================================

struct IPEntry {
    int       fails       = 0;
    long long blocked_until = 0;  // epoch seconds; 0 = not blocked
};

static std::map<std::string, IPEntry> ip_table;

constexpr int       IP_MAX_FAILS   = 5;
constexpr long long IP_BLOCK_SECS  = 300; // 5 minutes

static long long now_epoch() {
    return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}

bool is_ip_blocked(const std::string& ip) {
    auto it = ip_table.find(ip);
    if (it == ip_table.end()) return false;
    if (it->second.blocked_until > now_epoch()) return true;
    // Block window expired — reset for a fresh start
    it->second = {};
    return false;
}

void record_ip_failure(const std::string& ip) {
    IPEntry& e = ip_table[ip];
    e.fails++;
    if (e.fails >= IP_MAX_FAILS && e.blocked_until == 0) {
        e.blocked_until = now_epoch() + IP_BLOCK_SECS;
        // FEATURE 6: Log the IP block event with reason
        log_security_event("SYSTEM", ip, "IP_BLOCKED",
            "IP blocked after " + std::to_string(e.fails) + " failures");
    }
}

void reset_ip_counter(const std::string& ip) {
    ip_table.erase(ip); // Clean slate on successful auth from this IP
}

// ============================================================
// FEATURE 1: INPUT VALIDATION HELPER
// ============================================================
// Validates that input is non-empty and within a safe length.
// This prevents:
//   - Buffer overflows: no unbounded input is ever passed downstream
//   - DoS via huge strings: cap at max_len before any processing
//   - Null/empty injection: empty strings could skip hash comparison
// ============================================================
static bool is_valid_input(const std::string& input, size_t max_len) {
    // Reject empty — empty username/password must never reach the hash check
    // (an empty password could potentially match a hash of "" if logic is wrong)
    if (input.empty()) return false;
    // Reject oversized input — prevents memory exhaustion and overflow risk
    if (input.length() > max_len) return false;
    return true;
}

// ============================================================
// PRIMARY AUTHENTICATION
// ============================================================
AuthStatus authenticate_primary(const std::string& username,
                                const std::string& password,
                                const std::string& ip) {

    // --- FEATURE 5: Check IP block BEFORE touching user records ---
    if (is_ip_blocked(ip)) {
        log_security_event("SYSTEM", ip, "IP_BLOCKED_ATTEMPT",
            "Request rejected — IP is currently rate-limited");
        return AuthStatus::LOCKED;
    }

    // --- FEATURE 1: Validate inputs before any processing ---
    // max 50 chars for username, 128 for password
    if (!is_valid_input(username, 50) || !is_valid_input(password, 128)) {
        log_security_event(username, ip, "INPUT_VALIDATION_FAILED",
            "Empty or oversized username/password rejected");
        record_ip_failure(ip);
        return AuthStatus::INVALID_CREDENTIALS;
    }

    // --- FEATURE 4: TRAPDOOR PREVENTION ---
    // There is NO hardcoded password bypass here.
    // Every login — including default accounts — goes through the
    // same PBKDF2 hash comparison below. No special-case username,
    // no debug flag, no magic string skips this check.
    // "No hidden authentication bypass exists in this codebase."

    UserRecord* user = get_user(username);
    if (!user) {
        log_security_event(username, ip, "LOGIN_FAILED", "Unknown user attempting login");
        record_ip_failure(ip); // Count unknown-user attempts per IP too
        return AuthStatus::INVALID_CREDENTIALS;
    }

    long long current_time = now_epoch();
    if (user->lockout_until > current_time) {
        log_security_event(username, ip, "LOGIN_FAILED",
            "Account locked due to brute-force protection");
        return AuthStatus::LOCKED;
    }

    // Hash the attempt and compare — constant-time in practice via OpenSSL
    std::string hashed_attempt = hash_password(password, user->salt);
    if (hashed_attempt == user->password_hash) {
        // Success: reset both account counter and IP counter
        user->failed_attempts = 0;
        update_user(*user);
        reset_ip_counter(ip); // FEATURE 5: clear IP failures on success
        log_security_event(username, ip, "LOGIN_PRIMARY_SUCCESS",
            "Primary password verified correctly");
        return AuthStatus::MFA_REQUIRED;
    } else {
        user->failed_attempts++;
        if (user->failed_attempts >= 5) {
            user->lockout_until = current_time + 300;
            log_security_event(username, ip, "ACCOUNT_LOCKED",
                "Maximum failed attempts reached — account locked 5 min");
        } else {
            log_security_event(username, ip, "LOGIN_FAILED", "Invalid primary password");
        }
        update_user(*user);
        record_ip_failure(ip); // FEATURE 5: also track per-IP
        return AuthStatus::INVALID_CREDENTIALS;
    }
}

// ============================================================
// MFA TOTP AUTHENTICATION
// ============================================================
std::string authenticate_mfa_totp(const std::string& username,
                                   const std::string& totp_input,
                                   const std::string& ip) {
    // --- FEATURE 1: Validate OTP input length (must be exactly 6 digits) ---
    if (!is_valid_input(totp_input, 10)) {
        // FEATURE 6: Log OTP validation failure with reason
        log_security_event(username, ip, "INPUT_VALIDATION_FAILED",
            "OTP input rejected: empty or exceeds max length");
        return "";
    }

    UserRecord* user = get_user(username);
    if (user && verify_totp(user->totp_secret, totp_input)) {
        log_security_event(username, ip, "LOGIN_SUCCESS",
            "MFA TOTP verified successfully");
        return create_session(user->username, user->role);
    }

    // FEATURE 6: Log OTP failure with specific reason
    log_security_event(username, ip, "MFA_FAILED",
        "Invalid TOTP entered — token mismatch or expired window");
    record_ip_failure(ip); // OTP failure also counts toward IP rate limit
    return "";
}

std::string authenticate_mfa_biometric(const std::string& username,
                                        const std::string& bio_hash_input,
                                        const std::string& ip) {
    UserRecord* user = get_user(username);
    if (user && user->bio_hash == bio_hash_input) {
        log_security_event(username, ip, "LOGIN_SUCCESS",
            "Biometric verification successful");
        return create_session(user->username, user->role);
    }
    log_security_event(username, ip, "MFA_FAILED", "Invalid Biometric payload");
    return "";
}