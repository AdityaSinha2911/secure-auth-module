#include "pam_simulation.h"
#include "auth_core.h"
#include "credential_store.h"
#include "security_logger.h"
#include "mfa_totp.h"
#include <iostream>
#include <string>
#include <limits>

/*
 * CONCEPTUAL OS INTEGRATION:
 *
 * Linux (PAM):
 * This module simulates pam_sm_authenticate. In a real environment, it would
 * be compiled as a shared object (e.g., pam_custom_auth.so). The OS calls
 * pam_sm_authenticate, which fetches the user and password safely using
 * pam_get_user / pam_get_authtok.
 *
 * Windows (SSPI / LSA):
 * On Windows, this would be a Custom Authentication Package or Credential
 * Provider. The LSA calls LsaApLogonUserEx2. Our module verifies credentials
 * against the secure DB and returns a mapped access token.
 */

// ============================================================
// FEATURE 1: SAFE INPUT HELPER
// ============================================================
// Replaces raw `cin >>` which:
//   1. Stops at whitespace — passwords with spaces would be truncated
//   2. Leaves '\n' in the buffer — causes the next read to skip
//   3. Has no built-in length cap — long input fills the stream
//
// std::getline reads the full line including spaces, then we
// enforce a hard length cap and reject oversized input before
// it reaches any security-sensitive function.
//
// HOW THIS PREVENTS BUFFER OVERFLOW:
//   std::string is heap-allocated and resizes automatically —
//   no fixed C-style char[] buffer can overflow. The max_len
//   check additionally prevents DoS via enormous inputs.
// ============================================================
static bool safe_input(const std::string& prompt, std::string& out,
                       size_t max_len, const std::string& field_name,
                       const std::string& ip) {
    std::cout << prompt;
    if (!std::getline(std::cin, out)) {
        out.clear();
        return false; // EOF or stream error
    }

    // Trim trailing \r from Windows-style line endings (CRLF in WSL)
    if (!out.empty() && out.back() == '\r') out.pop_back();

    // Enforce maximum length — reject before passing to any crypto function
    if (out.length() > max_len) {
        std::cout << "[SECURITY] " << field_name
                  << " rejected: exceeds " << max_len << " character limit.\n";
        // FEATURE 6: Log the input validation failure
        log_security_event("UNKNOWN", ip, "INPUT_VALIDATION_FAILED",
            field_name + " input too long (" +
            std::to_string(out.length()) + " chars) — rejected");
        out.clear();
        return false;
    }

    if (out.empty()) {
        std::cout << "[SECURITY] " << field_name << " cannot be empty.\n";
        log_security_event("UNKNOWN", ip, "INPUT_VALIDATION_FAILED",
            field_name + " was empty — rejected");
        return false;
    }

    return true;
}

std::string pam_authenticate_sim(const std::string& ip) {
    std::string username, password;

    // --- FEATURE 1: Use safe_input() instead of cin >> ---
    // Max username: 50 chars | Max password: 128 chars
    if (!safe_input("login: ", username, 50, "username", ip))
        return "";

    if (!safe_input("Password: ", password, 128, "password", ip)) {
        return "";
    }

    AuthStatus status = authenticate_primary(username, password, ip);

    // MANDATORY: Secure memory zeroing of plaintext password immediately
    // after use — prevents it from lingering in heap memory
    secure_clear_string(password);

    if (status == AuthStatus::MFA_REQUIRED) {
        UserRecord* u = get_user(username);
        if (!u) return ""; // Defensive: should not happen here

        // OTP is verified by Google Authenticator app, do not print it.

        std::string totp;
        // --- FEATURE 1: Validate OTP input — max 10 chars, must be 6 digits ---
        if (!safe_input("Enter TOTP: ", totp, 10, "OTP", ip))
            return "";

        std::string token = authenticate_mfa_totp(username, totp, ip);
        if (!token.empty()) {
            std::cout << "\nAccess Granted. Secure session token generated.\n";
            return token;
        } else {
            std::cout << "\nAccess Denied: MFA validation failed.\n";
        }

    } else if (status == AuthStatus::LOCKED) {
        std::cout << "\nAccount is locked. Too many failed attempts. "
                     "Contact your Administrator.\n";
    } else {
        // LOCKED due to IP block also returns LOCKED from auth_core
        std::cout << "\nAuthentication failed.\n";
    }
    return "";
}