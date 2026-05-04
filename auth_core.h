#pragma once
#include <string>
 
enum class AuthStatus { SUCCESS, INVALID_CREDENTIALS, LOCKED, MFA_REQUIRED };
 
// --- FEATURE: IP-Based Rate Limiting ---
// Records failed attempts per IP. Blocks IPs that exceed threshold.
// Declared here so auth_core.cpp and main.cpp can both see it.
void    record_ip_failure(const std::string& ip);
bool    is_ip_blocked(const std::string& ip);
void    reset_ip_counter(const std::string& ip);
 
AuthStatus  authenticate_primary(const std::string& username, const std::string& password, const std::string& ip);
std::string authenticate_mfa_totp(const std::string& username, const std::string& totp_input, const std::string& ip);
std::string authenticate_mfa_biometric(const std::string& username, const std::string& bio_hash_input, const std::string& ip);
 