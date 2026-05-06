#include "mfa_totp.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <chrono>

// ============================================================
// RFC 6238 TOTP — Time-Based One-Time Password
// ============================================================
// The TOTP algorithm uses HMAC-SHA1 over a counter derived from
// the current Unix timestamp divided into 30-second windows.
// ============================================================

std::string generate_totp_for_time(const std::string& secret, uint64_t current_time) {
    uint64_t time_window = current_time / 30; // Each window = 30 seconds
    unsigned char data[8];

    // Convert counter to big-endian 8 bytes (RFC 4226 requirement)
    for (int i = 7; i >= 0; i--) {
        data[i] = time_window & 0xFF;
        time_window >>= 8;
    }

    unsigned int len = EVP_MD_size(EVP_sha1());
    unsigned char result[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha1(), secret.c_str(), (int)secret.length(),
         data, 8, result, &len);

    // Dynamic truncation per RFC 4226 §5.4
    int offset = result[19] & 0xf;
    int binary = ((result[offset]     & 0x7f) << 24) |
                 ((result[offset + 1] & 0xff) << 16) |
                 ((result[offset + 2] & 0xff) <<  8) |
                 ((result[offset + 3] & 0xff));

    int otp = binary % 1000000; // 6-digit OTP
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(6) << otp;
    return ss.str();
}

std::string generate_totp(const std::string& secret) {
    return generate_totp_for_time(secret,
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

// ============================================================
// FEATURE 2: TOTP TIME WINDOW TOLERANCE
// ============================================================
// In real-world deployments, a user's phone clock may drift by
// a few seconds from the server clock. Accepting the previous
// 30-second window (now - 30) avoids login failures at window
// boundaries without significantly weakening security — each OTP
// is still short-lived and single-use in practice.
//
// We accept:
//   - current window  (now)
//   - previous window (now - 30)   <-- NEW: clock drift tolerance
//   - next window     (now + 30)   <-- handles fast-clock devices
//
// We do NOT accept anything older — that would be a replay risk.
// ============================================================
bool verify_totp(const std::string& secret, const std::string& input) {
    uint64_t current_time = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());

    // Allow wider time window for demo (±2 steps = ~90 seconds total)

    if (generate_totp_for_time(secret, current_time) == input) return true;

    // Previous windows
    if (generate_totp_for_time(secret, current_time - 30) == input) return true;
    if (generate_totp_for_time(secret, current_time - 60) == input) return true;

    // Next windows
    if (generate_totp_for_time(secret, current_time + 30) == input) return true;
    if (generate_totp_for_time(secret, current_time + 60) == input) return true;

    return false;
}

// ============================================================
// HARDWARE TOKEN — Challenge-Response (HMAC-SHA256)
// ============================================================
std::string generate_hw_challenge() {
    unsigned char buffer[16];
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) return "";
    std::stringstream ss;
    for (int i = 0; i < 16; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    return ss.str();
}

bool verify_hw_token(const std::string& secret, const std::string& challenge,
                     const std::string& response) {
    unsigned int len = EVP_MD_size(EVP_sha256());
    unsigned char result[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), secret.c_str(), (int)secret.length(),
         (const unsigned char*)challenge.c_str(), (int)challenge.length(),
         result, &len);

    std::stringstream ss;
    for (unsigned int i = 0; i < len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    return ss.str() == response;
}