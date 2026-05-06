#include "security_logger.h"
#include <fstream>
#include <chrono>
#include <ctime>
#include <string>

// ============================================================
// FEATURE 6: ENHANCED SECURITY AUDIT LOGGER
// ============================================================
// Append-only audit log — every security event is written with:
//   [TIMESTAMP] IP: <ip> | EVENT: <type> | DETAILS: <msg>
//
// New event types logged by enhanced modules:
//   INPUT_VALIDATION_FAILED  — oversized / empty / malformed input
//   IP_BLOCKED               — IP exceeded failure threshold
//   IP_BLOCKED_ATTEMPT       — request from a currently-blocked IP
//   MFA_FAILED               — OTP mismatch with reason in details
//   IP_FAILURE_RECORDED      — each failed attempt count update
//
// The structured format (pipe-separated key:value) makes it
// easy to grep, parse, or feed into a SIEM system.
// ============================================================

void log_security_event(const std::string& username,
                        const std::string& ip,
                        const std::string& event_type,
                        const std::string& details) {

    std::ofstream logfile("audit.log", std::ios_base::app);
    if (!logfile.is_open()) return; // Fail silently — logging must never crash auth

    auto now   = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    char buf[32];

    // strftime is safe here — buf is sized for the format string
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S",
                      std::localtime(&now_c))) {
        // Structured log format — parseable by grep / SIEM / log analysis tools
        logfile << "[" << buf << "]"
                << " IP: "    << ip
                << " | USER: " << username
                << " | EVENT: " << event_type
                << " | DETAILS: " << details
                << "\n";
    }
}