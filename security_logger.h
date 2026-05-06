#pragma once
#include <string>

// Logs security events with strict timestamping to an append-only file mechanism
void log_security_event(const std::string& username, const std::string& ip, const std::string& event_type, const std::string& details);
