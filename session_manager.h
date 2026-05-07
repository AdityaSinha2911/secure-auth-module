#pragma once
#include <string>
#include "rbac.h"

struct Session {
    std::string token;
    std::string username;
    Role role;
    long long expires_at;
};

std::string create_session(const std::string& username, Role role);
bool validate_session(const std::string& token);
void invalidate_session(const std::string& token);
Role get_session_role(const std::string& token);
