#pragma once
#include <string>

// Role-Based Access Control Definitions
enum class Role { ADMIN, USER, GUEST };

bool has_permission(Role role, const std::string& action);
std::string role_to_string(Role role);
