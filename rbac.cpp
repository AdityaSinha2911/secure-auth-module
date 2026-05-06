#include "rbac.h"

// Enforces strict permission checks based on user roles
bool has_permission(Role role, const std::string& action) {
    if (role == Role::ADMIN) return true; // ADMIN role has access to all authorized actions
    if (role == Role::USER && (action == "change_password" || action == "view_session")) return true;
    if (role == Role::GUEST && action == "view_public") return true;
    return false; // Fail-safe default: deny access
}

std::string role_to_string(Role role) {
    if (role == Role::ADMIN) return "ADMIN";
    if (role == Role::USER) return "USER";
    return "GUEST";
}
