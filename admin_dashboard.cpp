#include "admin_dashboard.h"
#include "session_manager.h"
#include "rbac.h"
#include "credential_store.h"
#include "security_logger.h"
#include <iostream>
#include <fstream>

void show_admin_dashboard(const std::string& token) {
    if (!validate_session(token)) {
        std::cout << "Error: Invalid or expired cryptographic session token.\n";
        return;
    }
    if (!has_permission(get_session_role(token), "admin_access")) {
        std::cout << "Security Alert: Access Denied. Elevated ADMIN role is required.\n";
        return;
    }

    while (true) {
        std::cout << "\n=== ADMIN SECURITY DASHBOARD ===\n";
        std::cout << "1. View Audit Logs\n";
        std::cout << "2. Unlock User Account\n";
        std::cout << "3. Exit Dashboard\n";
        std::cout << "Select Operation: ";
        
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        if (choice == 1) {
            std::cout << "\n--- AUDIT.LOG DUMP ---\n";
            std::ifstream logfile("audit.log");
            if (logfile.is_open()) {
                std::string line;
                while (std::getline(logfile, line)) std::cout << line << "\n";
            } else {
                std::cout << "Audit logs are empty or unreadable.\n";
            }
            std::cout << "----------------------\n";
        } else if (choice == 2) {
            std::string target;
            std::cout << "Enter target username to unlock: ";
            std::cin >> target;
            UserRecord* u = get_user(target);
            if (u) {
                u->failed_attempts = 0;
                u->lockout_until = 0;
                update_user(*u);
                log_security_event("admin", "127.0.0.1", "ADMIN_ACTION", "Unlocked target account: " + target);
                std::cout << "Success: User account unlocked.\n";
            } else {
                std::cout << "Error: Target user not found in Credential Store.\n";
            }
        } else {
            break;
        }
    }
}
