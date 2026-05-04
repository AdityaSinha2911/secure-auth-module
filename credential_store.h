#pragma once
#include <string>
#include "rbac.h"

// ============================================================
// FEATURE 3: PERSISTENT CREDENTIAL STORE
// ============================================================
// Users are loaded from / saved to "users.db" at runtime.
// File format (pipe-delimited):
//   username|salt|password_hash|role|totp_secret|hw_secret|bio_hash|fails|lockout
//
// SECURITY GUARANTEES:
//   - Plaintext passwords are NEVER written to disk
//   - Only PBKDF2-SHA256 hashes + random salts are stored
//   - File is written atomically (temp file + rename)
//     so a crash mid-write cannot corrupt the DB
// ============================================================

struct UserRecord {
    std::string username;
    std::string salt;
    std::string password_hash;
    Role        role;
    std::string totp_secret;
    std::string hw_token_secret;
    std::string bio_hash;
    int         failed_attempts;
    long long   lockout_until;
};

constexpr const char* USERS_DB_PATH = "users.db";

void        init_credential_store();   // load from file or seed defaults
bool        save_credential_store();   // persist in-memory state to file
UserRecord* get_user(const std::string& username);
bool        update_user(const UserRecord& user); // updates + auto-saves to disk
std::string generate_salt();
std::string hash_password(const std::string& password, const std::string& salt);
void        secure_clear_string(std::string& str);