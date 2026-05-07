#pragma once
#include <string>
#include <cstdint>

std::string generate_totp_for_time(const std::string& secret, uint64_t current_time);
std::string generate_totp(const std::string& secret);
bool verify_totp(const std::string& secret, const std::string& input);

std::string generate_hw_challenge();
bool verify_hw_token(const std::string& secret, const std::string& challenge, const std::string& response);
