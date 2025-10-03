#ifndef KASMVNC_JWT_VALIDATOR_H
#define KASMVNC_JWT_VALIDATOR_H

#include <string>
#include <memory>
#include <chrono>
#include <vector>
#include "jwks_cache.h"
#include <nlohmann/json.hpp>

namespace kasmvnc {
namespace oauth {

/**
 * JWT Validation Result
 */
struct ValidationResult {
    bool valid = false;
    std::string user_id;        // sub claim
    std::string email;
    std::string name;
    std::vector<std::string> scopes;
    std::chrono::system_clock::time_point expiry;
    std::string error_message;

    // Additional claims
    bool email_verified = false;
    std::string preferred_username;
    std::string picture;  // Avatar URL
    std::string locale;
};

/**
 * JWT Token Validator
 * Validates JWT tokens using JWKS public keys
 */
class JWTValidator {
public:
    /**
     * Constructor
     * @param issuer Expected issuer (iss claim)
     * @param audience Expected audience (aud claim)
     * @param jwks_cache JWKS cache for public keys
     * @param clock_skew_seconds Allow clock skew (default 60s)
     */
    JWTValidator(
        const std::string& issuer,
        const std::string& audience,
        std::shared_ptr<JWKSCache> jwks_cache,
        int clock_skew_seconds = 60
    );

    /**
     * Validate JWT token
     * Checks signature, issuer, audience, expiration, etc.
     * @param token JWT token string
     * @return ValidationResult with user info or error
     */
    ValidationResult validate(const std::string& token);

    /**
     * Extract claims without validation (for debugging)
     * WARNING: Never trust these claims without validation!
     * @param token JWT token
     * @return JSON object with claims
     */
    nlohmann::json extract_claims_unsafe(const std::string& token);

private:
    std::string issuer_;
    std::string audience_;
    std::shared_ptr<JWKSCache> jwks_cache_;
    int clock_skew_seconds_;

    /**
     * Decode JWT header
     * @param token JWT token
     * @return Decoded header as JSON
     */
    nlohmann::json decode_header(const std::string& token);

    /**
     * Decode JWT payload
     * @param token JWT token
     * @return Decoded payload as JSON
     */
    nlohmann::json decode_payload(const std::string& token);
};

} // namespace oauth
} // namespace kasmvnc

#endif // KASMVNC_JWT_VALIDATOR_H