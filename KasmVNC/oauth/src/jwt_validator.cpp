#include "jwt_validator.h"
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <algorithm>

using json = nlohmann::json;

namespace kasmvnc {
namespace oauth {

JWTValidator::JWTValidator(
    const std::string& issuer,
    const std::string& audience,
    std::shared_ptr<JWKSCache> jwks_cache,
    int clock_skew_seconds
) : issuer_(issuer),
    audience_(audience),
    jwks_cache_(jwks_cache),
    clock_skew_seconds_(clock_skew_seconds) {
}

ValidationResult JWTValidator::validate(const std::string& token) {
    ValidationResult result;

    try {
        // Decode token to get header and payload
        auto decoded_token = jwt::decode(token);

        // Get kid from header
        if (!decoded_token.has_header_claim("kid")) {
            result.error_message = "JWT missing 'kid' in header";
            return result;
        }
        std::string kid = decoded_token.get_header_claim("kid").as_string();

        // Get algorithm from header
        std::string alg = decoded_token.get_algorithm();

        // Get public key from JWKS cache
        std::string jwk_json_str = jwks_cache_->get_public_key(kid);

        // Create verifier
        auto verifier = jwt::verify()
            .with_issuer(issuer_)
            .with_audience(audience_)
            .leeway(clock_skew_seconds_);  // Allow clock skew

        // Configure algorithm based on what's in the token
        if (alg == "RS256") {
            verifier.allow_algorithm(jwt::algorithm::rs256(jwt::jwk<jwt::traits::nlohmann_json>::parse(jwk_json_str)));
        } else if (alg == "ES256") {
            verifier.allow_algorithm(jwt::algorithm::es256(jwt::jwk<jwt::traits::nlohmann_json>::parse(jwk_json_str)));
        } else if (alg == "HS256") {
             // For HS256, the "key" is the secret from the JWK
            json jwk = json::parse(jwk_json_str);
            if (jwk.contains("k")) {
                 verifier.allow_algorithm(jwt::algorithm::hs256(jwk["k"].get<std::string>()));
            } else {
                result.error_message = "HS256 JWK missing 'k' (key)";
                return result;
            }
        }
        else {
            result.error_message = "Unsupported algorithm: " + alg;
            return result;
        }

        // Verify token
        verifier.verify(decoded_token);

        // Token is valid! Extract claims
        result.valid = true;

        const auto& payload = decoded_token.get_payload_json();

        if (payload.contains("sub")) result.user_id = payload.at("sub").get<std::string>();
        if (payload.contains("email")) result.email = payload.at("email").get<std::string>();
        if (payload.contains("name")) result.name = payload.at("name").get<std::string>();
        if (payload.contains("email_verified") && payload.at("email_verified").is_boolean()) result.email_verified = payload.at("email_verified").get<bool>();
        if (payload.contains("preferred_username")) result.preferred_username = payload.at("preferred_username").get<std::string>();
        if (payload.contains("picture")) result.picture = payload.at("picture").get<std::string>();
        if (payload.contains("locale")) result.locale = payload.at("locale").get<std::string>();

        // Extract scopes
        if (payload.contains("scope")) {
            std::string scope_str = payload.at("scope").get<std::string>();
            std::istringstream iss(scope_str);
            std::string scope;
            while (iss >> scope) {
                result.scopes.push_back(scope);
            }
        }

        // Get expiry time
        if (payload.contains("exp")) {
            auto exp = payload.at("exp").get<long long>();
            result.expiry = std::chrono::system_clock::from_time_t(exp);
        }

    } catch (const jwt::signature_verification_exception& e) {
        result.error_message = "Invalid JWT signature: " + std::string(e.what());
    } catch (const jwt::token_verification_exception& e) {
        result.error_message = "JWT verification failed: " + std::string(e.what());
    } catch (const std::exception& e) {
        result.error_message = "JWT validation error: " + std::string(e.what());
    }

    return result;
}

json JWTValidator::extract_claims_unsafe(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        return decoded.get_payload_json();
    } catch (const std::exception& e) {
        return json{{"error", e.what()}};
    }
}

json JWTValidator::decode_header(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        return decoded.get_header_json();
    } catch (const std::exception& e) {
        return json{{"error", e.what()}};
    }
}

json JWTValidator::decode_payload(const std::string& token) {
    return extract_claims_unsafe(token);
}

} // namespace oauth
} // namespace kasmvnc