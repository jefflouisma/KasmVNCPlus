#include "jwks_cache.h"
#include <restclient-cpp/restclient.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <sstream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

using json = nlohmann::json;

namespace kasmvnc {
namespace oauth {

JWKSCache::JWKSCache(
    const std::string& jwks_uri,
    std::chrono::seconds ttl
) : jwks_uri_(jwks_uri), ttl_(ttl) {
    // Initialize with epoch time (will trigger immediate refresh)
    last_refresh_ = std::chrono::system_clock::time_point();
}

std::string JWKSCache::get_public_key(const std::string& kid) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Refresh if expired
    if (is_expired()) {
        fetch_jwks();
    }

    // Find key by kid
    auto it = keys_.find(kid);
    if (it == keys_.end()) {
        // Key not found, try refreshing once
        fetch_jwks();
        it = keys_.find(kid);
        if (it == keys_.end()) {
            throw std::runtime_error("Public key not found for kid: " + kid);
        }
    }

    return it->second;
}

void JWKSCache::refresh() {
    std::lock_guard<std::mutex> lock(mutex_);
    fetch_jwks();
}

bool JWKSCache::is_expired() const {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_refresh_
    );
    return elapsed >= ttl_;
}

void JWKSCache::fetch_jwks() {
    // Fetch JWKS from endpoint
    RestClient::init();
    RestClient::Response response = RestClient::get(jwks_uri_);
    RestClient::disable();

    if (response.code != 200) {
        throw std::runtime_error(
            "Failed to fetch JWKS: HTTP " + std::to_string(response.code)
        );
    }

    // Parse JSON
    json jwks = json::parse(response.body);

    if (!jwks.contains("keys")) {
        throw std::runtime_error("Invalid JWKS: missing 'keys' field");
    }

    // Clear old keys
    keys_.clear();

    // Extract each key
    for (const auto& jwk : jwks["keys"]) {
        if (!jwk.contains("kid")) {
            continue;  // Skip keys without kid
        }

        std::string kid = jwk["kid"].get<std::string>();

        // Store JWK as JSON string, as jwt-cpp can parse it directly
        keys_[kid] = jwk.dump();
    }

    // Update last refresh time
    last_refresh_ = std::chrono::system_clock::now();
}

// This function is not used since jwt-cpp handles JWK parsing directly,
// but it's kept here for reference as per the design document.
std::string JWKSCache::jwk_to_pem(const json& jwk) {
    // Check key type
    if (!jwk.contains("kty")) {
        throw std::runtime_error("JWK missing 'kty' field");
    }

    std::string kty = jwk["kty"].get<std::string>();

    if (kty == "RSA") {
        // RSA key
        if (!jwk.contains("n") || !jwk.contains("e")) {
            throw std::runtime_error("RSA JWK missing 'n' or 'e'");
        }

        throw std::runtime_error("RSA key conversion not fully implemented; use direct JWK parsing with jwt-cpp.");

    } else if (kty == "oct") {
        // Symmetric key (HMAC)
        if (!jwk.contains("k")) {
            throw std::runtime_error("Symmetric JWK missing 'k'");
        }

        return jwk["k"].get<std::string>();

    } else {
        throw std::runtime_error("Unsupported key type: " + kty);
    }
}

} // namespace oauth
} // namespace kasmvnc