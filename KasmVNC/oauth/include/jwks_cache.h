#ifndef KASMVNC_JWKS_CACHE_H
#define KASMVNC_JWKS_CACHE_H

#include <string>
#include <map>
#include <chrono>
#include <mutex>
#include <memory>
#include <nlohmann/json.hpp>

namespace kasmvnc {
namespace oauth {

/**
 * JWKS (JSON Web Key Set) Cache
 * Fetches and caches public keys from OAuth provider
 * Automatically refreshes when TTL expires
 */
class JWKSCache {
public:
    /**
     * Constructor
     * @param jwks_uri JWKS endpoint URL
     * @param ttl Time-to-live for cache (default 24 hours)
     */
    explicit JWKSCache(
        const std::string& jwks_uri,
        std::chrono::seconds ttl = std::chrono::hours(24)
    );

    /**
     * Get public key by Key ID (kid)
     * Automatically refreshes if cache expired
     * @param kid Key ID from JWT header
     * @return Public key in PEM format
     * @throws std::runtime_error if key not found
     */
    std::string get_public_key(const std::string& kid);

    /**
     * Force refresh of JWKS
     * Fetches fresh keys from endpoint
     */
    void refresh();

    /**
     * Check if cache is expired
     * @return true if expired
     */
    bool is_expired() const;

private:
    std::string jwks_uri_;
    std::chrono::seconds ttl_;
    std::chrono::system_clock::time_point last_refresh_;
    std::map<std::string, std::string> keys_;  // kid -> public_key
    mutable std::mutex mutex_;

    /**
     * Fetch JWKS from endpoint
     * Parses JSON and extracts public keys
     */
    void fetch_jwks();

    /**
     * Convert JWK to PEM format
     * @param jwk JSON Web Key object
     * @return PEM formatted public key
     */
    std::string jwk_to_pem(const nlohmann::json& jwk);
};

} // namespace oauth
} // namespace kasmvnc

#endif // KASMVNC_JWKS_CACHE_H