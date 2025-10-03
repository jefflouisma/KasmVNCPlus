#ifndef KASMVNC_OAUTH_CONFIG_H
#define KASMVNC_OAUTH_CONFIG_H

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace kasmvnc {
namespace oauth {

/**
 * OAuth Provider Endpoints
 */
struct OAuthEndpoints {
    std::string issuer;
    std::string authorization;
    std::string token;
    std::string jwks;
    std::string userinfo;
    std::string discovery;
};

/**
 * OAuth Client Configuration
 */
struct OAuthClient {
    std::string client_id;
    std::string client_secret;
    std::string redirect_uri;
    std::string scope;
};

/**
 * Security Settings
 */
struct SecurityConfig {
    bool use_pkce = true;
    std::string pkce_method = "S256";  // SHA-256
    bool require_state = true;
    bool verify_signature = true;
    bool verify_issuer = true;
    bool verify_audience = true;
    bool verify_expiration = true;
    int clock_skew_seconds = 60;
};

/**
 * Token Settings
 */
struct TokenConfig {
    int access_token_lifetime = 3600;     // 1 hour
    int refresh_token_lifetime = 7776000; // 90 days
    int jwks_cache_ttl = 86400;           // 24 hours
};

/**
 * Session Settings
 */
struct SessionConfig {
    int timeout_seconds = 28800;      // 8 hours
    int idle_timeout_seconds = 3600;  // 1 hour
    bool allow_multiple_sessions = true;
};

/**
 * Complete OAuth Configuration
 */
class OAuthConfig {
public:
    bool enabled = false;
    std::string provider;
    OAuthEndpoints endpoints;
    OAuthClient client;
    SecurityConfig security;
    TokenConfig tokens;
    SessionConfig session;

    /**
     * Load configuration from YAML file
     * @param config_path Path to oauth.yaml
     * @return OAuthConfig instance
     */
    static OAuthConfig load_from_file(const std::string& config_path);

    /**
     * Load configuration from OIDC Discovery endpoint
     * Auto-populates endpoints from /.well-known/openid-configuration
     * @param discovery_url Discovery endpoint URL
     */
    void load_from_discovery(const std::string& discovery_url);

    /**
     * Validate configuration
     * @return true if valid, throws exception if invalid
     */
    bool validate() const;

private:
    /**
     * Replace environment variables in string
     * Example: ${OAUTH_CLIENT_ID} -> actual value
     */
    static std::string replace_env_vars(const std::string& str);
};

} // namespace oauth
} // namespace kasmvnc

#endif // KASMVNC_OAUTH_CONFIG_H