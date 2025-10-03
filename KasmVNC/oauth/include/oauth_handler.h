#ifndef KASMVNC_OAUTH_HANDLER_H
#define KASMVNC_OAUTH_HANDLER_H

#include <string>
#include <map>
#include "oauth_config.h"
#include <nlohmann/json.hpp>

namespace kasmvnc {
namespace oauth {

/**
 * OAuth Authorization Request
 */
struct AuthorizationRequest {
    std::string authorization_url;
    std::string state;
    std::string code_verifier;  // Store for later use
    std::string code_challenge;
};

/**
 * OAuth Token Response
 */
struct TokenResponse {
    bool success = false;
    std::string access_token;
    std::string id_token;
    std::string refresh_token;
    std::string token_type;  // Usually "Bearer"
    int expires_in = 0;      // Seconds until expiration
    std::string scope;
    std::string error;
    std::string error_description;
};

/**
 * OAuth 2.0 Flow Handler
 * Implements Authorization Code Flow with PKCE
 */
class OAuthHandler {
public:
    /**
     * Constructor
     * @param config OAuth configuration
     */
    explicit OAuthHandler(const OAuthConfig& config);

    /**
     * Generate authorization URL with PKCE
     * User should be redirected to this URL
     * @param state Optional state parameter (generated if empty)
     * @return AuthorizationRequest with URL and PKCE parameters
     */
    AuthorizationRequest generate_auth_url(const std::string& state = "");

    /**
     * Exchange authorization code for tokens
     * @param code Authorization code from callback
     * @param code_verifier PKCE code verifier
     * @param state State parameter for CSRF validation
     * @return TokenResponse with access/refresh tokens
     */
    TokenResponse exchange_code(
        const std::string& code,
        const std::string& code_verifier,
        const std::string& state
    );

    /**
     * Refresh access token using refresh token
     * @param refresh_token Refresh token
     * @return TokenResponse with new access token
     */
    TokenResponse refresh_token(const std::string& refresh_token);

    /**
     * Revoke token (logout)
     * @param token Token to revoke
     * @param token_type_hint "access_token" or "refresh_token"
     * @return true if successful
     */
    bool revoke_token(
        const std::string& token,
        const std::string& token_type_hint = ""
    );

    /**
     * Get user info from userinfo endpoint
     * @param access_token Access token
     * @return JSON with user information
     */
    nlohmann::json get_user_info(const std::string& access_token);

private:
    OAuthConfig config_;

    /**
     * Store for PKCE verifiers and state parameters
     * In production, use Redis or similar for distributed systems
     */
    std::map<std::string, std::string> pending_verifiers_;
    std::map<std::string, std::string> pending_states_;

    /**
     * URL encode a string
     * @param value String to encode
     * @return URL encoded string
     */
    std::string url_encode(const std::string& value);

    /**
     * Build query string from parameters
     * @param params Map of parameters
     * @return Query string
     */
    std::string build_query_string(
        const std::map<std::string, std::string>& params
    );

    /**
     * Send HTTP POST request
     * @param url Endpoint URL
     * @param data POST data
     * @param headers Additional headers
     * @return Response body
     */
    std::string http_post(
        const std::string& url,
        const std::string& data,
        const std::map<std::string, std::string>& headers = {}
    );
};

} // namespace oauth
} // namespace kasmvnc

#endif // KASMVNC_OAUTH_HANDLER_H