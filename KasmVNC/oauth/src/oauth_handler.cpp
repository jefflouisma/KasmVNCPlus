#include "oauth_handler.h"
#include "pkce_helper.h"
#include <restclient-cpp/restclient.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <cctype>

using json = nlohmann::json;

namespace kasmvnc {
namespace oauth {

OAuthHandler::OAuthHandler(const OAuthConfig& config) : config_(config) {
}

AuthorizationRequest OAuthHandler::generate_auth_url(const std::string& state) {
    AuthorizationRequest request;

    // Generate PKCE parameters
    request.code_verifier = PKCEHelper::generate_code_verifier();
    request.code_challenge = PKCEHelper::generate_code_challenge(
        request.code_verifier,
        config_.security.pkce_method
    );

    // Generate state if not provided
    request.state = state.empty() ? PKCEHelper::generate_state() : state;

    // Store verifier and state for later validation
    // In production, use Redis with TTL
    pending_verifiers_[request.state] = request.code_verifier;
    pending_states_[request.state] = request.state;

    // Build authorization URL
    std::map<std::string, std::string> params;
    params["response_type"] = "code";
    params["client_id"] = config_.client.client_id;
    params["redirect_uri"] = config_.client.redirect_uri;
    params["scope"] = config_.client.scope;
    params["state"] = request.state;

    // Add PKCE parameters
    if (config_.security.use_pkce) {
        params["code_challenge"] = request.code_challenge;
        params["code_challenge_method"] = config_.security.pkce_method;
    }

    // Optional: Add nonce for additional security
    params["nonce"] = PKCEHelper::generate_state();

    // Build full URL
    request.authorization_url = config_.endpoints.authorization + "?" +
                                build_query_string(params);

    return request;
}

TokenResponse OAuthHandler::exchange_code(
    const std::string& code,
    const std::string& code_verifier,
    const std::string& state
) {
    TokenResponse response;

    // Validate state (CSRF protection)
    if (config_.security.require_state) {
        auto it = pending_states_.find(state);
        if (it == pending_states_.end() || it->second != state) {
            response.error = "invalid_state";
            response.error_description = "State parameter mismatch";
            return response;
        }
        // Clean up used state
        pending_states_.erase(it);
    }

    // Build token request
    std::map<std::string, std::string> params;
    params["grant_type"] = "authorization_code";
    params["code"] = code;
    params["redirect_uri"] = config_.client.redirect_uri;
    params["client_id"] = config_.client.client_id;

    // Add client_secret for confidential clients
    if (!config_.client.client_secret.empty()) {
        params["client_secret"] = config_.client.client_secret;
    }

    // Add PKCE code_verifier
    if (config_.security.use_pkce) {
        params["code_verifier"] = code_verifier;
    }

    // Send token request
    std::string post_data = build_query_string(params);

    std::map<std::string, std::string> headers;
    headers["Content-Type"] = "application/x-www-form-urlencoded";

    std::string response_body = http_post(
        config_.endpoints.token,
        post_data,
        headers
    );

    // Parse response
    try {
        json token_json = json::parse(response_body);

        if (token_json.contains("error")) {
            response.error = token_json["error"].get<std::string>();
            if (token_json.contains("error_description")) {
                response.error_description =
                    token_json["error_description"].get<std::string>();
            }
        } else {
            response.success = true;
            response.access_token = token_json["access_token"].get<std::string>();

            if (token_json.contains("id_token")) {
                response.id_token = token_json["id_token"].get<std::string>();
            }
            if (token_json.contains("refresh_token")) {
                response.refresh_token = token_json["refresh_token"].get<std::string>();
            }
            if (token_json.contains("token_type")) {
                response.token_type = token_json["token_type"].get<std::string>();
            }
            if (token_json.contains("expires_in")) {
                response.expires_in = token_json["expires_in"].get<int>();
            }
            if (token_json.contains("scope")) {
                response.scope = token_json["scope"].get<std::string>();
            }
        }
    } catch (const std::exception& e) {
        response.error = "parse_error";
        response.error_description = e.what();
    }

    return response;
}

TokenResponse OAuthHandler::refresh_token(const std::string& refresh_token) {
    TokenResponse response;

    // Build refresh request
    std::map<std::string, std::string> params;
    params["grant_type"] = "refresh_token";
    params["refresh_token"] = refresh_token;
    params["client_id"] = config_.client.client_id;

    // Add client_secret for confidential clients
    if (!config_.client.client_secret.empty()) {
        params["client_secret"] = config_.client.client_secret;
    }

    // Send request
    std::string post_data = build_query_string(params);

    std::map<std::string, std::string> headers;
    headers["Content-Type"] = "application/x-www-form-urlencoded";

    std::string response_body = http_post(
        config_.endpoints.token,
        post_data,
        headers
    );

    // Parse response (same as exchange_code)
    try {
        json token_json = json::parse(response_body);

        if (token_json.contains("error")) {
            response.error = token_json["error"].get<std::string>();
            if (token_json.contains("error_description")) {
                response.error_description =
                    token_json["error_description"].get<std::string>();
            }
        } else {
            response.success = true;
            response.access_token = token_json["access_token"].get<std::string>();

            // Refresh may return new refresh token (rotation)
            if (token_json.contains("refresh_token")) {
                response.refresh_token = token_json["refresh_token"].get<std::string>();
            }
            if (token_json.contains("expires_in")) {
                response.expires_in = token_json["expires_in"].get<int>();
            }
        }
    } catch (const std::exception& e) {
        response.error = "parse_error";
        response.error_description = e.what();
    }

    return response;
}

bool OAuthHandler::revoke_token(
    const std::string& token,
    const std::string& token_type_hint
) {
    // Build revocation request
    std::map<std::string, std::string> params;
    params["token"] = token;

    if (!token_type_hint.empty()) {
        params["token_type_hint"] = token_type_hint;
    }

    params["client_id"] = config_.client.client_id;

    if (!config_.client.client_secret.empty()) {
        params["client_secret"] = config_.client.client_secret;
    }

    // Send request
    std::string post_data = build_query_string(params);

    std::map<std::string, std::string> headers;
    headers["Content-Type"] = "application/x-www-form-urlencoded";

    // Revocation endpoint is optional
    std::string revoke_endpoint = config_.endpoints.token + "/revoke";

    try {
        http_post(revoke_endpoint, post_data, headers);
        return true;  // Revocation endpoint typically returns 200 OK
    } catch (const std::exception& e) {
        return false;
    }
}

nlohmann::json OAuthHandler::get_user_info(const std::string& access_token) {
    RestClient::init();

    // Set Authorization header
    RestClient::Connection conn(config_.endpoints.userinfo);
    conn.SetTimeout(5);  // 5 second timeout
    conn.AppendHeader("Authorization", "Bearer " + access_token);

    RestClient::Response response = conn.get("");
    RestClient::disable();

    if (response.code != 200) {
        throw std::runtime_error(
            "Failed to get user info: HTTP " + std::to_string(response.code)
        );
    }

    return json::parse(response.body);
}

std::string OAuthHandler::url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        // Keep alphanumeric and other safe characters
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            // Percent encode everything else
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char)c);
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}

std::string OAuthHandler::build_query_string(
    const std::map<std::string, std::string>& params
) {
    std::stringstream ss;
    bool first = true;

    for (const auto& [key, value] : params) {
        if (!first) {
            ss << "&";
        }
        ss << url_encode(key) << "=" << url_encode(value);
        first = false;
    }

    return ss.str();
}

std::string OAuthHandler::http_post(
    const std::string& url,
    const std::string& data,
    const std::map<std::string, std::string>& headers
) {
    RestClient::init();
    RestClient::Connection conn(url);
    conn.SetTimeout(10);  // 10 second timeout

    // Set headers
    for (const auto& [key, value] : headers) {
        conn.AppendHeader(key, value);
    }

    RestClient::Response response = conn.post("", data);
    RestClient::disable();

    if (response.code >= 400) {
        throw std::runtime_error(
            "HTTP error " + std::to_string(response.code) + ": " + response.body
        );
    }

    return response.body;
}

} // namespace oauth
} // namespace kasmvnc