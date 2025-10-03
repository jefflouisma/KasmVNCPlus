#include "oauth_config.h"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <stdexcept>
#include <cstdlib>
#include <restclient-cpp/restclient.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace kasmvnc {
namespace oauth {

OAuthConfig OAuthConfig::load_from_file(const std::string& config_path) {
    // Check if file exists
    std::ifstream file(config_path);
    if (!file.good()) {
        throw std::runtime_error("OAuth config file not found: " + config_path);
    }

    // Parse YAML
    YAML::Node yaml = YAML::LoadFile(config_path);
    YAML::Node oauth_node = yaml["oauth"];

    OAuthConfig config;
    config.enabled = oauth_node["enabled"].as<bool>(false);
    config.provider = oauth_node["provider"].as<std::string>("");

    // Load endpoints
    YAML::Node endpoints = oauth_node["endpoints"];
    config.endpoints.issuer = replace_env_vars(
        endpoints["issuer"].as<std::string>("")
    );
    config.endpoints.authorization = replace_env_vars(
        endpoints["authorization"].as<std::string>("")
    );
    config.endpoints.token = replace_env_vars(
        endpoints["token"].as<std::string>("")
    );
    config.endpoints.jwks = replace_env_vars(
        endpoints["jwks"].as<std::string>("")
    );
    config.endpoints.userinfo = replace_env_vars(
        endpoints["userinfo"].as<std::string>("")
    );
    config.endpoints.discovery = replace_env_vars(
        endpoints["discovery"].as<std::string>("")
    );

    // If discovery endpoint provided, auto-configure
    if (!config.endpoints.discovery.empty()) {
        config.load_from_discovery(config.endpoints.discovery);
    }

    // Load client config
    YAML::Node client = oauth_node["client"];
    config.client.client_id = replace_env_vars(
        client["client_id"].as<std::string>("")
    );
    config.client.client_secret = replace_env_vars(
        client["client_secret"].as<std::string>("")
    );
    config.client.redirect_uri = replace_env_vars(
        client["redirect_uri"].as<std::string>("")
    );
    config.client.scope = client["scope"].as<std::string>("openid profile email");

    // Load security config
    YAML::Node security = oauth_node["security"];
    config.security.use_pkce = security["use_pkce"].as<bool>(true);
    config.security.pkce_method = security["pkce_method"].as<std::string>("S256");
    config.security.require_state = security["require_state"].as<bool>(true);

    YAML::Node validation = security["token_validation"];
    config.security.verify_signature = validation["verify_signature"].as<bool>(true);
    config.security.verify_issuer = validation["verify_issuer"].as<bool>(true);
    config.security.verify_audience = validation["verify_audience"].as<bool>(true);
    config.security.verify_expiration = validation["verify_expiration"].as<bool>(true);
    config.security.clock_skew_seconds = validation["clock_skew_seconds"].as<int>(60);

    // Load token config
    YAML::Node tokens = oauth_node["tokens"];
    config.tokens.access_token_lifetime = tokens["access_token_lifetime"].as<int>(3600);
    config.tokens.refresh_token_lifetime = tokens["refresh_token_lifetime"].as<int>(7776000);
    config.tokens.jwks_cache_ttl = tokens["jwks_cache_ttl"].as<int>(86400);

    // Load session config
    YAML::Node session = oauth_node["session"];
    config.session.timeout_seconds = session["timeout_seconds"].as<int>(28800);
    config.session.idle_timeout_seconds = session["idle_timeout_seconds"].as<int>(3600);
    config.session.allow_multiple_sessions = session["allow_multiple_sessions"].as<bool>(true);

    // Validate configuration
    config.validate();

    return config;
}

void OAuthConfig::load_from_discovery(const std::string& discovery_url) {
    // Fetch discovery document
    RestClient::init();
    RestClient::Response response = RestClient::get(discovery_url);
    RestClient::disable();

    if (response.code != 200) {
        throw std::runtime_error(
            "Failed to fetch OIDC discovery: " + std::to_string(response.code)
        );
    }

    // Parse JSON
    json discovery = json::parse(response.body);

    // Auto-populate endpoints
    if (discovery.contains("issuer")) {
        endpoints.issuer = discovery["issuer"].get<std::string>();
    }
    if (discovery.contains("authorization_endpoint")) {
        endpoints.authorization = discovery["authorization_endpoint"].get<std::string>();
    }
    if (discovery.contains("token_endpoint")) {
        endpoints.token = discovery["token_endpoint"].get<std::string>();
    }
    if (discovery.contains("jwks_uri")) {
        endpoints.jwks = discovery["jwks_uri"].get<std::string>();
    }
    if (discovery.contains("userinfo_endpoint")) {
        endpoints.userinfo = discovery["userinfo_endpoint"].get<std::string>();
    }
}

bool OAuthConfig::validate() const {
    if (!enabled) {
        return true;  // OAuth disabled, no validation needed
    }

    // Validate required fields
    if (client.client_id.empty()) {
        throw std::runtime_error("OAuth client_id is required");
    }
    if (client.redirect_uri.empty()) {
        throw std::runtime_error("OAuth redirect_uri is required");
    }
    if (endpoints.issuer.empty()) {
        throw std::runtime_error("OAuth issuer is required");
    }
    if (endpoints.authorization.empty()) {
        throw std::runtime_error("OAuth authorization endpoint is required");
    }
    if (endpoints.token.empty()) {
        throw std::runtime_error("OAuth token endpoint is required");
    }
    if (endpoints.jwks.empty()) {
        throw std::runtime_error("OAuth JWKS endpoint is required");
    }

    // Validate redirect_uri is HTTPS (except localhost)
    if (client.redirect_uri.find("http://localhost") != 0 &&
        client.redirect_uri.find("http://127.0.0.1") != 0 &&
        client.redirect_uri.find("https://") != 0) {
        throw std::runtime_error(
            "OAuth redirect_uri must use HTTPS (except localhost for development)"
        );
    }

    return true;
}

std::string OAuthConfig::replace_env_vars(const std::string& str) {
    std::string result = str;
    size_t start_pos = 0;

    // Find ${VAR_NAME} patterns
    while ((start_pos = result.find("${", start_pos)) != std::string::npos) {
        size_t end_pos = result.find("}", start_pos);
        if (end_pos == std::string::npos) {
            break;
        }

        // Extract variable name
        std::string var_name = result.substr(start_pos + 2, end_pos - start_pos - 2);

        // Get environment variable value
        const char* env_value = std::getenv(var_name.c_str());
        std::string replacement = env_value ? env_value : "";

        // Replace ${VAR} with value
        result.replace(start_pos, end_pos - start_pos + 1, replacement);
        start_pos += replacement.length();
    }

    return result;
}

} // namespace oauth
} // namespace kasmvnc