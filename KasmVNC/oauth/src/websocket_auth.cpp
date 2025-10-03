#include "websocket_auth.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <iostream>

using json = nlohmann::json;

namespace kasmvnc {
namespace oauth {

WebSocketAuthWrapper::WebSocketAuthWrapper(
    std::shared_ptr<JWTValidator> validator,
    std::shared_ptr<SessionManager> session_mgr
) : validator_(validator), session_manager_(session_mgr) {
}

void WebSocketAuthWrapper::on_open(
    connection_hdl hdl,
    server* ws_server
) {
    // In a real implementation, you might start a timer to close unauthenticated connections.
    json auth_required;
    auth_required["type"] = "auth_required";
    auth_required["methods"] = {"bearer"};
    auth_required["timeout"] = 10; // seconds

    try {
        ws_server->send(hdl, auth_required.dump(), websocketpp::frame::opcode::text);
    } catch (const websocketpp::exception& e) {
        std::cerr << "Failed to send auth_required message: " << e.what() << std::endl;
    }
}

void WebSocketAuthWrapper::on_message(
    connection_hdl hdl,
    message_ptr msg,
    server* ws_server
) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (is_authenticated(hdl)) {
        // Already authenticated, message should be forwarded to VNC handler
        return;
    }

    std::string payload = msg->get_payload();

    try {
        AuthMessage auth_msg = parse_auth_message(payload);

        if (auth_msg.type != "auth") {
            close_with_error(hdl, websocketpp::close::status::policy_violation, "First message must be for authentication", ws_server);
            return;
        }

        ValidationResult result = validator_->validate(auth_msg.token);

        if (!result.valid) {
            send_auth_response(hdl, false, result.error_message, ws_server);
            close_with_error(hdl, websocketpp::close::status::policy_violation, "Authentication failed: " + result.error_message, ws_server);
            return;
        }

        auto now = std::chrono::system_clock::now();
        if (result.expiry <= now) {
            send_auth_response(hdl, false, "Token expired", ws_server);
            close_with_error(hdl, websocketpp::close::status::policy_violation, "Token expired", ws_server);
            return;
        }

        auto session = session_manager_->create_session(result.user_id, result.email, result.scopes);
        session->authenticated = true;
        session->token_expiry = result.expiry;

        connections_[hdl] = session;

        json auth_success;
        auth_success["type"] = "auth_success";
        auth_success["session_id"] = session->session_id;
        auth_success["user_id"] = result.user_id;
        auth_success["email"] = result.email;

        send_auth_response(hdl, true, auth_success.dump(), ws_server);

    } catch (const json::exception& e) {
        close_with_error(hdl, websocketpp::close::status::invalid_payload, "Invalid JSON in auth message", ws_server);
    } catch (const std::exception& e) {
        close_with_error(hdl, websocketpp::close::status::internal_endpoint_error, std::string("Authentication error: ") + e.what(), ws_server);
    }
}

void WebSocketAuthWrapper::on_close(connection_hdl hdl) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = connections_.find(hdl);
    if (it != connections_.end()) {
        if (it->second) {
            session_manager_->terminate_session(it->second->session_id);
        }
        connections_.erase(it);
    }
}

bool WebSocketAuthWrapper::is_authenticated(connection_hdl hdl) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(hdl);
    return it != connections_.end() && it->second && it->second->authenticated;
}

std::shared_ptr<Session> WebSocketAuthWrapper::get_session(connection_hdl hdl) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(hdl);
    return (it != connections_.end()) ? it->second : nullptr;
}

AuthMessage WebSocketAuthWrapper::parse_auth_message(const std::string& msg) {
    json j = json::parse(msg);
    AuthMessage auth;
    auth.type = j.value("type", "");
    auth.token = j.value("token", "");
    auth.method = j.value("method", "bearer");
    return auth;
}

void WebSocketAuthWrapper::send_auth_response(
    connection_hdl hdl,
    bool success,
    const std::string& message,
    server* ws_server
) {
    json response;
    if (success) {
        try {
            response = json::parse(message);
        } catch (const json::exception&) {
            // if message is not a json, wrap it
            response["type"] = "auth_success";
            response["message"] = message;
        }
    } else {
        response["type"] = "auth_error";
        response["message"] = message;
    }

    try {
        ws_server->send(hdl, response.dump(), websocketpp::frame::opcode::text);
    } catch (const websocketpp::exception& e) {
        std::cerr << "Failed to send auth response: " << e.what() << std::endl;
    }
}

void WebSocketAuthWrapper::close_with_error(
    connection_hdl hdl,
    websocketpp::close::status::value code,
    const std::string& reason,
    server* ws_server
) {
    try {
        ws_server->close(hdl, code, reason);
    } catch (const websocketpp::exception& e) {
        std::cerr << "Failed to close connection with error: " << e.what() << std::endl;
    }
}

} // namespace oauth
} // namespace kasmvnc