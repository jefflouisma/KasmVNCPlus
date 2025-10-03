#ifndef KASMVNC_WEBSOCKET_AUTH_H
#define KASMVNC_WEBSOCKET_AUTH_H

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <memory>
#include <map>
#include <mutex>
#include "jwt_validator.h"
#include "session_manager.h"

namespace kasmvnc {
namespace oauth {

typedef websocketpp::server<websocketpp::config::asio> server;
typedef server::message_ptr message_ptr;
typedef websocketpp::connection_hdl connection_hdl;

/**
 * WebSocket Authentication Message
 */
struct AuthMessage {
    std::string type;     // "auth"
    std::string token;    // JWT access token
    std::string method;   // "bearer"
};

/**
 * WebSocket Authentication Wrapper
 * Intercepts WebSocket connections and validates JWT tokens
 */
class WebSocketAuthWrapper {
public:
    /**
     * Constructor
     * @param validator JWT validator
     * @param session_mgr Session manager
     */
    WebSocketAuthWrapper(
        std::shared_ptr<JWTValidator> validator,
        std::shared_ptr<SessionManager> session_mgr
    );

    /**
     * Handle new WebSocket connection
     * @param hdl Connection handle
     * @param ws_server WebSocket server instance
     */
    void on_open(
        connection_hdl hdl,
        server* ws_server
    );

    /**
     * Handle incoming message
     * First message MUST be authentication
     * @param hdl Connection handle
     * @param msg Message
     * @param ws_server WebSocket server instance
     */
    void on_message(
        connection_hdl hdl,
        message_ptr msg,
        server* ws_server
    );

    /**
     * Handle connection close
     * @param hdl Connection handle
     */
    void on_close(connection_hdl hdl);

    /**
     * Check if connection is authenticated
     * @param hdl Connection handle
     * @return true if authenticated
     */
    bool is_authenticated(connection_hdl hdl) const;

    /**
     * Get session for connection
     * @param hdl Connection handle
     * @return Session or nullptr if not authenticated
     */
    std::shared_ptr<Session> get_session(connection_hdl hdl) const;

private:
    std::shared_ptr<JWTValidator> validator_;
    std::shared_ptr<SessionManager> session_manager_;

    // Connection to session mapping
    mutable std::mutex mutex_;
    std::map<connection_hdl, std::shared_ptr<Session>,
             std::owner_less<connection_hdl>> connections_;

    /**
     * Parse authentication message
     * @param msg JSON message
     * @return AuthMessage
     */
    AuthMessage parse_auth_message(const std::string& msg);

    /**
     * Send authentication response
     * @param hdl Connection handle
     * @param success Success status
     * @param message Error/success message
     * @param ws_server WebSocket server
     */
    void send_auth_response(
        connection_hdl hdl,
        bool success,
        const std::string& message,
        server* ws_server
    );

    /**
     * Close connection with error
     * @param hdl Connection handle
     * @param code Close code
     * @param reason Close reason
     * @param ws_server WebSocket server
     */
    void close_with_error(
        connection_hdl hdl,
        websocketpp::close::status::value code,
        const std::string& reason,
        server* ws_server
    );
};

} // namespace oauth
} // namespace kasmvnc

#endif // KASMVNC_WEBSOCKET_AUTH_H