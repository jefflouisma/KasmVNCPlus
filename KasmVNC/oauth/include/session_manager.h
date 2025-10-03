#ifndef KASMVNC_SESSION_MANAGER_H
#define KASMVNC_SESSION_MANAGER_H

#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <vector>

namespace kasmvnc {
namespace oauth {

/**
 * VNC Session
 */
struct Session {
    std::string session_id;
    std::string user_id;
    std::string email;
    std::vector<std::string> scopes;

    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_activity;
    std::chrono::system_clock::time_point token_expiry;

    int vnc_display = -1;     // VNC display number (e.g., :1, :2)
    int vnc_port = -1;        // VNC port (5901, 5902, etc.)
    std::string vnc_password; // One-time password for this session

    bool authenticated = false;
    bool active = false;

    // User permissions
    bool can_view = true;
    bool can_control = true;
    bool can_clipboard = true;
    bool can_file_transfer = false;
};

/**
 * Session Manager
 * Manages VNC sessions for authenticated users
 */
class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    /**
     * Create new session for authenticated user
     * @param user_id User ID from JWT
     * @param email User email
     * @param scopes User scopes/permissions
     * @return New session
     */
    std::shared_ptr<Session> create_session(
        const std::string& user_id,
        const std::string& email,
        const std::vector<std::string>& scopes
    );

    /**
     * Get session by ID
     * @param session_id Session ID
     * @return Session or nullptr
     */
    std::shared_ptr<Session> get_session(const std::string& session_id);

    /**
     * Get all sessions for a user
     * @param user_id User ID
     * @return List of sessions
     */
    std::vector<std::shared_ptr<Session>> get_user_sessions(
        const std::string& user_id
    );

    /**
     * Update session activity
     * @param session_id Session ID
     */
    void update_activity(const std::string& session_id);

    /**
     * Terminate session
     * @param session_id Session ID
     */
    void terminate_session(const std::string& session_id);

    /**
     * Clean up expired sessions
     * Should be called periodically
     */
    void cleanup_expired();

    /**
     * Get session statistics
     */
    struct Stats {
        size_t total_sessions;
        size_t active_sessions;
        size_t unique_users;
    };
    Stats get_stats() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<Session>> sessions_;
    std::map<std::string, std::vector<std::string>> user_sessions_;

    int next_display_ = 1;  // Start with display :1

    /**
     * Generate unique session ID
     * @return UUID string
     */
    std::string generate_session_id();

    /**
     * Allocate VNC display number
     * @return Display number
     */
    int allocate_display();

    /**
     * Free VNC display number
     * @param display Display number
     */
    void free_display(int display);

    /**
     * Start VNC server for session
     * @param session Session
     * @return true if successful
     */
    bool start_vnc_server(std::shared_ptr<Session> session);

    /**
     * Stop VNC server for session
     * @param session Session
     */
    void stop_vnc_server(std::shared_ptr<Session> session);

    /**
     * Generate one-time VNC password
     * @return Random password
     */
    std::string generate_vnc_password();
};

} // namespace oauth
} // namespace kasmvnc

#endif // KASMVNC_SESSION_MANAGER_H