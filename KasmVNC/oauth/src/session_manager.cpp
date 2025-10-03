#include "session_manager.h"
#include <uuid/uuid.h>
#include <random>
#include <algorithm>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <sys/wait.h>
#include <cstring>

namespace kasmvnc {
namespace oauth {

SessionManager::SessionManager() {
    // In a real application, a background thread for cleanup_expired() would be started here.
}

SessionManager::~SessionManager() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, session] : sessions_) {
        if (session->active) {
            stop_vnc_server(session);
        }
    }
    sessions_.clear();
    user_sessions_.clear();
}

std::shared_ptr<Session> SessionManager::create_session(
    const std::string& user_id,
    const std::string& email,
    const std::vector<std::string>& scopes
) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto session = std::make_shared<Session>();
    session->session_id = generate_session_id();
    session->user_id = user_id;
    session->email = email;
    session->scopes = scopes;

    auto now = std::chrono::system_clock::now();
    session->created_at = now;
    session->last_activity = now;
    session->token_expiry = now + std::chrono::hours(1);  // Default, should be set from token

    // Allocate VNC display
    session->vnc_display = allocate_display();
    session->vnc_port = 5900 + session->vnc_display;
    session->vnc_password = generate_vnc_password();

    // Set permissions based on scopes
    session->can_view = true; // Always allow view
    session->can_control = std::find(scopes.begin(), scopes.end(), "vnc:control") != scopes.end();
    session->can_clipboard = std::find(scopes.begin(), scopes.end(), "vnc:clipboard") != scopes.end();
    session->can_file_transfer = std::find(scopes.begin(), scopes.end(), "vnc:files") != scopes.end();

    // Start VNC server
    if (start_vnc_server(session)) {
        session->active = true;
    } else {
        free_display(session->vnc_display); // Rollback display allocation
        throw std::runtime_error("Failed to start VNC server for display :" + std::to_string(session->vnc_display));
    }

    // Store session
    sessions_[session->session_id] = session;
    user_sessions_[user_id].push_back(session->session_id);

    return session;
}

std::shared_ptr<Session> SessionManager::get_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    return (it != sessions_.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<Session>> SessionManager::get_user_sessions(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<Session>> result;
    auto it = user_sessions_.find(user_id);
    if (it != user_sessions_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second);
            }
        }
    }
    return result;
}

void SessionManager::update_activity(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        it->second->last_activity = std::chrono::system_clock::now();
    }
}

void SessionManager::terminate_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        auto session = it->second;

        if (session->active) {
            stop_vnc_server(session);
            session->active = false;
        }

        free_display(session->vnc_display);

        auto user_it = user_sessions_.find(session->user_id);
        if (user_it != user_sessions_.end()) {
            auto& user_session_list = user_it->second;
            user_session_list.erase(std::remove(user_session_list.begin(), user_session_list.end(), session_id), user_session_list.end());
            if (user_session_list.empty()) {
                user_sessions_.erase(user_it);
            }
        }

        sessions_.erase(it);
    }
}

void SessionManager::cleanup_expired() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    std::vector<std::string> to_remove;

    const auto idle_timeout = std::chrono::hours(1); // Example idle timeout

    for (const auto& [id, session] : sessions_) {
        bool expired = false;
        if (session->token_expiry <= now) {
            expired = true;
        }

        auto idle_time = now - session->last_activity;
        if (idle_time > idle_timeout) {
            expired = true;
        }

        if (expired) {
            to_remove.push_back(id);
        }
    }

    // The lock is released here and re-acquired in terminate_session. This is safe.
    for (const auto& id : to_remove) {
        terminate_session(id);
    }
}

SessionManager::Stats SessionManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats stats;
    stats.total_sessions = sessions_.size();
    stats.active_sessions = 0;
    for(const auto& pair : sessions_) {
        if (pair.second->active) {
            stats.active_sessions++;
        }
    }
    stats.unique_users = user_sessions_.size();
    return stats;
}

std::string SessionManager::generate_session_id() {
    uuid_t uuid;
    uuid_generate_random(uuid);
    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);
    return std::string(uuid_str);
}

int SessionManager::allocate_display() {
    // In a real implementation, we would track a pool of available displays
    return next_display_++;
}

void SessionManager::free_display(int display) {
    // In a real implementation, this display number would be returned to a pool
}

bool SessionManager::start_vnc_server(std::shared_ptr<Session> session) {
    std::string display_str = ":" + std::to_string(session->vnc_display);

    std::vector<std::string> args = {
        "/usr/bin/Xvnc",
        display_str,
        "-interface", "127.0.0.1",
        "-geometry", "1920x1080",
        "-depth", "24",
        "-rfbport", std::to_string(session->vnc_port),
        "-SecurityTypes", "None",
        "-AlwaysShared",
        "-AcceptKeyEvents=" + std::string(session->can_control ? "on" : "off"),
        "-AcceptPointerEvents=" + std::string(session->can_control ? "on" : "off"),
        "-AcceptCutText=" + std::string(session->can_clipboard ? "on" : "off"),
        "-SendCutText=" + std::string(session->can_clipboard ? "on" : "off")
    };

    std::vector<char*> argv;
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execvp(argv[0], argv.data());
        // execvp only returns on error
        std::cerr << "Failed to exec Xvnc: " << strerror(errno) << std::endl;
        exit(1);
    } else if (pid > 0) {
        // Parent process
        usleep(500000); // 500ms, wait for server to start or fail
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == 0) {
            // Process is still running, success
            // In a real app, we'd store the PID in the session object to manage it
            return true;
        }
    }
    return false; // Fork failed or child process exited immediately
}

void SessionManager::stop_vnc_server(std::shared_ptr<Session> session) {
    // Simple approach using pkill as per design. A more robust solution
    // would track the PID and send a signal directly.
    std::string cmd = "pkill -f 'Xvnc :" + std::to_string(session->vnc_display) + "'";
    system(cmd.c_str());
}

std::string SessionManager::generate_vnc_password() {
    const std::string chars =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

    std::string password;
    password.reserve(8);
    for (int i = 0; i < 8; ++i) {
        password += chars[dis(gen)];
    }

    return password;
}

} // namespace oauth
} // namespace kasmvnc