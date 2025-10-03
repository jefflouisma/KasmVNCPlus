use novnc_recorder::{
    config::Config,
    oauth::{
        pkce::{generate_code_challenge, generate_code_verifier},
        session::SessionManager,
    },
};
use std::io::Write;
use tempfile::{NamedTempFile, tempdir};
use std::os::unix::fs::PermissionsExt;

// Test to ensure the OAuth configuration is parsed correctly from the main config file.
#[test]
fn test_oauth_config_parsing() {
    let yaml = r#"
oauth:
    enabled: true
    provider: "test_provider"
    client:
        client_id: "test_client_id"
        redirect_uri: "http://localhost/callback"
"#;
    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{yaml}").unwrap();

    let config = Config::from_file(file.path()).unwrap();
    let oauth_config = config.oauth.expect("OAuth config should be present");

    assert!(oauth_config.enabled);
    assert_eq!(oauth_config.provider, "test_provider");
    assert_eq!(oauth_config.client.client_id, "test_client_id");
    assert_eq!(oauth_config.client.redirect_uri, "http://localhost/callback");
}

// Test PKCE code generation to ensure it produces valid, non-empty strings.
#[test]
fn test_pkce_generation() {
    let verifier1 = generate_code_verifier();
    let challenge1 = generate_code_challenge(&verifier1);

    let verifier2 = generate_code_verifier();
    let challenge2 = generate_code_challenge(&verifier2);

    assert!(!verifier1.is_empty());
    assert!(!challenge1.is_empty());
    assert_ne!(verifier1, verifier2);
    assert_ne!(challenge1, challenge2);
}

fn create_mock_xvnc_script(temp_dir: &tempfile::TempDir) -> std::path::PathBuf {
    let script_path = temp_dir.path().join("mock_xvnc.sh");
    let mut file = std::fs::File::create(&script_path).unwrap();
    writeln!(file, "#!/bin/sh").unwrap();
    // The first argument ($1) will be the display, e.g., ":1"
    // We remove the ":" for the pid file name.
    writeln!(file, "pid_file=\"/tmp/mock_xvnc_$(echo $1 | tr -d ':').pid\"").unwrap();
    writeln!(file, "echo $$ > $pid_file").unwrap();
    writeln!(file, "sleep 300").unwrap();

    let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script_path, perms).unwrap();

    script_path
}


// Test session creation and termination using a mock Xvnc script.
#[tokio::test]
async fn test_session_manager() {
    let temp_dir = tempdir().unwrap();
    let mock_xvnc_path = create_mock_xvnc_script(&temp_dir);

    let config = Config {
        vnc_command: mock_xvnc_path.to_str().unwrap().to_string(),
        ..Default::default()
    };

    let session_manager = SessionManager::new(config);
    let user_id = "test_user".to_string();
    let email = Some("test@example.com".to_string());

    // Create a session
    let session = session_manager
        .create_session(user_id, email)
        .await
        .expect("Failed to create session");

    assert_eq!(session.vnc_display, 1);

    // Give the mock script time to write its PID
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Check if the mock process was created
    let pid_file = format!("/tmp/mock_xvnc_{}.pid", session.vnc_display);
    let pid_str = std::fs::read_to_string(&pid_file).expect("Mock PID file not found");
    let pid: i32 = pid_str.trim().parse().expect("Invalid PID in file");
    assert!(pid > 0);

    // Terminate the session
    session_manager
        .terminate_session(&session.id)
        .await
        .expect("Failed to terminate session");

    // Check if the process was killed (it might take a moment)
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let result = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None);
    assert!(result.is_err(), "Mock process should have been terminated");

    // Clean up the PID file
    let _ = std::fs::remove_file(pid_file);
}