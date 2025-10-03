use crate::config::Config;
use std::collections::{HashMap, HashSet};
use tokio::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{Utc, DateTime};
use nix::unistd::Pid;
use nix::sys::signal::{self, Signal};
use log::{info, error};
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub vnc_display: u32,
    pub vnc_port: u16,
}

#[derive(Clone)]
pub struct SessionManager {
    state: Arc<RwLock<SessionManagerState>>,
    config: Arc<Config>,
}

struct SessionManagerState {
    sessions: HashMap<Uuid, Session>,
    processes: HashMap<Uuid, u32>, // session_id -> child_pid
    active_displays: HashSet<u32>,
    next_display: u32,
}

impl SessionManager {
    pub fn new(config: Config) -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionManagerState {
                sessions: HashMap::new(),
                processes: HashMap::new(),
                active_displays: HashSet::new(),
                next_display: 1,
            })),
            config: Arc::new(config),
        }
    }

    pub async fn create_session(&self, user_id: String, email: Option<String>) -> Result<Session, anyhow::Error> {
        let mut state = self.state.write().await;

        let display_num = state.allocate_display()?;
        let vnc_port = 5900 + display_num as u16;

        let std_cmd = self.build_xvnc_command(display_num, vnc_port);
        let mut cmd = Command::from(std_cmd);

        let mut child = cmd.spawn()?;
        let pid = child.id().ok_or_else(|| anyhow::anyhow!("Failed to get child process PID"))?;

        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                use tokio::io::{BufReader, AsyncBufReadExt};
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    info!("[Xvnc:{display_num}] {line}");
                }
            });
        }

        let session = Session {
            id: Uuid::new_v4(),
            user_id,
            email,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            vnc_display: display_num,
            vnc_port,
        };

        state.sessions.insert(session.id, session.clone());
        state.processes.insert(session.id, pid);

        let state_clone = self.state.clone();
        let session_id = session.id;
        tokio::spawn(async move {
            let _ = child.wait().await;
            error!("Xvnc process for session {session_id} exited unexpectedly.");
            let mut state = state_clone.write().await;
            if let Some(session) = state.sessions.remove(&session_id) {
                state.processes.remove(&session_id);
                state.active_displays.remove(&session.vnc_display);
            }
        });

        info!("Created new VNC session {} for user {} on display :{}", session.id, session.user_id, session.vnc_display);
        Ok(session)
    }

    pub async fn terminate_session(&self, session_id: &Uuid) -> Result<(), anyhow::Error> {
        let mut state = self.state.write().await;
        if let Some(session) = state.sessions.remove(session_id) {
            if let Some(pid) = state.processes.remove(session_id) {
                info!("Terminating session {session_id} (PID: {pid})");
                let child_pid = Pid::from_raw(pid as i32);

                if let Err(e) = signal::kill(Pid::from_raw(-(pid as i32)), Signal::SIGINT) {
                    error!("Failed to send SIGINT to Xvnc process group {pid}: {e}");
                }

                sleep(Duration::from_secs(2)).await;

                if signal::kill(child_pid, None).is_ok() {
                    info!("Xvnc process {pid} did not exit gracefully, sending SIGKILL.");
                    if let Err(e) = signal::kill(Pid::from_raw(-(pid as i32)), Signal::SIGKILL) {
                         error!("Failed to send SIGKILL to Xvnc process group {pid}: {e}");
                    }
                }
            }
            state.active_displays.remove(&session.vnc_display);
            info!("Session {session_id} terminated.");
        }
        Ok(())
    }

    fn build_xvnc_command(&self, display: u32, port: u16) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.config.vnc_command);
        cmd.arg(format!(":{display}"))
            .arg("-rfbport")
            .arg(port.to_string())
            .arg("-localhost")
            .arg("-SecurityTypes")
            .arg("None")
            .arg("-AlwaysShared")
            .arg("-geometry")
            .arg("1920x1080")
            .arg("-depth")
            .arg("24")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                let _ = nix::unistd::setsid();
                Ok(())
            });
        }
        cmd
    }
}

impl SessionManagerState {
    fn allocate_display(&mut self) -> Result<u32, anyhow::Error> {
        loop {
            let display_num = self.next_display;
            self.next_display += 1;
            if !self.active_displays.contains(&display_num) {
                self.active_displays.insert(display_num);
                return Ok(display_num);
            }
            if self.next_display > 200 {
                 return Err(anyhow::anyhow!("No available displays"));
            }
        }
    }
}