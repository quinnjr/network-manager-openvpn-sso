// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! OpenVPN process management and management interface protocol

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::ConnectionConfig;
use crate::secrets;

/// Events from the OpenVPN management interface
#[derive(Debug, Clone)]
pub enum VpnEvent {
    /// Connection state changed
    State(VpnState),
    /// Authentication required (with optional auth URL for SSO)
    AuthRequired { auth_url: Option<String> },
    /// Connection established with config
    Connected(VpnConfig),
    /// Connection failed
    Failed(String),
    /// Log message
    Log(String),
}

/// VPN connection states (matching NM states)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum VpnState {
    Unknown = 0,
    Init = 1,
    Shutdown = 2,
    Starting = 3,
    Started = 4,
    Stopping = 5,
    Stopped = 6,
    // NM-specific states
    NeedAuth = 7,
    Connecting = 8,
    GettingConfig = 9,
    Connected = 10,
    Failed = 11,
}

/// IP configuration received from OpenVPN
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct VpnConfig {
    pub tun_device: Option<String>,
    pub local_ip: Option<String>,
    pub remote_ip: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub mtu: Option<u32>,
    pub dns_servers: Vec<String>,
    pub dns_search: Vec<String>,
    pub routes: Vec<Route>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Route {
    pub network: String,
    pub netmask: String,
    pub gateway: Option<String>,
}

/// OpenVPN process manager
pub struct OpenVpnManager {
    config: ConnectionConfig,
    socket_path: PathBuf,
    process: Option<Child>,
    event_tx: mpsc::Sender<VpnEvent>,
    /// Cached auth URL from server (received via >INFO:)
    pending_auth_url: Option<String>,
    /// Flag to track if SSO browser auth has been initiated (to prevent duplicates)
    sso_auth_initiated: bool,
    /// Auth token received from server after successful authentication
    /// This can be used for reconnection without browser auth
    auth_token: Option<String>,
}

impl OpenVpnManager {
    pub fn new(config: ConnectionConfig, event_tx: mpsc::Sender<VpnEvent>) -> Self {
        let socket_path = PathBuf::from(format!("/tmp/nm-openvpn-sso-{}.sock", config.uuid));

        Self {
            config,
            socket_path,
            process: None,
            event_tx,
            pending_auth_url: None,
            sso_auth_initiated: false,
            auth_token: None,
        }
    }

    /// Start OpenVPN and manage the connection
    pub async fn connect(&mut self) -> Result<()> {
        // Kill any stale openvpn processes using the same management socket
        self.kill_stale_openvpn_processes().await;

        // Clean up old socket if exists
        let _ = tokio::fs::remove_file(&self.socket_path).await;

        // Build OpenVPN arguments
        let args = self
            .config
            .build_openvpn_args(self.socket_path.to_str().unwrap());

        info!("Starting OpenVPN with args: {:?}", args);

        // Start OpenVPN process
        let child = Command::new("openvpn")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start OpenVPN process")?;

        let pid = child.id();
        info!("OpenVPN started with PID: {:?}", pid);

        self.process = Some(child);

        // Wait for management socket to be ready
        self.wait_for_socket().await?;

        // Connect to management interface and handle events
        self.run_management_loop().await
    }

    /// Kill any stale openvpn processes that reference our management socket path.
    /// This handles the case where a previous connection attempt left orphan processes.
    async fn kill_stale_openvpn_processes(&self) {
        let socket_str = self.socket_path.to_string_lossy().to_string();
        match Command::new("pkill")
            .args(["-f", &format!("openvpn.*{}", socket_str)])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                info!("Killed stale openvpn processes using socket {}", socket_str);
                // Give processes time to exit
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            _ => {}
        }
    }

    /// Wait for the management socket to become available
    async fn wait_for_socket(&mut self) -> Result<()> {
        for _ in 0..50 {
            if self.socket_path.exists() {
                return Ok(());
            }
            // Check if OpenVPN has already exited (e.g., config error)
            if let Some(ref mut child) = self.process {
                if let Ok(Some(status)) = child.try_wait() {
                    let mut stderr_msg = String::new();
                    if let Some(mut stderr) = child.stderr.take() {
                        use tokio::io::AsyncReadExt;
                        let mut buf = Vec::new();
                        let _ = stderr.read_to_end(&mut buf).await;
                        stderr_msg = String::from_utf8_lossy(&buf).to_string();
                    }
                    error!("OpenVPN exited early with status: {}", status);
                    if !stderr_msg.is_empty() {
                        error!("OpenVPN stderr: {}", stderr_msg);
                    }
                    return Err(anyhow!(
                        "OpenVPN exited with status {} before creating management socket. stderr: {}",
                        status,
                        stderr_msg
                    ));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err(anyhow!("Management socket not created after 5s"))
    }

    /// Main management interface loop
    async fn run_management_loop(&mut self) -> Result<()> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to management socket")?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // State tracking
        let mut vpn_config = VpnConfig::default();
        let mut initial_auth_sent = false;
        let mut used_cached_token = false;

        // Check for cached credentials before starting
        let cached_token = secrets::get_cached_credentials(&self.config.uuid).await;
        if cached_token.is_some() {
            info!(
                "Found cached credentials for connection {}",
                self.config.uuid
            );
        }

        // Send initial commands
        writer.write_all(b"state on\n").await?;
        writer.write_all(b"hold release\n").await?;

        self.event_tx
            .send(VpnEvent::State(VpnState::Starting))
            .await
            .ok();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;

            if n == 0 {
                warn!("Management connection closed");
                break;
            }

            let line = line.trim();
            info!("MGMT: {}", line);

            // Parse management interface messages
            if line.starts_with(">PASSWORD:") {
                // Password/auth required or auth-token received
                let auth_type = line.strip_prefix(">PASSWORD:").unwrap().trim();

                // Check if this is an Auth-Token (sent by server after successful auth)
                // Format: >PASSWORD:Auth-Token:SESS_ID_AT_...
                if auth_type.starts_with("Auth-Token:") {
                    let token = auth_type.strip_prefix("Auth-Token:").unwrap().trim();
                    info!("Received Auth-Token from server (length: {})", token.len());
                    if !token.is_empty() {
                        self.auth_token = Some(token.to_string());
                    }
                    continue;
                }

                // Check if this is a verification failure (contains URL)
                if auth_type.contains("Verification Failed") || auth_type.contains("AUTH_PENDING") {
                    // Server is responding to our initial auth - look for URL
                    if let Some(url) = extract_auth_url(auth_type) {
                        info!("Found auth URL in verification response: {}", url);
                        self.pending_auth_url = Some(url);
                    }

                    // Now handle the real SSO auth with the URL
                    if let Some(url) = self.pending_auth_url.clone() {
                        info!("Performing browser-based SSO authentication");
                        self.event_tx
                            .send(VpnEvent::AuthRequired {
                                auth_url: Some(url.clone()),
                            })
                            .await
                            .ok();

                        if let Err(e) = self.handle_sso_auth(&mut writer, &url).await {
                            error!("SSO authentication failed: {}", e);
                            self.event_tx
                                .send(VpnEvent::Failed(format!("Auth failed: {}", e)))
                                .await
                                .ok();
                            return Err(e);
                        }
                    } else {
                        error!("Verification failed but no auth URL found in response");
                        return Err(anyhow!(
                            "Auth verification failed without providing SSO URL"
                        ));
                    }
                    continue;
                }

                if auth_type.contains("Need") {
                    // Check for web-auth URL in the message itself
                    if let Some(url) = extract_auth_url(auth_type) {
                        info!("Found auth URL in PASSWORD message: {}", url);
                        self.pending_auth_url = Some(url);
                    }

                    // First time we get password request
                    if !initial_auth_sent {
                        // Try cached credentials first if available
                        if let Some(ref tokens) = cached_token {
                            if tokens.is_valid() && !used_cached_token {
                                info!("Attempting authentication with cached token");
                                used_cached_token = true;

                                let username = self.config.username.as_deref().unwrap_or("sso");
                                writer
                                    .write_all(
                                        format!("username \"Auth\" \"{}\"\n", username).as_bytes(),
                                    )
                                    .await?;
                                writer
                                    .write_all(
                                        format!(
                                            "password \"Auth\" \"{}\"\n",
                                            escape_management_string(&tokens.access_token)
                                        )
                                        .as_bytes(),
                                    )
                                    .await?;
                                writer.flush().await?;

                                initial_auth_sent = true;
                                info!("Sent cached credentials, waiting for server response...");
                                continue;
                            }
                        }

                        info!(
                            "Sending initial placeholder credentials to initiate TLS handshake..."
                        );

                        // Send placeholder credentials - the server should respond with SSO challenge
                        // Use credentials from NM config or default "oauth"
                        let username = self.config.username.as_deref().unwrap_or("oauth");
                        let password = self.config.password.as_deref().unwrap_or("oauth");

                        writer
                            .write_all(format!("username \"Auth\" \"{}\"\n", username).as_bytes())
                            .await?;
                        writer
                            .write_all(format!("password \"Auth\" \"{}\"\n", password).as_bytes())
                            .await?;
                        writer.flush().await?;

                        initial_auth_sent = true;
                        info!("Sent placeholder credentials, waiting for server response...");

                        // Now wait for server response - it should send back AUTH_PENDING or WEB_AUTH
                        let wait_start = std::time::Instant::now();
                        let max_wait = std::time::Duration::from_secs(60); // Longer timeout for TLS + server response

                        while self.pending_auth_url.is_none() && wait_start.elapsed() < max_wait {
                            // Try to read more messages with a short timeout
                            let mut next_line = String::new();
                            match tokio::time::timeout(
                                std::time::Duration::from_millis(500),
                                reader.read_line(&mut next_line),
                            )
                            .await
                            {
                                Ok(Ok(n)) if n > 0 => {
                                    let next_line = next_line.trim();
                                    info!("MGMT (waiting for SSO): {}", next_line);

                                    // Check for INFO or INFOMSG with auth URL
                                    if next_line.starts_with(">INFO:")
                                        || next_line.starts_with(">INFOMSG:")
                                    {
                                        let info = next_line
                                            .strip_prefix(">INFO:")
                                            .or_else(|| next_line.strip_prefix(">INFOMSG:"))
                                            .unwrap_or(next_line);
                                        info!("Server INFO/MSG: {}", info);
                                        if let Some(url) = extract_auth_url(info) {
                                            info!("Received auth URL from server: {}", url);
                                            self.pending_auth_url = Some(url);
                                        }
                                    }
                                    // Check for PASSWORD verification failure with URL
                                    else if next_line.starts_with(">PASSWORD:Verification Failed")
                                    {
                                        info!("Auth verification failed - checking for SSO URL");
                                        if let Some(url) = extract_auth_url(next_line) {
                                            info!(
                                                "Found auth URL in verification failure: {}",
                                                url
                                            );
                                            self.pending_auth_url = Some(url);
                                        }
                                    }
                                    // Check for state that indicates connected (no SSO needed)
                                    else if next_line.contains(">STATE:")
                                        && next_line.contains(",CONNECTED,")
                                    {
                                        info!("Connection established without SSO");
                                        break;
                                    }
                                    // Also check any line for WEB_AUTH URL pattern
                                    else if next_line.contains("WEB_AUTH::") {
                                        if let Some(url) = extract_auth_url(next_line) {
                                            info!("Found auth URL in message: {}", url);
                                            self.pending_auth_url = Some(url);
                                        }
                                    }
                                    // Auth password entered is not the end - server may still send SSO URL
                                    // so we continue waiting
                                }
                                Ok(Ok(_)) => break, // Connection closed
                                Ok(Err(e)) => {
                                    warn!("Error reading during SSO wait: {}", e);
                                    break;
                                }
                                Err(_) => continue, // Timeout, keep waiting
                            }
                        }

                        // If we got an auth URL, do browser auth
                        if let Some(url) = self.pending_auth_url.clone() {
                            info!("Got SSO URL, starting browser authentication");
                            self.event_tx
                                .send(VpnEvent::AuthRequired {
                                    auth_url: Some(url.clone()),
                                })
                                .await
                                .ok();

                            if let Err(e) = self.handle_sso_auth(&mut writer, &url).await {
                                error!("SSO authentication failed: {}", e);
                                self.event_tx
                                    .send(VpnEvent::Failed(format!("Auth failed: {}", e)))
                                    .await
                                    .ok();
                                return Err(e);
                            }
                        } else if wait_start.elapsed() >= max_wait {
                            warn!(
                                "Timeout waiting for SSO URL from server after {:?}",
                                wait_start.elapsed()
                            );
                            // Server might not support SSO or accepted placeholder credentials
                            info!("Server did not send SSO URL - may have accepted placeholder or not configured for SSO");
                        }
                        continue;
                    }

                    // If we already sent initial auth and get another password request,
                    // it means the server wants SSO credentials
                    let auth_url = self.pending_auth_url.clone();

                    self.event_tx
                        .send(VpnEvent::AuthRequired {
                            auth_url: auth_url.clone(),
                        })
                        .await
                        .ok();

                    // Attempt authentication
                    if let Err(e) = self.handle_auth(&mut writer, auth_url.as_deref()).await {
                        error!("Authentication failed: {}", e);
                        self.event_tx
                            .send(VpnEvent::Failed(format!("Auth failed: {}", e)))
                            .await
                            .ok();
                        return Err(e);
                    }
                }
            } else if line.starts_with(">STATE:") {
                // State change
                let parts: Vec<&str> = line.strip_prefix(">STATE:").unwrap().split(',').collect();

                if parts.len() >= 2 {
                    let state_name = parts[1];
                    match state_name {
                        "CONNECTING" => {
                            self.event_tx
                                .send(VpnEvent::State(VpnState::Connecting))
                                .await
                                .ok();
                        }
                        "WAIT" => {
                            self.event_tx
                                .send(VpnEvent::State(VpnState::Starting))
                                .await
                                .ok();
                        }
                        "AUTH" => {
                            self.event_tx
                                .send(VpnEvent::State(VpnState::NeedAuth))
                                .await
                                .ok();
                        }
                        "AUTH_PENDING" => {
                            // AUTH_PENDING indicates the server wants external authentication
                            // (e.g., OAuth/SSO). The OPEN_URL is in the state details.
                            let full_state = parts[2..].join(",");
                            info!("AUTH_PENDING state details: {}", full_state);

                            if let Some(url) = extract_open_url(&full_state) {
                                info!("Received SSO auth URL from AUTH_PENDING: {}", url);
                                self.pending_auth_url = Some(url.clone());
                                self.event_tx
                                    .send(VpnEvent::AuthRequired {
                                        auth_url: Some(url.clone()),
                                    })
                                    .await
                                    .ok();

                                // Start localhost callback server + open browser for SSO
                                if !self.sso_auth_initiated {
                                    self.sso_auth_initiated = true;

                                    // Extract server base URL from auth URL for POSTing back
                                    let server_base = match url::Url::parse(&url) {
                                        Ok(u) => format!(
                                            "{}://{}:{}",
                                            u.scheme(),
                                            u.host_str().unwrap_or(""),
                                            u.port().unwrap_or(9000)
                                        ),
                                        Err(e) => {
                                            error!("Failed to parse auth URL: {}", e);
                                            url.clone()
                                        }
                                    };

                                    // Spawn the SSO flow (localhost server + browser + POST)
                                    // in a background task so the management loop continues
                                    let url_clone = url.clone();
                                    tokio::spawn(async move {
                                        match crate::oauth::authenticate_sso(
                                            &url_clone,
                                            &server_base,
                                        )
                                        .await
                                        {
                                            Ok(()) => {
                                                info!("SSO authentication completed successfully")
                                            }
                                            Err(e) => error!("SSO authentication failed: {}", e),
                                        }
                                    });
                                } else {
                                    info!("SSO auth already initiated, skipping duplicate");
                                }
                            } else {
                                warn!(
                                    "AUTH_PENDING state but no OPEN_URL found in: {}",
                                    full_state
                                );
                            }

                            self.event_tx
                                .send(VpnEvent::State(VpnState::NeedAuth))
                                .await
                                .ok();
                        }
                        "GET_CONFIG" => {
                            self.event_tx
                                .send(VpnEvent::State(VpnState::GettingConfig))
                                .await
                                .ok();
                        }
                        "CONNECTED" => {
                            if parts.len() >= 4 {
                                vpn_config.local_ip = Some(parts[3].to_string());
                            }
                            if parts.len() >= 5 {
                                vpn_config.remote_ip = Some(parts[4].to_string());
                            }

                            // Save credentials for future reconnections
                            self.save_credentials_after_connect().await;

                            self.event_tx
                                .send(VpnEvent::State(VpnState::Connected))
                                .await
                                .ok();
                            self.event_tx
                                .send(VpnEvent::Connected(vpn_config.clone()))
                                .await
                                .ok();
                        }
                        "EXITING" | "RECONNECTING" => {
                            self.event_tx
                                .send(VpnEvent::State(VpnState::Stopping))
                                .await
                                .ok();
                        }
                        _ => {}
                    }
                }
            } else if line.starts_with(">INFO:") || line.starts_with(">INFOMSG:") {
                // Info message (may contain web-auth URL or auth-token)
                let info = line
                    .strip_prefix(">INFO:")
                    .or_else(|| line.strip_prefix(">INFOMSG:"))
                    .unwrap_or(line);
                info!("Server INFO: {}", info);

                // Check for auth-token (used for reconnection)
                if let Some(token) = extract_auth_token(info) {
                    info!("Received auth-token from server (length: {})", token.len());
                    self.auth_token = Some(token);
                }

                // Check for auth URL
                if let Some(url) = extract_auth_url(info) {
                    info!("Received auth URL from server: {}", url);
                    self.pending_auth_url = Some(url.clone());
                    self.event_tx
                        .send(VpnEvent::AuthRequired {
                            auth_url: Some(url.clone()),
                        })
                        .await
                        .ok();

                    // If we haven't already started SSO, open browser now
                    // This handles the case where cached token was rejected and server sends new SSO URL
                    if !self.sso_auth_initiated {
                        info!("Server sent SSO URL after cached token rejected, opening browser");
                        self.sso_auth_initiated = true;
                        if let Err(e) = crate::oauth::authenticate(&url, None).await {
                            warn!("Failed to open browser for SSO: {}", e);
                        }
                    }
                }
            } else if line.starts_with(">BYTECOUNT:") {
                // Byte count - connection is active
            } else if line.starts_with("SUCCESS:") {
                // Command succeeded
            } else if line.starts_with("ERROR:") {
                warn!("OpenVPN error: {}", line);
            } else if line.starts_with(">FATAL:") {
                let msg = line.strip_prefix(">FATAL:").unwrap_or(line);
                error!("OpenVPN fatal error: {}", msg);
                self.event_tx
                    .send(VpnEvent::Failed(msg.to_string()))
                    .await
                    .ok();
                return Err(anyhow!("OpenVPN fatal: {}", msg));
            } else if line.starts_with(">LOG:") {
                let log = line.strip_prefix(">LOG:").unwrap_or(line);
                self.event_tx
                    .send(VpnEvent::Log(log.to_string()))
                    .await
                    .ok();
            }
        }

        Ok(())
    }

    /// Handle authentication request (fallback for when no SSO URL is available)
    async fn handle_auth(
        &mut self,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        auth_url: Option<&str>,
    ) -> Result<()> {
        // First, check for cached credentials
        if let Some(tokens) = secrets::get_cached_credentials(&self.config.uuid).await {
            if tokens.is_valid() {
                info!("Using cached credentials");
                return self.send_credentials(writer, &tokens.access_token).await;
            }

            // TODO: Implement token refresh if we have a refresh token
            if tokens.can_refresh() {
                info!("Cached token expired, would refresh here");
            }
        }

        // No valid cached credentials, need to do browser auth
        info!("Starting browser authentication");

        // Check if we have an auth URL
        let url = match auth_url {
            Some(url) => {
                info!("Using auth URL: {}", url);
                url
            }
            None => {
                return Err(anyhow!(
                    "Browser authentication required but no auth URL received from server. \
                     The OpenVPN server must be configured to send a web-auth URL."
                ));
            }
        };

        // Perform SSO auth with the URL
        self.handle_sso_auth(writer, url).await
    }

    /// Handle SSO/browser-based authentication
    ///
    /// The flow:
    /// 1. Start a localhost HTTP server on port 19823 to receive the OAuth callback
    /// 2. Open the browser to the VPN server's /auth/start (which redirects to Google)
    /// 3. Google authenticates the user and redirects to localhost:19823/oauth/callback
    /// 4. We receive the auth code and POST it to the VPN server's /auth/complete
    /// 5. The VPN server exchanges the code for a token, verifies the user, and
    ///    completes the VPN authentication by sending PUSH_REPLY
    async fn handle_sso_auth(
        &mut self,
        _writer: &mut tokio::net::unix::OwnedWriteHalf,
        auth_url: &str,
    ) -> Result<()> {
        // Prevent duplicate browser launches
        if self.sso_auth_initiated {
            info!("SSO auth already initiated, skipping duplicate browser open");
            return Ok(());
        }

        info!("Starting SSO authentication with URL: {}", auth_url);
        self.sso_auth_initiated = true;

        // Extract the VPN server host from the auth URL for later POSTing
        // auth_url looks like: http://34.214.23.25:9000/auth/start?state=...
        let server_base_url = match url::Url::parse(auth_url) {
            Ok(u) => format!(
                "{}://{}:{}",
                u.scheme(),
                u.host_str().unwrap_or(""),
                u.port().unwrap_or(9000)
            ),
            Err(_) => {
                self.sso_auth_initiated = false;
                return Err(anyhow!("Invalid auth URL: {}", auth_url));
            }
        };

        // Start the localhost callback server and open the browser concurrently
        use crate::oauth;
        match oauth::authenticate_sso(auth_url, &server_base_url).await {
            Ok(()) => {
                info!("SSO authentication flow completed");
                Ok(())
            }
            Err(e) => {
                error!("SSO authentication failed: {}", e);
                self.sso_auth_initiated = false;
                Err(anyhow!("SSO authentication failed: {}", e))
            }
        }
    }

    /// Send credentials to OpenVPN via management interface
    async fn send_credentials(
        &self,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        token: &str,
    ) -> Result<()> {
        // Send username (often ignored for SSO)
        writer.write_all(b"username \"Auth\" \"sso\"\n").await?;

        // Send the token as the password
        let password_cmd = format!(
            "password \"Auth\" \"{}\"\n",
            escape_management_string(token)
        );
        writer.write_all(password_cmd.as_bytes()).await?;

        info!("Sent SSO credentials to OpenVPN");
        Ok(())
    }

    /// Disconnect the VPN
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.process {
            info!("Stopping OpenVPN process");

            // Try graceful shutdown via management interface first
            if let Ok(stream) = UnixStream::connect(&self.socket_path).await {
                let (_, mut writer) = stream.into_split();
                let _ = writer.write_all(b"signal SIGTERM\n").await;

                // Give it a moment to shut down gracefully
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }

            // Force kill if still running
            let _ = child.kill().await;
            let _ = child.wait().await;

            self.process = None;
        }

        // Clean up socket
        let _ = tokio::fs::remove_file(&self.socket_path).await;

        self.event_tx
            .send(VpnEvent::State(VpnState::Stopped))
            .await
            .ok();

        Ok(())
    }

    /// Check if process is still running
    #[allow(dead_code)]
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.process {
            match child.try_wait() {
                Ok(None) => true, // Still running
                _ => false,
            }
        } else {
            false
        }
    }

    /// Save credentials after successful connection for future reconnections
    async fn save_credentials_after_connect(&self) {
        info!(
            "save_credentials_after_connect called, auth_token={:?}, pending_auth_url={:?}",
            self.auth_token
                .as_ref()
                .map(|t| format!("{}...", &t[..t.len().min(20)])),
            self.pending_auth_url.is_some()
        );
        // Prefer auth_token if we received one from the server
        let token_to_save = if let Some(ref token) = self.auth_token {
            info!("Saving auth-token received from server");
            Some(token.clone())
        } else if let Some(ref url) = self.pending_auth_url {
            // If we did browser auth, create a marker token indicating successful SSO
            // The actual session is maintained server-side, but we track that auth was done
            info!("Saving SSO session marker for URL: {}", url);
            // Use a hash of the URL as a session identifier
            Some(format!("sso-session:{}", url))
        } else {
            None
        };

        if let Some(token) = token_to_save {
            let tokens = secrets::StoredTokens {
                access_token: token,
                refresh_token: None,
                // Auth tokens from OpenVPN servers typically last 24-48 hours
                // Set expiry to 24 hours from now
                expires_at: Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64 + 86400) // 24 hours
                        .unwrap_or(0),
                ),
            };

            match secrets::cache_credentials(&self.config.uuid, tokens).await {
                Ok(()) => info!(
                    "Successfully cached credentials for connection {}",
                    self.config.uuid
                ),
                Err(e) => warn!("Failed to cache credentials: {}", e),
            }
        } else {
            info!("No credentials to cache after connection");
        }
    }
}

/// Extract auth-token from OpenVPN server messages
/// Auth tokens can be sent via various formats:
/// - AUTH_TOKEN:token_value
/// - auth-token,token_value
/// - push-reply with auth-token
fn extract_auth_token(message: &str) -> Option<String> {
    // Pattern 1: AUTH_TOKEN:value or AUTH-TOKEN:value
    if let Some(pos) = message.to_uppercase().find("AUTH_TOKEN:") {
        let start = pos + "AUTH_TOKEN:".len();
        let token = message[start..]
            .split_whitespace()
            .next()
            .map(|s| s.trim_matches(|c| c == '"' || c == '\'' || c == ','));
        if let Some(t) = token {
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }

    // Pattern 2: auth-token,value (OpenVPN PUSH format)
    if let Some(pos) = message.find("auth-token,") {
        let start = pos + "auth-token,".len();
        let token = message[start..]
            .split(|c: char| c.is_whitespace() || c == ',')
            .next()
            .map(|s| s.trim_matches(|c| c == '"' || c == '\''));
        if let Some(t) = token {
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }

    // Pattern 3: CR_RESPONSE with session token
    if message.starts_with("CR_RESPONSE:") {
        let token = message.strip_prefix("CR_RESPONSE:").map(|s| s.trim());
        if let Some(t) = token {
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }

    None
}

/// Extract OPEN_URL from an OpenVPN AUTH_PENDING state message.
/// The state details may look like: "timeout 120,OPEN_URL:http://host:port/path?query"
fn extract_open_url(message: &str) -> Option<String> {
    if let Some(pos) = message.find("OPEN_URL:") {
        let url_start = pos + "OPEN_URL:".len();
        // URL ends at comma, whitespace, or end of string
        let url_end = message[url_start..]
            .find(|c: char| c == ',' || c.is_whitespace())
            .map(|i| url_start + i)
            .unwrap_or(message.len());
        let url = &message[url_start..url_end];
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }
    None
}

/// Extract auth URL from OpenVPN message
fn extract_auth_url(message: &str) -> Option<String> {
    // Look for common patterns in web-auth messages
    // Pattern 1: WEB_AUTH::<url>
    if let Some(start) = message.find("WEB_AUTH::") {
        let url_start = start + "WEB_AUTH::".len();
        let url_end = message[url_start..]
            .find(|c: char| c.is_whitespace())
            .map(|i| url_start + i)
            .unwrap_or(message.len());
        return Some(message[url_start..url_end].to_string());
    }

    // Pattern 1b: OPEN_URL:http://... (from AUTH_PENDING state or control message)
    if let Some(url) = extract_open_url(message) {
        return Some(url);
    }

    // Pattern 2: AUTH_PENDING with URL
    if message.contains("http://") || message.contains("https://") {
        // Try to extract URL
        for word in message.split_whitespace() {
            if word.starts_with("http://") || word.starts_with("https://") {
                return Some(word.trim_matches(|c| c == '"' || c == '\'').to_string());
            }
        }
    }

    // Pattern 3: CRV1 challenge (base64 encoded)
    if message.starts_with("CRV1:") {
        // Decode and parse CRV1 challenge
        // Format: CRV1:flags:state_id:username:challenge_text
        let parts: Vec<&str> = message.splitn(5, ':').collect();
        if parts.len() >= 5 {
            let challenge = parts[4];
            // Challenge text might contain the URL
            if challenge.contains("http") {
                for word in challenge.split_whitespace() {
                    if word.starts_with("http://") || word.starts_with("https://") {
                        return Some(word.trim_matches(|c| c == '"' || c == '\'').to_string());
                    }
                }
            }
        }
    }

    None
}

/// Escape special characters for the management interface
fn escape_management_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl Drop for OpenVpnManager {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.process {
            // Best effort cleanup
            let _ = child.start_kill();
        }
        // Clean up socket
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
