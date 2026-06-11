// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! OAuth 2.0 browser-based authentication flow

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use notify_rust::Notification;
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};
use url::Url;

/// Timeout for waiting for OAuth callback
const AUTH_TIMEOUT_SECS: u64 = 60;

/// Channel type for sending the OAuth result from the callback handler
type OAuthResultSender = Arc<tokio::sync::Mutex<Option<oneshot::Sender<Result<(String, String)>>>>>;

/// Result of OAuth authentication
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OAuthResult {
    /// The authorization code or token received
    pub code: String,
    /// State parameter (for CSRF verification)
    pub state: Option<String>,
    /// Full callback URL (some servers need this)
    pub callback_url: String,
}

/// Parameters received on OAuth callback
#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: Option<String>,
    token: Option<String>,
    access_token: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Shared state for the callback server
struct CallbackState {
    result_tx: oneshot::Sender<Result<OAuthResult>>,
    expected_state: Option<String>,
}

/// Perform OAuth authentication via browser
///
/// For OpenVPN web-auth, the server handles the OAuth callback itself.
/// We just need to open the browser and return immediately - the server
/// will signal auth success through the management interface.
pub async fn authenticate(auth_url: &str, _state: Option<&str>) -> Result<OAuthResult> {
    // Parse and validate the auth URL
    let _url = Url::parse(auth_url).context("Invalid auth URL")?;

    info!("Opening browser for server-handled OAuth authentication");

    // Try multiple methods to open the browser since we run as root
    // Use spawn_blocking to avoid nested runtime issues with open crate
    let url_owned = auth_url.to_string();
    let browser_opened = tokio::task::spawn_blocking(move || try_open_browser(&url_owned))
        .await
        .unwrap_or(false);

    if browser_opened {
        info!("Browser opened successfully");
        show_notification(
            "VPN Authentication",
            "Please complete login in your browser...",
        );
    } else {
        warn!("Could not open browser automatically");
        // Show the URL in a notification so user can open it manually
        show_notification(
            "VPN SSO Login Required",
            &format!("Please open: {}", auth_url),
        );
    }

    // Also log the URL to journald so it can be found if notifications fail
    info!("SSO Login URL: {}", auth_url);

    // Return a placeholder result - the actual authentication is handled
    // by the OpenVPN server. We'll know auth succeeded when the management
    // interface reports state changes.
    Ok(OAuthResult {
        code: "server-handled".to_string(),
        state: None,
        callback_url: auth_url.to_string(),
    })
}

/// The localhost port for receiving the OAuth callback from Google.
/// This must match CLIENT_OAUTH_CALLBACK_PORT on the server side.
const LOCAL_OAUTH_CALLBACK_PORT: u16 = 19823;

/// Perform SSO authentication with a localhost callback server.
///
/// Flow:
/// 1. Start localhost HTTP server on LOCAL_OAUTH_CALLBACK_PORT
/// 2. Open browser to auth_url (VPN server's /auth/start, which redirects to Google)
/// 3. Google authenticates user, redirects to localhost:LOCAL_OAUTH_CALLBACK_PORT/oauth/callback
/// 4. We receive code + state, POST them to VPN server's /auth/complete
/// 5. VPN server exchanges code, verifies user, sends PUSH_REPLY through VPN tunnel
pub async fn authenticate_sso(auth_url: &str, server_base_url: &str) -> Result<()> {
    info!("Starting SSO authentication flow");
    info!("  Auth URL: {}", auth_url);
    info!("  Server base: {}", server_base_url);

    // Create channel for receiving the OAuth callback result
    let (callback_tx, callback_rx) = oneshot::channel::<Result<(String, String)>>();
    let callback_tx = Arc::new(tokio::sync::Mutex::new(Some(callback_tx)));

    // Start localhost callback server
    let listener = TcpListener::bind(format!("127.0.0.1:{}", LOCAL_OAUTH_CALLBACK_PORT))
        .await
        .context(format!(
            "Failed to bind localhost:{}",
            LOCAL_OAUTH_CALLBACK_PORT
        ))?;
    info!(
        "OAuth callback server listening on localhost:{}",
        LOCAL_OAUTH_CALLBACK_PORT
    );

    let server_base_owned = server_base_url.to_string();
    let callback_state = SsoCallbackState {
        result_tx: callback_tx,
    };

    let app = Router::new()
        .route("/oauth/callback", get(handle_sso_callback))
        .with_state(Arc::new(callback_state));

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|e| error!("OAuth callback server error: {}", e))
            .ok();
    });

    // Open browser
    let url_owned = auth_url.to_string();
    let browser_opened = tokio::task::spawn_blocking(move || try_open_browser(&url_owned))
        .await
        .unwrap_or(false);

    if browser_opened {
        info!("Browser opened for SSO authentication");
        show_notification(
            "VPN Authentication",
            "Please complete login in your browser...",
        );
    } else {
        warn!("Could not open browser automatically");
        show_notification(
            "VPN SSO Login Required",
            &format!("Please open: {}", auth_url),
        );
    }

    info!("SSO Login URL: {}", auth_url);

    // Wait for the callback with timeout (120 seconds to match AUTH_PENDING timeout)
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), callback_rx)
        .await
        .map_err(|_| anyhow!("SSO authentication timed out after 120s"))?
        .map_err(|_| anyhow!("SSO callback channel dropped"))??;

    let (code, state) = result;
    info!("Received OAuth callback with state: {}", state);

    // POST the auth code to the VPN server
    let complete_url = format!("{}/auth/complete", server_base_owned);
    info!("Forwarding auth code to VPN server: {}", complete_url);

    let http_client = reqwest::Client::new();
    let response = http_client
        .post(&complete_url)
        .json(&serde_json::json!({
            "code": code,
            "state": state,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("Failed to send auth code to VPN server")?;

    if response.status().is_success() {
        info!("VPN server accepted OAuth authentication");
        show_notification("VPN Authentication", "Login successful! VPN connecting...");
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        error!("VPN server rejected OAuth: {} - {}", status, body);
        return Err(anyhow!("VPN server rejected authentication: {}", body));
    }

    // Clean up
    server_handle.abort();

    Ok(())
}

/// Shared state for the SSO callback handler
struct SsoCallbackState {
    result_tx: OAuthResultSender,
}

/// Query parameters from Google's OAuth redirect
#[derive(Debug, Deserialize)]
struct SsoCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Handle the OAuth callback from Google on localhost
async fn handle_sso_callback(
    State(state): State<Arc<SsoCallbackState>>,
    Query(params): Query<SsoCallbackParams>,
) -> impl IntoResponse {
    debug!(
        "Received OAuth callback on localhost: code={}, state={}, error={:?}",
        params
            .code
            .as_deref()
            .map(|c| &c[..c.len().min(10)])
            .unwrap_or("none"),
        params.state.as_deref().unwrap_or("none"),
        params.error
    );

    let tx = {
        let mut guard = state.result_tx.lock().await;
        guard.take()
    };

    if let Some(error) = params.error {
        let desc = params.error_description.unwrap_or_else(|| error.clone());
        if let Some(tx) = tx {
            let _ = tx.send(Err(anyhow!("OAuth error: {}", desc)));
        }
        return Html(error_page(&desc));
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            if let Some(tx) = tx {
                let _ = tx.send(Err(anyhow!("No authorization code in callback")));
            }
            return Html(error_page("No authorization code received"));
        }
    };

    let oauth_state = params.state.unwrap_or_default();

    // Send the code + state to the main task
    if let Some(tx) = tx {
        let _ = tx.send(Ok((code, oauth_state)));
    }

    // Show a "please wait" page - the main task will POST to the VPN server
    Html(r#"<!DOCTYPE html>
<html><head><title>CoreVPN - Authenticating</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#eee}
.card{background:#16213e;border-radius:12px;padding:40px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.3)}
h1{color:#4ecca3;margin-bottom:10px}p{color:#aaa}.spinner{width:40px;height:40px;border:4px solid rgba(78,204,163,.2);border-top:4px solid #4ecca3;border-radius:50%;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}</style></head>
<body><div class="card"><div class="spinner"></div><h1>Authenticating...</h1>
<p>Completing VPN authentication. You can close this window shortly.</p></div>
<script>setTimeout(()=>{document.querySelector('h1').textContent='✓ Authenticated';document.querySelector('.spinner').style.display='none';document.querySelector('p').textContent='VPN connection is being established. You can close this window.'},3000)</script>
</body></html>"#.to_string())
}

/// Try to open a browser, using multiple methods
/// Returns true if browser was successfully launched
fn try_open_browser(url: &str) -> bool {
    // When running as root (NetworkManager service), we need to launch
    // the browser as the actual logged-in user with their display environment

    info!("Attempting to open browser for URL: {}", url);

    // Find the active graphical user
    if let Some(user) = find_graphical_user() {
        info!("Found graphical user: {}", user);

        // Get the user's UID for XDG_RUNTIME_DIR
        let uid = match get_uid_for_user(&user) {
            Some(u) => u,
            None => {
                warn!("Could not get UID for user {}", user);
                return try_fallback_browser(url);
            }
        };

        // Method 1 (preferred): Use systemd-run --user to run in the user's session scope.
        // This inherits the user's full environment (DISPLAY, WAYLAND_DISPLAY, DBUS, etc.)
        // and properly communicates with existing browser instances.
        {
            let mut cmd = std::process::Command::new("systemd-run");
            cmd.args([
                "--user",
                &format!("--machine={}@", user),
                "--collect",
                "--no-block",
                "--quiet",
                "xdg-open",
                url,
            ]);

            info!(
                "Running: systemd-run --user --machine={}@ xdg-open {}",
                user, url
            );
            match cmd.output() {
                Ok(output) if output.status.success() => {
                    info!("Browser opened via systemd-run --user (using default browser)");
                    return true;
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!(
                        "systemd-run --user failed (status {:?}): {}",
                        output.status,
                        stderr.trim()
                    );
                }
                Err(e) => {
                    warn!("systemd-run failed to execute: {}", e);
                }
            }
        }

        let xdg_runtime = format!("/run/user/{}", uid);

        // Get user's environment from their processes
        let user_env = get_user_graphical_env(&user, uid);
        info!("User graphical env: {:?}", user_env);

        // Method 2: Try xdg-open with user's environment via runuser
        {
            let mut cmd = std::process::Command::new("runuser");
            cmd.args(["-u", &user, "--"]);

            // Ensure PATH includes standard locations
            cmd.env(
                "PATH",
                "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
            );

            for (key, value) in &user_env {
                cmd.env(key, value);
            }
            cmd.env("XDG_RUNTIME_DIR", &xdg_runtime);
            cmd.arg("xdg-open").arg(url);

            info!("Running: runuser -u {} -- xdg-open {}", user, url);
            match cmd.spawn() {
                Ok(mut child) => {
                    // Wait a moment to see if xdg-open immediately fails
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    match child.try_wait() {
                        Ok(Some(status)) if !status.success() => {
                            warn!("xdg-open exited with non-zero status: {:?}", status);
                            // Continue to try direct browsers
                        }
                        Ok(Some(_)) => {
                            info!("Browser opened via runuser xdg-open (using default browser)");
                            return true;
                        }
                        Ok(None) => {
                            // Still running, likely working
                            info!("Browser opened via runuser xdg-open (using default browser)");
                            return true;
                        }
                        Err(e) => {
                            warn!("Failed to check xdg-open status: {}", e);
                            return true; // Assume success
                        }
                    }
                }
                Err(e) => {
                    warn!("runuser xdg-open failed to spawn: {}", e);
                }
            }
        }

        // Method 3: Try browsers directly (fallback)
        for browser in &[
            "vivaldi-stable",
            "vivaldi",
            "firefox",
            "chromium",
            "google-chrome-stable",
            "brave",
        ] {
            let mut cmd = std::process::Command::new("runuser");
            cmd.args(["-u", &user, "--"]);

            // Ensure PATH includes standard locations
            cmd.env(
                "PATH",
                "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin",
            );

            // Set essential environment variables
            for (key, value) in &user_env {
                cmd.env(key, value);
            }
            cmd.env("XDG_RUNTIME_DIR", &xdg_runtime);

            info!("Trying browser: runuser -u {} -- {} {}", user, browser, url);
            cmd.arg(browser).arg(url);

            match cmd.spawn() {
                Ok(_) => {
                    info!("Browser opened via runuser -u {} {}", user, browser);
                    return true;
                }
                Err(e) => {
                    // Only log if the browser exists but failed for another reason
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!("Failed to launch {} via runuser: {}", browser, e);
                    }
                }
            }
        }
    } else {
        warn!("Could not find graphical user session");
    }

    try_fallback_browser(url)
}

/// Try fallback browser methods (unlikely to work from root)
fn try_fallback_browser(url: &str) -> bool {
    // These are unlikely to work from a root service, but try anyway
    if open::that(url).is_ok() {
        info!("Browser opened via open::that() (fallback)");
        return true;
    }

    if std::process::Command::new("xdg-open")
        .arg(url)
        .spawn()
        .is_ok()
    {
        info!("Browser opened via xdg-open (fallback)");
        return true;
    }

    false
}

/// Find the username of an active graphical session
fn find_graphical_user() -> Option<String> {
    // Use loginctl to find active sessions
    let output = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
        .ok()?;

    let sessions = String::from_utf8_lossy(&output.stdout);
    info!("loginctl sessions: {}", sessions.trim());

    for line in sessions.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let session_id = parts[0];
        let user = parts[2];

        // Skip root sessions
        if user == "root" {
            continue;
        }

        // Check session type and state
        let show_output = std::process::Command::new("loginctl")
            .args([
                "show-session",
                session_id,
                "-p",
                "Type",
                "-p",
                "State",
                "-p",
                "Active",
            ])
            .output()
            .ok()?;

        let session_info = String::from_utf8_lossy(&show_output.stdout);
        info!(
            "Session {} for {}: {}",
            session_id,
            user,
            session_info.replace('\n', " ")
        );

        // Check if graphical and active
        let is_graphical =
            session_info.contains("Type=x11") || session_info.contains("Type=wayland");
        let is_active =
            session_info.contains("Active=yes") || session_info.contains("State=active");

        if is_graphical && is_active {
            info!("Found active graphical session for user: {}", user);
            return Some(user.to_string());
        }
    }

    // Fallback: try to find any non-root user with an active session
    for line in sessions.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] != "root" {
            warn!("Using fallback non-graphical user: {}", parts[2]);
            return Some(parts[2].to_string());
        }
    }

    None
}

/// Get graphical environment variables from a user's processes
fn get_user_graphical_env(_username: &str, uid: u32) -> Vec<(String, String)> {
    let mut env_vars = Vec::new();
    let needed_vars = [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_CURRENT_DESKTOP",
        "DBUS_SESSION_BUS_ADDRESS",
        "XAUTHORITY",
        "GDK_BACKEND",
        "QT_QPA_PLATFORM",
    ];

    // Get list of PIDs for this user using ps command (more reliable)
    let ps_output = match std::process::Command::new("ps")
        .args(["-u", &uid.to_string(), "-o", "pid="])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            warn!("Failed to run ps: {}", e);
            return get_fallback_env(uid);
        }
    };

    let ps_stdout = String::from_utf8_lossy(&ps_output.stdout);
    let pids: Vec<&str> = ps_stdout.split_whitespace().collect();

    info!("Checking {} processes for user {}", pids.len(), uid);

    for pid_str in pids.iter().take(100) {
        // Limit to first 100 processes
        let environ_path = format!("/proc/{}/environ", pid_str.trim());

        // Read environment file
        let environ = match std::fs::read(&environ_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for var in environ.split(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(var) {
                if let Some((key, value)) = s.split_once('=') {
                    if needed_vars.contains(&key) && !env_vars.iter().any(|(k, _)| k == key) {
                        info!("Found {}={} from PID {}", key, value, pid_str);
                        env_vars.push((key.to_string(), value.to_string()));
                    }
                }
            }
        }

        // If we have DISPLAY or WAYLAND_DISPLAY, we have enough
        if env_vars
            .iter()
            .any(|(k, _)| k == "DISPLAY" || k == "WAYLAND_DISPLAY")
        {
            info!("Found display env, stopping search");
            break;
        }
    }

    // If we didn't find display env, use fallback
    if !env_vars
        .iter()
        .any(|(k, _)| k == "DISPLAY" || k == "WAYLAND_DISPLAY")
    {
        warn!("No display env found in processes, using fallback");
        return get_fallback_env(uid);
    }

    env_vars
}

/// Get fallback environment variables based on common defaults
fn get_fallback_env(uid: u32) -> Vec<(String, String)> {
    let mut env_vars = Vec::new();
    let xdg_runtime = format!("/run/user/{}", uid);

    // Check if Wayland socket exists
    let wayland_socket = format!("{}/wayland-0", xdg_runtime);
    if std::path::Path::new(&wayland_socket).exists() {
        info!("Wayland socket found at {}", wayland_socket);
        env_vars.push(("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string()));
        env_vars.push(("XDG_RUNTIME_DIR".to_string(), xdg_runtime.clone()));
        // Also set DISPLAY for XWayland apps
        env_vars.push(("DISPLAY".to_string(), ":1".to_string()));

        // Try to detect the desktop environment from common indicators
        let kde_indicators = [
            format!("{}/kwin_wayland", xdg_runtime),
            format!("{}/kwallet5.socket", xdg_runtime),
            format!("{}/kwalletd5.socket", xdg_runtime),
        ];
        let gnome_indicators = [format!("{}/gnome-shell", xdg_runtime)];

        let is_kde = kde_indicators
            .iter()
            .any(|p| std::path::Path::new(p).exists())
            || std::fs::read_dir(&xdg_runtime)
                .map(|d| {
                    d.into_iter().any(|e| {
                        let name = e
                            .ok()
                            .map(|e| e.file_name().to_string_lossy().to_lowercase())
                            .unwrap_or_default();
                        name.contains("plasma") || name.contains("kwin") || name.starts_with("ksm")
                    })
                })
                .unwrap_or(false);

        let is_gnome = gnome_indicators
            .iter()
            .any(|p| std::path::Path::new(p).exists());

        if is_kde {
            info!("Detected KDE Plasma session");
            env_vars.push(("XDG_CURRENT_DESKTOP".to_string(), "KDE".to_string()));
            env_vars.push(("XDG_SESSION_DESKTOP".to_string(), "KDE".to_string()));
            env_vars.push(("KDE_SESSION_VERSION".to_string(), "5".to_string()));
        } else if is_gnome {
            info!("Detected GNOME session");
            env_vars.push(("XDG_CURRENT_DESKTOP".to_string(), "GNOME".to_string()));
        } else {
            // Default to generic - but still set XDG_CURRENT_DESKTOP for xdg-open to work
            info!("Could not detect specific DE, using generic wayland settings");
            env_vars.push(("XDG_CURRENT_DESKTOP".to_string(), "X-Generic".to_string()));
        }

        // Set DBUS session address
        let dbus_socket = format!("{}/bus", xdg_runtime);
        if std::path::Path::new(&dbus_socket).exists() {
            env_vars.push((
                "DBUS_SESSION_BUS_ADDRESS".to_string(),
                format!("unix:path={}", dbus_socket),
            ));
        }
    } else {
        // Assume X11
        info!("No Wayland socket, assuming X11 with DISPLAY=:0");
        env_vars.push(("DISPLAY".to_string(), ":0".to_string()));
        env_vars.push(("XDG_RUNTIME_DIR".to_string(), xdg_runtime));
    }

    env_vars
}

/// Get the UID for a username
fn get_uid_for_user(username: &str) -> Option<u32> {
    let output = std::process::Command::new("id")
        .args(["-u", username])
        .output()
        .ok()?;

    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

/// Perform OAuth authentication with local callback server
///
/// Opens the auth URL in the system browser, starts a localhost server
/// to receive the callback, and returns the result.
#[allow(dead_code)]
pub async fn authenticate_with_callback(
    auth_url: &str,
    state: Option<&str>,
) -> Result<OAuthResult> {
    // Parse and validate the auth URL
    let _url = Url::parse(auth_url).context("Invalid auth URL")?;

    // Find an available port for the callback server
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("Failed to bind callback server")?;
    let addr = listener.local_addr()?;
    let callback_url = format!("http://127.0.0.1:{}/callback", addr.port());

    info!("OAuth callback server listening on {}", addr);

    // Modify auth URL to include our callback URL if needed
    let final_auth_url = inject_redirect_uri(auth_url, &callback_url)?;

    // Create channel for result
    let (tx, rx) = oneshot::channel();

    let state_clone = state.map(|s| s.to_string());
    let callback_state = Arc::new(tokio::sync::Mutex::new(Some(CallbackState {
        result_tx: tx,
        expected_state: state_clone,
    })));

    // Build the callback server
    let app = Router::new()
        .route("/callback", get(handle_callback))
        .with_state(callback_state.clone());

    // Spawn the server
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|e| error!("Callback server error: {}", e))
            .ok();
    });

    // Show notification
    show_notification("VPN Authentication", "Opening browser for SSO login...");

    // Open browser
    debug!("Opening browser to: {}", final_auth_url);
    if let Err(e) = open::that(&final_auth_url) {
        warn!("Failed to open browser: {}", e);
        show_notification(
            "VPN Authentication",
            &format!("Please open: {}", final_auth_url),
        );
    }

    // Wait for callback with timeout
    let result = tokio::time::timeout(std::time::Duration::from_secs(AUTH_TIMEOUT_SECS), rx)
        .await
        .map_err(|_| anyhow!("Authentication timed out after {}s", AUTH_TIMEOUT_SECS))?
        .map_err(|_| anyhow!("Authentication was cancelled"))??;

    // Clean up server
    server_handle.abort();

    info!("OAuth authentication completed successfully");
    show_notification("VPN Authentication", "Login successful!");

    Ok(result)
}

/// Handle the OAuth callback
async fn handle_callback(
    State(state): State<Arc<tokio::sync::Mutex<Option<CallbackState>>>>,
    Query(params): Query<CallbackParams>,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    debug!("Received OAuth callback: {:?}", params);

    // Take the state (one-shot)
    let callback_state = {
        let mut guard = state.lock().await;
        guard.take()
    };

    let Some(callback_state) = callback_state else {
        return Html(error_page("Callback already processed"));
    };

    // Check for OAuth errors
    if let Some(error) = params.error {
        let msg = params.error_description.unwrap_or_else(|| error.clone());
        let _ = callback_state
            .result_tx
            .send(Err(anyhow!("OAuth error: {}", msg)));
        return Html(error_page(&msg));
    }

    // Extract the code/token
    let code = params.code.or(params.token).or(params.access_token);

    let Some(code) = code else {
        let _ = callback_state
            .result_tx
            .send(Err(anyhow!("No code or token in callback")));
        return Html(error_page("No authorization code received"));
    };

    // Verify state if expected
    if let Some(expected) = &callback_state.expected_state {
        if params.state.as_ref() != Some(expected) {
            let _ = callback_state
                .result_tx
                .send(Err(anyhow!("State mismatch - possible CSRF attack")));
            return Html(error_page("Security validation failed"));
        }
    }

    let result = OAuthResult {
        code,
        state: params.state,
        callback_url: uri.to_string(),
    };

    let _ = callback_state.result_tx.send(Ok(result));

    Html(success_page().to_string())
}

/// Inject redirect_uri into auth URL if not present
fn inject_redirect_uri(auth_url: &str, callback_url: &str) -> Result<String> {
    let mut url = Url::parse(auth_url)?;

    // Check if redirect_uri is already present
    let has_redirect = url.query_pairs().any(|(k, _)| k == "redirect_uri");

    if !has_redirect {
        url.query_pairs_mut()
            .append_pair("redirect_uri", callback_url);
    }

    Ok(url.to_string())
}

/// Show a desktop notification (non-blocking wrapper)
fn show_notification(summary: &str, body: &str) {
    let summary = summary.to_string();
    let body = body.to_string();

    // Spawn in background thread to avoid blocking
    std::thread::spawn(move || {
        if let Err(e) = Notification::new()
            .summary(&summary)
            .body(&body)
            .appname("OpenVPN SSO")
            .timeout(5000)
            .show()
        {
            // Can't use warn! here as it might not be set up for this thread
            eprintln!("Failed to show notification: {}", e);
        }
    });
}

/// HTML page for successful auth
fn success_page() -> &'static str {
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            text-align: center;
            background: white;
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .checkmark {
            font-size: 4rem;
            color: #10b981;
        }
        h1 { color: #1f2937; margin: 1rem 0 0.5rem; }
        p { color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Authentication Successful</h1>
        <p>You can close this window and return to your application.</p>
    </div>
    <script>setTimeout(() => window.close(), 3000);</script>
</body>
</html>"#
}

/// HTML page for auth errors
fn error_page(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Authentication Failed</title>
    <style>
        body {{
            font-family: system-ui, -apple-system, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        }}
        .container {{
            text-align: center;
            background: white;
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .error-icon {{
            font-size: 4rem;
            color: #ef4444;
        }}
        h1 {{ color: #1f2937; margin: 1rem 0 0.5rem; }}
        p {{ color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>Authentication Failed</h1>
        <p>{}</p>
    </div>
</body>
</html>"#,
        message
    )
}
