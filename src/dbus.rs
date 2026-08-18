// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! D-Bus interface implementing NetworkManager VPN Plugin

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use zbus::zvariant::OwnedValue;
use zbus::{interface, Connection};

use crate::config::ConnectionConfig;
use crate::openvpn::{OpenVpnManager, VpnEvent, VpnState};

/// D-Bus service name
const SERVICE_NAME: &str = "org.freedesktop.NetworkManager.openvpn-sso";

/// D-Bus object path
const OBJECT_PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";

/// NM VPN Plugin states
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum NMVpnServiceState {
    Unknown = 0,
    Init = 1,
    Shutdown = 2,
    Starting = 3,
    Started = 4,
    Stopping = 5,
    Stopped = 6,
}

/// NM VPN failure reasons
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum NMVpnPluginFailure {
    LoginFailed = 0,
    ConnectFailed = 1,
    BadIpConfig = 2,
}

/// Shared plugin state
pub struct PluginState {
    pub vpn_manager: Option<OpenVpnManager>,
    pub current_config: Option<ConnectionConfig>,
    pub state: NMVpnServiceState,
}

impl Default for PluginState {
    fn default() -> Self {
        Self {
            vpn_manager: None,
            current_config: None,
            state: NMVpnServiceState::Init,
        }
    }
}

/// The VPN Plugin D-Bus object
pub struct VpnPlugin {
    inner_state: Arc<RwLock<PluginState>>,
    event_rx: Arc<Mutex<Option<mpsc::Receiver<VpnEvent>>>>,
    connection: Arc<Mutex<Option<Connection>>>,
}

#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl VpnPlugin {
    /// Connect to VPN
    async fn connect(
        &mut self,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<()> {
        info!("Connect called");
        debug!("Connection settings: {:?}", connection);

        // Parse connection config
        let config = ConnectionConfig::from_nm_settings(&connection)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        info!("Connecting to VPN: {} ({})", config.id, config.uuid);

        // Create event channel
        let (tx, rx) = mpsc::channel(100);

        // Store receiver for event processing
        {
            let mut rx_guard = self.event_rx.lock().await;
            *rx_guard = Some(rx);
        }

        // Create and store VPN manager
        let vpn_manager = OpenVpnManager::new(config.clone(), tx);

        // Update state
        {
            let mut state = self.inner_state.write().await;
            state.current_config = Some(config.clone());
            state.state = NMVpnServiceState::Starting;
            state.vpn_manager = Some(vpn_manager);
        }

        // Start connection in background
        let state_clone = self.inner_state.clone();

        tokio::spawn(async move {
            // Take manager temporarily to run connect
            let mut manager = {
                let mut state = state_clone.write().await;
                state.vpn_manager.take()
            };

            if let Some(ref mut mgr) = manager {
                match mgr.connect().await {
                    Ok(()) => {
                        info!("VPN connection established");
                    }
                    Err(e) => {
                        error!("VPN connection failed: {}", e);
                        let mut state = state_clone.write().await;
                        state.state = NMVpnServiceState::Stopped;
                    }
                }
            }

            // Store manager back
            {
                let mut state = state_clone.write().await;
                state.vpn_manager = manager;
            }
        });

        // Start event processing
        let emitter_state = self.inner_state.clone();
        let event_rx_clone = self.event_rx.clone();
        let conn_clone = self.connection.clone();

        tokio::spawn(async move {
            // Get connection for signal emission
            let conn = {
                let guard = conn_clone.lock().await;
                guard.clone()
            };
            if let Some(connection) = conn {
                process_vpn_events(event_rx_clone, emitter_state, connection).await;
            } else {
                error!("No D-Bus connection available for event processing");
            }
        });

        Ok(())
    }

    /// Connect interactively (same as connect for us)
    async fn connect_interactive(
        &mut self,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
        _details: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        self.connect(connection).await
    }

    /// Check if secrets are needed
    async fn need_secrets(
        &self,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<String> {
        info!("NeedSecrets called");

        // Log all received data for debugging
        for (section, data) in &connection {
            info!(
                "  Section '{}' keys: {:?}",
                section,
                data.keys().collect::<Vec<_>>()
            );
            for (key, val) in data {
                info!("    {}: {:?}", key, val);
            }
        }

        // Parse config to get connection UUID
        let config = ConnectionConfig::from_nm_settings(&connection).map_err(|e| {
            error!("Failed to parse connection config: {}", e);
            zbus::fdo::Error::Failed(e.to_string())
        })?;

        info!(
            "Parsed config: uuid={}, id={}, config_path={:?}, ca={:?}",
            config.uuid, config.id, config.config_path, config.ca
        );

        // Auth is handled entirely via browser SSO, so we never ask NM to
        // prompt for secrets. Return empty string = no secrets needed.
        Ok(String::new())
    }

    /// Disconnect from VPN
    async fn disconnect(&mut self) -> zbus::fdo::Result<()> {
        info!("Disconnect called");

        let mut state = self.inner_state.write().await;
        state.state = NMVpnServiceState::Stopping;

        if let Some(ref mut manager) = state.vpn_manager {
            if let Err(e) = manager.disconnect().await {
                warn!("Error during disconnect: {}", e);
            }
        }

        state.vpn_manager = None;
        state.current_config = None;
        state.state = NMVpnServiceState::Stopped;

        Ok(())
    }

    // The following methods (set_config, set_ip4_config, set_ip6_config,
    // new_secrets, set_failure) are required by the
    // org.freedesktop.NetworkManager.VPN.Plugin D-Bus interface, but are
    // intentionally no-ops here: this plugin parses OpenVPN's own output
    // and emits Config/Ip4Config/Failure as outbound signals itself (see
    // emit_config/emit_ip4_config/emit_failure below in this file), rather
    // than relying on an external helper calling back into these methods.

    /// Set generic configuration
    async fn set_config(&self, _config: HashMap<String, OwnedValue>) -> zbus::fdo::Result<()> {
        debug!("SetConfig called");
        Ok(())
    }

    /// Set IPv4 configuration
    async fn set_ip4_config(&self, _config: HashMap<String, OwnedValue>) -> zbus::fdo::Result<()> {
        debug!("SetIp4Config called");
        Ok(())
    }

    /// Set IPv6 configuration
    async fn set_ip6_config(&self, _config: HashMap<String, OwnedValue>) -> zbus::fdo::Result<()> {
        debug!("SetIp6Config called");
        Ok(())
    }

    /// Called when new secrets are available
    async fn new_secrets(
        &self,
        _connection: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<()> {
        debug!("NewSecrets called");
        Ok(())
    }

    /// Set failure notification
    async fn set_failure(&self, reason: String) -> zbus::fdo::Result<()> {
        error!("SetFailure called: {}", reason);
        Ok(())
    }

    /// Current state property
    #[zbus(property, name = "State")]
    async fn vpn_state(&self) -> u32 {
        let state = self.inner_state.read().await;
        state.state as u32
    }

    // Note: Signals (StateChanged, Config, Ip4Config, Failure) are emitted
    // directly via connection.emit_signal() in process_vpn_events()
}

/// Process VPN events and emit D-Bus signals
async fn process_vpn_events(
    event_rx: Arc<Mutex<Option<mpsc::Receiver<VpnEvent>>>>,
    state: Arc<RwLock<PluginState>>,
    connection: Connection,
) {
    let mut rx = {
        let mut guard = event_rx.lock().await;
        match guard.take() {
            Some(rx) => rx,
            None => return,
        }
    };

    while let Some(event) = rx.recv().await {
        match event {
            VpnEvent::State(vpn_state) => {
                debug!("VPN state: {:?}", vpn_state);

                // Map VPN states to NM states
                // During auth/config phases, stay in Starting - don't emit Unknown
                let (nm_state, should_emit) = match vpn_state {
                    VpnState::Starting | VpnState::Connecting => {
                        (NMVpnServiceState::Starting, true)
                    }
                    VpnState::Init => (NMVpnServiceState::Init, true),
                    // During auth phases, keep as Starting but don't spam state signals
                    VpnState::NeedAuth | VpnState::GettingConfig => {
                        (NMVpnServiceState::Starting, false)
                    }
                    VpnState::Connected => (NMVpnServiceState::Started, false), // Handled in VpnEvent::Connected
                    VpnState::Stopping => (NMVpnServiceState::Stopping, true),
                    VpnState::Stopped | VpnState::Failed | VpnState::Shutdown => {
                        (NMVpnServiceState::Stopped, true)
                    }
                    _ => (NMVpnServiceState::Starting, false), // Default to Starting for unknown
                };

                {
                    let mut state_guard = state.write().await;
                    state_guard.state = nm_state;
                }

                // Only emit state changes for certain transitions
                if should_emit {
                    if let Err(e) = emit_state_changed(&connection, nm_state as u32).await {
                        warn!("Failed to emit StateChanged signal: {}", e);
                    }
                }
            }
            VpnEvent::AuthRequired { auth_url } => {
                // Just log - the browser auth is already handled by openvpn.rs
                // to avoid duplicate browser windows
                info!("Auth required event received, URL: {:?}", auth_url);
            }
            VpnEvent::Connected(vpn_config) => {
                info!("VPN connected: {:?}", vpn_config);

                // Update state to Started/Connected
                {
                    let mut state_guard = state.write().await;
                    state_guard.state = NMVpnServiceState::Started;
                }

                // First emit Config signal with tunnel device info
                if let Err(e) = emit_config(&connection, &vpn_config).await {
                    warn!("Failed to emit Config signal: {}", e);
                }

                // Then emit Ip4Config signal with IP configuration
                if let Err(e) = emit_ip4_config(&connection, &vpn_config).await {
                    warn!("Failed to emit Ip4Config signal: {}", e);
                }

                // Finally emit StateChanged signal (state 5 = NM_VPN_CONNECTION_STATE_ACTIVATED)
                if let Err(e) = emit_state_changed(&connection, 5).await {
                    warn!("Failed to emit StateChanged signal: {}", e);
                }
            }
            VpnEvent::Failed(reason) => {
                error!("VPN failed: {}", reason);
                let mut state_guard = state.write().await;
                state_guard.state = NMVpnServiceState::Stopped;

                // Emit Failure signal (1 = connect failed)
                if let Err(e) = emit_failure(&connection, 1).await {
                    warn!("Failed to emit Failure signal: {}", e);
                }
            }
            VpnEvent::Log(msg) => {
                debug!("OpenVPN: {}", msg);
            }
        }
    }
}

/// Emit StateChanged signal
async fn emit_state_changed(connection: &Connection, state: u32) -> Result<()> {
    info!("Emitting StateChanged signal with state: {}", state);
    connection
        .emit_signal(
            None::<&str>,
            OBJECT_PATH,
            "org.freedesktop.NetworkManager.VPN.Plugin",
            "StateChanged",
            &(state,),
        )
        .await
        .map_err(|e| anyhow!("Failed to emit signal: {}", e))
}

/// Emit Config signal with tunnel device info
async fn emit_config(
    connection: &Connection,
    vpn_config: &crate::openvpn::VpnConfig,
) -> Result<()> {
    use zbus::zvariant::Value;

    let mut config: HashMap<String, Value> = HashMap::new();

    // Add tunnel device - try to find the actual tun device
    let tundev = vpn_config
        .tun_device
        .clone()
        .unwrap_or_else(|| "tun0".to_string());
    config.insert("tundev".to_string(), Value::new(tundev.clone()));

    // Add gateway (VPN server external IP) as u32 - this is the remote server
    // NetworkManager expects this as a u32 in network byte order
    if let Some(ref gateway) = vpn_config.remote_ip {
        if let Ok(addr) = gateway.parse::<std::net::Ipv4Addr>() {
            let gw_u32: u32 = addr.into();
            config.insert("gateway".to_string(), Value::new(gw_u32));
        }
    }

    // Mark that we have IPv4 config
    config.insert("has-ip4".to_string(), Value::new(true));

    info!("Emitting Config signal: {:?}", config);
    connection
        .emit_signal(
            None::<&str>,
            OBJECT_PATH,
            "org.freedesktop.NetworkManager.VPN.Plugin",
            "Config",
            &(config,),
        )
        .await
        .map_err(|e| anyhow!("Failed to emit Config signal: {}", e))
}

/// Emit Ip4Config signal
async fn emit_ip4_config(
    connection: &Connection,
    vpn_config: &crate::openvpn::VpnConfig,
) -> Result<()> {
    use zbus::zvariant::Value;

    let mut config: HashMap<String, Value> = HashMap::new();

    // Add internal IP address (VPN address assigned to us)
    if let Some(ref ip) = vpn_config.local_ip {
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            // NetworkManager expects IPs as u32 (host byte order, which Ipv4Addr::into provides)
            let ip_u32: u32 = addr.into();
            config.insert("address".to_string(), Value::new(ip_u32));

            // Add prefix length (default /24 for VPN subnet)
            let prefix: u32 = 24;
            config.insert("prefix".to_string(), Value::new(prefix));

            // For internal VPN gateway, use .1 of the subnet (typical OpenVPN server address)
            let octets = addr.octets();
            let internal_gw = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
            let internal_gw_u32: u32 = internal_gw.into();
            config.insert("int-gw".to_string(), Value::new(internal_gw_u32));
        }
    }

    // Add VPN server's public/external gateway address for routing
    // This tells NM where VPN traffic should be routed through
    if let Some(ref gateway) = vpn_config.remote_ip {
        if let Ok(gw_addr) = gateway.parse::<std::net::Ipv4Addr>() {
            let gw_u32: u32 = gw_addr.into();
            config.insert("gateway".to_string(), Value::new(gw_u32));
        }
    }

    // Add DNS servers
    if !vpn_config.dns_servers.is_empty() {
        let dns: Vec<u32> = vpn_config
            .dns_servers
            .iter()
            .filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .map(|a| a.into())
            .collect();
        if !dns.is_empty() {
            config.insert("dns".to_string(), Value::new(dns));
        }
    }

    // Add DNS search domains
    if !vpn_config.dns_search.is_empty() {
        config.insert(
            "dns-search".to_string(),
            Value::new(vpn_config.dns_search.clone()),
        );
    }

    info!("Emitting Ip4Config signal: {:?}", config);
    connection
        .emit_signal(
            None::<&str>,
            OBJECT_PATH,
            "org.freedesktop.NetworkManager.VPN.Plugin",
            "Ip4Config",
            &(config,),
        )
        .await
        .map_err(|e| anyhow!("Failed to emit Ip4Config signal: {}", e))
}

/// Emit Failure signal
async fn emit_failure(connection: &Connection, reason: u32) -> Result<()> {
    info!("Emitting Failure signal with reason: {}", reason);
    connection
        .emit_signal(
            None::<&str>,
            OBJECT_PATH,
            "org.freedesktop.NetworkManager.VPN.Plugin",
            "Failure",
            &(reason,),
        )
        .await
        .map_err(|e| anyhow!("Failed to emit signal: {}", e))
}

/// Run the D-Bus service
pub async fn run_service() -> Result<()> {
    // Connect to the system bus first
    let connection = Connection::system()
        .await
        .map_err(|e| anyhow!("Failed to connect to system bus: {}", e))?;

    let plugin = VpnPlugin {
        inner_state: Arc::new(RwLock::new(PluginState::default())),
        event_rx: Arc::new(Mutex::new(None)),
        connection: Arc::new(Mutex::new(Some(connection.clone()))),
    };

    // Register the object
    connection
        .object_server()
        .at(OBJECT_PATH, plugin)
        .await
        .map_err(|e| anyhow!("Failed to register object: {}", e))?;

    // Request the service name
    connection
        .request_name(SERVICE_NAME)
        .await
        .map_err(|e| anyhow!("Failed to request service name: {}", e))?;

    info!("D-Bus service registered as {}", SERVICE_NAME);
    info!("Listening on {}", OBJECT_PATH);

    // Keep the service running
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
