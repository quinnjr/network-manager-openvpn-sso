// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! D-Bus interface implementing NetworkManager VPN Plugin

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use zbus::zvariant::{OwnedValue, Value};
use zbus::{interface, Connection};

use crate::config::ConnectionConfig;
use crate::openvpn::{OpenVpnManager, VpnConfig, VpnEvent, VpnState};

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
    /// Asks the task running `OpenVpnManager::connect` to disconnect. While that
    /// task runs (i.e. for the whole lifetime of a connection) it owns the
    /// manager, so `vpn_manager` above is `None`.
    pub stop_tx: Option<oneshot::Sender<()>>,
}

impl Default for PluginState {
    fn default() -> Self {
        Self {
            vpn_manager: None,
            current_config: None,
            state: NMVpnServiceState::Init,
            stop_tx: None,
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
        let (stop_tx, mut stop_rx) = oneshot::channel();

        // Update state
        {
            let mut state = self.inner_state.write().await;
            state.current_config = Some(config.clone());
            state.state = NMVpnServiceState::Starting;
            state.vpn_manager = Some(vpn_manager);
            state.stop_tx = Some(stop_tx);
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
                let result = tokio::select! {
                    result = mgr.connect() => Some(result),
                    _ = &mut stop_rx => None,
                };
                match result {
                    Some(Ok(())) => {
                        info!("OpenVPN management session ended");
                    }
                    Some(Err(e)) => {
                        error!("VPN connection failed: {}", e);
                        // OpenVPN may still be running, e.g. waiting for a hold
                        // release after the server rejected the session.
                        if let Err(e) = mgr.disconnect().await {
                            warn!("Error during disconnect: {}", e);
                        }
                        let mut state = state_clone.write().await;
                        state.state = NMVpnServiceState::Stopped;
                    }
                    None => {
                        // Disconnect was requested while connecting/connected.
                        // Dropping the connect future closed our management
                        // connection, so disconnect() can open its own.
                        if let Err(e) = mgr.disconnect().await {
                            warn!("Error during disconnect: {}", e);
                        }
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

        // A running connection task owns the manager; ask it to disconnect.
        if let Some(stop_tx) = state.stop_tx.take() {
            let _ = stop_tx.send(());
        }

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

                // Finally report the plugin as started. StateChanged carries the
                // service state (NMVpnServiceState), not the connection state:
                // 5 would mean "stopping".
                if let Err(e) =
                    emit_state_changed(&connection, NMVpnServiceState::Started as u32).await
                {
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

                // NetworkManager only gives up on the activation once the
                // plugin reports that it stopped; Failure alone leaves it
                // waiting for its timeout.
                if let Err(e) =
                    emit_state_changed(&connection, NMVpnServiceState::Stopped as u32).await
                {
                    warn!("Failed to emit StateChanged signal: {}", e);
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

/// NetworkManager expects IPv4 addresses as u32 holding the address in network
/// byte order (an `in_addr_t`), not the numeric value of the address.
fn nm_ip4(addr: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

/// Build the generic VPN configuration (the Config signal)
fn build_config(vpn_config: &VpnConfig) -> HashMap<&'static str, Value<'static>> {
    let mut config = HashMap::new();

    let tundev = vpn_config
        .tun_device
        .clone()
        .unwrap_or_else(|| "tun0".to_string());
    config.insert("tundev", Value::new(tundev));

    // Public address of the VPN server; NetworkManager keeps it routed outside
    // the tunnel.
    if let Some(gateway) = vpn_config.external_gateway {
        config.insert("gateway", Value::new(nm_ip4(gateway)));
    }
    if let Some(mtu) = vpn_config.mtu {
        config.insert("mtu", Value::new(mtu));
    }
    config.insert("has-ip4", Value::new(vpn_config.local_ip.is_some()));

    config
}

/// Build the IPv4 configuration (the Ip4Config signal); None without an address
fn build_ip4_config(vpn_config: &VpnConfig) -> Option<HashMap<&'static str, Value<'static>>> {
    let local_ip = vpn_config.local_ip?;
    let mut config = HashMap::new();

    config.insert("address", Value::new(nm_ip4(local_ip)));
    if let Some(prefix) = vpn_config.prefix {
        config.insert("prefix", Value::new(prefix));
    }
    if let Some(ptp) = vpn_config.ptp {
        config.insert("ptp", Value::new(nm_ip4(ptp)));
    }
    if let Some(gateway) = vpn_config.internal_gateway {
        config.insert("internal-gateway", Value::new(nm_ip4(gateway)));
    }
    if !vpn_config.routes.is_empty() {
        let routes: Vec<Vec<u32>> = vpn_config
            .routes
            .iter()
            .map(|r| {
                vec![
                    nm_ip4(r.network),
                    r.prefix,
                    r.gateway.map(nm_ip4).unwrap_or(0),
                    r.metric,
                ]
            })
            .collect();
        config.insert("routes", Value::new(routes));
    }
    if !vpn_config.dns_servers.is_empty() {
        let dns: Vec<u32> = vpn_config.dns_servers.iter().copied().map(nm_ip4).collect();
        config.insert("dns", Value::new(dns));
    }
    if !vpn_config.domains.is_empty() {
        config.insert("domains", Value::new(vpn_config.domains.clone()));
    }

    Some(config)
}

/// Emit Config signal with tunnel device info
async fn emit_config(connection: &Connection, vpn_config: &VpnConfig) -> Result<()> {
    let config = build_config(vpn_config);
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
async fn emit_ip4_config(connection: &Connection, vpn_config: &VpnConfig) -> Result<()> {
    let Some(config) = build_ip4_config(vpn_config) else {
        return Err(anyhow!("OpenVPN reported no IPv4 address for the tunnel"));
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openvpn::Route;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn sample_config() -> VpnConfig {
        VpnConfig {
            tun_device: Some("tun0".to_string()),
            external_gateway: Some(ip("80.150.73.4")),
            local_ip: Some(ip("10.20.93.66")),
            ptp: Some(ip("10.20.93.65")),
            prefix: Some(32),
            internal_gateway: Some(ip("10.20.93.65")),
            mtu: Some(1500),
            dns_servers: vec![ip("10.20.20.1")],
            domains: vec!["example.com".to_string()],
            routes: vec![Route {
                network: ip("10.20.10.0"),
                prefix: 24,
                gateway: Some(ip("10.20.93.65")),
                metric: 0,
            }],
        }
    }

    #[test]
    fn nm_ip4_uses_network_byte_order() {
        // The first octet must be the first byte in memory, like in_addr_t.
        assert_eq!(nm_ip4(ip("10.20.93.66")).to_ne_bytes(), [10, 20, 93, 66]);
        #[cfg(target_endian = "little")]
        assert_eq!(nm_ip4(ip("10.20.93.66")), 0x425D_140A);
    }

    #[test]
    fn build_config_uses_networkmanager_keys() {
        let config = build_config(&sample_config());

        assert_eq!(config["tundev"], Value::new("tun0"));
        assert_eq!(config["gateway"], Value::new(nm_ip4(ip("80.150.73.4"))));
        assert_eq!(config["mtu"], Value::new(1500u32));
        assert_eq!(config["has-ip4"], Value::new(true));
    }

    #[test]
    fn build_ip4_config_uses_networkmanager_keys() {
        let config = build_ip4_config(&sample_config()).unwrap();

        assert_eq!(config["address"], Value::new(nm_ip4(ip("10.20.93.66"))));
        assert_eq!(config["prefix"], Value::new(32u32));
        assert_eq!(config["ptp"], Value::new(nm_ip4(ip("10.20.93.65"))));
        assert_eq!(
            config["internal-gateway"],
            Value::new(nm_ip4(ip("10.20.93.65")))
        );
        assert_eq!(
            config["routes"],
            Value::new(vec![vec![
                nm_ip4(ip("10.20.10.0")),
                24u32,
                nm_ip4(ip("10.20.93.65")),
                0u32
            ]])
        );
        assert_eq!(config["dns"], Value::new(vec![nm_ip4(ip("10.20.20.1"))]));
        assert_eq!(
            config["domains"],
            Value::new(vec!["example.com".to_string()])
        );
        assert_eq!(config["routes"].value_signature(), "aau");
    }

    #[test]
    fn build_ip4_config_without_address_is_none() {
        let mut vpn_config = sample_config();
        vpn_config.local_ip = None;

        assert!(build_ip4_config(&vpn_config).is_none());
        assert_eq!(build_config(&vpn_config)["has-ip4"], Value::new(false));
    }
}
