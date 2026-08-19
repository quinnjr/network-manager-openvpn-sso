// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! Connection configuration parsing and management

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zbus::zvariant::OwnedValue;

/// VPN connection settings extracted from NetworkManager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Unique connection identifier (used for keyring storage)
    pub uuid: String,
    /// Human-readable connection name
    pub id: String,
    /// Path to the .ovpn configuration file (None for NM-imported connections)
    pub config_path: Option<PathBuf>,
    /// Optional server override
    pub remote: Option<String>,
    /// Optional port override
    pub port: Option<u16>,
    /// Optional protocol override (udp/tcp)
    pub protocol: Option<String>,
    /// Username for initial auth (placeholder for SSO)
    pub username: Option<String>,
    /// Password for initial auth (placeholder for SSO)
    pub password: Option<String>,
    /// Additional OpenVPN arguments. Not populated by `from_nm_settings` — no
    /// NetworkManager setting is mapped to this field today. It exists for
    /// programmatic use (e.g. callers constructing a `ConnectionConfig`
    /// directly) rather than end-user configuration via NM.
    pub extra_args: Vec<String>,
    /// CA certificate path (from vpn.data "ca")
    pub ca: Option<String>,
    /// Client certificate path (from vpn.data "cert")
    pub cert: Option<String>,
    /// Client key path (from vpn.data "key")
    pub key: Option<String>,
    /// TLS auth key path (from vpn.data "ta")
    pub ta: Option<String>,
    /// TLS auth key direction (from vpn.data "ta-dir")
    pub ta_dir: Option<String>,
    /// Cipher algorithm (from vpn.data "cipher")
    pub cipher: Option<String>,
    /// Auth/digest algorithm (from vpn.data "auth")
    pub auth: Option<String>,
    /// Tunnel device type (from vpn.data "dev")
    pub dev: Option<String>,
    /// Remote cert TLS check (from vpn.data "remote-cert-tls")
    pub remote_cert_tls: Option<String>,
    /// Connection type: tls, password, etc. (from vpn.data "connection-type")
    pub connection_type: Option<String>,
}

impl ConnectionConfig {
    /// Parse connection settings from NetworkManager D-Bus format
    /// The format is a{sa{sv}} - dict of setting-name -> dict of key -> variant
    pub fn from_nm_settings(
        settings: &HashMap<String, HashMap<String, OwnedValue>>,
    ) -> Result<Self> {
        // Extract connection section
        let connection = settings
            .get("connection")
            .ok_or_else(|| anyhow!("Missing 'connection' settings section"))?;

        let uuid = get_string(connection, "uuid")?;
        let id = get_string(connection, "id").unwrap_or_else(|_| "OpenVPN SSO".to_string());

        // Extract VPN section
        let vpn = settings
            .get("vpn")
            .ok_or_else(|| anyhow!("Missing 'vpn' settings section"))?;

        // Get VPN data (nested dict)
        let vpn_data = get_string_dict(vpn, "data").unwrap_or_default();

        let config_path = vpn_data.get("config").map(PathBuf::from);

        // Parse individual NM settings (used when config_path is None)
        let ca = vpn_data.get("ca").cloned();
        let cert = vpn_data.get("cert").cloned();
        let key = vpn_data.get("key").cloned();
        let ta = vpn_data.get("ta").cloned();
        let ta_dir = vpn_data.get("ta-dir").cloned();
        let cipher = vpn_data.get("cipher").cloned();
        let auth = vpn_data.get("auth").cloned();
        let dev = vpn_data.get("dev").cloned();
        let remote_cert_tls = vpn_data.get("remote-cert-tls").cloned();
        let connection_type = vpn_data.get("connection-type").cloned();

        // Validate: need either a config file or at least a CA cert
        if config_path.is_none() && ca.is_none() {
            return Err(anyhow!(
                "Missing OpenVPN config: need either vpn.data.config path or vpn.data.ca certificate"
            ));
        }

        let remote = vpn_data.get("remote").cloned();
        let port = vpn_data.get("port").and_then(|p| p.parse().ok());
        let protocol = vpn_data.get("proto").cloned();
        let username = vpn_data.get("username").cloned();

        // Get secrets section for password
        let vpn_secrets = get_string_dict(vpn, "secrets").unwrap_or_default();
        let password = vpn_secrets.get("password").cloned();

        Ok(Self {
            uuid,
            id,
            config_path,
            remote,
            port,
            protocol,
            username,
            password,
            extra_args: Vec::new(),
            ca,
            cert,
            key,
            ta,
            ta_dir,
            cipher,
            auth,
            dev,
            remote_cert_tls,
            connection_type,
        })
    }

    /// Build OpenVPN command line arguments
    pub fn build_openvpn_args(&self, management_socket: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(ref config_path) = self.config_path {
            // .ovpn file mode: use --config
            args.extend([
                "--config".to_string(),
                config_path.to_string_lossy().to_string(),
            ]);
        } else {
            // NM-imported mode: build from individual settings
            args.extend([
                "--client".to_string(),
                "--nobind".to_string(),
                "--dev".to_string(),
                self.dev.clone().unwrap_or_else(|| "tun".to_string()),
                "--persist-key".to_string(),
                "--persist-tun".to_string(),
                "--resolv-retry".to_string(),
                "infinite".to_string(),
            ]);

            if let Some(ref ca) = self.ca {
                args.extend(["--ca".to_string(), ca.clone()]);
            }
            if let Some(ref cert) = self.cert {
                args.extend(["--cert".to_string(), cert.clone()]);
            }
            if let Some(ref key) = self.key {
                args.extend(["--key".to_string(), key.clone()]);
            }
            if let Some(ref ta) = self.ta {
                args.push("--tls-auth".to_string());
                args.push(ta.clone());
                if let Some(ref dir) = self.ta_dir {
                    args.push(dir.clone());
                }
            }
            if let Some(ref cipher) = self.cipher {
                args.extend(["--cipher".to_string(), cipher.clone()]);
            }
            if let Some(ref auth) = self.auth {
                args.extend(["--auth".to_string(), auth.clone()]);
            }
            if let Some(ref remote_cert_tls) = self.remote_cert_tls {
                args.extend(["--remote-cert-tls".to_string(), remote_cert_tls.clone()]);
            }
        }

        // Common: management interface
        args.extend([
            "--management".to_string(),
            management_socket.to_string(),
            "unix".to_string(),
            "--management-query-passwords".to_string(),
            "--management-hold".to_string(),
            "--script-security".to_string(),
            "2".to_string(),
        ]);

        // Common: apply overrides
        if let Some(ref remote) = self.remote {
            // NM stores remote as "host:port" — split for OpenVPN's --remote host [port]
            if let Some((host, port)) = remote.rsplit_once(':') {
                args.extend(["--remote".to_string(), host.to_string(), port.to_string()]);
            } else {
                args.extend(["--remote".to_string(), remote.clone()]);
            }
        }

        if let Some(port) = self.port {
            args.extend(["--port".to_string(), port.to_string()]);
        }

        if let Some(ref proto) = self.protocol {
            args.extend(["--proto".to_string(), proto.clone()]);
        }

        args.extend(self.extra_args.clone());

        args
    }
}

fn get_string(dict: &HashMap<String, OwnedValue>, key: &str) -> Result<String> {
    dict.get(key)
        .ok_or_else(|| anyhow!("Missing key: {}", key))
        .and_then(|v| {
            // Try to extract string from the variant value
            // zvariant stores strings as Str or String types
            let s = v.to_string();
            // Remove quotes if present (zvariant's Display adds them)
            let trimmed = s.trim_matches('"');
            if !trimmed.is_empty() {
                Ok(trimmed.to_string())
            } else {
                Err(anyhow!("Key {} is not a string or is empty", key))
            }
        })
}

fn get_string_dict(
    dict: &HashMap<String, OwnedValue>,
    key: &str,
) -> Option<HashMap<String, String>> {
    use tracing::info;
    use zbus::zvariant::Value;

    dict.get(key).and_then(|v| {
        let mut result = HashMap::new();

        // Log the raw value for debugging
        info!(
            "Parsing vpn.data key '{}', raw value type: {:?}",
            key,
            v.value_signature()
        );

        // Try to access as Dict<String, String> using Value
        let value: Value = v.clone().into();
        info!("Converted to Value variant: {:?}", value);

        // Try as Dict
        if let Value::Dict(dict_val) = &value {
            for (k, v_inner) in dict_val.iter() {
                // k and v_inner are &Value
                if let (Value::Str(key_str), Value::Str(val_str)) = (k, v_inner) {
                    result.insert(key_str.to_string(), val_str.to_string());
                }
            }
        }

        // Fallback: try parsing from string representation
        if result.is_empty() {
            let s = v.to_string();
            info!("Trying string parse from: {}", s);

            // Format from NetworkManager is often "key = value, key2 = value2"
            // when converted to string
            for pair in s.split(", ") {
                if let Some((k, val)) = pair.split_once(" = ") {
                    let k = k.trim().trim_matches('"');
                    let val = val.trim().trim_matches('"');
                    if !k.is_empty() && !val.is_empty() {
                        result.insert(k.to_string(), val.to_string());
                    }
                }
            }
        }

        info!("Parsed vpn.data result: {:?}", result);

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `connection` settings section with the given uuid/id.
    fn connection_section(uuid: &str, id: &str) -> HashMap<String, OwnedValue> {
        use zbus::zvariant::Str;

        let mut connection = HashMap::new();
        connection.insert(
            "uuid".to_string(),
            OwnedValue::from(Str::from(uuid.to_string())),
        );
        connection.insert(
            "id".to_string(),
            OwnedValue::from(Str::from(id.to_string())),
        );
        connection
    }

    /// Build a `vpn` settings section whose `data` key is a string->string
    /// dict built from `data`, matching the shape NetworkManager sends over
    /// D-Bus (a{sv} with a nested a{ss} for "data").
    fn vpn_section(data: &[(&str, &str)]) -> HashMap<String, OwnedValue> {
        let data_map: HashMap<String, String> = data
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut vpn = HashMap::new();
        vpn.insert("data".to_string(), OwnedValue::from(data_map));
        vpn
    }

    fn settings_with(
        connection: HashMap<String, OwnedValue>,
        vpn: HashMap<String, OwnedValue>,
    ) -> HashMap<String, HashMap<String, OwnedValue>> {
        let mut settings = HashMap::new();
        settings.insert("connection".to_string(), connection);
        settings.insert("vpn".to_string(), vpn);
        settings
    }

    #[test]
    fn from_nm_settings_config_file_mode_with_required_keys() {
        let connection = connection_section(
            "11111111-1111-1111-1111-111111111111",
            "Test Connection",
        );
        let vpn = vpn_section(&[
            ("config", "/etc/openvpn/client/test.ovpn"),
            ("remote", "vpn.example.com:1194"),
            ("proto", "udp"),
        ]);
        let settings = settings_with(connection, vpn);

        let config = ConnectionConfig::from_nm_settings(&settings)
            .expect("config-file based settings should parse");

        assert_eq!(config.uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(config.id, "Test Connection");
        assert_eq!(
            config.config_path,
            Some(PathBuf::from("/etc/openvpn/client/test.ovpn"))
        );
        assert_eq!(config.remote, Some("vpn.example.com:1194".to_string()));
        assert_eq!(config.protocol, Some("udp".to_string()));
        assert!(config.extra_args.is_empty());
        assert!(config.ca.is_none());
    }

    #[test]
    fn from_nm_settings_missing_required_keys_errors() {
        // No "config" and no "ca" in vpn.data — from_nm_settings should
        // reject this as there's no way to build an OpenVPN invocation.
        let connection = connection_section(
            "22222222-2222-2222-2222-222222222222",
            "Broken Connection",
        );
        let vpn = vpn_section(&[("remote", "vpn.example.com:1194")]);
        let settings = settings_with(connection, vpn);

        let result = ConnectionConfig::from_nm_settings(&settings);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Missing OpenVPN config"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn from_nm_settings_missing_connection_section_errors() {
        let vpn = vpn_section(&[("config", "/etc/openvpn/client/test.ovpn")]);
        let mut settings = HashMap::new();
        settings.insert("vpn".to_string(), vpn);

        let result = ConnectionConfig::from_nm_settings(&settings);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Missing 'connection' settings section"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn from_nm_settings_nm_imported_mode_with_ca() {
        // No "config" key, but a "ca" key satisfies the required-keys check
        // and puts the config in NM-imported (individual settings) mode.
        let connection = connection_section(
            "33333333-3333-3333-3333-333333333333",
            "Imported Connection",
        );
        let vpn = vpn_section(&[
            ("ca", "/etc/openvpn/client/ca.crt"),
            ("cert", "/etc/openvpn/client/client.crt"),
            ("key", "/etc/openvpn/client/client.key"),
            ("dev", "tun"),
        ]);
        let settings = settings_with(connection, vpn);

        let config = ConnectionConfig::from_nm_settings(&settings)
            .expect("NM-imported settings with ca should parse");

        assert!(config.config_path.is_none());
        assert_eq!(config.ca, Some("/etc/openvpn/client/ca.crt".to_string()));
        assert_eq!(
            config.cert,
            Some("/etc/openvpn/client/client.crt".to_string())
        );
        assert_eq!(config.dev, Some("tun".to_string()));
    }

    #[test]
    fn build_openvpn_args_config_file_mode() {
        let config = ConnectionConfig {
            uuid: "uuid".to_string(),
            id: "id".to_string(),
            config_path: Some(PathBuf::from("/etc/openvpn/client/test.ovpn")),
            remote: None,
            port: None,
            protocol: None,
            username: None,
            password: None,
            extra_args: Vec::new(),
            ca: None,
            cert: None,
            key: None,
            ta: None,
            ta_dir: None,
            cipher: None,
            auth: None,
            dev: None,
            remote_cert_tls: None,
            connection_type: None,
        };

        let args = config.build_openvpn_args("/run/user/1000/openvpn-sso.sock");

        assert_eq!(args[0], "--config");
        assert_eq!(args[1], "/etc/openvpn/client/test.ovpn");
        assert!(!args.iter().any(|a| a == "--client"));

        let mgmt_idx = args
            .iter()
            .position(|a| a == "--management")
            .expect("--management flag should be present");
        assert_eq!(args[mgmt_idx + 1], "/run/user/1000/openvpn-sso.sock");
        assert_eq!(args[mgmt_idx + 2], "unix");
        assert!(args.iter().any(|a| a == "--management-query-passwords"));
        assert!(args.iter().any(|a| a == "--management-hold"));
        assert!(args.iter().any(|a| a == "--script-security"));
    }

    #[test]
    fn build_openvpn_args_nm_imported_mode() {
        let config = ConnectionConfig {
            uuid: "uuid".to_string(),
            id: "id".to_string(),
            config_path: None,
            remote: Some("vpn.example.com:1194".to_string()),
            port: None,
            protocol: Some("udp".to_string()),
            username: None,
            password: None,
            extra_args: vec!["--verb".to_string(), "3".to_string()],
            ca: Some("/etc/openvpn/client/ca.crt".to_string()),
            cert: Some("/etc/openvpn/client/client.crt".to_string()),
            key: Some("/etc/openvpn/client/client.key".to_string()),
            ta: Some("/etc/openvpn/client/ta.key".to_string()),
            ta_dir: Some("1".to_string()),
            cipher: Some("AES-256-GCM".to_string()),
            auth: Some("SHA256".to_string()),
            dev: Some("tun".to_string()),
            remote_cert_tls: Some("server".to_string()),
            connection_type: Some("tls".to_string()),
        };

        let args = config.build_openvpn_args("/run/user/1000/openvpn-sso.sock");

        assert!(args.iter().any(|a| a == "--client"));
        assert!(!args.iter().any(|a| a == "--config"));

        assert!(args
            .windows(2)
            .any(|w| w[0] == "--ca" && w[1] == "/etc/openvpn/client/ca.crt"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--cert" && w[1] == "/etc/openvpn/client/client.crt"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--key" && w[1] == "/etc/openvpn/client/client.key"));
        assert!(args.windows(3).any(|w| w[0] == "--tls-auth"
            && w[1] == "/etc/openvpn/client/ta.key"
            && w[2] == "1"));

        let mgmt_idx = args
            .iter()
            .position(|a| a == "--management")
            .expect("--management flag should be present");
        assert_eq!(args[mgmt_idx + 1], "/run/user/1000/openvpn-sso.sock");
        assert_eq!(args[mgmt_idx + 2], "unix");
        assert!(args.iter().any(|a| a == "--management-query-passwords"));
        assert!(args.iter().any(|a| a == "--management-hold"));

        // "host:port" remote is split into --remote host port
        assert!(args
            .windows(3)
            .any(|w| w[0] == "--remote" && w[1] == "vpn.example.com" && w[2] == "1194"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--proto" && w[1] == "udp"));

        // extra_args are appended at the end
        assert_eq!(args[args.len() - 2], "--verb");
        assert_eq!(args[args.len() - 1], "3");
    }
}
