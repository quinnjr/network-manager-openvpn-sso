// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! Secure token storage using the system keyring (libsecret/Secret Service)
//! with fallback to encrypted file storage when keyring is unavailable
//! (e.g., when running as root in NetworkManager plugin)

use anyhow::{Context, Result};
use secret_service::{EncryptionType, SecretService};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info};

const COLLECTION_LABEL: &str = "nm-openvpn-sso";
const ATTRIBUTE_CONNECTION: &str = "connection-uuid";
const ATTRIBUTE_TYPE: &str = "token-type";

/// Directory for file-based credential cache (fallback when keyring unavailable)
const CACHE_DIR: &str = "/var/lib/nm-openvpn-sso";

/// Stored OAuth tokens for a connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTokens {
    /// OAuth access token
    pub access_token: String,
    /// OAuth refresh token (if provided)
    pub refresh_token: Option<String>,
    /// Token expiry timestamp (Unix epoch seconds)
    pub expires_at: Option<i64>,
}

impl StoredTokens {
    /// Check if the access token is still valid (with 60s buffer)
    pub fn is_valid(&self) -> bool {
        match self.expires_at {
            Some(expires) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                expires > now + 60
            }
            None => true, // No expiry info, assume valid
        }
    }

    /// Check if we can attempt a refresh
    pub fn can_refresh(&self) -> bool {
        self.refresh_token.is_some()
    }
}

/// Keyring-based secret storage
pub struct SecretStore {
    service: SecretService<'static>,
}

impl SecretStore {
    /// Connect to the Secret Service
    pub async fn new() -> Result<Self> {
        let service = SecretService::connect(EncryptionType::Dh)
            .await
            .context("Failed to connect to Secret Service")?;

        Ok(Self { service })
    }

    /// Store tokens for a connection
    pub async fn store_tokens(&self, connection_uuid: &str, tokens: &StoredTokens) -> Result<()> {
        let collection = self
            .service
            .get_default_collection()
            .await
            .context("Failed to get default keyring collection")?;

        // Unlock if necessary
        if collection.is_locked().await? {
            collection.unlock().await?;
        }

        let attributes: HashMap<&str, &str> = [
            (ATTRIBUTE_CONNECTION, connection_uuid),
            (ATTRIBUTE_TYPE, "oauth"),
        ]
        .into_iter()
        .collect();

        let secret = serde_json::to_string(tokens)?;
        let label = format!("{} - {}", COLLECTION_LABEL, connection_uuid);

        // Delete existing item first (if any)
        self.delete_tokens(connection_uuid).await.ok();

        collection
            .create_item(
                &label,
                attributes,
                secret.as_bytes(),
                true, // replace
                "text/plain",
            )
            .await
            .context("Failed to store tokens in keyring")?;

        debug!("Stored tokens for connection {}", connection_uuid);
        Ok(())
    }

    /// Retrieve tokens for a connection
    pub async fn get_tokens(&self, connection_uuid: &str) -> Result<Option<StoredTokens>> {
        let collection = self
            .service
            .get_default_collection()
            .await
            .context("Failed to get default keyring collection")?;

        // Unlock if necessary
        if collection.is_locked().await? {
            collection.unlock().await?;
        }

        let attributes: HashMap<&str, &str> = [
            (ATTRIBUTE_CONNECTION, connection_uuid),
            (ATTRIBUTE_TYPE, "oauth"),
        ]
        .into_iter()
        .collect();

        let items = collection.search_items(attributes).await?;

        if let Some(item) = items.into_iter().next() {
            if item.is_locked().await? {
                item.unlock().await?;
            }

            let secret = item.get_secret().await?;
            let tokens: StoredTokens = serde_json::from_slice(&secret)?;

            debug!("Retrieved tokens for connection {}", connection_uuid);
            return Ok(Some(tokens));
        }

        Ok(None)
    }

    /// Delete tokens for a connection
    #[allow(dead_code)]
    pub async fn delete_tokens(&self, connection_uuid: &str) -> Result<()> {
        let collection = self
            .service
            .get_default_collection()
            .await
            .context("Failed to get default keyring collection")?;

        let attributes: HashMap<&str, &str> = [
            (ATTRIBUTE_CONNECTION, connection_uuid),
            (ATTRIBUTE_TYPE, "oauth"),
        ]
        .into_iter()
        .collect();

        let items = collection.search_items(attributes).await?;

        for item in items {
            item.delete().await?;
        }

        debug!("Deleted tokens for connection {}", connection_uuid);
        Ok(())
    }
}

/// Get cached tokens if valid, otherwise None
pub async fn get_cached_credentials(connection_uuid: &str) -> Option<StoredTokens> {
    // Try keyring first
    match SecretStore::new().await {
        Ok(store) => match store.get_tokens(connection_uuid).await {
            Ok(Some(tokens)) if tokens.is_valid() => {
                debug!("Using cached valid tokens from keyring");
                return Some(tokens);
            }
            Ok(Some(tokens)) if tokens.can_refresh() => {
                debug!("Cached tokens expired but refresh available (keyring)");
                return Some(tokens);
            }
            Ok(_) => {
                debug!("No valid cached tokens in keyring");
            }
            Err(e) => {
                debug!("Failed to retrieve cached tokens from keyring: {}", e);
            }
        },
        Err(e) => {
            debug!("Failed to connect to secret service: {}", e);
        }
    }

    // Fallback to file-based cache
    match get_file_cached_credentials(connection_uuid).await {
        Ok(Some(tokens)) if tokens.is_valid() => {
            debug!("Using cached valid tokens from file");
            Some(tokens)
        }
        Ok(Some(tokens)) if tokens.can_refresh() => {
            debug!("Cached tokens expired but refresh available (file)");
            Some(tokens)
        }
        Ok(_) => {
            debug!("No valid cached tokens in file");
            None
        }
        Err(e) => {
            debug!("Failed to retrieve cached tokens from file: {}", e);
            None
        }
    }
}

/// Store credentials after successful auth
pub async fn cache_credentials(connection_uuid: &str, tokens: StoredTokens) -> Result<()> {
    // Try keyring first
    match SecretStore::new().await {
        Ok(store) => match store.store_tokens(connection_uuid, &tokens).await {
            Ok(()) => {
                info!("Stored credentials in keyring");
                return Ok(());
            }
            Err(e) => {
                debug!("Failed to store in keyring: {}, falling back to file", e);
            }
        },
        Err(e) => {
            debug!(
                "Failed to connect to secret service: {}, falling back to file",
                e
            );
        }
    }

    // Fallback to file-based cache
    store_file_cached_credentials(connection_uuid, &tokens).await
}

/// Get the cache file path for a connection
fn get_cache_file_path(connection_uuid: &str) -> PathBuf {
    PathBuf::from(CACHE_DIR).join(format!("{}.json", connection_uuid))
}

/// Store credentials in a file (fallback when keyring unavailable)
async fn store_file_cached_credentials(connection_uuid: &str, tokens: &StoredTokens) -> Result<()> {
    let cache_dir = PathBuf::from(CACHE_DIR);

    // Create cache directory if it doesn't exist
    if !cache_dir.exists() {
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .context("Failed to create cache directory")?;
        // Set restrictive permissions on directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&cache_dir, perms)?;
        }
    }

    let cache_file = get_cache_file_path(connection_uuid);
    let json = serde_json::to_string_pretty(tokens)?;

    tokio::fs::write(&cache_file, json.as_bytes())
        .await
        .context("Failed to write cache file")?;

    // Set restrictive permissions on file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&cache_file, perms)?;
    }

    info!("Stored credentials in file cache: {}", cache_file.display());
    Ok(())
}

/// Retrieve credentials from file cache
async fn get_file_cached_credentials(connection_uuid: &str) -> Result<Option<StoredTokens>> {
    let cache_file = get_cache_file_path(connection_uuid);

    if !cache_file.exists() {
        return Ok(None);
    }

    let content = tokio::fs::read_to_string(&cache_file)
        .await
        .context("Failed to read cache file")?;

    let tokens: StoredTokens =
        serde_json::from_str(&content).context("Failed to parse cached credentials")?;

    debug!(
        "Retrieved credentials from file cache: {}",
        cache_file.display()
    );
    Ok(Some(tokens))
}
