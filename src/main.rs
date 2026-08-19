// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

mod config;
mod dbus;
mod oauth;
mod openvpn;
mod secrets;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging - try journald first, fall back to stderr
    // Default to INFO level if RUST_LOG is not set
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry().with(filter);

    if let Ok(journald) = tracing_journald::layer() {
        subscriber.with(journald).init();
    } else {
        subscriber
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
    }

    info!("Starting nm-openvpn-sso-service");

    // Start the D-Bus service
    dbus::run_service().await?;

    Ok(())
}
