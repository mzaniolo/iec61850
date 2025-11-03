use std::{fmt, path::PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use tracing_error::SpanTrace;

use cotp::COTP_MAX_TPDU_SIZE;

pub mod acse;
pub mod ans1;
pub mod cotp;
pub mod presentation;
pub mod session;

pub mod client;

//TODO: Split this into multiple configs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientConfig {
    /// The address of the server.
    pub address: String,
    /// The port of the server.
    pub port: u16,
    pub local_t_sel: Vec<u8>,
    pub remote_t_sel: Vec<u8>,
    pub tpdu_size: u32,
    pub local_s_sel: Vec<u8>,
    pub remote_s_sel: Vec<u8>,
    pub local_p_sel: Vec<u8>,
    pub remote_p_sel: Vec<u8>,
    pub local_ap_title: Option<Vec<u32>>,
    pub remote_ap_title: Option<Vec<u32>>,
    pub local_ae_qualifier: Option<u32>,
    pub remote_ae_qualifier: Option<u32>,
    pub max_serv_outstanding_calling: i16,
    pub max_serv_outstanding_called: i16,
    pub data_structure_nesting_level: i8,
    pub max_pdu_size: i32,
    /// The TLS configuration.
    #[serde(default)]
    pub tls: Option<TlsClientConfig>,
}

/// The client TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TlsClientConfig {
    /// Path to the client key; if not specified, it will be assumed
    /// that the server is configured not to verify client
    /// certificates.
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    /// Path to the client certificate; if not specified, it will be
    /// assumed that the server is configured not to verify client
    /// certificates.
    #[serde(default)]
    pub client_certificate: Option<PathBuf>,
    /// Path to the server certificate; if not specified, the host's
    /// CA will be used to verify the server.
    #[serde(default)]
    pub server_certificate: Option<PathBuf>,
    /// Whether to verify the server's certificates.
    ///
    /// This should normally only be used in test environments, as
    /// disabling certificate validation defies the purpose of using
    /// TLS in the first place.
    #[serde(default)]
    pub danger_disable_tls_verify: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            address: "localhost".to_string(),
            port: 102,
            tpdu_size: COTP_MAX_TPDU_SIZE,
            local_t_sel: vec![0x00, 0x01],
            remote_t_sel: vec![0x00, 0x01],
            local_s_sel: vec![0x00, 0x01],
            remote_s_sel: vec![0x00, 0x01],
            local_p_sel: vec![0x00, 0x00, 0x00, 0x01],
            remote_p_sel: vec![0x00, 0x00, 0x00, 0x01],
            local_ap_title: Some(vec![1, 1, 1, 999]),
            remote_ap_title: Some(vec![1, 1, 1, 999, 1]),
            local_ae_qualifier: Some(12),
            remote_ae_qualifier: Some(12),
            max_serv_outstanding_calling: 10,
            max_serv_outstanding_called: 10,
            data_structure_nesting_level: 10,
            max_pdu_size: 8192,
            tls: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpanTraceWrapper(SpanTrace);

impl snafu::GenerateImplicitData for Box<SpanTraceWrapper> {
    fn generate() -> Self {
        Box::new(SpanTraceWrapper(SpanTrace::capture()))
    }
}

impl fmt::Display for SpanTraceWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.status() == tracing_error::SpanTraceStatus::CAPTURED {
            write!(f, "\nAt:\n")?;
            self.0.fmt(f)?;
        }
        Ok(())
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum Error {
    #[snafu(whatever, display("{message}{context}\n{source:?}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
}

#[async_trait]
trait ReadHalfConnection {
    type Error: std::error::Error + Send + Sync;
    async fn receive_data(&mut self) -> std::result::Result<Vec<u8>, Self::Error>;
}

#[async_trait]
trait WriteHalfConnection {
    type Error: std::error::Error + Send + Sync;
    async fn send_data(&mut self, data: Vec<u8>) -> std::result::Result<(), Self::Error>;
}
