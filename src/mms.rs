//! MMS implementation.

use std::{fmt, path::PathBuf};

use async_trait::async_trait;
use cotp::COTP_MAX_TPDU_SIZE;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tracing_error::SpanTrace;

use crate::iec61850::report::Report;

pub mod acse;
pub mod ans1;
pub mod cotp;
pub mod presentation;
pub mod session;

pub mod client;

//TODO: Split this into multiple configs
/// The client configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientConfig {
	/// The address of the server.
	pub address: String,
	/// The port of the server.
	pub port: u16,
	/// The local transport selector.
	#[serde(default)]
	pub local_t_sel: Vec<u8>,
	/// The remote transport selector.
	#[serde(default)]
	pub remote_t_sel: Vec<u8>,
	/// The TPDU size.
	#[serde(default)]
	pub tpdu_size: u32,
	/// The local session selector.
	#[serde(default)]
	pub local_s_sel: Vec<u8>,
	/// The remote session selector.
	#[serde(default)]
	pub remote_s_sel: Vec<u8>,
	/// The local presentation selector.
	#[serde(default)]
	pub local_p_sel: Vec<u8>,
	/// The remote presentation selector.
	#[serde(default)]
	pub remote_p_sel: Vec<u8>,
	/// The local AP title.
	#[serde(default)]
	pub local_ap_title: Option<Vec<u32>>,
	/// The remote AP title.
	#[serde(default)]
	pub remote_ap_title: Option<Vec<u32>>,
	/// The local AE qualifier.
	#[serde(default)]
	pub local_ae_qualifier: Option<u32>,
	/// The remote AE qualifier.
	#[serde(default)]
	pub remote_ae_qualifier: Option<u32>,
	/// The maximum number of outstanding calling services.
	#[serde(default)]
	pub max_serv_outstanding_calling: i16,
	/// The maximum number of outstanding called services.
	#[serde(default)]
	pub max_serv_outstanding_called: i16,
	/// The data structure nesting level.
	#[serde(default)]
	pub data_structure_nesting_level: i8,
	/// The maximum PDU size.
	#[serde(default)]
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
			address: "localhost".to_owned(),
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

/// A wrapper for the span trace
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

#[allow(missing_docs)]
/// MMS errors
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

/// A trait for a read half connection.
#[async_trait]
trait ReadHalfConnection {
	/// The error type for the read half connection.
	type Error: std::error::Error + Send + Sync;
	async fn receive_data(&mut self) -> Result<Vec<u8>, Self::Error>;
}

/// A trait for a write half connection.
#[async_trait]
trait WriteHalfConnection {
	/// The error type for the write half connection.
	type Error: std::error::Error + Send + Sync;
	async fn send_data(&mut self, data: Vec<u8>) -> Result<(), Self::Error>;
}

#[allow(missing_docs)]
// This is defined on the mms.ans file but the compiler is not generating the
// enum automatically. So we define it manually here.
/// The MMS object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MmsObjectClass {
	NamedVariable = 0,
	ScatteredAccess = 1,
	NamedVariableList = 2,
	NamedType = 3,
	Semaphore = 4,
	EventCondition = 5,
	EventAction = 6,
	EventEnrollment = 7,
	Journal = 8,
	Domain = 9,
	ProgramInvocation = 10,
	OperatorStation = 11,
	DataExchange = 12,
	AccessControlList = 13,
}

impl TryFrom<u8> for MmsObjectClass {
	type Error = Error;
	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(MmsObjectClass::NamedVariable),
			1 => Ok(MmsObjectClass::ScatteredAccess),
			2 => Ok(MmsObjectClass::NamedVariableList),
			3 => Ok(MmsObjectClass::NamedType),
			4 => Ok(MmsObjectClass::Semaphore),
			5 => Ok(MmsObjectClass::EventCondition),
			6 => Ok(MmsObjectClass::EventAction),
			7 => Ok(MmsObjectClass::EventEnrollment),
			8 => Ok(MmsObjectClass::Journal),
			9 => Ok(MmsObjectClass::Domain),
			10 => Ok(MmsObjectClass::ProgramInvocation),
			11 => Ok(MmsObjectClass::OperatorStation),
			12 => Ok(MmsObjectClass::DataExchange),
			13 => Ok(MmsObjectClass::AccessControlList),
			_ => Err(Error::Whatever {
				message: "Invalid object class".to_owned(),
				source: None,
				context: Box::new(SpanTraceWrapper(SpanTrace::capture())),
			}),
		}
	}
}

/// A trait for reacting to a new report.
#[async_trait]
#[allow(missing_docs)]
pub trait ReportCallback {
	async fn on_report(&self, report: Report);
}
