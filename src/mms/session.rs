//! ISO Session Layer Implementation (ISO 8327)

use async_trait::async_trait;
use snafu::{OptionExt as _, Snafu};
use tracing::instrument;

use crate::mms::{
	ClientConfig, ReadHalfConnection, SpanTraceWrapper, WriteHalfConnection,
	cotp::{CotpConnection, CotpError, CotpReadHalf, CotpWriteHalf},
};

/// Maximum size for session selectors (S-SEL)
const MAX_SESSION_SELECTOR_SIZE: usize = 16;
/// Marker byte that introduces the extended length form per ISO 8327.
const EXTENDED_LENGTH_MARKER: u8 = 0xFF;
/// Inclusive upper bound for an LI/PI/PGI length encoded in the short form.
const SHORT_LENGTH_MAX: usize = 254;

/// Read an ISO 8327 length indicator (LI / PGI length / PI length).
///
/// Short form is a single byte in `0..=254`. The marker `0xFF` introduces
/// the extended form, which is followed by a big-endian `u16` length.
/// Returns `(length, bytes_consumed)`.
fn read_li(bytes: &[u8], offset: usize) -> Result<(usize, usize), SessionError> {
	let first = *bytes.get(offset).context(NotEnoughBytes)?;
	if first == EXTENDED_LENGTH_MARKER {
		let hi = *bytes.get(offset + 1).context(NotEnoughBytes)?;
		let lo = *bytes.get(offset + 2).context(NotEnoughBytes)?;
		Ok((u16::from_be_bytes([hi, lo]) as usize, 3))
	} else {
		Ok((first as usize, 1))
	}
}

/// Append an ISO 8327 length indicator to `buf`, using the extended form
/// when `length > 254`.
fn push_li(buf: &mut Vec<u8>, length: usize) {
	if length <= SHORT_LENGTH_MAX {
		buf.push(length as u8);
	} else {
		// ISO 8327 caps the extended length at u16::MAX. Anything beyond
		// that cannot be represented; the COTP layer rejects oversized
		// frames upstream so this branch is unreachable in practice.
		let length = u16::try_from(length).unwrap_or(u16::MAX);
		buf.push(EXTENDED_LENGTH_MARKER);
		buf.extend_from_slice(&length.to_be_bytes());
	}
}

/// The ISO Session layer connection.
#[derive(Debug)]
pub struct Session {
	/// The COTP connection.
	cotp_connection: CotpConnection,
	/// The local session selector.
	local_s_sel: SSelector,
	/// The remote session selector.
	remote_s_sel: SSelector,
}

impl Session {
	/// Create a new ISO Session layer connection.
	pub async fn new(config: &ClientConfig) -> Result<Self, SessionError> {
		let cotp_connection = CotpConnection::connect(config).await?;
		Ok(Self {
			cotp_connection,
			local_s_sel: SSelector::from_bytes(&config.connection.local_s_sel)?,
			remote_s_sel: SSelector::from_bytes(&config.connection.remote_s_sel)?,
		})
	}
	/// Connect to the remote session.
	#[instrument(skip(self))]
	pub async fn connect(&mut self, data: &[u8]) -> Result<Vec<u8>, SessionError> {
		let spdu = ConnectSpdu::new(
			self.local_s_sel.clone(),
			self.remote_s_sel.clone(),
			SessionRequirement::Duplex,
			data.to_vec(),
		);
		let spdu_bytes = spdu.to_bytes();
		self.cotp_connection.send_data(spdu_bytes).await?;
		let response = self.cotp_connection.receive_data().await?;
		let response_spdu = Spdu::from_bytes(&response)?;
		match response_spdu {
			Spdu::Accept(accept_spdu) => Ok(accept_spdu.data),
			// Surface the peer's rejection reason instead of a generic
			// "invalid response" so callers can distinguish a refused
			// association from a protocol error.
			Spdu::Refuse(refuse) => ConnectionRefused { reason_code: refuse.reason_code }.fail(),
			Spdu::Abort(_) => ConnectionAborted.fail(),
			Spdu::Disconnect(_) | Spdu::Finish(_) => ConnectionRefused { reason_code: 0 }.fail(),
			_ => InvalidCotpResponse.fail(),
		}
	}
	/// Split the connection into a read half and a write half.
	#[must_use]
	pub fn split(self) -> (SessionReadHalf, SessionWriteHalf) {
		let (cotp_read, cotp_write) = self.cotp_connection.split();
		(SessionReadHalf { cotp_read }, SessionWriteHalf { cotp_write })
	}
}

#[async_trait]
impl WriteHalfConnection for Session {
	type Error = SessionError;

	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
		SessionWriteHalf::send_data_internal(&mut self.cotp_connection, data).await
	}
}
#[async_trait]
impl ReadHalfConnection for Session {
	type Error = SessionError;

	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> Result<Vec<u8>, SessionError> {
		SessionReadHalf::receive_data_internal(&mut self.cotp_connection).await
	}
}

/// The write half of the ISO Session layer connection.
#[derive(Debug)]
pub struct SessionWriteHalf {
	/// The write half of the COTP connection.
	cotp_write: CotpWriteHalf,
}

impl SessionWriteHalf {
	/// Send data to the remote session.
	#[instrument(skip_all)]
	async fn send_data_internal<W: WriteHalfConnection<Error = CotpError>>(
		cotp_write: &mut W,
		data: Vec<u8>,
	) -> Result<(), SessionError> {
		let spdu = DataSpdu::new(data.clone());
		let spdu_bytes = spdu.to_bytes();
		cotp_write.send_data(spdu_bytes).await?;
		Ok(())
	}
}

#[async_trait]
impl WriteHalfConnection for SessionWriteHalf {
	type Error = SessionError;

	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> Result<(), SessionError> {
		SessionWriteHalf::send_data_internal(&mut self.cotp_write, data).await
	}
}

/// The read half of the ISO Session layer connection.
#[derive(Debug)]
pub struct SessionReadHalf {
	/// The read half of the COTP connection.
	cotp_read: CotpReadHalf,
}

impl SessionReadHalf {
	/// Receive data from the remote session.
	#[instrument(skip_all)]
	async fn receive_data_internal<R: ReadHalfConnection<Error = CotpError>>(
		cotp_read: &mut R,
	) -> Result<Vec<u8>, SessionError> {
		let response = cotp_read.receive_data().await?;
		let response_spdu = Spdu::from_bytes(&response)?;
		if let Spdu::Data(data_spdu) = response_spdu {
			Ok(data_spdu.data)
		} else {
			InvalidCotpResponse.fail()
		}
	}
}

#[async_trait]
impl ReadHalfConnection for SessionReadHalf {
	type Error = SessionError;

	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> Result<Vec<u8>, SessionError> {
		Self::receive_data_internal(&mut self.cotp_read).await
	}
}

/// Session requirement bit flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SessionRequirement {
	/// Half-duplex functional unit
	HalfDuplex = 0x0001,
	/// Duplex functional unit (default)
	Duplex = 0x0002,
	/// Expedited data functional unit
	ExpeditedData = 0x0004,
	/// Minor synchronization functional unit
	MinorSync = 0x0008,
	/// Major synchronization functional unit
	MajorSync = 0x0010,
	/// Resynchronize functional unit
	Resync = 0x0020,
	/// Activity management functional unit
	ActivityMgmt = 0x0080,
	/// Negotiated release functional unit
	NegotiatedRelease = 0x0100,
}

impl TryFrom<u16> for SessionRequirement {
	type Error = SessionError;

	fn try_from(value: u16) -> Result<Self, Self::Error> {
		Ok(match value {
			0x0001 => Self::HalfDuplex,
			0x0002 => Self::Duplex,
			0x0004 => Self::ExpeditedData,
			0x0008 => Self::MinorSync,
			0x0010 => Self::MajorSync,
			0x0020 => Self::Resync,
			0x0080 => Self::ActivityMgmt,
			0x0100 => Self::NegotiatedRelease,
			_ => return InvalidSessionRequirement { value }.fail(),
		})
	}
}

/// Session selector (S-SEL) - addressing mechanism at the session layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSelector {
	/// The value of the session selector.
	pub value: Vec<u8>,
}

impl SSelector {
	/// Parse a session selector from bytes.
	fn from_bytes(bytes: &[u8]) -> Result<Self, SessionError> {
		if bytes.len() > MAX_SESSION_SELECTOR_SIZE {
			return InvalidSelectorSize.fail();
		}

		Ok(Self { value: bytes.to_vec() })
	}

	/// Convert a session selector to bytes.
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		let mut buffer = Vec::new();
		buffer.push(self.value.len() as u8);
		buffer.extend_from_slice(&self.value);
		buffer
	}
}

/// SPDU Type identifier
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpduType {
	/// GIVE TOKEN / DATA SPDU
	GiveTokenData = 0x01,
	/// NOT-FINISHED SPDU
	NotFinished = 0x08,
	/// FINISH SPDU
	Finish = 0x09,
	/// DISCONNECT SPDU
	Disconnect = 0x0A,
	/// REFUSE SPDU
	Refuse = 0x0C,
	/// CONNECT SPDU
	Connect = 0x0D,
	/// ACCEPT SPDU
	Accept = 0x0E,
	/// ABORT SPDU
	Abort = 0x19,
	/// Invalid/Unknown SPDU type
	Invalid = 0xFF,
}

impl From<u8> for SpduType {
	fn from(value: u8) -> Self {
		match value {
			0x01 => Self::GiveTokenData,
			0x08 => Self::NotFinished,
			0x09 => Self::Finish,
			0x0A => Self::Disconnect,
			0x0C => Self::Refuse,
			0x0D => Self::Connect,
			0x0E => Self::Accept,
			0x19 => Self::Abort,
			_ => Self::Invalid,
		}
	}
}

/// Parameter Group Identifier (PGI)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pgi {
	ConnectionIdentifier = 0x01,
	ConnectAcceptItem = 0x05,
	TransportDisconnect = 0x11,
	SessionUserRequirements = 0x14,
	EnclosureItem = 0x19,
	Unknown49 = 0x31,
	CallingSessionSelector = 0x33,
	CalledSessionSelector = 0x34,
	DataOverflow = 0x3C,
	UserData = 0xC1,
	ExtendedUserData = 0xC2,
	Invalid = 0xFF,
}

impl From<u8> for Pgi {
	fn from(value: u8) -> Self {
		match value {
			0x01 => Self::ConnectionIdentifier,
			0x05 => Self::ConnectAcceptItem,
			0x11 => Self::TransportDisconnect,
			0x14 => Self::SessionUserRequirements,
			0x19 => Self::EnclosureItem,
			0x31 => Self::Unknown49,
			0x33 => Self::CallingSessionSelector,
			0x34 => Self::CalledSessionSelector,
			0x3C => Self::DataOverflow,
			0xC1 => Self::UserData,
			0xC2 => Self::ExtendedUserData,
			_ => Self::Invalid,
		}
	}
}

/// Parameter Identifier (PI)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pi {
	ProtocolOptions = 0x13,
	TsduMaximumSize = 0x15,
	VersionNumber = 0x16,
	InitialSerialNumber = 0x17,
	TokenSettingItem = 0x1A,
	ReasonCode = 0x32,
	SecondInitialSerialNumber = 0x37,
	UpperLimitSerialNumber = 0x38,
	LargeInitialSerialNumber = 0x39,
	LargeSecondInitialSerialNumber = 0x3A,
	Invalid = 0xFF,
}

impl From<u8> for Pi {
	fn from(value: u8) -> Self {
		match value {
			0x13 => Self::ProtocolOptions,
			0x15 => Self::TsduMaximumSize,
			0x16 => Self::VersionNumber,
			0x17 => Self::InitialSerialNumber,
			0x1A => Self::TokenSettingItem,
			0x32 => Self::ReasonCode,
			0x37 => Self::SecondInitialSerialNumber,
			0x38 => Self::UpperLimitSerialNumber,
			0x39 => Self::LargeInitialSerialNumber,
			0x3A => Self::LargeSecondInitialSerialNumber,
			_ => Self::Invalid,
		}
	}
}

/// Session Protocol Data Unit (SPDU)
#[derive(Debug, Clone)]
pub enum Spdu {
	/// Connect SPDU
	Connect(ConnectSpdu),
	/// Accept SPDU
	Accept(AcceptSpdu),
	/// Data SPDU
	Data(DataSpdu),
	/// Finish SPDU
	Finish(FinishSpdu),
	/// Disconnect SPDU
	Disconnect(DisconnectSpdu),
	/// Abort SPDU
	Abort(AbortSpdu),
	/// Refuse SPDU
	Refuse(RefuseSpdu),
	/// Not Finished SPDU
	NotFinished,
}

impl Spdu {
	/// Parse SPDU from bytes
	#[instrument(skip_all)]
	fn from_bytes(bytes: &[u8]) -> Result<Self, SessionError> {
		let si = *bytes.first().context(NotEnoughBytes)?;
		let (length, li_consumed) = read_li(bytes, 1)?;
		let header_size = 1 + li_consumed;
		let body = bytes.get(header_size..).context(NotEnoughBytes)?;

		match si.into() {
			SpduType::Connect => {
				if body.len() != length {
					return InvalidLength.fail();
				}
				ConnectSpdu::from_body(body).map(Self::Connect)
			}
			SpduType::Accept => {
				if body.len() != length {
					return InvalidLength.fail();
				}
				AcceptSpdu::from_body(body).map(Self::Accept)
			}
			SpduType::GiveTokenData => DataSpdu::from_bytes(bytes).map(Self::Data),
			SpduType::Finish => {
				if body.len() != length {
					return InvalidLength.fail();
				}
				FinishSpdu::from_body(body).map(Self::Finish)
			}
			SpduType::Disconnect => {
				if body.len() != length {
					return InvalidLength.fail();
				}
				DisconnectSpdu::from_body(body).map(Self::Disconnect)
			}
			SpduType::Abort => Ok(Self::Abort(AbortSpdu::from_body(body)?)),
			SpduType::Refuse => Ok(Self::Refuse(RefuseSpdu::from_body(body)?)),
			SpduType::NotFinished => Ok(Self::NotFinished),
			SpduType::Invalid => InvalidSpduType { value: si }.fail(),
		}
	}

	#[allow(dead_code)]
	/// Encode SPDU to bytes
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		match self {
			Self::Connect(spdu) => spdu.to_bytes(),
			Self::Accept(spdu) => spdu.to_bytes(),
			Self::Data(spdu) => spdu.to_bytes(),
			Self::Finish(spdu) => spdu.to_bytes(),
			Self::Disconnect(spdu) => spdu.to_bytes(),
			Self::Abort(spdu) => spdu.to_bytes(),
			Self::Refuse(spdu) => spdu.to_bytes(),
			Self::NotFinished => vec![SpduType::NotFinished as u8, 0x00],
		}
	}
}

/// CONNECT SPDU
#[derive(Debug, Clone)]
pub struct ConnectSpdu {
	/// The calling session selector.
	pub calling_session_selector: Option<SSelector>,
	/// The called session selector.
	pub called_session_selector: Option<SSelector>,
	/// The session requirement.
	pub session_requirement: SessionRequirement,
	/// The protocol options.
	pub protocol_options: u8,
	/// The user data.
	pub data: Vec<u8>,
}

impl ConnectSpdu {
	/// Create a new Connect SPDU.
	#[must_use]
	pub const fn new(
		calling: SSelector,
		called: SSelector,
		requirement: SessionRequirement,
		data: Vec<u8>,
	) -> Self {
		Self {
			calling_session_selector: Some(calling),
			called_session_selector: Some(called),
			session_requirement: requirement,
			protocol_options: 0,
			data,
		}
	}

	/// Parse a Connect SPDU body (the bytes after the SI + LI).
	#[instrument(skip_all)]
	pub fn from_body(bytes: &[u8]) -> Result<Self, SessionError> {
		let mut offset = 0;

		let mut called_session_selector = None;
		let mut calling_session_selector = None;
		let mut session_requirement = None;
		let mut protocol_options = None;
		let mut user_data = None;

		while offset < bytes.len() {
			let pgi = Pgi::from(*bytes.get(offset).context(UnexpectedEndOfMessage)?);
			let (param_len, li_consumed) = read_li(bytes, offset + 1)?;
			offset += 1 + li_consumed;
			let end = offset.checked_add(param_len).context(NotEnoughBytes)?;

			match pgi {
				Pgi::ConnectAcceptItem => {
					protocol_options = Some(Self::parse_connect_accept_item(
						bytes.get(offset..end).context(NotEnoughBytes)?,
					)?);
				}
				Pgi::SessionUserRequirements => {
					if param_len != 2 {
						return InvalidParameterLength.fail();
					}
					let req = u16::from_le_bytes([
						*bytes.get(offset).context(NotEnoughBytes)?,
						*bytes.get(offset + 1).context(NotEnoughBytes)?,
					]);
					session_requirement = Some(req.try_into()?);
				}
				Pgi::CallingSessionSelector => {
					calling_session_selector = Some(SSelector::from_bytes(
						bytes.get(offset..end).context(NotEnoughBytes)?,
					)?);
				}
				Pgi::CalledSessionSelector => {
					called_session_selector = Some(SSelector::from_bytes(
						bytes.get(offset..end).context(NotEnoughBytes)?,
					)?);
				}
				Pgi::UserData => {
					user_data = Some(bytes.get(offset..end).context(NotEnoughBytes)?.to_vec());
					break;
				}
				Pgi::Unknown49
				| Pgi::EnclosureItem
				| Pgi::TransportDisconnect
				| Pgi::ConnectionIdentifier
				| Pgi::DataOverflow
				| Pgi::ExtendedUserData
				| Pgi::Invalid => {
					tracing::debug!("Got PGI: 0x{:02x}. Ignoring it.", pgi as u8);
				}
			}
			offset = end;
		}

		Ok(Self {
			calling_session_selector,
			called_session_selector,
			session_requirement: session_requirement.context(MissingSessionRequirement)?,
			protocol_options: protocol_options.context(MissingProtocolOptions)?,
			data: user_data.context(MissingUserData)?,
		})
	}

	/// Encode a Connect SPDU to bytes.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		// Build the body first so we know its exact length and can encode the
		// SPDU LI in the correct (short or extended) form.
		let mut body = Vec::new();
		Self::encode_connect_accept_item(&mut body, 0);
		self.encode_session_requirement(&mut body);
		self.encode_calling_session_selector(&mut body);
		self.encode_called_session_selector(&mut body);
		body.push(Pgi::UserData as u8);
		push_li(&mut body, self.data.len());
		body.extend_from_slice(&self.data);

		let mut buffer = Vec::with_capacity(1 + 3 + body.len());
		buffer.push(SpduType::Connect as u8);
		push_li(&mut buffer, body.len());
		buffer.extend_from_slice(&body);
		buffer
	}

	/// Parse a Connect Accept Item from bytes.
	#[instrument(skip_all)]
	fn parse_connect_accept_item(bytes: &[u8]) -> Result<u8, SessionError> {
		let mut offset = 0;
		let mut has_protocol_options = false;
		let mut has_protocol_version = false;

		let mut protocol_options = 0;

		while offset < bytes.len() {
			let pi = Pi::from(*bytes.get(offset).context(UnexpectedEndOfMessage)?);
			let (param_len, li_consumed) = read_li(bytes, offset + 1)?;
			offset += 1 + li_consumed;
			let end = offset.checked_add(param_len).context(NotEnoughBytes)?;

			match pi {
				Pi::ProtocolOptions => {
					if param_len != 1 {
						return InvalidParameterLength.fail();
					}
					protocol_options = *bytes.get(offset).context(NotEnoughBytes)?;
					has_protocol_options = true;
				}
				Pi::VersionNumber => {
					if param_len != 1 {
						return InvalidParameterLength.fail();
					}
					let version = *bytes.get(offset).context(NotEnoughBytes)?;
					if version != 2 {
						return InvalidVersion { value: version }.fail();
					}
					has_protocol_version = true;
				}
				Pi::InitialSerialNumber
				| Pi::ReasonCode
				| Pi::TsduMaximumSize
				| Pi::TokenSettingItem
				| Pi::SecondInitialSerialNumber
				| Pi::UpperLimitSerialNumber
				| Pi::LargeInitialSerialNumber
				| Pi::LargeSecondInitialSerialNumber => {
					tracing::debug!("Got PI: 0x{:02x}. Ignoring it.", pi as u8);
				}
				Pi::Invalid => {
					return InvalidParameter { value: pi as u8 }.fail();
				}
			}
			offset = end;
		}

		if has_protocol_options && has_protocol_version {
			Ok(protocol_options)
		} else {
			tracing::debug!(
				"Missing required parameters. has_protocol_options: {}, has_protocol_version: {}",
				has_protocol_options,
				has_protocol_version
			);
			MissingRequiredParameters.fail()
		}
	}

	/// Encode a Connect Accept Item to bytes.
	fn encode_connect_accept_item(buffer: &mut Vec<u8>, options: u8) {
		buffer.push(Pgi::ConnectAcceptItem as u8);
		buffer.push(6); // Length
		buffer.push(Pi::ProtocolOptions as u8);
		buffer.push(1); // Length
		buffer.push(options);
		buffer.push(Pi::VersionNumber as u8);
		buffer.push(1); // Length
		buffer.push(2); // Version = 2
	}

	/// Encode a Session Requirement to bytes.
	fn encode_session_requirement(&self, buffer: &mut Vec<u8>) {
		buffer.push(Pgi::SessionUserRequirements as u8);
		buffer.push(2); // Length
		buffer.extend_from_slice(&(self.session_requirement as u16).to_le_bytes());
	}

	/// Encode a Calling Session Selector to bytes.
	fn encode_calling_session_selector(&self, buffer: &mut Vec<u8>) {
		if let Some(calling_session_selector) = &self.calling_session_selector {
			buffer.push(Pgi::CallingSessionSelector as u8);
			buffer.extend_from_slice(&calling_session_selector.to_bytes());
		}
	}

	/// Encode a Called Session Selector to bytes.
	fn encode_called_session_selector(&self, buffer: &mut Vec<u8>) {
		if let Some(called_session_selector) = &self.called_session_selector {
			buffer.push(Pgi::CalledSessionSelector as u8);
			buffer.extend_from_slice(&called_session_selector.to_bytes());
		}
	}
}

/// Accept SPDU
#[derive(Debug, Clone)]
pub struct AcceptSpdu {
	/// The called session selector.
	pub called_session_selector: Option<SSelector>,
	/// The session requirement.
	pub session_requirement: SessionRequirement,
	/// The protocol options.
	pub protocol_options: u8,
	/// The user data.
	pub data: Vec<u8>,
}

impl AcceptSpdu {
	#[allow(dead_code)]
	/// Create a new Accept SPDU.
	#[must_use]
	const fn new(
		called: SSelector,
		requirement: SessionRequirement,
		protocol_options: u8,
		data: Vec<u8>,
	) -> Self {
		Self {
			called_session_selector: Some(called),
			session_requirement: requirement,
			protocol_options,
			data,
		}
	}

	/// Parse an Accept SPDU body (the bytes after SI + LI).
	#[instrument(skip_all)]
	fn from_body(bytes: &[u8]) -> Result<Self, SessionError> {
		let connect_spdu = ConnectSpdu::from_body(bytes)?;
		Ok(Self {
			called_session_selector: connect_spdu.called_session_selector,
			session_requirement: connect_spdu.session_requirement,
			protocol_options: connect_spdu.protocol_options,
			data: connect_spdu.data,
		})
	}

	/// Encode an Accept SPDU to bytes.
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		// Connection/Accept Item
		let mut body = vec![
			Pgi::ConnectAcceptItem as u8,
			6,
			Pi::ProtocolOptions as u8,
			1,
			self.protocol_options,
			Pi::VersionNumber as u8,
			1,
			2,
			// Session User Requirements
			Pgi::SessionUserRequirements as u8,
			2,
		];
		body.extend_from_slice(&(self.session_requirement as u16).to_le_bytes());

		// Called Session Selector
		if let Some(called_session_selector) = &self.called_session_selector {
			body.push(Pgi::CalledSessionSelector as u8);
			body.extend_from_slice(&called_session_selector.to_bytes());
		}

		// User Data
		body.push(Pgi::UserData as u8);
		push_li(&mut body, self.data.len());
		body.extend_from_slice(&self.data);

		let mut buffer = Vec::with_capacity(1 + 3 + body.len());
		buffer.push(SpduType::Accept as u8);
		push_li(&mut buffer, body.len());
		buffer.extend_from_slice(&body);
		buffer
	}
}

/// Data SPDU (fixed 4-byte header)
#[derive(Debug, Clone)]
pub struct DataSpdu {
	/// The user data.
	pub data: Vec<u8>,
}

impl DataSpdu {
	/// Create a new Data SPDU.
	#[must_use]
	const fn new(data: Vec<u8>) -> Self {
		Self { data }
	}

	/// Parse a Data SPDU from bytes.
	#[instrument(skip_all)]
	fn from_bytes(bytes: &[u8]) -> Result<Self, SessionError> {
		if bytes.len() < 4 {
			return MessageTooShort.fail();
		}

		let length = bytes[1] as usize;
		if length == 0 && bytes[2] == Pgi::ConnectionIdentifier as u8 && bytes[3] == 0 {
			Ok(Self { data: bytes[4..].to_vec() })
		} else {
			InvalidDataSpdu.fail()
		}
	}

	/// Encode a Data SPDU to bytes.
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		let mut buffer = Vec::with_capacity(4 + self.data.len());
		buffer.extend_from_slice(&[
			SpduType::GiveTokenData as u8,
			0x00,
			Pgi::ConnectionIdentifier as u8,
			0x00,
		]);
		buffer.extend_from_slice(&self.data);
		buffer
	}
}

/// Finish SPDU
#[derive(Debug, Clone)]
pub struct FinishSpdu {
	/// The user data.
	pub data: Vec<u8>,
}

impl FinishSpdu {
	#[allow(dead_code)]
	/// Create a new Finish SPDU.
	#[must_use]
	const fn new(user_data: Vec<u8>) -> Self {
		Self { data: user_data }
	}

	/// Parse a Finish SPDU body (the bytes after SI + LI).
	#[instrument(skip_all)]
	fn from_body(bytes: &[u8]) -> Result<Self, SessionError> {
		let mut spdu = Self { data: Vec::new() };
		spdu.parse_parameters(bytes)?;
		Ok(spdu)
	}

	/// Encode a Finish SPDU to bytes.
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		// User-Data PI: identifier + LI + data
		let mut body = Vec::with_capacity(1 + 3 + self.data.len());
		body.push(Pgi::UserData as u8);
		push_li(&mut body, self.data.len());
		body.extend_from_slice(&self.data);

		let mut buffer = Vec::with_capacity(1 + 3 + body.len());
		buffer.push(SpduType::Finish as u8);
		push_li(&mut buffer, body.len());
		buffer.extend_from_slice(&body);
		buffer
	}

	/// Parse the parameters of a Finish SPDU.
	#[instrument(skip_all)]
	fn parse_parameters(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
		let mut offset = 0;

		while offset < bytes.len() {
			let pgi = Pgi::from(*bytes.get(offset).context(UnexpectedEndOfMessage)?);
			let (param_len, li_consumed) = read_li(bytes, offset + 1)?;
			offset += 1 + li_consumed;
			let end = offset.checked_add(param_len).context(NotEnoughBytes)?;

			match pgi {
				Pgi::UserData => {
					self.data = bytes.get(offset..end).context(NotEnoughBytes)?.to_vec();
					return Ok(());
				}
				_ => {
					offset = end;
				}
			}
		}

		Ok(())
	}
}

/// Disconnect SPDU
#[derive(Debug, Clone)]
pub struct DisconnectSpdu {
	/// The user data.
	pub user_data: Vec<u8>,
}

impl DisconnectSpdu {
	/// Create a new Disconnect SPDU.
	#[must_use]
	pub const fn new(user_data: Vec<u8>) -> Self {
		Self { user_data }
	}

	/// Parse a Disconnect SPDU body (the bytes after SI + LI).
	#[instrument(skip_all)]
	fn from_body(bytes: &[u8]) -> Result<Self, SessionError> {
		FinishSpdu::from_body(bytes).map(|f| Self { user_data: f.data })
	}

	/// Encode a Disconnect SPDU to bytes.
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		let mut body = Vec::with_capacity(1 + 3 + self.user_data.len());
		body.push(Pgi::UserData as u8);
		push_li(&mut body, self.user_data.len());
		body.extend_from_slice(&self.user_data);

		let mut buffer = Vec::with_capacity(1 + 3 + body.len());
		buffer.push(SpduType::Disconnect as u8);
		push_li(&mut buffer, body.len());
		buffer.extend_from_slice(&body);
		buffer
	}
}

/// Abort SPDU
#[derive(Debug, Clone)]
pub struct AbortSpdu {
	/// The user data.
	pub user_data: Vec<u8>,
}

impl AbortSpdu {
	#[allow(dead_code)]
	/// Create a new Abort SPDU.
	#[must_use]
	const fn new(user_data: Vec<u8>) -> Self {
		Self { user_data }
	}

	/// Parse an Abort SPDU body (the bytes after SI + LI).
	#[instrument(skip_all)]
	fn from_body(bytes: &[u8]) -> Result<Self, SessionError> {
		// Body layout sent by the encoder: TransportDisconnect PGI (id + LI=1 + 1
		// reason byte = 3 bytes) followed by UserData PI (id + LI + data).
		// Skip the transport-disconnect parameters by parsing their LI.
		let pgi_id = *bytes.first().context(NotEnoughBytes)?;
		if pgi_id != Pgi::TransportDisconnect as u8 {
			return InvalidParameter { value: pgi_id }.fail();
		}
		let (td_len, td_li_consumed) = read_li(bytes, 1)?;
		let after_td = 1 + td_li_consumed + td_len;

		// UserData PI.
		let ud_id = *bytes.get(after_td).context(NotEnoughBytes)?;
		if ud_id != Pgi::UserData as u8 {
			return InvalidParameter { value: ud_id }.fail();
		}
		let (ud_len, ud_li_consumed) = read_li(bytes, after_td + 1)?;
		let ud_start = after_td + 1 + ud_li_consumed;
		let ud_end = ud_start.checked_add(ud_len).context(NotEnoughBytes)?;
		Ok(Self { user_data: bytes.get(ud_start..ud_end).context(NotEnoughBytes)?.to_vec() })
	}

	/// Encode an Abort SPDU to bytes.
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		let mut body = Vec::with_capacity(3 + 1 + 3 + self.user_data.len());
		// TransportDisconnect PGI
		body.push(Pgi::TransportDisconnect as u8);
		body.push(1);
		body.push(11); // transport-connection-released | user-abort | no-reason
		// User Data PI
		body.push(Pgi::UserData as u8);
		push_li(&mut body, self.user_data.len());
		body.extend_from_slice(&self.user_data);

		let mut buffer = Vec::with_capacity(1 + 3 + body.len());
		buffer.push(SpduType::Abort as u8);
		push_li(&mut buffer, body.len());
		buffer.extend_from_slice(&body);
		buffer
	}
}

/// Refuse SPDU
#[derive(Debug, Clone)]
pub struct RefuseSpdu {
	/// The reason code.
	pub reason_code: u8,
}

impl RefuseSpdu {
	#[allow(dead_code)]
	/// Create a new Refuse SPDU.
	#[must_use]
	const fn new(reason_code: u8) -> Self {
		Self { reason_code }
	}

	/// Parse a Refuse SPDU body (the bytes after SI + LI).
	#[instrument(skip_all)]
	fn from_body(bytes: &[u8]) -> Result<Self, SessionError> {
		// Walk: ConnectionIdentifier PGI (containing TransportDisconnect PGI
		// and ReasonCode PI) — extract the reason byte from the ReasonCode PI.
		let pgi_id = *bytes.first().context(NotEnoughBytes)?;
		if pgi_id != Pgi::ConnectionIdentifier as u8 {
			return InvalidParameter { value: pgi_id }.fail();
		}
		let (conn_len, conn_li_consumed) = read_li(bytes, 1)?;
		let conn_start = 1 + conn_li_consumed;
		let conn_end = conn_start.checked_add(conn_len).context(NotEnoughBytes)?;
		let conn = bytes.get(conn_start..conn_end).context(NotEnoughBytes)?;

		// Inside the ConnectionIdentifier scan for ReasonCode PI.
		let mut offset = 0;
		while offset < conn.len() {
			let id = *conn.get(offset).context(NotEnoughBytes)?;
			let (param_len, li_consumed) = read_li(conn, offset + 1)?;
			offset += 1 + li_consumed;
			let end = offset.checked_add(param_len).context(NotEnoughBytes)?;
			if id == Pi::ReasonCode as u8 && param_len >= 1 {
				return Ok(Self { reason_code: *conn.get(offset).context(NotEnoughBytes)? });
			}
			offset = end;
		}
		MissingRequiredParameters.fail()
	}

	/// Encode a Refuse SPDU to bytes.
	#[must_use]
	fn to_bytes(&self) -> Vec<u8> {
		vec![
			SpduType::Refuse as u8,
			8, // Length
			// Connection Identifier
			Pgi::ConnectionIdentifier as u8,
			6,
			Pgi::TransportDisconnect as u8,
			1,
			1, // release transport connection
			Pi::ReasonCode as u8,
			1,
			self.reason_code,
		]
	}
}

#[allow(missing_docs)]
/// Session layer errors
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum SessionError {
	#[snafu(display("Missing calling session selector"))]
	MissingCallingSessionSelector {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing called session selector"))]
	MissingCalledSessionSelector {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing session requirement"))]
	MissingSessionRequirement {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing protocol options"))]
	MissingProtocolOptions {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing user data"))]
	MissingUserData {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error in COTP layer"))]
	CotpLayer {
		source: CotpError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid response from COTP"))]
	InvalidCotpResponse {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid parameter: 0x{:02x}", value))]
	InvalidParameter {
		value: u8,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid session requirement: 0x{:04x}", value))]
	InvalidSessionRequirement {
		value: u16,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid SPDU type: 0x{:02x}", value))]
	InvalidSpduType {
		value: u8,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Message too short"))]
	MessageTooShort {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid length field"))]
	InvalidLength {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid DATA SPDU format"))]
	InvalidDataSpdu {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Connection refused by peer (reason code {reason_code})"))]
	ConnectionRefused {
		reason_code: u8,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Connection aborted by peer"))]
	ConnectionAborted {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Unexpected end of message"))]
	UnexpectedEndOfMessage {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid parameter length"))]
	InvalidParameterLength {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid session selector size"))]
	InvalidSelectorSize {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("No user data found in message"))]
	NoUserData {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid protocol version: {}", value))]
	InvalidVersion {
		value: u8,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing required parameters"))]
	MissingRequiredParameters {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Payload too large (> 255 bytes for some SPDUs)"))]
	PayloadTooLarge {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Not enough bytes"))]
	NotEnoughBytes {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
}

impl SessionError {
	/// Get the context of the session error.
	#[must_use]
	pub fn get_context(&self) -> &SpanTraceWrapper {
		match self {
			SessionError::CotpLayer { context, .. } => context,
			SessionError::InvalidCotpResponse { context, .. } => context,
			SessionError::NotEnoughBytes { context } => context,
			SessionError::InvalidVersion { context, .. } => context,
			SessionError::MissingRequiredParameters { context } => context,
			SessionError::PayloadTooLarge { context } => context,
			SessionError::InvalidSessionRequirement { context, .. } => context,
			SessionError::InvalidParameter { context, .. } => context,
			SessionError::InvalidSpduType { context, .. } => context,
			SessionError::MessageTooShort { context } => context,
			SessionError::InvalidLength { context } => context,
			SessionError::InvalidDataSpdu { context } => context,
			SessionError::ConnectionRefused { context, .. } => context,
			SessionError::ConnectionAborted { context } => context,
			SessionError::UnexpectedEndOfMessage { context } => context,
			SessionError::InvalidParameterLength { context } => context,
			SessionError::InvalidSelectorSize { context } => context,
			SessionError::NoUserData { context } => context,
			SessionError::MissingCallingSessionSelector { context } => context,
			SessionError::MissingCalledSessionSelector { context } => context,
			SessionError::MissingSessionRequirement { context } => context,
			SessionError::MissingProtocolOptions { context } => context,
			SessionError::MissingUserData { context } => context,
		}
	}
}

impl From<CotpError> for SessionError {
	fn from(error: CotpError) -> Self {
		SessionError::CotpLayer { context: Box::new((*error.get_context()).clone()), source: error }
	}
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_sselector_new() {
		let data = [1, 2, 3, 4];
		let selector = SSelector::from_bytes(&data).unwrap();
		assert_eq!(selector.value.len(), 4);
		assert_eq!(selector.value, &data);
	}

	#[test]
	fn test_sselector_too_large() {
		let data = [0_u8; 17]; // Too large
		let result = SSelector::from_bytes(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_data_spdu_roundtrip() {
		let payload = b"Hello, World!";
		let spdu = DataSpdu::new(payload.to_vec());
		let bytes = spdu.to_bytes();

		let parsed = DataSpdu::from_bytes(&bytes).unwrap();
		assert_eq!(parsed.data, payload);
	}

	#[test]
	fn test_connect_spdu_roundtrip() {
		let calling = SSelector::from_bytes(&[0, 1, 2, 3]).unwrap();
		let called = SSelector::from_bytes(&[4, 5, 6, 7]).unwrap();
		let requirement = SessionRequirement::Duplex;
		let user_data = b"ACSE data".to_vec();

		let spdu =
			ConnectSpdu::new(calling.clone(), called.clone(), requirement, user_data.clone());
		let bytes = spdu.to_bytes();

		let Spdu::Connect(parsed) = Spdu::from_bytes(&bytes).unwrap() else {
			panic!("expected Connect SPDU");
		};
		assert_eq!(parsed.calling_session_selector, Some(calling));
		assert_eq!(parsed.called_session_selector, Some(called));
		assert_eq!(parsed.session_requirement, requirement);
		assert_eq!(parsed.data, user_data);
	}

	#[test]
	fn test_connect_spdu_extended_length_roundtrip() {
		// A user-data payload larger than 254 forces the extended LI form for
		// both the inner User-Data PI and the outer SPDU LI.
		let calling = SSelector::from_bytes(&[0, 1, 2, 3]).unwrap();
		let called = SSelector::from_bytes(&[4, 5, 6, 7]).unwrap();
		let user_data = vec![0xab_u8; 600];

		let spdu = ConnectSpdu::new(
			calling.clone(),
			called.clone(),
			SessionRequirement::Duplex,
			user_data.clone(),
		);
		let bytes = spdu.to_bytes();

		// Sanity-check that the outer SPDU LI is in the extended form
		// (marker 0xFF followed by a 2-byte big-endian length).
		assert_eq!(bytes[0], SpduType::Connect as u8);
		assert_eq!(bytes[1], 0xFF, "outer LI should be extended");

		let Spdu::Connect(parsed) = Spdu::from_bytes(&bytes).unwrap() else {
			panic!("expected Connect SPDU");
		};
		assert_eq!(parsed.calling_session_selector, Some(calling));
		assert_eq!(parsed.called_session_selector, Some(called));
		assert_eq!(parsed.data, user_data);
	}

	#[test]
	fn test_finish_spdu_roundtrip() {
		let user_data = b"Goodbye".to_vec();
		let spdu = FinishSpdu::new(user_data.clone());
		let bytes = spdu.to_bytes();

		let Spdu::Finish(parsed) = Spdu::from_bytes(&bytes).unwrap() else {
			panic!("expected Finish SPDU");
		};
		assert_eq!(parsed.data, user_data);
	}

	#[test]
	fn test_abort_spdu_roundtrip() {
		let user_data = b"Error".to_vec();
		let spdu = AbortSpdu::new(user_data.clone());
		let bytes = spdu.to_bytes();

		let Spdu::Abort(parsed) = Spdu::from_bytes(&bytes).unwrap() else {
			panic!("expected Abort SPDU");
		};
		assert_eq!(parsed.user_data, user_data);
	}

	#[test]
	fn test_connect_spdu_truncated_does_not_panic() {
		// Crafted SPDU header claiming a body length much bigger than the
		// actual byte slice. Before the bounds-check tightening, the inner
		// loop could index past `bytes.len()`.
		let truncated: Vec<u8> = vec![SpduType::Connect as u8, 0x80, 0x05, 0x06];
		assert!(Spdu::from_bytes(&truncated).is_err());
	}

	#[test]
	fn test_spdu_enum_parsing() {
		let data_spdu = DataSpdu::new(b"test".to_vec());
		let bytes = data_spdu.to_bytes();

		let parsed = Spdu::from_bytes(&bytes).unwrap();
		match parsed {
			Spdu::Data(d) => assert_eq!(d.data, b"test"),
			_ => panic!("Wrong SPDU type"),
		}
	}

	#[test]
	fn test_session_requirement_flags() {
		assert_eq!(SessionRequirement::HalfDuplex as u16, 0x0001);
		assert_eq!(SessionRequirement::Duplex as u16, 0x0002);
		assert_eq!(SessionRequirement::ExpeditedData as u16, 0x0004);
	}

	#[test]
	fn test_invalid_spdu_type() {
		let invalid_bytes = vec![0xFF, 0x00];
		let result = Spdu::from_bytes(&invalid_bytes);
		assert!(result.is_err());
	}

	#[test]
	fn test_refuse_spdu_roundtrip_carries_reason() {
		// A Refuse SPDU should parse back with its reason code intact so the
		// connect path can surface it.
		let refuse = RefuseSpdu::new(0x05);
		let bytes = refuse.to_bytes();
		let Spdu::Refuse(parsed) = Spdu::from_bytes(&bytes).unwrap() else {
			panic!("expected Refuse SPDU");
		};
		assert_eq!(parsed.reason_code, 0x05);
	}
}
