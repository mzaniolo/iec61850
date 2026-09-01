//! COTP and RFC1006 implementation.

use std::{pin::Pin, time::Duration};

use async_trait::async_trait;
#[cfg(not(any(feature = "native_tls", feature = "rustls")))]
use snafu::whatever;
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use tokio::{
	io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
	net::TcpStream,
};
use tracing::instrument;

use crate::mms::{ClientConfig, ReadHalfConnection, SpanTraceWrapper, WriteHalfConnection};

/// The version of the TPKT protocol.
pub(super) const TPKT_VERSION: u8 = 0x03;
/// The maximum size of a COTP TPDU.
pub(super) const COTP_MAX_TPDU_SIZE: u32 = 8192;
/// The size of the COTP DT header.
pub(super) const COTP_DT_HEADER_SIZE: usize = 3;
/// The size of the TPKT header.
pub(super) const TPKT_HEADER_SIZE: usize = 4;
/// Hard upper bound on the aggregate payload reassembled from a chain of
/// `NoEot` DT TPDUs. A misbehaving peer could otherwise stream segments
/// indefinitely and exhaust memory. Sized comfortably above any realistic
/// MMS PDU (the MMS layer separately negotiates its own per-PDU limit).
pub(super) const COTP_MAX_REASSEMBLED_SIZE: usize = 16 * 1024 * 1024;
/// Maximum value an `LI` byte can carry in CR/CC TPDUs (it must fit in `u8`,
/// and the value 0xFF is reserved).
const COTP_MAX_LI: usize = 254;

/// The COTP connection.
#[derive(Debug)]
pub struct CotpConnection {
	/// The read half of the connection.
	read_connection: CotpReadHalf,
	/// The write half of the connection.
	write_connection: CotpWriteHalf,
}

impl CotpConnection {
	/// Establish a connection to the server.
	#[instrument]
	pub async fn connect(config: &ClientConfig) -> Result<Self, CotpError> {
		let connection = make_connection(config).await?;
		Self::request_connection(connection, config).await
	}

	/// Request a connection to the server and negotiate the connection
	/// parameters.
	#[instrument(skip(config))]
	async fn request_connection(
		mut connection: Connection,
		config: &ClientConfig,
	) -> Result<Self, CotpError> {
		let options = vec![
			CotpOptions::TpduSize(TpduSize::new(config.connection.tpdu_size)),
			CotpOptions::TSelDst(TselDst { value: config.connection.remote_t_sel.clone() }),
			CotpOptions::TSelSrc(TselSrc { value: config.connection.local_t_sel.clone() }),
		];

		let local_ref = 1;

		let tpkt = Tpkt::from_cotp(Cotp::Cr(CrTpdu::new(0, local_ref, options)?));
		connection
			.write_all(&tpkt.to_bytes())
			.await
			.whatever_context("Error writing to connection")?;

		let tpkt =
			CotpReadHalf::read_tpkt(&mut connection, config.connection.frame_read_timeout).await?;

		if !matches!(tpkt.cotp, Cotp::Cc(_)) {
			return WrongCotpType.fail();
		}

		if let Cotp::Cc(cc_tpdu) = &tpkt.cotp
			&& cc_tpdu.dst_ref == local_ref
		{
			let tpdu_size = cc_tpdu
				.options
				.iter()
				.find_map(|option| {
					if let CotpOptions::TpduSize(tpdu_size) = option {
						Some(tpdu_size.get_value())
					} else {
						None
					}
				})
				.unwrap_or(COTP_MAX_TPDU_SIZE);
			let (read_half, write_half) = tokio::io::split(connection);
			return Ok(Self {
				read_connection: CotpReadHalf {
					connection: read_half,
					frame_read_timeout: config.connection.frame_read_timeout,
				},
				write_connection: CotpWriteHalf { connection: write_half, tpdu_size },
			});
		}

		ConnectionFailed.fail()
	}

	/// Split the connection into a read half and a write half.
	#[must_use]
	pub fn split(self) -> (CotpReadHalf, CotpWriteHalf) {
		(self.read_connection, self.write_connection)
	}
}

#[async_trait]
impl ReadHalfConnection for CotpConnection {
	type Error = CotpError;

	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> Result<Vec<u8>, Self::Error> {
		self.read_connection.receive_data().await
	}
}

#[async_trait]
impl WriteHalfConnection for CotpConnection {
	type Error = CotpError;

	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
		self.write_connection.send_data(data).await
	}
}

/// The read half of the COTP connection.
#[derive(Debug)]
pub struct CotpReadHalf {
	/// The read half of the connection.
	connection: ReadHalf<Connection>,
	/// Bounds the read of the rest of a frame once its header arrives.
	frame_read_timeout: Option<Duration>,
}

#[async_trait]
impl ReadHalfConnection for CotpReadHalf {
	type Error = CotpError;

	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> Result<Vec<u8>, Self::Error> {
		Self::receive_data_from(&mut self.connection, self.frame_read_timeout).await
	}
}

impl CotpReadHalf {
	/// Read DT TPDUs from `connection` until EOT, returning the reassembled
	/// payload. Caps the aggregate at [`COTP_MAX_REASSEMBLED_SIZE`] so a
	/// misbehaving peer can't exhaust memory by streaming `NoEot` fragments.
	#[instrument(skip(connection))]
	async fn receive_data_from<R: AsyncRead + Unpin>(
		connection: &mut R,
		frame_read_timeout: Option<Duration>,
	) -> Result<Vec<u8>, CotpError> {
		let mut data = Vec::new();
		loop {
			let tpkt = Self::read_tpkt(connection, frame_read_timeout).await.inspect_err(|e| {
				tracing::error!("Error reading TPKT: {:?}", e);
			})?;
			let dt = match tpkt.cotp {
				Cotp::Dt(dt) => dt,
				// A DR/DC mid-stream is the peer tearing down the transport
				// connection (e.g. on graceful shutdown). Surface it as a
				// clean, typed disconnect instead of WrongCotpType so the
				// upper layers can distinguish it from a protocol violation.
				Cotp::Dr(dr) => return PeerDisconnected { reason: dr.reason }.fail(),
				Cotp::Dc(_) => return PeerDisconnected { reason: 0 }.fail(),
				_ => return WrongCotpType.fail(),
			};
			if data.len().saturating_add(dt.data.len()) > COTP_MAX_REASSEMBLED_SIZE {
				return ReassemblyTooLarge { limit: COTP_MAX_REASSEMBLED_SIZE }.fail();
			}
			data.extend_from_slice(&dt.data);
			if dt.eot == Eot::Eot {
				return Ok(data);
			}
		}
	}

	/// Read a TPKT from the connection.
	///
	/// The wait for the 4-byte header is intentionally unbounded: an idle
	/// connection legitimately has no data while it waits for the next frame
	/// (e.g. an unsolicited report). Once the header arrives, the rest of the
	/// frame is expected promptly, so the payload read is bounded by
	/// `frame_read_timeout` to defend against a peer that stalls mid-frame.
	#[instrument(skip(connection))]
	async fn read_tpkt<R: AsyncRead + Unpin>(
		connection: &mut R,
		frame_read_timeout: Option<Duration>,
	) -> Result<Tpkt, CotpError> {
		let mut buffer = [0; TPKT_HEADER_SIZE];
		connection
			.read_exact(&mut buffer)
			.await
			.whatever_context("Error reading from connection")?;
		if buffer[0] != TPKT_VERSION {
			return InvalidTpktVersion.fail();
		}
		if buffer[1] != 0 {
			return InvalidTpktVersion.fail();
		}

		let length =
			u16::from_be_bytes(buffer[2..TPKT_HEADER_SIZE].try_into().context(SizedSlice)?);

		let payload_len = (length as usize)
			.checked_sub(TPKT_HEADER_SIZE)
			.context(TpktLengthTooShort { length })?;
		if payload_len > COTP_MAX_TPDU_SIZE as usize {
			return TpktLengthTooLarge { length }.fail();
		}

		//TODO: This needs to be optimized. Make this static and always clean it before
		// use.
		let mut buffer = vec![0; payload_len];
		let read_payload = connection.read_exact(&mut buffer);
		match frame_read_timeout {
			Some(timeout) => tokio::time::timeout(timeout, read_payload)
				.await
				.map_err(|_| FrameReadTimeout { timeout }.build())?
				.whatever_context("Error reading from connection")?,
			None => read_payload.await.whatever_context("Error reading from connection")?,
		};
		let cotp = Cotp::from_bytes(&buffer)?;

		Ok(Tpkt::from_cotp(cotp))
	}
}

/// The write half of the COTP connection.
#[derive(Debug)]
pub struct CotpWriteHalf {
	/// The write half of the connection.
	connection: WriteHalf<Connection>,
	/// The TPDU size of the COTP connection.
	tpdu_size: u32,
}

#[async_trait]
impl WriteHalfConnection for CotpWriteHalf {
	type Error = CotpError;
	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
		let max_dt_data_size = self.tpdu_size as usize - COTP_DT_HEADER_SIZE;
		let num_dts = data.len().div_ceil(max_dt_data_size);
		let buffer_size = num_dts * (TPKT_HEADER_SIZE + COTP_DT_HEADER_SIZE) + data.len();
		let mut buffer = Vec::with_capacity(buffer_size);
		for (i, chunk) in data.chunks(max_dt_data_size).enumerate() {
			let eot = if i == num_dts - 1 { Eot::Eot } else { Eot::NoEot };
			let dt_tpdu = Cotp::Dt(DtTpdu::new(eot, chunk.to_vec()));
			//TODO: This needs to be optimized
			buffer.extend_from_slice(&Tpkt::from_cotp(dt_tpdu).to_bytes());
		}

		self.connection.write_all(&buffer).await.whatever_context("Error writing to connection")?;

		Ok(())
	}
}

/// The TPKT packet.
#[derive(Debug, Clone)]
struct Tpkt {
	/// The length of the TPKT packet, including the header.
	/// The COTP TPDU length is length - 4.
	length: u16,
	/// The COTP TPDU.
	cotp: Cotp,
}

impl Tpkt {
	/// Convert the TPKT packet to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.length as usize);
		bytes.push(TPKT_VERSION);
		bytes.push(0x00);
		bytes.extend_from_slice(&self.length.to_be_bytes());
		bytes.extend_from_slice(&self.cotp.to_bytes());
		bytes
	}

	/// Convert a COTP TPDU to a TPKT packet.
	#[instrument(level = "debug")]
	fn from_cotp(cotp: Cotp) -> Self {
		Self { length: (cotp.len() + TPKT_HEADER_SIZE) as u16, cotp }
	}
}

/// The COTP TPDU.
#[derive(Debug, Clone)]
enum Cotp {
	/// The CR TPDU.
	Cr(CrTpdu),
	/// The CC TPDU.
	Cc(CcTpdu),
	/// The DT TPDU.
	Dt(DtTpdu),
	/// The DR (Disconnect Request) TPDU.
	Dr(DrTpdu),
	/// The DC (Disconnect Confirm) TPDU.
	Dc(DcTpdu),
}

impl Cotp {
	/// Convert a byte array to a COTP TPDU.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		match (*bytes.get(1).context(NotEnoughBytes)?).into() {
			TpduType::CR => CrTpdu::from_bytes(bytes).map(Self::Cr),
			TpduType::CC => CcTpdu::from_bytes(bytes).map(Self::Cc),
			TpduType::DT => DtTpdu::from_bytes(bytes).map(Self::Dt),
			TpduType::DR => DrTpdu::from_bytes(bytes).map(Self::Dr),
			TpduType::DC => DcTpdu::from_bytes(bytes).map(Self::Dc),
			_ => InvalidTpduType {
				value: *bytes.get(1).context(NotEnoughBytes)?,
				expected: TpduType::Invalid,
			}
			.fail(),
		}
	}

	/// Convert a COTP TPDU to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		match self {
			Self::Cr(tpdu) => tpdu.to_bytes(),
			Self::Cc(tpdu) => tpdu.to_bytes(),
			Self::Dt(tpdu) => tpdu.to_bytes(),
			Self::Dr(tpdu) => tpdu.to_bytes(),
			Self::Dc(tpdu) => tpdu.to_bytes(),
		}
	}

	/// Get the length of the COTP TPDU.
	const fn len(&self) -> usize {
		match self {
			Self::Cr(tpdu) => tpdu.len(),
			Self::Cc(tpdu) => tpdu.len(),
			Self::Dt(tpdu) => tpdu.len(),
			Self::Dr(tpdu) => tpdu.len(),
			Self::Dc(tpdu) => tpdu.len(),
		}
	}
}

/// The type of the COTP TPDU
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpduType {
	/// The CR TPDU type.
	CR = 0xe0,
	/// The CC TPDU type.
	CC = 0xd0,
	/// The DT TPDU type.
	DT = 0xf0,
	/// The DR (Disconnect Request) TPDU type.
	DR = 0x80,
	/// The DC (Disconnect Confirm) TPDU type.
	DC = 0xc0,
	/// The invalid TPDU type.
	Invalid = 0xff,
}

impl From<u8> for TpduType {
	#[instrument(level = "debug")]
	fn from(value: u8) -> Self {
		match value {
			val if val == TpduType::CR as u8 => TpduType::CR,
			val if val == TpduType::CC as u8 => TpduType::CC,
			val if val == TpduType::DT as u8 => TpduType::DT,
			val if val == TpduType::DR as u8 => TpduType::DR,
			val if val == TpduType::DC as u8 => TpduType::DC,
			_ => TpduType::Invalid,
		}
	}
}

/// The CR TPDU.
#[derive(Debug, Clone)]
struct CrTpdu {
	/// The length indicator of the CR TPDU.
	li: u8,
	/// The destination reference of the CR TPDU.
	dst_ref: u16,
	/// The source reference of the CR TPDU.
	src_ref: u16,

	// class: u8, -> Always 0
	/// The options of the CR TPDU.
	options: Vec<CotpOptions>,
}

impl CrTpdu {
	/// Create a new CR TPDU.
	fn new(dst_ref: u16, src_ref: u16, options: Vec<CotpOptions>) -> Result<Self, CotpError> {
		let li = options.iter().map(CotpOptions::len).sum::<usize>() + 6;
		if li > COTP_MAX_LI {
			return CrCcTooLarge { li }.fail();
		}
		Ok(Self { li: li as u8, dst_ref, src_ref, options })
	}

	/// Convert a byte array to a CR TPDU.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		let li = *bytes.first().context(NotEnoughBytes)?;

		if *bytes.get(1).context(NotEnoughBytes)? != TpduType::CR as u8 {
			return InvalidTpduType {
				value: *bytes.get(1).context(NotEnoughBytes)?,
				expected: TpduType::CR,
			}
			.fail();
		}

		let dst_ref = u16::from_be_bytes(
			bytes.get(2..4).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		let src_ref = u16::from_be_bytes(
			bytes.get(4..6).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		//skip class- must always be 0
		// The size of options is LI - 6. So the options goes from 7 to 7+size of
		// options.
		let options = bytes_to_options(bytes.get(7..li as usize + 1).context(NotEnoughBytes)?)?;

		Ok(Self { li, dst_ref, src_ref, options })
	}

	/// Convert a CR TPDU to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.li as usize + 1);
		bytes.push(self.li);
		bytes.push(TpduType::CR as u8);
		bytes.extend_from_slice(&self.dst_ref.to_be_bytes());
		bytes.extend_from_slice(&self.src_ref.to_be_bytes());
		bytes.push(0x00); // class 0
		bytes.extend_from_slice(&options_to_bytes(&self.options));
		bytes
	}

	/// Get the length of the CR TPDU.
	const fn len(&self) -> usize {
		self.li as usize + 1
	}
}

/// The CC TPDU.
#[derive(Debug, Clone)]
struct CcTpdu {
	/// The length indicator of the CC TPDU.
	li: u8,
	/// The destination reference of the CC TPDU.
	dst_ref: u16,
	/// The source reference of the CC TPDU.
	src_ref: u16,
	// class: u8, -> Always 0
	/// The options of the CC TPDU.
	options: Vec<CotpOptions>,
}

impl CcTpdu {
	/// Create a new CC TPDU.
	#[allow(dead_code)]
	fn new(dst_ref: u16, src_ref: u16, options: Vec<CotpOptions>) -> Result<Self, CotpError> {
		let li = options.iter().map(CotpOptions::len).sum::<usize>() + 6;
		if li > COTP_MAX_LI {
			return CrCcTooLarge { li }.fail();
		}
		Ok(Self { li: li as u8, dst_ref, src_ref, options })
	}

	/// Convert a byte array to a CC TPDU.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		let li = *bytes.first().context(NotEnoughBytes)?;

		if *bytes.get(1).context(NotEnoughBytes)? != TpduType::CC as u8 {
			return InvalidTpduType {
				value: *bytes.get(1).context(NotEnoughBytes)?,
				expected: TpduType::CC,
			}
			.fail();
		}

		let dst_ref = u16::from_be_bytes(
			bytes.get(2..4).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		let src_ref = u16::from_be_bytes(
			bytes.get(4..6).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		//skip class- must always be 0
		// The size of options is LI - 6. So the options goes from 7 to 7+size of
		// options.
		let options = bytes_to_options(bytes.get(7..li as usize + 1).context(NotEnoughBytes)?)?;

		Ok(Self { li, dst_ref, src_ref, options })
	}

	/// Convert a CC TPDU to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.li as usize + 1);
		bytes.push(self.li);
		bytes.push(TpduType::CC as u8);
		bytes.extend_from_slice(&self.dst_ref.to_be_bytes());
		bytes.extend_from_slice(&self.src_ref.to_be_bytes());
		bytes.push(0x00); // class 0
		bytes.extend_from_slice(&options_to_bytes(&self.options));
		bytes
	}

	/// Get the length of the CC TPDU.
	const fn len(&self) -> usize {
		self.li as usize + 1
	}
}

/// The DT TPDU.
#[derive(Debug, Clone)]
struct DtTpdu {
	/// The end of transmission of the DT TPDU.
	eot: Eot,
	/// The data of the DT TPDU.
	data: Vec<u8>,
}

impl DtTpdu {
	/// Create a new DT TPDU.
	#[must_use]
	const fn new(eot: Eot, data: Vec<u8>) -> Self {
		Self { eot, data }
	}

	/// Convert a byte array to a DT TPDU.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		if *bytes.first().context(NotEnoughBytes)? != 0x02 {
			return InvalidLiValue {
				value: *bytes.first().context(NotEnoughBytes)?,
				expected: 0x02,
			}
			.fail();
		}
		if *bytes.get(1).context(NotEnoughBytes)? != TpduType::DT as u8 {
			return InvalidTpduType {
				value: *bytes.get(1).context(NotEnoughBytes)?,
				expected: TpduType::DT,
			}
			.fail();
		}

		let eot = Eot::try_from(*bytes.get(2).context(NotEnoughBytes)?)?;
		let data = bytes.get(3..).context(NotEnoughBytes)?.to_vec();

		Ok(Self { eot, data })
	}

	/// Convert a DT TPDU to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(2 + self.data.len());
		bytes.push(0x02); // LI
		bytes.push(TpduType::DT as u8);
		bytes.push(self.eot as u8);
		bytes.extend_from_slice(&self.data);
		bytes
	}

	/// Get the length of the DT TPDU.
	const fn len(&self) -> usize {
		3 + self.data.len()
	}
}

/// The DR (Disconnect Request) TPDU. Sent by either peer to tear down the
/// transport connection (RFC 905 §13.5).
#[derive(Debug, Clone)]
struct DrTpdu {
	/// The destination reference.
	dst_ref: u16,
	/// The source reference.
	src_ref: u16,
	/// The disconnect reason code.
	reason: u8,
}

impl DrTpdu {
	/// Parse a DR TPDU from bytes.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		if *bytes.get(1).context(NotEnoughBytes)? != TpduType::DR as u8 {
			return InvalidTpduType {
				value: *bytes.get(1).context(NotEnoughBytes)?,
				expected: TpduType::DR,
			}
			.fail();
		}
		let dst_ref = u16::from_be_bytes(
			bytes.get(2..4).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		let src_ref = u16::from_be_bytes(
			bytes.get(4..6).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		let reason = *bytes.get(6).context(NotEnoughBytes)?;
		Ok(Self { dst_ref, src_ref, reason })
	}

	/// Convert a DR TPDU to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(8);
		bytes.push(6); // LI = 6 (header after LI, excluding variable part)
		bytes.push(TpduType::DR as u8);
		bytes.extend_from_slice(&self.dst_ref.to_be_bytes());
		bytes.extend_from_slice(&self.src_ref.to_be_bytes());
		bytes.push(self.reason);
		bytes
	}

	/// Get the length of the DR TPDU.
	#[allow(clippy::unused_self)] // instance method for the Cotp::len() match
	const fn len(&self) -> usize {
		7
	}
}

/// The DC (Disconnect Confirm) TPDU. Acknowledges a DR (RFC 905 §13.6).
#[derive(Debug, Clone)]
struct DcTpdu {
	/// The destination reference.
	dst_ref: u16,
	/// The source reference.
	src_ref: u16,
}

impl DcTpdu {
	/// Parse a DC TPDU from bytes.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		if *bytes.get(1).context(NotEnoughBytes)? != TpduType::DC as u8 {
			return InvalidTpduType {
				value: *bytes.get(1).context(NotEnoughBytes)?,
				expected: TpduType::DC,
			}
			.fail();
		}
		let dst_ref = u16::from_be_bytes(
			bytes.get(2..4).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		let src_ref = u16::from_be_bytes(
			bytes.get(4..6).context(NotEnoughBytes)?.try_into().context(SizedSlice)?,
		);
		Ok(Self { dst_ref, src_ref })
	}

	/// Convert a DC TPDU to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(7);
		bytes.push(5); // LI = 5
		bytes.push(TpduType::DC as u8);
		bytes.extend_from_slice(&self.dst_ref.to_be_bytes());
		bytes.extend_from_slice(&self.src_ref.to_be_bytes());
		bytes
	}

	/// Get the length of the DC TPDU.
	#[allow(clippy::unused_self)] // instance method for the Cotp::len() match
	const fn len(&self) -> usize {
		6
	}
}

/// The end of transmission of the DT TPDU.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Eot {
	/// Indicates that there is more data to come.
	NoEot = 0x00,
	/// Indicates that this is the last data package.
	Eot = 0x80,
}

impl TryFrom<u8> for Eot {
	type Error = CotpError;
	#[instrument(level = "debug")]
	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0x00 => Ok(Eot::NoEot),
			0x80 => Ok(Eot::Eot),
			_ => InvalidEot.fail(),
		}
	}
}

/// Convert a byte array to a vector of COTP options.
#[instrument(level = "debug")]
fn bytes_to_options(bytes: &[u8]) -> Result<Vec<CotpOptions>, CotpError> {
	let mut options = Vec::new();
	let mut start = 0;
	while start < bytes.len() {
		match *bytes.get(start).context(NotEnoughBytes)? {
			0xc0 => {
				let end = start.checked_add(3).context(NotEnoughBytes)?;
				let tpdu_size = TpduSize::from_bytes(
					bytes
						.get(start..end)
						.context(NotEnoughBytes)?
						.try_into()
						.context(SizedSlice)?,
				)?;
				options.push(CotpOptions::TpduSize(tpdu_size));
				start = end;
			}
			0xc2 => {
				let len = *bytes.get(start + 1).context(NotEnoughBytes)? as usize;
				let end = start.checked_add(len + 2).context(NotEnoughBytes)?;
				let ts_el_dst =
					TselDst::from_bytes(bytes.get(start..end).context(NotEnoughBytes)?)?;
				options.push(CotpOptions::TSelDst(ts_el_dst));
				start = end;
			}
			0xc1 => {
				let len = *bytes.get(start + 1).context(NotEnoughBytes)? as usize;
				let end = start.checked_add(len + 2).context(NotEnoughBytes)?;
				let ts_el_src =
					TselSrc::from_bytes(bytes.get(start..end).context(NotEnoughBytes)?)?;
				options.push(CotpOptions::TSelSrc(ts_el_src));
				start = end;
			}
			0xc6 if *bytes.get(start + 1).context(NotEnoughBytes)? == 1 => {
				start = start.checked_add(3).context(NotEnoughBytes)?;
			}
			_ => {
				return InvalidTpduOption.fail();
			}
		}
	}
	Ok(options)
}

/// Convert a vector of COTP options to a byte array.
fn options_to_bytes(options: &[CotpOptions]) -> Vec<u8> {
	let mut bytes = Vec::new();
	for option in options {
		bytes.extend_from_slice(&option.to_bytes());
	}
	bytes
}

/// The options of the COTP TPDU.
#[derive(Debug, Clone)]
enum CotpOptions {
	/// The TPDU size option.
	TpduSize(TpduSize),
	/// The TSelDst option.
	TSelDst(TselDst),
	/// The TSelSrc option.
	TSelSrc(TselSrc),
}

impl CotpOptions {
	/// Convert a COTP option to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		match self {
			CotpOptions::TpduSize(tpdu_size) => tpdu_size.to_bytes().to_vec(),
			CotpOptions::TSelDst(ts_el_dst) => ts_el_dst.to_bytes(),
			CotpOptions::TSelSrc(ts_el_src) => ts_el_src.to_bytes(),
		}
	}
	/// Get the length of the COTP option.
	const fn len(&self) -> usize {
		match self {
			CotpOptions::TpduSize(_) => TpduSize::len(),
			CotpOptions::TSelDst(ts_el_dst) => ts_el_dst.len(),
			CotpOptions::TSelSrc(ts_el_src) => ts_el_src.len(),
		}
	}
}

/// The TPDU size option.
#[derive(Debug, Clone)]
struct TpduSize {
	/// The value of the TPDU size option.
	value: u8,
}

impl TpduSize {
	/// Create a new TPDU size option.
	pub fn new(value: u32) -> Self {
		Self { value: Self::calculate_value(value) }
	}
	/// Get the value of the TPDU size option.
	#[must_use]
	pub const fn get_value(&self) -> u32 {
		1 << self.value
	}
	/// Calculate the value of the TPDU size option.
	fn calculate_value(mut value: u32) -> u8 {
		if !(1..=COTP_MAX_TPDU_SIZE).contains(&value) {
			value = COTP_MAX_TPDU_SIZE;
		}
		value.ilog2() as u8
	}
	/// Convert a byte array to a TPDU size option.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: [u8; 3]) -> Result<Self, CotpError> {
		if bytes[0] != 0xc0 {
			return InvalidTpduSize.fail();
		}
		if bytes[1] != 0x01 {
			return InvalidTpduSize.fail();
		}
		let value = bytes[2];
		// RFC 905 / ISO 8073 class 0 limits the size code to 2^6..=2^13 bytes.
		if !(6..=13).contains(&value) {
			return InvalidTpduSizeValue { value }.fail();
		}
		Ok(Self { value })
	}
	/// Convert a TPDU size option to a byte array.
	#[must_use]
	const fn to_bytes(&self) -> [u8; 3] {
		[0xc0, 0x01, self.value]
	}
	/// Get the length of the TPDU size option.
	const fn len() -> usize {
		3
	}
}

/// The TSelDst option.
#[derive(Debug, Clone)]
struct TselDst {
	/// The value of the TSelDst option.
	value: Vec<u8>,
}

impl TselDst {
	/// Convert a byte array to a TSelDst option.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		if *bytes.first().context(NotEnoughBytes)? != 0xc2 {
			return InvalidTselDst.fail();
		}
		let len = *bytes.get(1).context(NotEnoughBytes)?;
		let value = bytes.get(2..2 + len as usize).context(NotEnoughBytes)?.to_vec();
		Ok(Self { value })
	}
	/// Convert a TSelDst option to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(2 + self.value.len());
		bytes.push(0xc2);
		bytes.push(self.value.len() as u8);
		bytes.extend_from_slice(&self.value);
		bytes
	}
	/// Get the length of the TSelDst option.
	const fn len(&self) -> usize {
		2 + self.value.len()
	}
}

/// The TSelSrc option.
#[derive(Debug, Clone)]
struct TselSrc {
	/// The value of the TSelSrc option.
	value: Vec<u8>,
}

impl TselSrc {
	/// Convert a byte array to a TSelSrc option.
	#[instrument(level = "debug")]
	fn from_bytes(bytes: &[u8]) -> Result<Self, CotpError> {
		if *bytes.first().context(NotEnoughBytes)? != 0xc1 {
			return InvalidTselSrc.fail();
		}
		let len = *bytes.get(1).context(NotEnoughBytes)?;
		let value = bytes.get(2..2 + len as usize).context(NotEnoughBytes)?.to_vec();
		Ok(Self { value })
	}

	/// Convert a TSelSrc option to a byte array.
	fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(2 + self.value.len());
		bytes.push(0xc1);
		bytes.push(self.value.len() as u8);
		bytes.extend_from_slice(&self.value);
		bytes
	}
	/// Get the length of the TSelSrc option.
	const fn len(&self) -> usize {
		2 + self.value.len()
	}
}

/// The error type for the COTP library.
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum CotpError {
	#[snafu(display("Invalid LI value. Expected: {:x}, Got: {:x}", expected, value))]
	InvalidLiValue {
		value: u8,
		expected: u8,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Wrong COTP type"))]
	WrongCotpType {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Connection failed"))]
	ConnectionFailed {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid TPKT version"))]
	InvalidTpktVersion {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("TPKT length {length} is smaller than the 4-byte header"))]
	TpktLengthTooShort {
		length: u16,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("TPKT length {length} exceeds the maximum TPDU size"))]
	TpktLengthTooLarge {
		length: u16,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid TPDU option"))]
	InvalidTpduOption {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid TPDU size option"))]
	InvalidTpduSize {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid TPDU size value {value} (must be in 6..=13)"))]
	InvalidTpduSizeValue {
		value: u8,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid TSelDst option"))]
	InvalidTselDst {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid TSelSrc option"))]
	InvalidTselSrc {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid EOT"))]
	InvalidEot {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Invalid TPDU type. Expected: {:x}, Got: {:x}", *expected as u8, value))]
	InvalidTpduType {
		value: u8,
		expected: TpduType,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Failed to convert to sized slice"))]
	SizedSlice {
		source: std::array::TryFromSliceError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Not enough bytes"))]
	NotEnoughBytes {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Reassembled COTP payload exceeds {limit} bytes; aborting to avoid OOM"))]
	ReassemblyTooLarge {
		limit: usize,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("CR/CC TPDU length indicator {li} does not fit in a u8"))]
	CrCcTooLarge {
		li: usize,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Peer disconnected the transport connection (reason={reason})"))]
	PeerDisconnected {
		reason: u8,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Timed out after {timeout:?} reading the rest of a TPKT frame"))]
	FrameReadTimeout {
		timeout: Duration,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(whatever, display("{message}{context}\n{source:?}"))]
	Whatever {
		message: String,
		#[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
		source: Option<Box<dyn std::error::Error + Send + Sync>>,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
}

impl CotpError {
	/// Get the context of the error.
	#[must_use]
	pub fn get_context(&self) -> &SpanTraceWrapper {
		match self {
			CotpError::InvalidLiValue { context, .. } => context,
			CotpError::WrongCotpType { context } => context,
			CotpError::ConnectionFailed { context } => context,
			CotpError::InvalidTpktVersion { context } => context,
			CotpError::TpktLengthTooShort { context, .. } => context,
			CotpError::TpktLengthTooLarge { context, .. } => context,
			CotpError::InvalidTpduOption { context } => context,
			CotpError::InvalidTpduSize { context } => context,
			CotpError::InvalidTpduSizeValue { context, .. } => context,
			CotpError::InvalidTselDst { context } => context,
			CotpError::InvalidTselSrc { context } => context,
			CotpError::InvalidEot { context } => context,
			CotpError::InvalidTpduType { context, .. } => context,
			CotpError::SizedSlice { context, .. } => context,
			CotpError::NotEnoughBytes { context } => context,
			CotpError::ReassemblyTooLarge { context, .. } => context,
			CotpError::CrCcTooLarge { context, .. } => context,
			CotpError::PeerDisconnected { context, .. } => context,
			CotpError::FrameReadTimeout { context, .. } => context,
			CotpError::Whatever { context, .. } => context,
		}
	}
}

/// Connection
#[derive(Debug)]
enum Connection {
	/// The TCP connection.
	Tcp(TcpStream),
	/// The TLS connection.
	#[cfg(any(feature = "native_tls", feature = "rustls"))]
	Tls(Box<crate::tls::TlsStream>),
}

/// Create a new cotp connection
#[instrument(level = "debug")]
async fn make_connection(config: &ClientConfig) -> Result<Connection, CotpError> {
	let stream = tokio::time::timeout(
		config.connection.connect_timeout,
		TcpStream::connect(format!("{}:{}", config.address, config.port)),
	)
	.await
	.whatever_context("Connection timeout")?
	.whatever_context("Error connecting")?;

	match &config.tls {
		None => Ok(Connection::Tcp(stream)),
		#[cfg(any(feature = "native_tls", feature = "rustls"))]
		Some(tls) => {
			use crate::tls::TlsClientConnector as _;

			let connector = crate::tls::build_client_connector(tls)?;
			Ok(Connection::Tls(Box::new(
				connector
					.connect(&config.address, stream)
					.await
					.whatever_context("Error connecting")?,
			)))
		}
		#[cfg(not(any(feature = "native_tls", feature = "rustls")))]
		Some(_) => {
			whatever!("TLS support is disabled; enable the `native_tls` or `rustls` Cargo feature")
		}
	}
}

impl AsyncRead for Connection {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		match self.get_mut() {
			Connection::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
			#[cfg(any(feature = "native_tls", feature = "rustls"))]
			Connection::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for Connection {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<Result<usize, std::io::Error>> {
		match self.get_mut() {
			Connection::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
			#[cfg(any(feature = "native_tls", feature = "rustls"))]
			Connection::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
		}
	}

	fn poll_flush(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		match self.get_mut() {
			Connection::Tcp(stream) => Pin::new(stream).poll_flush(cx),
			#[cfg(any(feature = "native_tls", feature = "rustls"))]
			Connection::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
		}
	}

	fn poll_shutdown(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), std::io::Error>> {
		match self.get_mut() {
			Connection::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
			#[cfg(any(feature = "native_tls", feature = "rustls"))]
			Connection::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
		}
	}
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
	use super::*;

	// Test data for various scenarios
	const TEST_DATA_SMALL: &[u8] = b"Hello";
	const TEST_DATA_LARGE: &[u8] = b"This is a much longer test message that will be used to test data fragmentation and reassembly in COTP";
	const TEST_T_SEL: &[u8] = &[0x00, 0x01];
	const TEST_T_SEL_LONG: &[u8] = &[0x00, 0x01, 0x02, 0x03];

	#[test]
	fn test_tpdu_type_from_u8() {
		assert_eq!(TpduType::from(0xe0), TpduType::CR);
		assert_eq!(TpduType::from(0xd0), TpduType::CC);
		assert_eq!(TpduType::from(0xf0), TpduType::DT);
		assert_eq!(TpduType::from(0x00), TpduType::Invalid);
		assert_eq!(TpduType::from(0xff), TpduType::Invalid);
	}

	#[test]
	fn test_eot_try_from() -> Result<(), CotpError> {
		assert_eq!(Eot::try_from(0x00)?, Eot::NoEot);
		assert_eq!(Eot::try_from(0x80)?, Eot::Eot);
		assert!(Eot::try_from(0x40).is_err());
		assert!(Eot::try_from(0xff).is_err());
		Ok(())
	}

	#[test]
	fn test_tpdu_size_encoding_decoding() {
		let tpdu_size = TpduSize { value: 13 };
		let bytes = tpdu_size.to_bytes();
		assert_eq!(bytes, [0xc0, 0x01, 13]);

		let decoded = TpduSize::from_bytes(bytes).unwrap();
		assert_eq!(decoded.value, 13);
	}

	#[test]
	fn test_tpdu_size_invalid_encoding() {
		let invalid_bytes = [0xc1, 0x01, 13]; // Wrong option type
		assert!(TpduSize::from_bytes(invalid_bytes).is_err());

		let invalid_bytes = [0xc0, 0x02, 13]; // Wrong length
		assert!(TpduSize::from_bytes(invalid_bytes).is_err());
	}

	#[test]
	fn test_tpdu_size_invalid_value_rejected() {
		// Per RFC 905 the size code must be in 6..=13. Values outside that range
		// would overflow the `1 << value` shift in get_value().
		assert!(matches!(
			TpduSize::from_bytes([0xc0, 0x01, 5]),
			Err(CotpError::InvalidTpduSizeValue { value: 5, .. })
		));
		assert!(matches!(
			TpduSize::from_bytes([0xc0, 0x01, 14]),
			Err(CotpError::InvalidTpduSizeValue { value: 14, .. })
		));
		assert!(matches!(
			TpduSize::from_bytes([0xc0, 0x01, 32]),
			Err(CotpError::InvalidTpduSizeValue { value: 32, .. })
		));
		// Boundaries are accepted.
		assert!(TpduSize::from_bytes([0xc0, 0x01, 6]).is_ok());
		assert!(TpduSize::from_bytes([0xc0, 0x01, 13]).is_ok());
	}

	#[test]
	fn test_bytes_to_options_truncated_does_not_panic() {
		// 0xc2 (TSelDst) claiming 8 bytes of value but only 2 follow.
		let truncated = [0xc2, 0x08, 0x00, 0x01];
		assert!(bytes_to_options(&truncated).is_err());

		// 0xc1 (TSelSrc) with the length byte missing.
		let truncated = [0xc1];
		assert!(bytes_to_options(&truncated).is_err());

		// 0xc0 (TPDU size) header only — needs 3 bytes total.
		let truncated = [0xc0, 0x01];
		assert!(bytes_to_options(&truncated).is_err());

		// 0xc6 vendor option with the length byte missing.
		let truncated = [0xc6];
		assert!(bytes_to_options(&truncated).is_err());

		// Length that would overflow start + len + 2.
		let overflow = [0xc2, 0xff];
		assert!(bytes_to_options(&overflow).is_err());
	}

	#[test]
	fn test_tsel_dst_encoding_decoding() {
		let tsel_dst = TselDst { value: TEST_T_SEL.to_vec() };
		let bytes = tsel_dst.to_bytes();
		assert_eq!(bytes, vec![0xc2, 0x02, 0x00, 0x01]);

		let decoded = TselDst::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.value, TEST_T_SEL);
	}

	#[test]
	fn test_tsel_dst_long_encoding_decoding() {
		let tsel_dst = TselDst { value: TEST_T_SEL_LONG.to_vec() };
		let bytes = tsel_dst.to_bytes();
		assert_eq!(bytes, vec![0xc2, 0x04, 0x00, 0x01, 0x02, 0x03]);

		let decoded = TselDst::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.value, TEST_T_SEL_LONG);
	}

	#[test]
	fn test_tsel_src_encoding_decoding() {
		let tsel_src = TselSrc { value: TEST_T_SEL.to_vec() };
		let bytes = tsel_src.to_bytes();
		assert_eq!(bytes, vec![0xc1, 0x02, 0x00, 0x01]);

		let decoded = TselSrc::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.value, TEST_T_SEL);
	}

	#[test]
	fn test_dt_tpdu_encoding_decoding() {
		let dt_tpdu = DtTpdu::new(Eot::Eot, TEST_DATA_SMALL.to_vec());
		let bytes = dt_tpdu.to_bytes();
		assert_eq!(bytes[0], 0x02); // LI
		assert_eq!(bytes[1], 0xf0); // DT type
		assert_eq!(bytes[2], 0x80); // EOT
		assert_eq!(&bytes[3..], TEST_DATA_SMALL);

		let decoded = DtTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.eot, Eot::Eot);
		assert_eq!(decoded.data, TEST_DATA_SMALL);
	}

	#[test]
	fn test_dt_tpdu_no_eot_encoding_decoding() {
		let dt_tpdu = DtTpdu::new(Eot::NoEot, TEST_DATA_SMALL.to_vec());
		let bytes = dt_tpdu.to_bytes();
		assert_eq!(bytes[0], 0x02); // LI
		assert_eq!(bytes[1], 0xf0); // DT type
		assert_eq!(bytes[2], 0x00); // No EOT
		assert_eq!(&bytes[3..], TEST_DATA_SMALL);

		let decoded = DtTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.eot, Eot::NoEot);
		assert_eq!(decoded.data, TEST_DATA_SMALL);
	}

	#[test]
	fn test_dt_tpdu_invalid_li() {
		let invalid_bytes = [0x03, 0xf0, 0x80]; // Wrong LI
		assert!(DtTpdu::from_bytes(&invalid_bytes).is_err());
	}

	#[test]
	fn test_dt_tpdu_invalid_type() {
		let invalid_bytes = [0x02, 0xe0, 0x80]; // Wrong type (CR instead of DT)
		assert!(DtTpdu::from_bytes(&invalid_bytes).is_err());
	}

	#[test]
	fn test_cr_tpdu_encoding_decoding() {
		let options = vec![
			CotpOptions::TpduSize(TpduSize { value: 13 }),
			CotpOptions::TSelDst(TselDst { value: TEST_T_SEL.to_vec() }),
			CotpOptions::TSelSrc(TselSrc { value: TEST_T_SEL.to_vec() }),
		];
		let cr_tpdu = CrTpdu::new(0x1234, 0x5678, options).unwrap();
		let bytes = cr_tpdu.to_bytes();

		// Verify basic structure
		assert_eq!(bytes[0], 17); // LI = 6 + 3 + 4 + 4 = 17
		assert_eq!(bytes[1], 0xe0); // CR type
		assert_eq!(&bytes[2..4], &[0x12, 0x34]); // dst_ref
		assert_eq!(&bytes[4..6], &[0x56, 0x78]); // src_ref
		assert_eq!(bytes[6], 0x00); // class

		let decoded = CrTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.dst_ref, 0x1234);
		assert_eq!(decoded.src_ref, 0x5678);
		assert_eq!(decoded.options.len(), 3);
	}

	#[test]
	fn test_cc_tpdu_encoding_decoding() {
		let options = vec![
			CotpOptions::TpduSize(TpduSize { value: 13 }),
			CotpOptions::TSelDst(TselDst { value: TEST_T_SEL.to_vec() }),
		];
		let cc_tpdu = CcTpdu::new(0x1234, 0x5678, options).unwrap();
		let bytes = cc_tpdu.to_bytes();

		// Verify basic structure
		assert_eq!(bytes[1], 0xd0); // CC type (this was the bug we fixed)
		assert_eq!(&bytes[2..4], &[0x12, 0x34]); // dst_ref
		assert_eq!(&bytes[4..6], &[0x56, 0x78]); // src_ref
		assert_eq!(bytes[6], 0x00); // class

		let decoded = CcTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.dst_ref, 0x1234);
		assert_eq!(decoded.src_ref, 0x5678);
		assert_eq!(decoded.options.len(), 2);
	}

	#[test]
	fn test_cotp_enum_encoding_decoding() {
		// Test CR
		let options = vec![CotpOptions::TpduSize(TpduSize { value: 13 })];
		let cr_tpdu = CrTpdu::new(0x1234, 0x5678, options).unwrap();
		let cotp = Cotp::Cr(cr_tpdu);
		let bytes = cotp.to_bytes();

		let decoded = Cotp::from_bytes(&bytes).unwrap();
		match decoded {
			Cotp::Cr(decoded_cr) => {
				assert_eq!(decoded_cr.dst_ref, 0x1234);
				assert_eq!(decoded_cr.src_ref, 0x5678);
			}
			_ => panic!("Expected CR TPDU"),
		}

		// Test CC
		let cc_tpdu = CcTpdu::new(0x1234, 0x5678, vec![]).unwrap();
		let cotp = Cotp::Cc(cc_tpdu);
		let bytes = cotp.to_bytes();

		let decoded = Cotp::from_bytes(&bytes).unwrap();
		match decoded {
			Cotp::Cc(decoded_cc) => {
				assert_eq!(decoded_cc.dst_ref, 0x1234);
				assert_eq!(decoded_cc.src_ref, 0x5678);
			}
			_ => panic!("Expected CC TPDU"),
		}

		// Test DT
		let dt_tpdu = DtTpdu::new(Eot::Eot, TEST_DATA_SMALL.to_vec());
		let cotp = Cotp::Dt(dt_tpdu);
		let bytes = cotp.to_bytes();

		let decoded = Cotp::from_bytes(&bytes).unwrap();
		match decoded {
			Cotp::Dt(decoded_dt) => {
				assert_eq!(decoded_dt.eot, Eot::Eot);
				assert_eq!(decoded_dt.data, TEST_DATA_SMALL);
			}
			_ => panic!("Expected DT TPDU"),
		}
	}

	#[test]
	fn test_tpkt_encoding_decoding() {
		let dt_tpdu = DtTpdu::new(Eot::Eot, TEST_DATA_SMALL.to_vec());
		let cotp = Cotp::Dt(dt_tpdu);
		let tpkt = Tpkt::from_cotp(cotp);
		let bytes = tpkt.to_bytes();

		// Verify TPKT header
		assert_eq!(bytes[0], 0x03); // Version
		assert_eq!(bytes[1], 0x00); // Reserved
		let length = u16::from_be_bytes([bytes[2], bytes[3]]);
		assert_eq!(length, 12); // 4 (TPKT) + 3 (COTP) + 5 (data) = 12

		// Verify COTP part
		assert_eq!(bytes[4], 0x02); // LI
		assert_eq!(bytes[5], 0xf0); // DT type
		assert_eq!(bytes[6], 0x80); // EOT
		assert_eq!(&bytes[7..], TEST_DATA_SMALL);
	}

	#[test]
	fn test_cotp_options_roundtrip() {
		let options = vec![
			CotpOptions::TpduSize(TpduSize { value: 13 }),
			CotpOptions::TSelDst(TselDst { value: TEST_T_SEL.to_vec() }),
			CotpOptions::TSelSrc(TselSrc { value: TEST_T_SEL_LONG.to_vec() }),
		];

		let bytes = options_to_bytes(&options);
		let decoded = bytes_to_options(&bytes).unwrap();

		assert_eq!(decoded.len(), 3);

		// Verify each option
		match &decoded[0] {
			CotpOptions::TpduSize(tpdu_size) => assert_eq!(tpdu_size.value, 13),
			_ => panic!("Expected TpduSize option"),
		}

		match &decoded[1] {
			CotpOptions::TSelDst(tsel_dst) => assert_eq!(tsel_dst.value, TEST_T_SEL),
			_ => panic!("Expected TSelDst option"),
		}

		match &decoded[2] {
			CotpOptions::TSelSrc(tsel_src) => assert_eq!(tsel_src.value, TEST_T_SEL_LONG),
			_ => panic!("Expected TSelSrc option"),
		}
	}

	#[test]
	fn test_cotp_invalid_type() {
		let invalid_bytes = [0x02, 0x00, 0x80]; // Invalid TPDU type
		assert!(Cotp::from_bytes(&invalid_bytes).is_err());
	}

	#[test]
	fn test_cotp_insufficient_bytes() {
		let short_bytes = [0x02]; // Too short
		assert!(Cotp::from_bytes(&short_bytes).is_err());
	}

	#[tokio::test]
	async fn test_read_tpkt_length_too_short_does_not_panic() {
		// TPKT header with length=3 (less than the 4-byte header itself).
		// Before the fix this would underflow `length as usize - TPKT_HEADER_SIZE`
		// and panic; it must now return an error cleanly.
		let bytes: &[u8] = &[0x03, 0x00, 0x00, 0x03];
		let mut cursor = bytes;
		let result = CotpReadHalf::read_tpkt(&mut cursor, None).await;
		assert!(matches!(result, Err(CotpError::TpktLengthTooShort { length: 3, .. })));
	}

	#[tokio::test]
	async fn test_read_tpkt_length_too_large_does_not_overallocate() {
		// TPKT length larger than COTP_MAX_TPDU_SIZE (8192) — must be rejected
		// before attempting the payload allocation.
		let bytes: &[u8] = &[0x03, 0x00, 0xff, 0xff];
		let mut cursor = bytes;
		let result = CotpReadHalf::read_tpkt(&mut cursor, None).await;
		assert!(matches!(result, Err(CotpError::TpktLengthTooLarge { length: 0xffff, .. })));
	}

	#[tokio::test]
	async fn test_read_tpkt_frame_timeout_on_stalled_payload() {
		// A valid header promising a 6-byte payload, but the stream then
		// blocks forever. With a frame timeout set, read_tpkt must give up
		// with FrameReadTimeout rather than hang.
		use tokio::io::AsyncRead;
		// A reader that yields the header then never returns more data.
		struct HeaderThenStall {
			header: Vec<u8>,
			pos: usize,
		}
		impl AsyncRead for HeaderThenStall {
			fn poll_read(
				mut self: Pin<&mut Self>,
				_cx: &mut std::task::Context<'_>,
				buf: &mut tokio::io::ReadBuf<'_>,
			) -> std::task::Poll<std::io::Result<()>> {
				if self.pos < self.header.len() {
					let n = (self.header.len() - self.pos).min(buf.remaining());
					let end = self.pos + n;
					buf.put_slice(&self.header[self.pos..end]);
					self.pos = end;
					std::task::Poll::Ready(Ok(()))
				} else {
					// Stall forever.
					std::task::Poll::Pending
				}
			}
		}

		// TPKT length 10 => 6-byte payload that never arrives.
		let mut reader = HeaderThenStall { header: vec![0x03, 0x00, 0x00, 0x0a], pos: 0 };
		let result = CotpReadHalf::read_tpkt(&mut reader, Some(Duration::from_millis(50))).await;
		assert!(matches!(result, Err(CotpError::FrameReadTimeout { .. })));
	}

	#[test]
	fn test_dt_tpdu_large_data() {
		let dt_tpdu = DtTpdu::new(Eot::Eot, TEST_DATA_LARGE.to_vec());
		let bytes = dt_tpdu.to_bytes();

		let decoded = DtTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.eot, Eot::Eot);
		assert_eq!(decoded.data, TEST_DATA_LARGE);
	}

	#[test]
	fn test_dr_tpdu_roundtrip() {
		let dr = DrTpdu { dst_ref: 0x1234, src_ref: 0x5678, reason: 0x80 };
		let bytes = dr.to_bytes();
		assert_eq!(bytes[0], 6); // LI
		assert_eq!(bytes[1], 0x80); // DR type
		assert_eq!(&bytes[2..4], &[0x12, 0x34]);
		assert_eq!(&bytes[4..6], &[0x56, 0x78]);
		assert_eq!(bytes[6], 0x80); // reason

		let decoded = DrTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.dst_ref, 0x1234);
		assert_eq!(decoded.src_ref, 0x5678);
		assert_eq!(decoded.reason, 0x80);

		// And dispatches through the Cotp enum.
		assert!(matches!(Cotp::from_bytes(&bytes), Ok(Cotp::Dr(_))));
	}

	#[test]
	fn test_dc_tpdu_roundtrip() {
		let dc = DcTpdu { dst_ref: 0x1234, src_ref: 0x5678 };
		let bytes = dc.to_bytes();
		assert_eq!(bytes[0], 5); // LI
		assert_eq!(bytes[1], 0xc0); // DC type
		let decoded = DcTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.dst_ref, 0x1234);
		assert_eq!(decoded.src_ref, 0x5678);
		assert!(matches!(Cotp::from_bytes(&bytes), Ok(Cotp::Dc(_))));
	}

	#[tokio::test]
	async fn test_receive_data_clean_disconnect_on_dr() {
		// A DR TPDU arriving where data is expected must surface as a clean
		// PeerDisconnected error rather than WrongCotpType.
		let dr = DrTpdu { dst_ref: 1, src_ref: 2, reason: 0 };
		let tpkt = Tpkt::from_cotp(Cotp::Dr(dr));
		let bytes = tpkt.to_bytes();
		let mut cursor = &bytes[..];
		let result = CotpReadHalf::receive_data_from(&mut cursor, None).await;
		assert!(matches!(result, Err(CotpError::PeerDisconnected { reason: 0, .. })));
	}

	#[test]
	fn test_cr_tpdu_no_options() {
		let cr_tpdu = CrTpdu::new(0x1234, 0x5678, vec![]).unwrap();
		let bytes = cr_tpdu.to_bytes();

		// Should have LI = 6 (no options)
		assert_eq!(bytes[0], 6);
		assert_eq!(bytes[1], 0xe0); // CR type
		assert_eq!(&bytes[2..4], &[0x12, 0x34]); // dst_ref
		assert_eq!(&bytes[4..6], &[0x56, 0x78]); // src_ref
		assert_eq!(bytes[6], 0x00); // class

		let decoded = CrTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.dst_ref, 0x1234);
		assert_eq!(decoded.src_ref, 0x5678);
		assert_eq!(decoded.options.len(), 0);
	}

	#[test]
	fn test_cc_tpdu_no_options() {
		let cc_tpdu = CcTpdu::new(0x1234, 0x5678, vec![]).unwrap();
		let bytes = cc_tpdu.to_bytes();

		// Should have LI = 6 (no options)
		assert_eq!(bytes[0], 6);
		assert_eq!(bytes[1], 0xd0); // CC type
		assert_eq!(&bytes[2..4], &[0x12, 0x34]); // dst_ref
		assert_eq!(&bytes[4..6], &[0x56, 0x78]); // src_ref
		assert_eq!(bytes[6], 0x00); // class

		let decoded = CcTpdu::from_bytes(&bytes).unwrap();
		assert_eq!(decoded.dst_ref, 0x1234);
		assert_eq!(decoded.src_ref, 0x5678);
		assert_eq!(decoded.options.len(), 0);
	}

	#[test]
	fn test_cotp_len_calculation() {
		let dt_tpdu = DtTpdu::new(Eot::Eot, TEST_DATA_SMALL.to_vec());
		let cotp = Cotp::Dt(dt_tpdu);
		assert_eq!(cotp.len(), 8); // 3 (header) + 5 (data)

		let options = vec![CotpOptions::TpduSize(TpduSize { value: 13 })];
		let cr_tpdu = CrTpdu::new(0x1234, 0x5678, options).unwrap();
		let cotp = Cotp::Cr(cr_tpdu);
		assert_eq!(cotp.len(), 10); // 6 (header) + 3 (tpdu_size) + 1 (li includes options)
	}

	#[test]
	fn test_cr_tpdu_li_overflow_rejected() {
		// Three TSelDst options each carrying 250 bytes of value pushes the LI
		// above 254 and must be rejected at construction time instead of
		// silently truncating.
		let big = vec![0_u8; 250];
		let options = vec![
			CotpOptions::TSelDst(TselDst { value: big.clone() }),
			CotpOptions::TSelDst(TselDst { value: big.clone() }),
			CotpOptions::TSelDst(TselDst { value: big }),
		];
		assert!(matches!(CrTpdu::new(0, 1, options), Err(CotpError::CrCcTooLarge { .. })));
	}

	#[tokio::test]
	async fn test_receive_data_caps_reassembled_payload() {
		// Build a stream of NoEot DT TPDUs large enough that their cumulative
		// payload would exceed COTP_MAX_REASSEMBLED_SIZE. The reader must
		// stop with ReassemblyTooLarge rather than keep accumulating.
		let payload_len = (COTP_MAX_TPDU_SIZE as usize) - COTP_DT_HEADER_SIZE;
		let tpkt_len = (TPKT_HEADER_SIZE + COTP_DT_HEADER_SIZE + payload_len) as u16;
		let header = [
			TPKT_VERSION,
			0,
			(tpkt_len >> 8) as u8,
			tpkt_len as u8,
			0x02, // LI
			TpduType::DT as u8,
			Eot::NoEot as u8,
		];
		let needed = (COTP_MAX_REASSEMBLED_SIZE / payload_len) + 2;
		let mut buf = Vec::with_capacity(needed * (header.len() + payload_len));
		for _ in 0..needed {
			buf.extend_from_slice(&header);
			buf.resize(buf.len() + payload_len, 0);
		}
		let mut cursor = &buf[..];
		let result = CotpReadHalf::receive_data_from(&mut cursor, None).await;
		assert!(matches!(result, Err(CotpError::ReassemblyTooLarge { .. })));
	}

	#[test]
	fn test_tpkt_length_calculation() {
		let dt_tpdu = DtTpdu::new(Eot::Eot, TEST_DATA_SMALL.to_vec());
		let cotp = Cotp::Dt(dt_tpdu);
		let tpkt = Tpkt::from_cotp(cotp);

		// TPKT length should be TPKT_HEADER_SIZE + COTP length
		assert_eq!(tpkt.length, 4 + 8); // 4 (TPKT header) + 8 (COTP + data)
	}
}
