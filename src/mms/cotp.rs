use std::pin::Pin;
use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use snafu::{OptionExt as _, ResultExt as _, Snafu, whatever};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::{
    TlsConnector, TlsStream,
    native_tls::{Certificate, Identity},
};
use tracing::instrument;

use crate::mms::SpanTraceWrapper;

const TPKT_VERSION: u8 = 0x03;
const COTP_MAX_TPDU_SIZE: usize = 8192;
const COTP_DT_HEADER_SIZE: usize = 3;
const TPKT_HEADER_SIZE: usize = 4;

#[derive(Debug)]
pub struct CotpConnection {
    connection: Connection,
    tpdu_size: u32,
}

impl CotpConnection {
    #[instrument(level = "debug")]
    pub async fn connect(config: &ClientConfig) -> Result<Self, Error> {
        let connection = make_connection(config).await?;
        Self::request_connection(connection, config).await
    }
    #[instrument(level = "debug", skip(config))]
    async fn request_connection(
        mut connection: Connection,
        config: &ClientConfig,
    ) -> Result<Self, Error> {
        let options = vec![
            CotpOptions::TpduSize(TpduSize {
                //TODO: Make this configurable
                value: COTP_MAX_TPDU_SIZE as u8,
            }),
            CotpOptions::TSelDst(TselDst {
                value: config.remote_t_sel.clone(),
            }),
            CotpOptions::TSelSrc(TselSrc {
                value: config.local_t_sel.clone(),
            }),
        ];

        let local_ref = 1;

        let tpkt = Tpkt::from_cotp(Cotp::Cr(CrTpdu::new(0, local_ref, options)));
        connection
            .write_all(&tpkt.to_bytes())
            .await
            .whatever_context("Error writing to connection")?;

        let tpkt = Self::read_tpkt(&mut connection).await?;

        if !matches!(tpkt.cotp, Cotp::Cc(_)) {
            return WrongCotpType.fail();
        }
        if let Cotp::Cc(cc_tpdu) = &tpkt.cotp
            && cc_tpdu.dst_ref == local_ref
        {
            return Ok(Self {
                connection,
                //TODO: Fix this
                tpdu_size: COTP_MAX_TPDU_SIZE as u32,
            });
        }

        ConnectionFailed.fail()
    }
    #[instrument(level = "debug", skip(self))]
    pub async fn send_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let max_dt_data_size = self.tpdu_size as usize - COTP_DT_HEADER_SIZE;
        let num_dts = data.len().div_ceil(max_dt_data_size);
        let buffer_size = num_dts * (TPKT_HEADER_SIZE + COTP_DT_HEADER_SIZE) + data.len();
        let mut buffer = Vec::with_capacity(buffer_size);
        for (i, chunk) in data.chunks(max_dt_data_size).enumerate() {
            let eot = if i == num_dts - 1 {
                Eot::Eot
            } else {
                Eot::NoEot
            };
            let dt_tpdu = Cotp::Dt(DtTpdu::new(eot, chunk.to_vec()));
            //TODO: This needs to be optimized
            buffer.extend_from_slice(&Tpkt::from_cotp(dt_tpdu).to_bytes());
        }

        self.connection
            .write_all(&buffer)
            .await
            .whatever_context("Error writing to connection")?;

        Ok(())
    }
    #[instrument(level = "debug", skip(self))]
    pub async fn receive_data(&mut self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        loop {
            match Self::read_tpkt(&mut self.connection).await {
                Ok(tpkt) => match tpkt.cotp {
                    Cotp::Dt(dt) => {
                        data.extend_from_slice(&dt.data);
                        if dt.eot == Eot::Eot {
                            break;
                        }
                    }
                    _ => return WrongCotpType.fail(),
                },
                Err(e) => {
                    println!("Error reading TPKT: {:?}", e);
                    return Err(e);
                }
            }
        }
        Ok(data)
    }

    #[instrument(level = "debug", skip(connection))]
    async fn read_tpkt(connection: &mut Connection) -> Result<Tpkt, Error> {
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

        //TODO: This needs to be optimized. Make this static and always clean it before use.
        let mut buffer = vec![0; length as usize - TPKT_HEADER_SIZE];
        connection
            .read_exact(&mut buffer)
            .await
            .whatever_context("Error reading from connection")?;
        let cotp = Cotp::from_bytes(&buffer)?;

        Ok(Tpkt::from_cotp(cotp))
    }
}

#[derive(Debug, Clone)]
struct Tpkt {
    length: u16, //includes the header. The tpdu length is length - 4
    cotp: Cotp,
}

impl Tpkt {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.length as usize);
        bytes.push(TPKT_VERSION);
        bytes.push(0x00);
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.cotp.to_bytes());
        bytes
    }
    #[instrument(level = "debug")]
    fn from_cotp(cotp: Cotp) -> Self {
        Self {
            length: (cotp.len() + TPKT_HEADER_SIZE) as u16,
            cotp,
        }
    }
}

#[derive(Debug, Clone)]
enum Cotp {
    Cr(CrTpdu),
    Cc(CcTpdu),
    Dt(DtTpdu),
}

impl Cotp {
    #[instrument(level = "debug")]
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match (*bytes.get(1).context(NotEnoughBytes)?).into() {
            TpduType::CR => CrTpdu::from_bytes(bytes).map(Self::Cr),
            TpduType::CC => CcTpdu::from_bytes(bytes).map(Self::Cc),
            TpduType::DT => DtTpdu::from_bytes(bytes).map(Self::Dt),
            _ => InvalidTpduType {
                value: *bytes.get(1).context(NotEnoughBytes)?,
                expected: TpduType::Invalid,
            }
            .fail(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Cr(tpdu) => tpdu.to_bytes(),
            Self::Cc(tpdu) => tpdu.to_bytes(),
            Self::Dt(tpdu) => tpdu.to_bytes(),
        }
    }
    fn len(&self) -> usize {
        match self {
            Self::Cr(tpdu) => tpdu.len(),
            Self::Cc(tpdu) => tpdu.len(),
            Self::Dt(tpdu) => tpdu.len(),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpduType {
    CR = 0xe0,
    CC = 0xd0,
    DT = 0xf0,
    Invalid = 0xff,
}

impl From<u8> for TpduType {
    #[instrument(level = "debug")]
    fn from(value: u8) -> Self {
        match value {
            val if val == TpduType::CR as u8 => TpduType::CR,
            val if val == TpduType::CC as u8 => TpduType::CC,
            val if val == TpduType::DT as u8 => TpduType::DT,
            _ => TpduType::Invalid,
        }
    }
}

#[derive(Debug, Clone)]
struct CrTpdu {
    li: u8,
    dst_ref: u16,
    src_ref: u16,
    // class: u8, -> Always 0
    options: Vec<CotpOptions>,
}

impl CrTpdu {
    fn new(dst_ref: u16, src_ref: u16, options: Vec<CotpOptions>) -> Self {
        Self {
            li: (options.iter().map(|option| option.len()).sum::<usize>() + 6) as u8,
            dst_ref,
            src_ref,
            options,
        }
    }
    #[instrument(level = "debug")]
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let li = *bytes.first().context(NotEnoughBytes)?;

        if *bytes.get(1).context(NotEnoughBytes)? != TpduType::CR as u8 {
            return InvalidTpduType {
                value: *bytes.get(1).context(NotEnoughBytes)?,
                expected: TpduType::CR,
            }
            .fail();
        }

        let dst_ref = u16::from_be_bytes(
            bytes
                .get(2..4)
                .context(NotEnoughBytes)?
                .try_into()
                .context(SizedSlice)?,
        );
        let src_ref = u16::from_be_bytes(
            bytes
                .get(4..6)
                .context(NotEnoughBytes)?
                .try_into()
                .context(SizedSlice)?,
        );
        //skip class- must always be 0
        // The size of options is LI - 6. So the options goes from 7 to 7+size of options.
        let options = bytes_to_options(bytes.get(7..li as usize + 1).context(NotEnoughBytes)?)?;

        Ok(Self {
            li,
            dst_ref,
            src_ref,
            options,
        })
    }

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
    fn len(&self) -> usize {
        self.li as usize + 1
    }
}

#[derive(Debug, Clone)]
struct CcTpdu {
    li: u8,
    dst_ref: u16,
    src_ref: u16,
    // class: u8, -> Always 0
    options: Vec<CotpOptions>,
}

impl CcTpdu {
    fn new(dst_ref: u16, src_ref: u16, options: Vec<CotpOptions>) -> Self {
        Self {
            li: (options.iter().map(|option| option.len()).sum::<usize>() + 6) as u8,
            dst_ref,
            src_ref,
            options,
        }
    }
    #[instrument(level = "debug")]
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let li = *bytes.first().context(NotEnoughBytes)?;

        if *bytes.get(1).context(NotEnoughBytes)? != TpduType::CC as u8 {
            return InvalidTpduType {
                value: *bytes.get(1).context(NotEnoughBytes)?,
                expected: TpduType::CC,
            }
            .fail();
        }

        let dst_ref = u16::from_be_bytes(
            bytes
                .get(2..4)
                .context(NotEnoughBytes)?
                .try_into()
                .context(SizedSlice)?,
        );
        let src_ref = u16::from_be_bytes(
            bytes
                .get(4..6)
                .context(NotEnoughBytes)?
                .try_into()
                .context(SizedSlice)?,
        );
        //skip class- must always be 0
        // The size of options is LI - 6. So the options goes from 7 to 7+size of options.
        let options = bytes_to_options(bytes.get(7..li as usize + 1).context(NotEnoughBytes)?)?;

        Ok(Self {
            li,
            dst_ref,
            src_ref,
            options,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.li as usize + 6);
        bytes.push(self.li);
        bytes.push(TpduType::CC as u8);
        bytes.extend_from_slice(&self.dst_ref.to_be_bytes());
        bytes.extend_from_slice(&self.src_ref.to_be_bytes());
        bytes.push(0x00); // class 0
        bytes.extend_from_slice(&options_to_bytes(&self.options));
        bytes
    }
    fn len(&self) -> usize {
        self.li as usize + 1
    }
}

#[derive(Debug, Clone)]
struct DtTpdu {
    eot: Eot,
    data: Vec<u8>,
}

impl DtTpdu {
    fn new(eot: Eot, data: Vec<u8>) -> Self {
        Self { eot, data }
    }
    #[instrument(level = "debug")]
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
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

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.data.len());
        bytes.push(0x02); // LI
        bytes.push(TpduType::DT as u8);
        bytes.push(self.eot as u8);
        bytes.extend_from_slice(&self.data);
        bytes
    }
    fn len(&self) -> usize {
        3 + self.data.len()
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Eot {
    NoEot = 0x00,
    Eot = 0x80,
}

impl TryFrom<u8> for Eot {
    type Error = Error;
    #[instrument(level = "debug")]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Eot::NoEot),
            0x80 => Ok(Eot::Eot),
            _ => InvalidEot.fail(),
        }
    }
}

#[instrument(level = "debug")]
fn bytes_to_options(bytes: &[u8]) -> Result<Vec<CotpOptions>, Error> {
    let mut options = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        match *bytes.get(start).context(NotEnoughBytes)? {
            0xc0 => {
                let tpdu_size = TpduSize::from_bytes(
                    bytes
                        .get(start..start + 3)
                        .context(NotEnoughBytes)?
                        .try_into()
                        .context(SizedSlice)?,
                )?;
                options.push(CotpOptions::TpduSize(tpdu_size));
                start += 3;
            }
            0xc2 => {
                let len = bytes[start + 1] as usize;
                let ts_el_dst = TselDst::from_bytes(&bytes[start..start + len + 2])?;
                options.push(CotpOptions::TSelDst(ts_el_dst));
                start += len + 2;
            }
            0xc1 => {
                let len = bytes[start + 1] as usize;
                let ts_el_src = TselSrc::from_bytes(&bytes[start..start + len + 2])?;
                options.push(CotpOptions::TSelSrc(ts_el_src));
                start += len + 2;
            }
            0xc6 if bytes[start + 1] == 1 => {
                start += 3;
            }
            _ => {
                return InvalidTpduOption.fail();
            }
        }
    }
    Ok(options)
}

fn options_to_bytes(options: &[CotpOptions]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for option in options {
        bytes.extend_from_slice(&option.to_bytes());
    }
    bytes
}

#[derive(Debug, Clone)]
enum CotpOptions {
    TpduSize(TpduSize),
    TSelDst(TselDst),
    TSelSrc(TselSrc),
}

impl CotpOptions {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            CotpOptions::TpduSize(tpdu_size) => tpdu_size.to_bytes().to_vec(),
            CotpOptions::TSelDst(ts_el_dst) => ts_el_dst.to_bytes(),
            CotpOptions::TSelSrc(ts_el_src) => ts_el_src.to_bytes(),
        }
    }
    fn len(&self) -> usize {
        match self {
            CotpOptions::TpduSize(tpdu_size) => tpdu_size.len(),
            CotpOptions::TSelDst(ts_el_dst) => ts_el_dst.len(),
            CotpOptions::TSelSrc(ts_el_src) => ts_el_src.len(),
        }
    }
}

#[derive(Debug, Clone)]
struct TpduSize {
    value: u8,
}

impl TpduSize {
    #[instrument(level = "debug")]
    fn from_bytes(bytes: &[u8; 3]) -> Result<Self, Error> {
        if bytes[0] != 0xc0 {
            return InvalidTpduSize.fail();
        }
        if bytes[1] != 0x01 {
            return InvalidTpduSize.fail();
        }
        //TODO: I think we need to do a shift here
        let value = bytes[2];
        Ok(Self { value })
    }
    fn to_bytes(&self) -> [u8; 3] {
        [0xc0, 0x01, self.value]
    }
    fn len(&self) -> usize {
        3
    }
}

#[derive(Debug, Clone)]
struct TselDst {
    value: Vec<u8>,
}

impl TselDst {
    #[instrument(level = "debug")]
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if *bytes.first().context(NotEnoughBytes)? != 0xc2 {
            return InvalidTselDst.fail();
        }
        let len = *bytes.get(1).context(NotEnoughBytes)?;
        let value = bytes
            .get(2..2 + len as usize)
            .context(NotEnoughBytes)?
            .to_vec();
        Ok(Self { value })
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.value.len());
        bytes.push(0xc2);
        bytes.push(self.value.len() as u8);
        bytes.extend_from_slice(&self.value);
        bytes
    }
    fn len(&self) -> usize {
        2 + self.value.len()
    }
}

#[derive(Debug, Clone)]
struct TselSrc {
    value: Vec<u8>,
}

impl TselSrc {
    #[instrument(level = "debug")]
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if *bytes.first().context(NotEnoughBytes)? != 0xc1 {
            return InvalidTselSrc.fail();
        }
        let len = *bytes.get(1).context(NotEnoughBytes)?;
        let value = bytes
            .get(2..2 + len as usize)
            .context(NotEnoughBytes)?
            .to_vec();
        Ok(Self { value })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.value.len());
        bytes.push(0xc1);
        bytes.push(self.value.len() as u8);
        bytes.extend_from_slice(&self.value);
        bytes
    }
    fn len(&self) -> usize {
        2 + self.value.len()
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum Error {
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
    #[snafu(whatever, display("{message}{context}\n{source:?}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
}

//TODO: Split this into multiple configs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientConfig {
    /// The address of the server.
    pub address: String,
    /// The port of the server.
    pub port: u16,
    pub local_t_sel: Vec<u8>,
    pub remote_t_sel: Vec<u8>,
    pub local_s_sel: Vec<u8>,
    pub remote_s_sel: Vec<u8>,
    pub local_p_sel: Vec<u8>,
    pub remote_p_sel: Vec<u8>,
    pub local_ap_title: Option<Vec<u32>>,
    pub remote_ap_title: Option<Vec<u32>>,
    pub local_ae_qualifier: Option<u32>,
    pub remote_ae_qualifier: Option<u32>,
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

/// Connection
#[derive(Debug)]
enum Connection {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

#[instrument(level = "debug")]
async fn make_connection(config: &ClientConfig) -> Result<Connection, Error> {
    let stream = tokio::time::timeout(
        //TODO: Make this configurable
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:{}", config.address, config.port)),
    )
    .await
    .whatever_context("Connection timeout")?
    .whatever_context("Error connecting")?;

    Ok(if let Some(ref tls) = config.tls {
        let connector = make_tls_connector(tls)?;
        Connection::Tls(
            connector
                .connect(&config.address, stream)
                .await
                .whatever_context("Error connecting")?,
        )
    } else {
        Connection::Tcp(stream)
    })
}

#[instrument(level = "debug")]
fn make_tls_connector(tls: &TlsClientConfig) -> Result<TlsConnector, Error> {
    let root_cert: Option<Certificate> = tls
        .server_certificate
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .whatever_context("Failed to read server certificate")?
        .map(|cert_data| Certificate::from_pem(cert_data.as_slice()))
        .transpose()
        .whatever_context("Invalid server certificate")?;

    let identity: Option<Identity> = match (&tls.client_key, &tls.client_certificate) {
        (Some(client_key), Some(client_cert)) => Some(
            Identity::from_pkcs8(
                std::fs::read(client_cert)
                    .whatever_context("Failed to read client certificate")?
                    .as_slice(),
                std::fs::read(client_key)
                    .whatever_context("Failed to read client key")?
                    .as_slice(),
            )
            .whatever_context("Could not create client identity")?,
        ),
        (None, None) => None,
        _ => whatever!("Both client key *and* certificate must be specified"),
    };

    let mut connector = tokio_native_tls::native_tls::TlsConnector::builder();

    if let Some(root_cert) = root_cert {
        connector.add_root_certificate(root_cert);
    }

    if let Some(identity) = identity {
        connector.identity(identity);
    }

    connector.danger_accept_invalid_certs(tls.danger_disable_tls_verify);

    let connector = connector
        .build()
        .whatever_context("Error building TLS connector")?;
    Ok(TlsConnector::from(connector))
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Connection::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Connection::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
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
            Connection::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Connection::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Connection::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Connection::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Connection::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

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
    fn test_eot_try_from() -> Result<(), Error> {
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

        let decoded = TpduSize::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.value, 13);
    }

    #[test]
    fn test_tpdu_size_invalid_encoding() {
        let invalid_bytes = [0xc1, 0x01, 13]; // Wrong option type
        assert!(TpduSize::from_bytes(&invalid_bytes).is_err());

        let invalid_bytes = [0xc0, 0x02, 13]; // Wrong length
        assert!(TpduSize::from_bytes(&invalid_bytes).is_err());
    }

    #[test]
    fn test_tsel_dst_encoding_decoding() {
        let tsel_dst = TselDst {
            value: TEST_T_SEL.to_vec(),
        };
        let bytes = tsel_dst.to_bytes();
        assert_eq!(bytes, vec![0xc2, 0x02, 0x00, 0x01]);

        let decoded = TselDst::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.value, TEST_T_SEL);
    }

    #[test]
    fn test_tsel_dst_long_encoding_decoding() {
        let tsel_dst = TselDst {
            value: TEST_T_SEL_LONG.to_vec(),
        };
        let bytes = tsel_dst.to_bytes();
        assert_eq!(bytes, vec![0xc2, 0x04, 0x00, 0x01, 0x02, 0x03]);

        let decoded = TselDst::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.value, TEST_T_SEL_LONG);
    }

    #[test]
    fn test_tsel_src_encoding_decoding() {
        let tsel_src = TselSrc {
            value: TEST_T_SEL.to_vec(),
        };
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
            CotpOptions::TSelDst(TselDst {
                value: TEST_T_SEL.to_vec(),
            }),
            CotpOptions::TSelSrc(TselSrc {
                value: TEST_T_SEL.to_vec(),
            }),
        ];
        let cr_tpdu = CrTpdu::new(0x1234, 0x5678, options);
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
            CotpOptions::TSelDst(TselDst {
                value: TEST_T_SEL.to_vec(),
            }),
        ];
        let cc_tpdu = CcTpdu::new(0x1234, 0x5678, options);
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
        let cr_tpdu = CrTpdu::new(0x1234, 0x5678, options);
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
        let cc_tpdu = CcTpdu::new(0x1234, 0x5678, vec![]);
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
            CotpOptions::TSelDst(TselDst {
                value: TEST_T_SEL.to_vec(),
            }),
            CotpOptions::TSelSrc(TselSrc {
                value: TEST_T_SEL_LONG.to_vec(),
            }),
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

    #[test]
    fn test_dt_tpdu_large_data() {
        let dt_tpdu = DtTpdu::new(Eot::Eot, TEST_DATA_LARGE.to_vec());
        let bytes = dt_tpdu.to_bytes();

        let decoded = DtTpdu::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.eot, Eot::Eot);
        assert_eq!(decoded.data, TEST_DATA_LARGE);
    }

    #[test]
    fn test_cr_tpdu_no_options() {
        let cr_tpdu = CrTpdu::new(0x1234, 0x5678, vec![]);
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
        let cc_tpdu = CcTpdu::new(0x1234, 0x5678, vec![]);
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
        let cr_tpdu = CrTpdu::new(0x1234, 0x5678, options);
        let cotp = Cotp::Cr(cr_tpdu);
        assert_eq!(cotp.len(), 10); // 6 (header) + 3 (tpdu_size) + 1 (li includes options)
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
