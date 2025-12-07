//! ISO Presentation Layer Implementation (ISO 8327)

use async_trait::async_trait;
use lazy_static::lazy_static;
use rasn::{ber, prelude::*};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use tracing::instrument;

use crate::mms::{
	ClientConfig, ReadHalfConnection, SpanTraceWrapper, WriteHalfConnection,
	ans1::presentation::asn1::*,
	session::{Session, SessionError, SessionReadHalf, SessionWriteHalf},
};

/// The ACSE OID.
const ACSE_OID: [u32; 5] = [2, 2, 1, 0, 1];
/// The MMS OID.
const MMS_OID: [u32; 5] = [1, 0, 9506, 2, 1];
/// The BER OID.
const BER_OID: [u32; 3] = [2, 1, 1];

/// The ACSE context ID.
const ACSE_CONTEXT_ID: u64 = 1;
/// The MMS context ID.
const MMS_CONTEXT_ID: u64 = 3;

lazy_static! {
	static ref BER_OID_OBJECT_IDENTIFIER: ObjectIdentifier = #[allow(clippy::expect_used)]
	ObjectIdentifier::new(&BER_OID)
		.expect("BER OID is valid");
	static ref ACSE_OID_OBJECT_IDENTIFIER: ObjectIdentifier = #[allow(clippy::expect_used)]
	ObjectIdentifier::new(&ACSE_OID)
		.expect("ACSE OID is valid");
	static ref MMS_OID_OBJECT_IDENTIFIER: ObjectIdentifier = #[allow(clippy::expect_used)]
	ObjectIdentifier::new(&MMS_OID)
		.expect("MMS OID is valid");
	static ref PRESENTATION_CONTEXT_DEFINITION_LIST: PresentationContextDefinitionList =
		PresentationContextDefinitionList(ContextList(vec![
			AnonymousContextList {
				presentation_context_identifier: PresentationContextIdentifier(Integer::from(
					ACSE_CONTEXT_ID,
				)),
				abstract_syntax_name: AbstractSyntaxName(ACSE_OID_OBJECT_IDENTIFIER.clone()),
				transfer_syntax_name_list: vec![TransferSyntaxName(
					BER_OID_OBJECT_IDENTIFIER.clone()
				)],
			},
			AnonymousContextList {
				presentation_context_identifier: PresentationContextIdentifier(Integer::from(
					MMS_CONTEXT_ID,
				)),
				abstract_syntax_name: AbstractSyntaxName(MMS_OID_OBJECT_IDENTIFIER.clone()),
				transfer_syntax_name_list: vec![TransferSyntaxName(
					BER_OID_OBJECT_IDENTIFIER.clone()
				)],
			},
		]));
}

/// Presentation layer.
#[derive(Debug)]
pub struct Presentation {
	/// The session connection.
	session: Session,
	/// The local presentation selector.
	local_p_sel: CallingPresentationSelector,
	/// The remote presentation selector.
	remote_p_sel: CalledPresentationSelector,
}

impl Presentation {
	/// Create a new presentation layer connection.
	#[instrument]
	pub async fn new(config: &ClientConfig) -> std::result::Result<Self, PresentationError> {
		let session = Session::new(config).await.context(CreateSession)?;
		Ok(Self {
			session,
			local_p_sel: CallingPresentationSelector(PresentationSelector(OctetString::from(
				config.connection.local_p_sel.as_ref(),
			))),
			remote_p_sel: CalledPresentationSelector(PresentationSelector(OctetString::from(
				config.connection.remote_p_sel.as_ref(),
			))),
		})
	}

	/// Connect to the remote presentation.
	#[instrument(skip(self))]
	pub async fn connect(
		&mut self,
		data: Vec<u8>,
	) -> std::result::Result<(Vec<u8>, u64), PresentationError> {
		let cp = Self::make_cp_ppdu(self.local_p_sel.clone(), self.remote_p_sel.clone(), data);
		let cp_bytes = ber::encode(&cp).context(EncodeCp)?;
		let response = self.session.connect(&cp_bytes).await?;
		let cpa: CPAPPDU = ber::decode(&response).context(DecodeCpa)?;
		//TODO: Check the CPA for errors

		let user_data = cpa
			.normal_mode_parameters
			.context(MissingNormalModeParameters)?
			.user_data
			.context(MissingUserData)?;
		let mut pdvs = match user_data {
			UserData::fully_encoded_data(data) => data.0,
			UserData::simply_encoded_data(_) => {
				return UnsupportedUserData.fail();
			}
		};
		//TODO: Do I need to look at all the PDVs?
		let pdv = pdvs.pop().context(MissingPdv)?;
		let context_id = pdv
			.presentation_context_identifier
			.0
			.try_into()
			.map_err(|_| InvalidContextId.build())?;
		let user_data = pdv.presentation_data_values;
		match user_data {
			PDVListPresentationDataValues::single_ASN1_type(data) => {
				Ok((data.into_bytes(), context_id))
			}
			_ => UnsupportedPresentationDataValues.fail(),
		}
	}

	/// Split the presentation layer connection into a read half and a write
	/// half.
	#[must_use]
	pub fn split(self) -> (PresentationReadHalf, PresentationWriteHalf) {
		let (session_read, session_write) = self.session.split();
		(
			PresentationReadHalf { session_connection: session_read },
			PresentationWriteHalf { session_connection: session_write },
		)
	}

	/// Make a CP PPDU
	fn make_cp_ppdu(
		local_p_sel: CallingPresentationSelector,
		remote_p_sel: CalledPresentationSelector,
		data: Vec<u8>,
	) -> CPType {
		let p_context_id = PresentationContextIdentifier(Integer::from(1));
		let p_data_values = PDVListPresentationDataValues::from(Any::from(data));
		let p_list = PDVList::new(None, p_context_id, p_data_values);
		let p_data = FullyEncodedData(vec![p_list]);

		let normal_mode_params = CPTypeNormalModeParameters::new(
			ProtocolVersion([true].into_iter().collect()),
			Some(local_p_sel),
			Some(remote_p_sel),
			Some(PRESENTATION_CONTEXT_DEFINITION_LIST.clone()),
			None,
			None,
			None,
			Some(UserData::fully_encoded_data(p_data)),
		);
		CPType::new(ModeSelector::new(Integer::from(1)), Some(normal_mode_params))
	}
}

#[async_trait]
impl WriteHalfConnection for Presentation {
	type Error = PresentationError;

	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> std::result::Result<(), Self::Error> {
		PresentationWriteHalf::send_data_internal(&mut self.session, data).await
	}
}

#[async_trait]
impl ReadHalfConnection for Presentation {
	type Error = PresentationError;

	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> std::result::Result<Vec<u8>, Self::Error> {
		PresentationReadHalf::receive_data_internal(&mut self.session)
			.await
			.map(|(data, _context_id)| data)
	}
}

/// Presentation write half.
#[derive(Debug)]
pub struct PresentationWriteHalf {
	/// The session connection write half.
	session_connection: SessionWriteHalf,
}

#[async_trait]
impl WriteHalfConnection for PresentationWriteHalf {
	type Error = PresentationError;

	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> std::result::Result<(), Self::Error> {
		Self::send_data_internal(&mut self.session_connection, data).await
	}
}

impl PresentationWriteHalf {
	/// Send data to the remote presentation.
	#[instrument(skip_all)]
	async fn send_data_internal<T: WriteHalfConnection<Error = SessionError>>(
		session_connection: &mut T,
		data: Vec<u8>,
	) -> std::result::Result<(), PresentationError> {
		let data = UserData::fully_encoded_data(FullyEncodedData(vec![PDVList::new(
			None,
			PresentationContextIdentifier(Integer::from(MMS_CONTEXT_ID)),
			PDVListPresentationDataValues::from(Any::from(data.clone())),
		)]));
		let data = ber::encode(&data).context(EncodeData)?;
		session_connection.send_data(data).await?;
		Ok(())
	}
}

/// Presentation read half.
#[derive(Debug)]
pub struct PresentationReadHalf {
	/// The session connection read half.
	session_connection: SessionReadHalf,
}

#[async_trait]
impl ReadHalfConnection for PresentationReadHalf {
	type Error = PresentationError;

	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> std::result::Result<Vec<u8>, Self::Error> {
		Self::receive_data_internal(&mut self.session_connection)
			.await
			.map(|(data, _context_id)| data)
	}
}

impl PresentationReadHalf {
	/// Receive data from the remote presentation.
	#[instrument(skip_all)]
	async fn receive_data_internal<R: ReadHalfConnection<Error = SessionError>>(
		session_connection: &mut R,
	) -> std::result::Result<(Vec<u8>, u64), PresentationError> {
		let data = session_connection.receive_data().await?;
		let data: UserData = ber::decode(&data).context(DecodeData)?;
		let mut pdvs = match data {
			UserData::fully_encoded_data(data) => data.0,
			UserData::simply_encoded_data(_) => {
				return UnsupportedUserData.fail();
			}
		};
		//TODO: Do I need to look at all the PDVs?
		let pdv = pdvs.pop().context(MissingPdv)?;
		if pdv.transfer_syntax_name.is_some_and(|tsn| tsn.0 != *BER_OID_OBJECT_IDENTIFIER) {
			return UnsupportedTransferSyntax.fail();
		}

		let context_id = pdv
			.presentation_context_identifier
			.0
			.try_into()
			.map_err(|_| InvalidContextId.build())?;

		let user_data = pdv.presentation_data_values;
		match user_data {
			PDVListPresentationDataValues::single_ASN1_type(data) => {
				Ok((data.into_bytes(), context_id))
			}
			_ => UnsupportedPresentationDataValues.fail(),
		}
	}
}

#[allow(missing_docs)]
/// Presentation layer errors
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum PresentationError {
	#[snafu(display("Invalid context ID"))]
	InvalidContextId {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Unsupported presentation data values"))]
	UnsupportedPresentationDataValues {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error encoding data"))]
	EncodeData {
		source: rasn::der::enc::EncodeError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error in session layer"))]
	SessionLayer {
		source: SessionError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Unsupported transfer syntax"))]
	UnsupportedTransferSyntax {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error decoding data"))]
	DecodeData {
		source: ber::de::DecodeError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing PDV"))]
	MissingPdv {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Unsupported user data"))]
	UnsupportedUserData {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing normal mode parameters"))]
	MissingNormalModeParameters {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing user data"))]
	MissingUserData {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error creating session"))]
	CreateSession {
		source: SessionError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error creating object identifier"))]
	CreateObjectIdentifier {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error encoding CP"))]
	EncodeCp {
		source: rasn::der::enc::EncodeError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error decoding CPA"))]
	DecodeCpa {
		source: ber::de::DecodeError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
}

impl PresentationError {
	/// Get the context of the presentation error.
	#[must_use]
	pub fn get_context(&self) -> &SpanTraceWrapper {
		match self {
			PresentationError::InvalidContextId { context } => context,
			PresentationError::UnsupportedPresentationDataValues { context } => context,
			PresentationError::EncodeData { context, .. } => context,
			PresentationError::SessionLayer { context, .. } => context,
			PresentationError::UnsupportedTransferSyntax { context } => context,
			PresentationError::DecodeData { context, .. } => context,
			PresentationError::MissingPdv { context } => context,
			PresentationError::UnsupportedUserData { context } => context,
			PresentationError::MissingNormalModeParameters { context } => context,
			PresentationError::MissingUserData { context } => context,
			PresentationError::CreateSession { context, .. } => context,
			PresentationError::CreateObjectIdentifier { context } => context,
			PresentationError::EncodeCp { context, .. } => context,
			PresentationError::DecodeCpa { context, .. } => context,
		}
	}
}

impl From<SessionError> for PresentationError {
	fn from(error: SessionError) -> Self {
		PresentationError::SessionLayer {
			context: Box::new((*error.get_context()).clone()),
			source: error,
		}
	}
}
