//! ISO ACSE Layer Implementation (ISO 8327)

use async_trait::async_trait;
use rasn::{ber, prelude::*};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use tracing::instrument;

use crate::mms::{
	ClientConfig, ReadHalfConnection, SpanTraceWrapper, WriteHalfConnection,
	ans1::acse::acse_1::*,
	presentation::{Presentation, PresentationError, PresentationReadHalf, PresentationWriteHalf},
};

/// The ASO context name.
const ASO_CONTEXT_NAME: [u32; 5] = [1, 0, 9506, 2, 3];

/// The ACSE layer.
#[derive(Debug)]
pub struct Acse {
	/// The presentation layer.
	presentation: Presentation,
	/// The local AP title.
	local_ap_title: Option<Vec<u32>>,
	/// The local AE qualifier.
	local_ae_qualifier: Option<u32>,
	/// The remote AP title.
	remote_ap_title: Option<Vec<u32>>,
	/// The remote AE qualifier.
	remote_ae_qualifier: Option<u32>,
}

impl Acse {
	/// Create a new ACSE layer connection.
	#[instrument(skip(config))]
	pub async fn new(config: &ClientConfig) -> Result<Self, AcseError> {
		let presentation = Presentation::new(config).await?;
		Ok(Self {
			presentation,
			local_ap_title: config.local_ap_title.clone(),
			local_ae_qualifier: config.local_ae_qualifier,
			remote_ap_title: config.remote_ap_title.clone(),
			remote_ae_qualifier: config.remote_ae_qualifier,
		})
	}

	/// Connect to the remote ACSE.
	#[instrument(skip(self))]
	pub async fn connect(&mut self, data: Vec<u8>) -> Result<Vec<u8>, AcseError> {
		//TODO: Handle Auth parameters
		let aarq = AARQApdu::new(
			None,
			ObjectIdentifier::new(&ASO_CONTEXT_NAME).context(CreateObjectIdentifier)?,
			self.remote_ap_title.as_ref().and_then(|title| {
				ObjectIdentifier::new(title.clone()).map(APTitleForm2).map(APTitle::from)
			}),
			self.remote_ae_qualifier
				.map(|q| AEQualifier(ASOQualifier::from(ASOQualifierForm2(q.into())))),
			None,
			None,
			self.local_ap_title.as_ref().and_then(|title| {
				ObjectIdentifier::new(title.clone()).map(APTitleForm2).map(APTitle::from)
			}),
			self.local_ae_qualifier
				.map(|q| AEQualifier(ASOQualifier::from(ASOQualifierForm2(q.into())))),
			None,
			None,
			None,
			None,
			None,
			None,
			None,
			Some(AssociationData(vec![Myexternal::new(
				None,
				Some(Integer::from(3)),
				MyexternalEncoding::single_ASN1_type(Any::from(data)),
			)])),
		);

		//TODO: Handle context id
		let (data, _context_id) =
			self.presentation.connect(ber::encode(&aarq).context(EncodeAarq)?).await?;
		let aare: AAREApdu = ber::decode(&data).context(DecodeAare)?;

		//Check if the AARE result is successful
		if aare.result.0 != Integer::from(0) {
			return AareResultNotSuccessful.fail();
		}

		let user_data = aare
			.user_information
			.and_then(|mut data| data.0.pop())
			.context(MissingUserInformation)?;

		match user_data.encoding {
			MyexternalEncoding::single_ASN1_type(data) => Ok(data.into_bytes()),
			_ => WrongUserInformationEncoding.fail(),
		}
	}

	/// Split the ACSE layer connection into a read half and a write half.
	#[must_use]
	pub fn split(self) -> (AcseReadHalf, AcseWriteHalf) {
		let (presentation_read, presentation_write) = self.presentation.split();
		(
			AcseReadHalf { presentation: presentation_read },
			AcseWriteHalf { presentation: presentation_write },
		)
	}
}

#[async_trait]
impl WriteHalfConnection for Acse {
	type Error = AcseError;
	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
		AcseWriteHalf::send_data_internal(&mut self.presentation, data).await
	}
}

#[async_trait]
impl ReadHalfConnection for Acse {
	type Error = AcseError;
	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> Result<Vec<u8>, Self::Error> {
		AcseReadHalf::receive_data_internal(&mut self.presentation).await
	}
}

/// ACSE write half.
#[derive(Debug)]
pub struct AcseWriteHalf {
	/// The presentation layer write half.
	presentation: PresentationWriteHalf,
}

impl AcseWriteHalf {
	/// Send data to the remote ACSE.
	#[instrument(skip_all)]
	async fn send_data_internal<W: WriteHalfConnection<Error = PresentationError>>(
		presentation: &mut W,
		data: Vec<u8>,
	) -> Result<(), AcseError> {
		Ok(presentation.send_data(data).await?)
	}
}

#[async_trait]
impl WriteHalfConnection for AcseWriteHalf {
	type Error = AcseError;
	#[instrument(skip(self))]
	async fn send_data(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
		Self::send_data_internal(&mut self.presentation, data).await
	}
}

/// ACSE read half.
#[derive(Debug)]
pub struct AcseReadHalf {
	/// The presentation layer read half.
	presentation: PresentationReadHalf,
}

impl AcseReadHalf {
	/// Receive data from the remote ACSE.
	#[instrument(skip_all)]
	async fn receive_data_internal<R: ReadHalfConnection<Error = PresentationError>>(
		presentation: &mut R,
	) -> Result<Vec<u8>, AcseError> {
		Ok(presentation.receive_data().await?)
	}
}

#[async_trait]
impl ReadHalfConnection for AcseReadHalf {
	type Error = AcseError;
	#[instrument(skip(self))]
	async fn receive_data(&mut self) -> Result<Vec<u8>, Self::Error> {
		Self::receive_data_internal(&mut self.presentation).await
	}
}

#[allow(missing_docs)]
/// ACSE layer errors
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum AcseError {
	#[snafu(display("Error in presentation layer"))]
	PresentationLayer {
		source: PresentationError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},

	#[snafu(display("Wrong user information encoding"))]
	WrongUserInformationEncoding {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Missing user information"))]
	MissingUserInformation {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error decoding AARE"))]
	DecodeAare {
		source: ber::de::DecodeError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("AARE result not successful"))]
	AareResultNotSuccessful {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error encoding AARQ"))]
	EncodeAarq {
		source: ber::enc::EncodeError,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Error creating object identifier"))]
	CreateObjectIdentifier {
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
}

impl AcseError {
	/// Get the context of the ACSE error.
	#[must_use]
	pub fn get_context(&self) -> &SpanTraceWrapper {
		match self {
			AcseError::PresentationLayer { context, .. } => context,
			AcseError::WrongUserInformationEncoding { context } => context,
			AcseError::MissingUserInformation { context } => context,
			AcseError::DecodeAare { context, .. } => context,
			AcseError::AareResultNotSuccessful { context } => context,
			AcseError::EncodeAarq { context, .. } => context,
			AcseError::CreateObjectIdentifier { context } => context,
		}
	}
}

impl From<PresentationError> for AcseError {
	fn from(error: PresentationError) -> Self {
		AcseError::PresentationLayer {
			context: Box::new((*error.get_context()).clone()),
			source: error,
		}
	}
}
