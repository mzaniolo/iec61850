//! ISO Presentation Layer Implementation (ISO 8327)

use rasn::{ber, prelude::*};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use tracing::instrument;

use crate::mms::{ClientConfig, SpanTraceWrapper, ans1::presentation::asn1::*, session::Session};

const ACSE_OID: [u32; 5] = [2, 2, 1, 0, 1];
const MMS_OID: [u32; 5] = [1, 0, 9506, 2, 1];
const BER_OID: [u32; 3] = [2, 1, 1];

const ACSE_CONTEXT_ID: u64 = 1;
const MMS_CONTEXT_ID: u64 = 3;

#[derive(Debug)]
pub struct Presentation {
    session: Session,
    local_p_sel: CallingPresentationSelector,
    remote_p_sel: CalledPresentationSelector,
}

impl Presentation {
    pub async fn new(config: &ClientConfig) -> std::result::Result<Self, PresentationError> {
        let session = Session::new(config).await.context(CreateSession)?;
        Ok(Self {
            session,
            local_p_sel: CallingPresentationSelector(PresentationSelector(OctetString::from(
                config.local_p_sel.as_ref(),
            ))),
            remote_p_sel: CalledPresentationSelector(PresentationSelector(OctetString::from(
                config.remote_p_sel.as_ref(),
            ))),
        })
    }
    #[instrument(skip(self))]
    pub async fn connect(
        &mut self,
        data: Vec<u8>,
    ) -> std::result::Result<(Vec<u8>, u64), PresentationError> {
        let presentation_context_definition_list =
            PresentationContextDefinitionList(ContextList(vec![
                AnonymousContextList {
                    presentation_context_identifier: PresentationContextIdentifier(Integer::from(
                        ACSE_CONTEXT_ID,
                    )),
                    abstract_syntax_name: AbstractSyntaxName(
                        ObjectIdentifier::new(&ACSE_OID).context(CreateObjectIdentifier)?,
                    ),
                    transfer_syntax_name_list: vec![TransferSyntaxName(
                        ObjectIdentifier::new(&BER_OID).context(CreateObjectIdentifier)?,
                    )],
                },
                AnonymousContextList {
                    presentation_context_identifier: PresentationContextIdentifier(Integer::from(
                        MMS_CONTEXT_ID,
                    )),
                    abstract_syntax_name: AbstractSyntaxName(
                        ObjectIdentifier::new(&MMS_OID).context(CreateObjectIdentifier)?,
                    ),
                    transfer_syntax_name_list: vec![TransferSyntaxName(
                        ObjectIdentifier::new(&BER_OID).context(CreateObjectIdentifier)?,
                    )],
                },
            ]));

        let p_context_id = PresentationContextIdentifier(Integer::from(1));
        let p_data_values = PDVListPresentationDataValues::from(Any::from(data));
        let p_list = PDVList::new(None, p_context_id, p_data_values);
        let p_data = FullyEncodedData(vec![p_list]);

        let normal_mode_params = CPTypeNormalModeParameters::new(
            ProtocolVersion([true].into_iter().collect()),
            Some(self.local_p_sel.clone()),
            Some(self.remote_p_sel.clone()),
            Some(presentation_context_definition_list),
            None,
            None,
            None,
            Some(UserData::fully_encoded_data(p_data)),
        );
        let cp = CPType::new(
            ModeSelector::new(Integer::from(1)),
            Some(normal_mode_params),
        );
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
    #[instrument(skip(self))]
    pub async fn receive_data(&mut self) -> std::result::Result<(Vec<u8>, u64), PresentationError> {
        let data = self.session.receive_data().await?;
        let data: UserData = ber::decode(&data).context(DecodeData)?;
        let mut pdvs = match data {
            UserData::fully_encoded_data(data) => data.0,
            UserData::simply_encoded_data(_) => {
                return UnsupportedUserData.fail();
            }
        };
        //TODO: Do I need to look at all the PDVs?
        let pdv = pdvs.pop().context(MissingPdv)?;
        if pdv
            .transfer_syntax_name
            .is_some_and(|tsn| tsn.0 != ObjectIdentifier::new(&BER_OID).expect("BER OID is valid"))
        {
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
    #[instrument(skip(self))]
    pub async fn send_data(&mut self, data: Vec<u8>) -> std::result::Result<(), PresentationError> {
        let data = UserData::fully_encoded_data(FullyEncodedData(vec![PDVList::new(
            None,
            PresentationContextIdentifier(Integer::from(MMS_CONTEXT_ID)),
            PDVListPresentationDataValues::from(Any::from(data)),
        )]));
        let data = ber::encode(&data).context(EncodeData)?;
        self.session.send_data(&data).await?;
        Ok(())
    }
}

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
        source: super::session::SessionError,
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
        source: super::session::SessionError,
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

impl From<super::session::SessionError> for PresentationError {
    fn from(error: super::session::SessionError) -> Self {
        PresentationError::SessionLayer {
            context: Box::new((*error.get_context()).clone()),
            source: error,
        }
    }
}
