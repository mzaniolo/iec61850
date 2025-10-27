use snafu::{OptionExt as _, ResultExt as _, Snafu};

use crate::mms::{
    SpanTraceWrapper,
    ans1::acse::acse_1::*,
    cotp::ClientConfig,
    presentation::{Presentation, PresentationError},
};
use rasn::{ber, prelude::*};

const ASO_CONTEXT_NAME: [u32; 5] = [1, 0, 9506, 2, 3];
pub struct Acse {
    presentation: Presentation,
    local_ap_title: Option<Vec<u32>>,
    local_ae_qualifier: Option<u32>,
    remote_ap_title: Option<Vec<u32>>,
    remote_ae_qualifier: Option<u32>,
}

impl Acse {
    pub async fn new(config: &ClientConfig) -> Result<Self, AcseError> {
        let presentation = Presentation::new(config)
            .await
            .context(CreatePresentation)?;
        Ok(Self {
            presentation,
            local_ap_title: config.local_ap_title.clone(),
            local_ae_qualifier: config.local_ae_qualifier,
            remote_ap_title: config.remote_ap_title.clone(),
            remote_ae_qualifier: config.remote_ae_qualifier,
        })
    }
    pub async fn connect(&mut self, data: Vec<u8>) -> Result<Vec<u8>, AcseError> {
        //TODO: Handle Auth parameters
        let aarq = AARQApdu::new(
            [true].into_iter().collect(),
            ASOContextName(
                ObjectIdentifier::new(&ASO_CONTEXT_NAME).context(CreateObjectIdentifier)?,
            ),
            self.remote_ap_title.as_ref().and_then(|title| {
                ObjectIdentifier::new(title.clone())
                    .map(APTitleForm2)
                    .map(APTitle::from)
            }),
            self.remote_ae_qualifier
                .map(|q| AEQualifier(ASOQualifier::from(ASOQualifierForm2(q.into())))),
            None,
            None,
            self.local_ap_title.as_ref().and_then(|title| {
                ObjectIdentifier::new(title.clone())
                    .map(APTitleForm2)
                    .map(APTitle::from)
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
        let (data, context_id) = self
            .presentation
            .connect(ber::encode(&aarq).context(EncodeAarq)?)
            .await
            .context(Connect)?;
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

    pub async fn send_data(&mut self, data: Vec<u8>) -> Result<(), AcseError> {
        self.presentation.send_data(data).await.context(SendData)
    }

    pub async fn receive_data(&mut self) -> Result<Vec<u8>, AcseError> {
        let (data, context_id) = self
            .presentation
            .receive_data()
            .await
            .context(ReceiveData)?;
        //TODO: Handle context id
        Ok(data)
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum AcseError {
    #[snafu(display("Error receiving data"))]
    ReceiveData {
        source: PresentationError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error sending data"))]
    SendData {
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
        source: rasn::ber::de::DecodeError,
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
        source: rasn::ber::enc::EncodeError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error creating object identifier"))]
    CreateObjectIdentifier {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error creating presentation"))]
    CreatePresentation {
        source: PresentationError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error connecting to presentation"))]
    Connect {
        source: PresentationError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
}
