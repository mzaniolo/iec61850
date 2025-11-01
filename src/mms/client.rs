use snafu::{ResultExt as _, Snafu};
use tracing::instrument;

use crate::mms::{
    ClientConfig, SpanTraceWrapper,
    acse::{Acse, AcseError},
    ans1::mms::asn1::*,
};
use rasn::{ber, prelude::*};

const VERSION_NUMBER: i16 = 1;
const MIN_PDU_SIZE: i32 = 64;

struct MmsClient {
    acse: Acse,
    max_serv_outstanding_calling: i16,
    max_serv_outstanding_called: i16,
    data_structure_nesting_level: i8,
    max_pdu_size: i32,
}

impl MmsClient {
    #[instrument(skip(config))]
    pub async fn new(config: &ClientConfig) -> Result<Self, MmsClientError> {
        let acse = Acse::new(config).await?;
        Ok(Self {
            acse,
            max_serv_outstanding_calling: config.max_serv_outstanding_calling,
            max_serv_outstanding_called: config.max_serv_outstanding_called,
            data_structure_nesting_level: config.data_structure_nesting_level,
            max_pdu_size: config.max_pdu_size,
        })
    }
    #[instrument(skip(self))]
    pub async fn connect(&mut self) -> Result<(), MmsClientError> {
        let mut s = BitString::from_slice(&[
            0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18,
        ]);
        for _ in 0..3 {
            s.pop();
        }
        let mut cbb = BitString::from_slice(&[0xf1, 0x00]);
        for _ in 0..5 {
            cbb.pop();
        }
        let request = MMSpdu::initiate_RequestPDU(InitiateRequestPDU::new(
            Some(Integer32(self.max_pdu_size)),
            Integer16(self.max_serv_outstanding_calling),
            Integer16(self.max_serv_outstanding_called),
            Some(Integer8(self.data_structure_nesting_level)),
            InitiateRequestPDUInitRequestDetail::new(
                Integer16(VERSION_NUMBER),
                ParameterSupportOptions(cbb),
                ServiceSupportOptions(s),
            ),
        ));
        let data = ber::encode(&request).context(EncodeRequest)?;
        let response = self.acse.connect(data).await?;
        let response: MMSpdu = ber::decode(&response).context(DecodeResponse)?;

        let MMSpdu::initiate_ResponsePDU(response) = response else {
            return UnexpectedServiceResponse.fail();
        };

        if response.init_response_detail.negotiated_version_number != Integer16(VERSION_NUMBER) {
            return VersionMismatch.fail();
        }
        if response
            .local_detail_called
            .as_ref()
            .is_some_and(|size| size.0 < MIN_PDU_SIZE)
        {
            return MinPduSizeExceeded.fail();
        }
        if response.negotiated_max_serv_outstanding_called.0 > self.max_serv_outstanding_called {
            return MaxServOutstandingCalledExceeded.fail();
        }
        if response.negotiated_max_serv_outstanding_calling.0 > self.max_serv_outstanding_calling {
            return MaxServOutstandingCallingExceeded.fail();
        }
        if response
            .negotiated_data_structure_nesting_level
            .as_ref()
            .is_some_and(|level| level.0 > self.data_structure_nesting_level)
        {
            return DataStructureNestingLevelExceeded.fail();
        }

        // TODO: Check if the services supported by the server are supported by the client

        self.max_serv_outstanding_called = response.negotiated_max_serv_outstanding_called.0;
        self.max_serv_outstanding_calling = response.negotiated_max_serv_outstanding_calling.0;
        if let Some(level) = response.negotiated_data_structure_nesting_level {
            self.data_structure_nesting_level = level.0;
        }
        if let Some(size) = response.local_detail_called {
            self.max_pdu_size = size.0;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn get_logical_devices(&mut self) -> Result<Vec<String>, MmsClientError> {
        let request = ConfirmedRequestPDU::new(
            Unsigned32(0),
            ConfirmedServiceRequest::getNameList(GetNameListRequest::new(
                ObjectClass::basicObjectClass(9.into()), // domain
                GetNameListRequestObjectScope::vmdSpecific(()),
                None,
            )),
        );
        let data =
            ber::encode(&MMSpdu::confirmed_RequestPDU(request.clone())).context(EncodeRequest)?;
        self.acse.send_data(data).await?;
        let response = self.acse.receive_data().await?;
        let response: MMSpdu = ber::decode(&response).context(DecodeResponse)?;
        let MMSpdu::confirmed_ResponsePDU(response) = response else {
            return UnexpectedServiceResponse.fail();
        };

        if response.invoke_id != request.invoke_id {
            return InvokeIdMismatch.fail();
        }
        let ConfirmedServiceResponse::getNameList(response) = response.service else {
            return UnexpectedServiceResponse.fail();
        };

        Ok(response
            .list_of_identifier
            .into_iter()
            .map(|id| id.0.to_string())
            .collect())
    }
}

/// Presentation layer errors
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum MmsClientError {
    #[snafu(display("Error in acse layer"))]
    AcseLayer {
        source: AcseError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Invoke ID mismatch"))]
    InvokeIdMismatch {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Unexpected service response"))]
    UnexpectedServiceResponse {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Min PDU size exceeded"))]
    MinPduSizeExceeded {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Max serv outstanding called exceeded"))]
    MaxServOutstandingCalledExceeded {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Max serv outstanding calling exceeded"))]
    MaxServOutstandingCallingExceeded {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Data structure nesting level exceeded"))]
    DataStructureNestingLevelExceeded {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Version mismatch"))]
    VersionMismatch {
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error decoding response"))]
    DecodeResponse {
        source: ber::de::DecodeError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error encoding request"))]
    EncodeRequest {
        source: ber::enc::EncodeError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
}

impl MmsClientError {
    pub fn get_context(&self) -> &SpanTraceWrapper {
        match self {
            MmsClientError::AcseLayer { context, .. } => context,
            MmsClientError::InvokeIdMismatch { context } => context,
            MmsClientError::UnexpectedServiceResponse { context } => context,
            MmsClientError::MinPduSizeExceeded { context } => context,
            MmsClientError::MaxServOutstandingCalledExceeded { context } => context,
            MmsClientError::MaxServOutstandingCallingExceeded { context } => context,
            MmsClientError::DataStructureNestingLevelExceeded { context } => context,
            MmsClientError::VersionMismatch { context } => context,
            MmsClientError::DecodeResponse { context, .. } => context,
            MmsClientError::EncodeRequest { context, .. } => context,
        }
    }
}

impl From<AcseError> for MmsClientError {
    fn from(error: AcseError) -> Self {
        MmsClientError::AcseLayer {
            context: Box::new((*error.get_context()).clone()),
            source: error,
        }
    }
}

#[cfg(test)]
mod tests {
    use rust_telemetry::config::OtelConfig;

    use super::*;

    #[tokio::test]
    async fn test_get_logical_devices() -> Result<(), MmsClientError> {
        let _g = rust_telemetry::init_otel!(&OtelConfig::for_tests());
        if let Err(e) = async {
            let config = ClientConfig::default();
            println!("Creating client...");
            let mut client = MmsClient::new(&config).await?;
            println!("Connecting to server...");
            client.connect().await?;
            println!("Getting logical devices...");
            let devices = client.get_logical_devices().await?;
            println!("Devices: {:?}", devices);
            Ok::<(), MmsClientError>(())
        }
        .await
        {
            let context = e.get_context();
            println!("Error: {}\n{context}", snafu::Report::from_error(&e));
        }
        Ok(())
    }
}
