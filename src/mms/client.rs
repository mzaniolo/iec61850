use std::collections::HashMap;

use snafu::{ResultExt as _, Snafu};
use tokio::{
    select,
    sync::{mpsc, oneshot},
};
use tracing::instrument;

use crate::mms::{
    ClientConfig, ReadHalfConnection, SpanTraceWrapper, WriteHalfConnection,
    acse::{Acse, AcseError, AcseReadHalf, AcseWriteHalf},
    ans1::mms::asn1::{self, *},
};
use rasn::{ber, prelude::*};

const VERSION_NUMBER: i16 = 1;
const MIN_PDU_SIZE: i32 = 64;
const SERVICE_SUPPORT_OPTIONS: [u8; 11] = [
    0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18,
];
const PARAMETER_SUPPORT_OPTIONS: [u8; 2] = [0xf1, 0x00];

struct MmsClient {
    max_serv_outstanding_calling: i16,
    max_serv_outstanding_called: i16,
    data_structure_nesting_level: i8,
    max_pdu_size: i32,
    tx: mpsc::Sender<(
        ConfirmedServiceRequest,
        oneshot::Sender<ConfirmedServiceResponse>,
    )>,
}

impl MmsClient {
    #[instrument]
    pub async fn connect(config: &ClientConfig) -> Result<Self, MmsClientError> {
        let mut acse = Acse::new(config).await?;

        let mut max_serv_outstanding_called = config.max_serv_outstanding_called;
        let mut max_serv_outstanding_calling = config.max_serv_outstanding_calling;
        let mut data_structure_nesting_level = config.data_structure_nesting_level;
        let mut max_pdu_size = config.max_pdu_size;

        let request = MMSpdu::initiate_RequestPDU(InitiateRequestPDU::new(
            Some(Integer32(max_pdu_size)),
            Integer16(max_serv_outstanding_calling),
            Integer16(max_serv_outstanding_called),
            Some(Integer8(data_structure_nesting_level)),
            InitiateRequestPDUInitRequestDetail::new(
                Integer16(VERSION_NUMBER),
                ParameterSupportOptions(make_bitstring(&PARAMETER_SUPPORT_OPTIONS, 11)),
                ServiceSupportOptions(make_bitstring(&SERVICE_SUPPORT_OPTIONS, 85)),
            ),
        ));
        let data = ber::encode(&request).context(EncodeRequest)?;
        let response = acse.connect(data).await?;
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
        if response.negotiated_max_serv_outstanding_called.0 > max_serv_outstanding_called {
            return MaxServOutstandingCalledExceeded.fail();
        }
        if response.negotiated_max_serv_outstanding_calling.0 > max_serv_outstanding_calling {
            return MaxServOutstandingCallingExceeded.fail();
        }
        if response
            .negotiated_data_structure_nesting_level
            .as_ref()
            .is_some_and(|level| level.0 > data_structure_nesting_level)
        {
            return DataStructureNestingLevelExceeded.fail();
        }

        // TODO: Check if the services supported by the server are supported by the client

        max_serv_outstanding_called = response.negotiated_max_serv_outstanding_called.0;
        max_serv_outstanding_calling = response.negotiated_max_serv_outstanding_calling.0;
        if let Some(level) = response.negotiated_data_structure_nesting_level {
            data_structure_nesting_level = level.0;
        }
        if let Some(size) = response.local_detail_called {
            max_pdu_size = size.0;
        }

        let (read_half, write_half) = acse.split();
        let (tx, rx) = mpsc::channel(100);
        tokio::spawn(handle_connection(read_half, write_half, rx));

        Ok(Self {
            tx,
            max_serv_outstanding_calling,
            max_serv_outstanding_called,
            data_structure_nesting_level,
            max_pdu_size,
        })
    }

    async fn send_request(
        &self,
        request: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse, MmsClientError> {
        let (tx, rx) = oneshot::channel();
        self.tx.send((request, tx)).await.context(SendRequest)?;
        rx.await.context(ReceiveResponse)
    }

    async fn get_name_list(
        &self,
        object_class: u8,
        scope: GetNameListRequestObjectScope,
    ) -> Result<Vec<String>, MmsClientError> {
        let mut name_list = Vec::new();
        let mut continue_after = None;
        let mut more_follows = true;

        while more_follows {
            let request = ConfirmedServiceRequest::getNameList(GetNameListRequest::new(
                ObjectClass::basicObjectClass(object_class.into()),
                scope.clone(),
                continue_after.clone(),
            ));

            let response = self.send_request(request).await?;

            let ConfirmedServiceResponse::getNameList(response) = response else {
                return UnexpectedServiceResponse.fail();
            };

            more_follows = response.more_follows;
            let ids = response.list_of_identifier;
            continue_after = ids.last().cloned();
            name_list.extend(ids.into_iter().map(|id| id.0.to_string()));
        }
        Ok(name_list)
    }

    async fn read(
        &self,
        variable_access_specification: VariableAccessSpecification,
        specification_with_result: bool,
    ) -> Result<Vec<Data>, MmsClientError> {
        let request = ConfirmedServiceRequest::read(ReadRequest::new(
            specification_with_result,
            variable_access_specification,
        ));

        let response = self.send_request(request).await?;
        let ConfirmedServiceResponse::read(response) = response else {
            return UnexpectedServiceResponse.fail();
        };
        response
            .list_of_access_result
            .into_iter()
            .map(|result| match result {
                AccessResult::success(data) => Ok(data),
                AccessResult::failure(error) => DataAccess { error: error.0 }.fail(),
            })
            .collect::<Result<Vec<Data>, MmsClientError>>()
    }

    async fn write(
        &self,
        variable_access_specification: VariableAccessSpecification,
        list_of_data: Vec<Data>,
    ) -> Result<(), MmsClientError> {
        let request = ConfirmedServiceRequest::write(WriteRequest::new(
            variable_access_specification,
            list_of_data,
        ));
        let response = self.send_request(request).await?;
        let ConfirmedServiceResponse::write(response) = response else {
            return UnexpectedServiceResponse.fail();
        };

        response
            .0
            .into_iter()
            .find_map(|result| match result {
                AnonymousWriteResponse::success(()) => None,
                AnonymousWriteResponse::failure(error) => {
                    Some(DataAccess { error: error.0 }.fail())
                }
            })
            .unwrap_or(Ok(()))
    }

    async fn get_variable_access_attributes(
        &self,
        object_name: ObjectName,
    ) -> Result<GetVariableAccessAttributesResponse, MmsClientError> {
        let request = ConfirmedServiceRequest::getVariableAccessAttributes(
            GetVariableAccessAttributesRequest::name(object_name),
        );
        let response = self.send_request(request).await?;
        let ConfirmedServiceResponse::getVariableAccessAttributes(response) = response else {
            return UnexpectedServiceResponse.fail();
        };

        Ok(response)
    }

    async fn define_named_variable_list(
        &self,
        variable_list_name: ObjectName,
        list_of_variable: Vec<AnonymousVariableDefs>,
    ) -> Result<(), MmsClientError> {
        let request = ConfirmedServiceRequest::defineNamedVariableList(
            DefineNamedVariableListRequest::new(variable_list_name, VariableDefs(list_of_variable)),
        );
        let response = self.send_request(request).await?;
        if matches!(
            response,
            ConfirmedServiceResponse::defineNamedVariableList(_)
        ) {
            return UnexpectedServiceResponse.fail();
        };
        Ok(())
    }

    async fn get_named_variable_list_attributes(
        &self,
        object_name: ObjectName,
    ) -> Result<GetNamedVariableListAttributesResponse, MmsClientError> {
        let request = ConfirmedServiceRequest::getNamedVariableListAttributes(
            GetNamedVariableListAttributesRequest(object_name),
        );
        let response = self.send_request(request).await?;
        let ConfirmedServiceResponse::getNamedVariableListAttributes(response) = response else {
            return UnexpectedServiceResponse.fail();
        };
        Ok(response)
    }

    async fn delete_named_variable_list(
        &self,
        scope_of_delete: u32,
        list_of_variable_list_name: Option<Vec<ObjectName>>,
        domain_name: Option<String>,
    ) -> Result<DeleteNamedVariableListResponse, MmsClientError> {
        let request =
            ConfirmedServiceRequest::deleteNamedVariableList(DeleteNamedVariableListRequest::new(
                scope_of_delete.into(),
                list_of_variable_list_name,
                domain_name
                    .map(|name| {
                        VisibleString::from_iso646_bytes(name.as_bytes()).map(asn1::Identifier)
                    })
                    .transpose()
                    .context(VisibleStringConversion)?,
            ));
        let response = self.send_request(request).await?;
        let ConfirmedServiceResponse::deleteNamedVariableList(response) = response else {
            return UnexpectedServiceResponse.fail();
        };
        Ok(response)
    }

    async fn file_open(
        &self,
        file_name: Vec<String>,
        initial_position: Option<u32>,
    ) -> Result<FileOpenResponse, MmsClientError> {
        let request = ConfirmedServiceRequest::fileOpen(FileOpenRequest::new(
            FileName(
                file_name
                    .into_iter()
                    .map(|name| {
                        GraphicString::from_bytes(name.as_bytes())
                            .map(AnonymousFileName)
                            .context(VisibleStringConversion)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Unsigned32(initial_position.unwrap_or(0)),
        ));
        let response = self.send_request(request).await?;
        let ConfirmedServiceResponse::fileOpen(response) = response else {
            return UnexpectedServiceResponse.fail();
        };
        Ok(response)
    }

    async fn file_read(&self, frsm_id: i32) -> Result<Vec<u8>, MmsClientError> {
        let mut more_follows = true;
        let mut data = Vec::new();
        while more_follows {
            let request = ConfirmedServiceRequest::fileRead(FileReadRequest(Integer32(frsm_id)));
            let response = self.send_request(request).await?;
            let ConfirmedServiceResponse::fileRead(response) = response else {
                return UnexpectedServiceResponse.fail();
            };
            more_follows = response.more_follows;
            data.extend(response.file_data.into_iter());
        }
        Ok(data)
    }

    async fn file_close(&self, frsm_id: i32) -> Result<(), MmsClientError> {
        let request = ConfirmedServiceRequest::fileClose(FileCloseRequest(Integer32(frsm_id)));
        let response = self.send_request(request).await?;
        if matches!(response, ConfirmedServiceResponse::fileClose(_)) {
            return UnexpectedServiceResponse.fail();
        };
        Ok(())
    }

    async fn file_delete(&self, file_name: Vec<String>) -> Result<(), MmsClientError> {
        let request = ConfirmedServiceRequest::fileDelete(FileDeleteRequest(FileName(
            file_name
                .into_iter()
                .map(|name| {
                    GraphicString::from_bytes(name.as_bytes())
                        .map(AnonymousFileName)
                        .context(VisibleStringConversion)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )));
        let response = self.send_request(request).await?;
        if matches!(response, ConfirmedServiceResponse::fileDelete(_)) {
            return UnexpectedServiceResponse.fail();
        };
        Ok(())
    }

    async fn file_directory(
        &self,
        file_specification: Option<Vec<String>>,
    ) -> Result<Vec<DirectoryEntry>, MmsClientError> {
        let mut continue_after = None;
        let mut more_follows = true;
        let mut list_of_directory_entry = Vec::new();

        while more_follows {
            let request = ConfirmedServiceRequest::fileDirectory(FileDirectoryRequest::new(
                file_specification
                    .as_ref()
                    .map(|names| {
                        names
                            .iter()
                            .map(|name| {
                                GraphicString::from_bytes(name.as_bytes())
                                    .context(VisibleStringConversion)
                                    .map(AnonymousFileName)
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .map(FileName)
                    })
                    .transpose()?,
                continue_after,
            ));
            let response = self.send_request(request).await?;
            let ConfirmedServiceResponse::fileDirectory(response) = response else {
                return UnexpectedServiceResponse.fail();
            };

            more_follows = response.more_follows;
            continue_after = response
                .list_of_directory_entry
                .last()
                .cloned()
                .map(|entry| entry.file_name);
            list_of_directory_entry.extend(response.list_of_directory_entry.into_iter());
        }
        Ok(list_of_directory_entry)
    }

    // TODO: This is a IEC61850 specific. Move to a separate module.
    #[instrument(skip(self))]
    pub async fn get_logical_devices(&mut self) -> Result<Vec<String>, MmsClientError> {
        // TODO: Make a enum for the object classes.
        self.get_name_list(9, GetNameListRequestObjectScope::vmdSpecific(()))
            .await
    }
}

async fn handle_connection(
    mut read_half: AcseReadHalf,
    mut write_half: AcseWriteHalf,
    mut rx: mpsc::Receiver<(
        ConfirmedServiceRequest,
        oneshot::Sender<ConfirmedServiceResponse>,
    )>,
) {
    let mut invoke_id = 0;
    let mut response_map: HashMap<u32, oneshot::Sender<ConfirmedServiceResponse>> = HashMap::new();
    loop {
        select! {
            data = read_half.receive_data() => {
                let data = match data {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("Error receiving data: {:?}", e);
                        // TODO: Handle error better
                        break;
                    }
                };

                let response: MMSpdu = match ber::decode(&data).context(DecodeResponse) {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::error!("Error decoding response: {:?}", e);
                        // TODO: Handle error better
                        continue;
                    }
                };
                let MMSpdu::confirmed_ResponsePDU(response) = response else {
                    tracing::error!("Unexpected service response. Response: {:?}", response);
                    continue;
                };
                let invoke_id = response.invoke_id;
                let response = response.service;
                let sender = match response_map.remove(&invoke_id.0) {
                    Some(sender) => sender,
                    None => {
                        tracing::error!("No sender found for invoke ID: {}", invoke_id.0);
                        continue;
                    }
                };
                let _ = sender.send(response).inspect_err(|e| {
                    tracing::error!("Error sending response: {:?}", e);
                    // TODO: Handle error better
                });

            },
            request = rx.recv() => {
                match request {
                    Some((request, sender)) => {
                        let data = match prepare_request(invoke_id, request) {
                            Ok(data) => data,
                            Err(e) => {
                                tracing::error!("Error preparing request: {:?}", e);
                                // TODO: Handle error better
                                continue;
                            }
                        };
                        if let Err(e) = write_half.send_data(data).await {
                            tracing::error!("Error sending data: {:?}", e);
                            // TODO: Handle error better
                            continue;
                        }
                        response_map.insert(invoke_id, sender);
                        invoke_id += 1;
                    }
                    None => {
                        tracing::info!("No more requests to send");
                        break;
                    }
                }
            },
        }
    }
}

fn prepare_request(
    invoke_id: u32,
    request: ConfirmedServiceRequest,
) -> Result<Vec<u8>, MmsClientError> {
    let request =
        MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU::new(Unsigned32(invoke_id), request));
    ber::encode(&request).context(EncodeRequest)
}

fn make_bitstring(data: &[u8], length: usize) -> BitString {
    let mut bitstring = BitString::from_slice(data);
    bitstring.truncate(length);
    bitstring
}

/// Presentation layer errors
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum MmsClientError {
    #[snafu(display("Visible string error"))]
    VisibleStringConversion {
        source: rasn::error::strings::PermittedAlphabetError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Data access error: {}", error))]
    DataAccessError {
        error: Integer,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error sending request"))]
    SendRequest {
        source: mpsc::error::SendError<(
            ConfirmedServiceRequest,
            oneshot::Sender<ConfirmedServiceResponse>,
        )>,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
    #[snafu(display("Error receiving response"))]
    ReceiveResponse {
        source: oneshot::error::RecvError,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
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
            MmsClientError::SendRequest { context, .. } => context,
            MmsClientError::ReceiveResponse { context, .. } => context,
            MmsClientError::DataAccessError { context, .. } => context,
            MmsClientError::VisibleStringConversion { context, .. } => context,
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
            println!("Connecting to server...");
            let mut client = MmsClient::connect(&config).await?;
            println!("Getting logical devices...");
            let devices = client.get_logical_devices().await?;
            println!("Devices: {:?}", devices);
            println!("Getting directory...");
            let directory = client
                .file_directory(None)
                .await?
                .iter()
                .map(|d| {
                    d.file_name
                        .0
                        .iter()
                        .map(|f| str::from_utf8(&f.0).expect("Invalid UTF-8"))
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .collect::<Vec<_>>();
            println!("Directory: {:?}", directory);
            Ok::<(), MmsClientError>(())
        }
        .await
        {
            let context = e.get_context();
            println!("Error: {}\n{context}", snafu::Report::from_error(&e));
        }
        Ok(())
    }

    #[test]
    fn test_decode_file_directory_response() {
        use rasn::ber;
        // Full MMSpdu data from the log
        let data = vec![
            0xa1, 0x5d, 0x02, 0x01, 0x01, 0xbf, 0x4d, 0x57, 0xa0, 0x55, 0x30, 0x53, 0x30, 0x29,
            0xa0, 0x0d, 0x19, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6c, 0x6f,
            0x67, 0xa1, 0x18, 0x80, 0x01, 0x0d, 0x81, 0x13, 0x32, 0x30, 0x32, 0x35, 0x31, 0x31,
            0x30, 0x34, 0x31, 0x39, 0x30, 0x35, 0x32, 0x37, 0x2e, 0x30, 0x30, 0x30, 0x5a, 0x30,
            0x26, 0xa0, 0x0a, 0x19, 0x08, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0xa1,
            0x18, 0x80, 0x01, 0x10, 0x81, 0x13, 0x32, 0x30, 0x32, 0x35, 0x31, 0x31, 0x30, 0x34,
            0x31, 0x39, 0x30, 0x35, 0x32, 0x31, 0x2e, 0x30, 0x30, 0x30, 0x5a,
        ];

        println!("Decoding MMSpdu from {} bytes", data.len());
        let mms_pdu: MMSpdu = ber::decode(&data).expect("Failed to decode MMSpdu");
        println!("Decoded MMSpdu: {:?}", mms_pdu);

        if let MMSpdu::confirmed_ResponsePDU(response_pdu) = mms_pdu {
            if let ConfirmedServiceResponse::fileDirectory(file_dir_response) = response_pdu.service
            {
                println!("FileDirectory response: {:?}", file_dir_response);
                println!(
                    "Number of entries: {}",
                    file_dir_response.list_of_directory_entry.len()
                );
                assert_eq!(file_dir_response.list_of_directory_entry.len(), 2);

                // Check the file names
                let entries = &file_dir_response.list_of_directory_entry;
                assert_eq!(entries.len(), 2);
            } else {
                panic!("Expected fileDirectory response");
            }
        } else {
            panic!("Expected confirmed_ResponsePDU");
        }
    }
}
