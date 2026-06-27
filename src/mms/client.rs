//! MMS client implementation.

use std::{collections::HashMap, sync::Arc, time::Duration};

use rasn::{ber, prelude::*};
use snafu::{ResultExt as _, Snafu};
use tokio::{
	select,
	sync::{Semaphore, mpsc, oneshot},
};
use tracing::instrument;

use crate::{
	iec61850::report::Report,
	mms::{
		ClientConfig, ReadHalfConnection, ReportCallback, SpanTraceWrapper, WriteHalfConnection,
		acse::{Acse, AcseError, AcseReadHalf, AcseWriteHalf},
		ans1::mms::asn1::{self, *},
	},
};

/// The MMS version number.
const VERSION_NUMBER: i16 = 1;
/// The minimum PDU size.
const MIN_PDU_SIZE: i32 = 64;

/// Result returned by the connection handler to a waiting caller. `Ok`
/// carries the service response; `Err` carries the structured failure
/// reported by the peer (Confirmed-Error or Reject PDU).
type ServiceResult = Result<ConfirmedServiceResponse, ServiceFailure>;

/// Result of a Cancel request: `Ok` if the peer confirmed the cancel,
/// `Err` with the structured failure otherwise.
type CancelResult = Result<(), ServiceFailure>;

/// A command sent from an `MmsClient` handle to the connection-handler task.
enum Command {
	/// A confirmed service request awaiting a response.
	Request {
		/// The service request to encode and send.
		request: ConfirmedServiceRequest,
		/// Channel the handler uses to deliver the response/failure.
		responder: oneshot::Sender<ServiceResult>,
	},
	/// Cancel an outstanding confirmed request by its original invoke id.
	Cancel {
		/// The invoke id of the request to cancel.
		original_invoke_id: u32,
		/// Channel the handler uses to deliver the cancel result.
		responder: oneshot::Sender<CancelResult>,
	},
	/// Begin a graceful teardown: send an MMS Conclude-Request, then stop
	/// the loop (which drops the transport and closes the TCP socket).
	Shutdown {
		/// Signaled once the teardown PDU has been written (best-effort).
		responder: oneshot::Sender<()>,
	},
}

/// Structured server-side failure for a confirmed service request, carried
/// back to the caller instead of an opaque dropped-channel error.
#[derive(Debug, Clone)]
pub enum ServiceFailure {
	/// The peer answered with a Confirmed-ErrorPDU.
	ConfirmedError {
		/// Optional modifier position from the Confirmed-Error PDU.
		modifier_position: Option<u32>,
		/// The service error from the Confirmed-Error PDU.
		service_error: ServiceError,
	},
	/// The peer answered with a RejectPDU.
	Rejected {
		/// Reject reason from the Reject PDU.
		reason: RejectPDURejectReason,
	},
	/// The connection to the peer was closed (gracefully or by I/O error)
	/// while this request was outstanding.
	ConnectionClosed {
		/// Human-readable reason captured from the connection-handler loop.
		reason: String,
	},
	/// The BER-encoded request exceeds the MMS PDU size negotiated with
	/// the peer. The caller must split the request and retry.
	PduTooLarge {
		/// Size of the encoded PDU that was about to be sent.
		encoded: usize,
		/// Negotiated maximum PDU size from `Initiate-ResponsePDU`.
		limit: usize,
	},
}
/// The service support options (servicesSupportedCalling), 85 bits.
/// Byte-for-byte identical to the libiec61850 reference client's proposed
/// set, which interoperates with IEC 61850-8-1 servers; verified against
/// libiec61850 v1.5 `mms_client_initiate.c`.
const SERVICE_SUPPORT_OPTIONS: [u8; 11] =
	[0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18];
/// The parameter support options (parameterCBB), 11 bits. `0xf1` advertises
/// str1, str2, vnam, vlis and valt — matching the libiec61850 reference
/// client.
const PARAMETER_SUPPORT_OPTIONS: [u8; 2] = [0xf1, 0x00];

/// The MMS client.
#[derive(Debug)]
pub struct MmsClient {
	/// Sender used to hand commands (requests, cancels) to the connection
	/// handler task.
	tx: mpsc::Sender<Command>,
	/// Per-request timeout, copied from `ClientConfig` at connect time.
	request_timeout: Option<Duration>,
	/// MMS PDU size negotiated with the peer; we refuse to send PDUs larger
	/// than this so the peer doesn't have to do the rejection for us.
	negotiated_max_pdu_size: usize,
	/// Limits the number of in-flight requests to the value negotiated with
	/// the peer (`negotiated_max_serv_outstanding_calling`). Acts as
	/// back-pressure on `send_request`.
	outstanding: Arc<Semaphore>,
}

impl MmsClient {
	/// Connect to the MMS server.
	#[instrument(skip(report_callback))]
	pub async fn connect(
		config: &ClientConfig,
		report_callback: Box<dyn ReportCallback + Send + Sync>,
	) -> Result<Self, MmsClientError> {
		let mut acse = Acse::new(config).await?;

		let max_serv_outstanding_called = config.connection.max_serv_outstanding_called;
		let max_serv_outstanding_calling = config.connection.max_serv_outstanding_calling;
		let data_structure_nesting_level = config.connection.data_structure_nesting_level;
		let max_pdu_size = config.connection.max_pdu_size;

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
		if response.local_detail_called.as_ref().is_some_and(|size| size.0 < MIN_PDU_SIZE) {
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

		// TODO: Check if the services supported by the server are supported by the
		// client

		// Honor what the peer negotiated. The peer may have asked for a
		// smaller PDU or fewer outstanding services than we proposed.
		let negotiated_max_pdu_size: usize = response
			.local_detail_called
			.as_ref()
			.map_or(max_pdu_size, |size| size.0)
			.try_into()
			.unwrap_or(0);
		let negotiated_max_outstanding =
			response.negotiated_max_serv_outstanding_calling.0.max(1) as usize;

		let (read_half, write_half) = acse.split();
		let (tx, rx) = mpsc::channel(100);
		let outstanding = Arc::new(Semaphore::new(negotiated_max_outstanding));
		let handler = ConnectionHandler::new(
			read_half,
			write_half,
			rx,
			report_callback,
			negotiated_max_pdu_size,
		);
		tokio::spawn(handler.handle_connection());

		Ok(Self {
			tx,
			request_timeout: config.connection.request_timeout,
			negotiated_max_pdu_size,
			outstanding,
		})
	}

	/// Return the MMS PDU size negotiated with the peer. Callers building
	/// large requests can use this to chunk their payloads (e.g. read/write
	/// of long variable lists) before invoking `send_request`.
	#[must_use]
	pub const fn max_pdu_size(&self) -> usize {
		self.negotiated_max_pdu_size
	}

	/// Send a confirmed service request.
	///
	/// Enforces three things in order:
	/// 1. Back-pressure: no more concurrent requests than the peer negotiated
	///    (`max_serv_outstanding_calling`).
	/// 2. Per-request timeout (configurable via
	///    `ClientConfig::connection::request_timeout`).
	/// 3. The encoded PDU size check is done inside the connection handler once
	///    the invoke-id is known; this method does not encode.
	#[instrument(skip(self))]
	async fn send_request(
		&self,
		request: ConfirmedServiceRequest,
	) -> Result<ConfirmedServiceResponse, MmsClientError> {
		let permit =
			self.outstanding.clone().acquire_owned().await.map_err(|_| ConnectionGone.build())?;
		let (tx, rx) = oneshot::channel();
		self.tx
			.send(Command::Request { request, responder: tx })
			.await
			.map_err(|_| ConnectionGone.build())?;

		let result = match self.request_timeout {
			Some(timeout) => tokio::time::timeout(timeout, rx)
				.await
				.map_err(|_| RequestTimeout { timeout }.build())?,
			None => rx.await,
		};
		drop(permit);

		match result.context(ReceiveResponse)? {
			Ok(response) => Ok(response),
			Err(failure) => ServiceFailed { failure }.fail(),
		}
	}

	/// Get the name list.
	#[instrument(skip(self))]
	pub async fn get_name_list(
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

	/// Read data from the MMS server.
	#[instrument(skip(self))]
	pub async fn read(
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

	/// Write data to the MMS server.
	#[instrument(skip(self))]
	pub async fn write(
		&self,
		variable_access_specification: VariableAccessSpecification,
		list_of_data: Vec<Data>,
	) -> Result<(), MmsClientError> {
		let expected_results = list_of_data.len();
		let request = ConfirmedServiceRequest::write(WriteRequest::new(
			variable_access_specification,
			list_of_data,
		));
		let response = self.send_request(request).await?;
		let ConfirmedServiceResponse::write(response) = response else {
			return UnexpectedServiceResponse.fail();
		};

		// The Write-Response must carry exactly one result per data item
		// written. An empty or short list is a malformed response and must
		// not be silently reported as success.
		if response.0.len() != expected_results {
			return UnexpectedServiceResponse.fail();
		}

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

	/// Get the variable access attributes.
	#[instrument(skip(self))]
	pub async fn get_variable_access_attributes(
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

	/// Define a named variable list.
	#[instrument(skip(self))]
	pub async fn define_named_variable_list(
		&self,
		variable_list_name: ObjectName,
		list_of_variable: Vec<AnonymousVariableDefs>,
	) -> Result<(), MmsClientError> {
		let request = ConfirmedServiceRequest::defineNamedVariableList(
			DefineNamedVariableListRequest::new(variable_list_name, VariableDefs(list_of_variable)),
		);
		let response = self.send_request(request).await?;
		if !matches!(response, ConfirmedServiceResponse::defineNamedVariableList(_)) {
			return UnexpectedServiceResponse.fail();
		};
		Ok(())
	}

	/// Get the named variable list attributes.
	#[instrument(skip(self))]
	pub async fn get_named_variable_list_attributes(
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

	/// Delete a named variable list.
	#[instrument(skip(self))]
	pub async fn delete_named_variable_list(
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

	/// Open a file.
	#[instrument(skip(self))]
	pub async fn file_open(
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

	/// Read data from a file.
	#[instrument(skip(self))]
	pub async fn file_read(&self, frsm_id: i32) -> Result<Vec<u8>, MmsClientError> {
		let mut more_follows = true;
		let mut data = Vec::new();
		while more_follows {
			let request = ConfirmedServiceRequest::fileRead(FileReadRequest(Integer32(frsm_id)));
			let response = self.send_request(request).await?;
			let ConfirmedServiceResponse::fileRead(response) = response else {
				return UnexpectedServiceResponse.fail();
			};
			more_follows = response.more_follows;
			data.extend(response.file_data.iter());
		}
		Ok(data)
	}

	/// Close a file.
	#[instrument(skip(self))]
	pub async fn file_close(&self, frsm_id: i32) -> Result<(), MmsClientError> {
		let request = ConfirmedServiceRequest::fileClose(FileCloseRequest(Integer32(frsm_id)));
		let response = self.send_request(request).await?;
		if !matches!(response, ConfirmedServiceResponse::fileClose(_)) {
			return UnexpectedServiceResponse.fail();
		};
		Ok(())
	}

	/// Delete a file.
	#[instrument(skip(self))]
	pub async fn file_delete(&self, file_name: Vec<String>) -> Result<(), MmsClientError> {
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
		if !matches!(response, ConfirmedServiceResponse::fileDelete(_)) {
			return UnexpectedServiceResponse.fail();
		};
		Ok(())
	}

	/// Get the file directory.
	#[instrument(skip(self))]
	pub async fn file_directory(
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
			continue_after =
				response.list_of_directory_entry.last().cloned().map(|entry| entry.file_name);
			list_of_directory_entry.extend(response.list_of_directory_entry.into_iter());
		}
		Ok(list_of_directory_entry)
	}

	/// Rename a file on the server.
	#[instrument(skip(self))]
	pub async fn file_rename(
		&self,
		current_file_name: Vec<String>,
		new_file_name: Vec<String>,
	) -> Result<(), MmsClientError> {
		let to_file_name = |names: Vec<String>| {
			names
				.into_iter()
				.map(|name| {
					GraphicString::from_bytes(name.as_bytes())
						.map(AnonymousFileName)
						.context(VisibleStringConversion)
				})
				.collect::<Result<Vec<_>, _>>()
				.map(FileName)
		};
		let request = ConfirmedServiceRequest::fileRename(FileRenameRequest::new(
			to_file_name(current_file_name)?,
			to_file_name(new_file_name)?,
		));
		let response = self.send_request(request).await?;
		if !matches!(response, ConfirmedServiceResponse::fileRename(_)) {
			return UnexpectedServiceResponse.fail();
		}
		Ok(())
	}

	/// Cancel an outstanding confirmed request by its original invoke id.
	///
	/// Returns `Ok(())` when the peer confirms the cancellation. Note the
	/// invoke id is the MMS protocol id assigned internally; this is a
	/// best-effort control operation primarily useful for long-running
	/// services.
	#[instrument(skip(self))]
	pub async fn cancel(&self, original_invoke_id: u32) -> Result<(), MmsClientError> {
		let (tx, rx) = oneshot::channel();
		self.tx
			.send(Command::Cancel { original_invoke_id, responder: tx })
			.await
			.map_err(|_| ConnectionGone.build())?;
		let result = match self.request_timeout {
			Some(timeout) => tokio::time::timeout(timeout, rx)
				.await
				.map_err(|_| RequestTimeout { timeout }.build())?,
			None => rx.await,
		};
		match result.context(ReceiveResponse)? {
			Ok(()) => Ok(()),
			Err(failure) => ServiceFailed { failure }.fail(),
		}
	}

	/// Gracefully close the connection.
	///
	/// Sends an MMS Conclude-Request and then drops the transport (which
	/// closes the TCP socket). This is the pragmatic teardown used by most
	/// IEC 61850 clients; it does not send an ACSE RLRQ. Any requests still
	/// in flight are completed with `ServiceFailure::ConnectionClosed`.
	///
	/// Consumes the client; the connection is unusable afterwards.
	#[instrument(skip(self))]
	pub async fn close(self) -> Result<(), MmsClientError> {
		let (tx, rx) = oneshot::channel();
		// If the handler is already gone the connection is effectively
		// closed, so treat a send failure as success.
		if self.tx.send(Command::Shutdown { responder: tx }).await.is_err() {
			return Ok(());
		}
		// Best-effort: wait (bounded) for the teardown PDU to be written.
		match self.request_timeout {
			Some(timeout) => {
				let _ = tokio::time::timeout(timeout, rx).await;
			}
			None => {
				let _ = rx.await;
			}
		}
		Ok(())
	}
}

/// The handler for the MMS connection.
struct ConnectionHandler {
	/// The read half.
	read_half: AcseReadHalf,
	/// The write half.
	write_half: AcseWriteHalf,
	/// The receiver for commands from `MmsClient` handles.
	rx: mpsc::Receiver<Command>,
	/// The map of the response senders, keyed by invoke id.
	response_map: HashMap<u32, oneshot::Sender<ServiceResult>>,
	/// Pending cancel requests, keyed by the original invoke id being
	/// cancelled.
	cancel_map: HashMap<u32, oneshot::Sender<CancelResult>>,
	/// The report callback.
	report_callback: Box<dyn ReportCallback + Send + Sync>,
	/// MMS PDU size negotiated with the peer; encoded requests larger than
	/// this are rejected to the caller with `ServiceFailure::PduTooLarge`
	/// instead of being sent. Zero means "no limit known".
	max_pdu_size: usize,
}

impl ConnectionHandler {
	/// Create a new connection handler.
	#[must_use]
	pub fn new(
		read_half: AcseReadHalf,
		write_half: AcseWriteHalf,
		rx: mpsc::Receiver<Command>,
		report_callback: Box<dyn ReportCallback + Send + Sync>,
		max_pdu_size: usize,
	) -> Self {
		Self {
			read_half,
			write_half,
			rx,
			response_map: HashMap::new(),
			cancel_map: HashMap::new(),
			report_callback,
			max_pdu_size,
		}
	}

	/// Handle the MMS connection.
	/// This is the main loop for the MMS connection.
	#[instrument(skip(self))]
	async fn handle_connection(mut self) {
		let mut invoke_id: u32 = 0;
		let close_reason = loop {
			select! {
				data = self.read_half.receive_data() => {
					match self.handle_incoming(data).await {
						LoopAction::Continue => {}
						LoopAction::Break(reason) => break reason,
					}
				},
				request = self.rx.recv() => {
					match self.handle_outgoing(request, &mut invoke_id).await {
						LoopAction::Continue => {}
						LoopAction::Break(reason) => break reason,
					}
				},
			}
		};

		// Drain any waiters so callers get a typed error instead of an
		// opaque oneshot RecvError.
		for (_, sender) in self.response_map.drain() {
			let _ =
				sender.send(Err(ServiceFailure::ConnectionClosed { reason: close_reason.clone() }));
		}
		for (_, sender) in self.cancel_map.drain() {
			let _ =
				sender.send(Err(ServiceFailure::ConnectionClosed { reason: close_reason.clone() }));
		}
		// Close the request channel so subsequent send_request calls fail
		// fast rather than hang on the now-orphaned receiver.
		self.rx.close();
	}

	/// Handle one frame received from the peer. Returns whether the main
	/// loop should keep going or exit (with a reason for the waiters).
	async fn handle_incoming(&mut self, data: Result<Vec<u8>, AcseError>) -> LoopAction {
		let data = match data {
			Ok(data) => data,
			Err(e) => {
				let reason = format!("receive failed: {e}");
				tracing::error!("{}", reason);
				return LoopAction::Break(reason);
			}
		};
		let response: MMSpdu = match ber::decode(&data).context(DecodeResponse) {
			Ok(response) => response,
			Err(e) => {
				tracing::error!("Error decoding response: {:?}", e);
				return LoopAction::Continue;
			}
		};
		match response {
			MMSpdu::confirmed_ResponsePDU(response) => {
				self.handle_confirmed_response(response).await;
			}
			MMSpdu::confirmed_ErrorPDU(response) => {
				self.handle_confirmed_error(response).await;
			}
			MMSpdu::unconfirmed_PDU(response) => match response.service {
				UnconfirmedService::informationReport(report) => match Report::try_from(report) {
					Ok(report) => self.report_callback.on_report(report).await,
					Err(e) => tracing::error!("Error decoding report: {:?}", e),
				},
			},
			MMSpdu::rejectPDU(response) => {
				self.handle_rejected_pdu(response).await;
			}
			MMSpdu::cancel_ResponsePDU(response) => {
				let id = response.0.0;
				if let Some(sender) = self.cancel_map.remove(&id) {
					let _ = sender.send(Ok(()));
				} else {
					tracing::warn!("cancel-Response for unknown invoke id {id}");
				}
			}
			MMSpdu::cancel_ErrorPDU(response) => {
				let id = response.original_invoke_id.0;
				if let Some(sender) = self.cancel_map.remove(&id) {
					let failure = ServiceFailure::ConfirmedError {
						modifier_position: None,
						service_error: response.service_error,
					};
					let _ = sender.send(Err(failure));
				} else {
					tracing::warn!("cancel-Error for unknown invoke id {id}");
				}
			}
			MMSpdu::initiate_ResponsePDU(response) => {
				tracing::warn!("Unexpected initiate-Response after connect: {:?}", response);
			}
			MMSpdu::initiate_ErrorPDU(response) => {
				// Fatal: the peer told us the association is broken.
				let reason = format!("initiate-Error from peer: {:?}", response);
				tracing::error!("{}", reason);
				return LoopAction::Break(reason);
			}
			MMSpdu::conclude_RequestPDU(_) => {
				// Peer is closing gracefully. Reply with a Conclude-Response
				// (best-effort) and then stop the loop so waiters learn the
				// connection is closing.
				let pdu = MMSpdu::conclude_ResponsePDU(ConcludeResponsePDU(()));
				if let Ok(data) = ber::encode(&pdu).context(EncodeRequest)
					&& let Err(e) = self.write_half.send_data(data).await
				{
					tracing::warn!("Error writing conclude-Response: {e}");
				}
				let reason = "peer sent conclude-Request".to_owned();
				tracing::info!("{}", reason);
				return LoopAction::Break(reason);
			}
			MMSpdu::conclude_ResponsePDU(_) => {
				// Peer acknowledged our Conclude-Request; the loop will exit
				// via the Shutdown path that initiated it.
				tracing::debug!("Received conclude-Response from peer");
			}
			_ => {
				tracing::error!("Unexpected service response. Response: {:?}", response);
			}
		}
		LoopAction::Continue
	}

	/// Handle one command from the rx channel.
	async fn handle_outgoing(
		&mut self,
		command: Option<Command>,
		invoke_id: &mut u32,
	) -> LoopAction {
		match command {
			Some(Command::Request { request, responder }) => {
				self.handle_request_command(request, responder, invoke_id).await
			}
			Some(Command::Cancel { original_invoke_id, responder }) => {
				self.handle_cancel_command(original_invoke_id, responder).await
			}
			Some(Command::Shutdown { responder }) => {
				// Best-effort graceful close: write a Conclude-Request, then
				// stop the loop so the transport is dropped (TCP FIN).
				let pdu = MMSpdu::conclude_RequestPDU(ConcludeRequestPDU(()));
				if let Ok(data) = ber::encode(&pdu).context(EncodeRequest)
					&& let Err(e) = self.write_half.send_data(data).await
				{
					tracing::warn!("Error writing conclude-Request during close: {e}");
				}
				let _ = responder.send(());
				LoopAction::Break("local close".to_owned())
			}
			None => LoopAction::Break("client dropped".to_owned()),
		}
	}

	/// Encode and send a confirmed service request, registering its waiter.
	async fn handle_request_command(
		&mut self,
		request: ConfirmedServiceRequest,
		responder: oneshot::Sender<ServiceResult>,
		invoke_id: &mut u32,
	) -> LoopAction {
		let id = self.next_free_invoke_id(invoke_id);
		let data = match prepare_request(id, request) {
			Ok(data) => data,
			Err(e) => {
				tracing::error!("Error preparing request: {:?}", e);
				let _ = responder.send(Err(ServiceFailure::ConnectionClosed {
					reason: format!("encode failed: {e}"),
				}));
				return LoopAction::Continue;
			}
		};
		if self.max_pdu_size > 0 && data.len() > self.max_pdu_size {
			let _ = responder.send(Err(ServiceFailure::PduTooLarge {
				encoded: data.len(),
				limit: self.max_pdu_size,
			}));
			return LoopAction::Continue;
		}
		if let Err(e) = self.write_half.send_data(data).await {
			let reason = format!("send failed: {e}");
			tracing::error!("{}", reason);
			let _ =
				responder.send(Err(ServiceFailure::ConnectionClosed { reason: reason.clone() }));
			return LoopAction::Break(reason);
		}
		self.response_map.insert(id, responder);
		LoopAction::Continue
	}

	/// Encode and send a Cancel-Request, registering its waiter keyed by the
	/// original invoke id.
	async fn handle_cancel_command(
		&mut self,
		original_invoke_id: u32,
		responder: oneshot::Sender<CancelResult>,
	) -> LoopAction {
		let pdu = MMSpdu::cancel_RequestPDU(CancelRequestPDU(Unsigned32(original_invoke_id)));
		let data = match ber::encode(&pdu).context(EncodeRequest) {
			Ok(data) => data,
			Err(e) => {
				let _ = responder.send(Err(ServiceFailure::ConnectionClosed {
					reason: format!("encode failed: {e}"),
				}));
				return LoopAction::Continue;
			}
		};
		if let Err(e) = self.write_half.send_data(data).await {
			let reason = format!("send failed: {e}");
			tracing::error!("{}", reason);
			let _ =
				responder.send(Err(ServiceFailure::ConnectionClosed { reason: reason.clone() }));
			return LoopAction::Break(reason);
		}
		self.cancel_map.insert(original_invoke_id, responder);
		LoopAction::Continue
	}

	/// Delegate to the free function; kept as a method only so the caller
	/// site stays terse inside the select loop.
	fn next_free_invoke_id(&self, counter: &mut u32) -> u32 {
		next_free_invoke_id(counter, &self.response_map)
	}

	/// Handle a confirmed response.
	#[instrument(skip(self))]
	async fn handle_confirmed_response(&mut self, response: ConfirmedResponsePDU) {
		let invoke_id = response.invoke_id;
		let response = response.service;
		let Some(sender) = self.response_map.remove(&invoke_id.0) else {
			tracing::error!("No sender found for invoke ID: {}", invoke_id.0);
			return;
		};

		let _ = sender.send(Ok(response)).inspect_err(|e| {
			tracing::error!("Error sending response: {:?}", e);
		});
	}

	/// Handle a confirmed error.
	#[instrument(skip(self))]
	async fn handle_confirmed_error(&mut self, response: ConfirmedErrorPDU) {
		let invoke_id = response.invoke_id;
		let Some(sender) = self.response_map.remove(&invoke_id.0) else {
			tracing::error!("No sender found for invoke ID: {} (confirmed-error)", invoke_id.0);
			return;
		};
		let failure = ServiceFailure::ConfirmedError {
			modifier_position: response.modifier_position.map(|m| m.0),
			service_error: response.service_error,
		};
		let _ = sender.send(Err(failure)).inspect_err(|e| {
			tracing::error!("Error forwarding confirmed-error to caller: {:?}", e);
		});
	}

	/// Handle a rejected PDU.
	#[instrument(skip(self))]
	async fn handle_rejected_pdu(&mut self, response: RejectPDU) {
		tracing::info!("Rejected PDU: {:?}", response);
		let Some(invoke_id) = response.original_invoke_id else {
			tracing::warn!("Reject PDU without original_invoke_id; cannot route");
			return;
		};
		let Some(sender) = self.response_map.remove(&invoke_id.0) else {
			tracing::error!("No sender found for invoke ID: {} (reject)", invoke_id.0);
			return;
		};
		let failure = ServiceFailure::Rejected { reason: response.reject_reason };
		let _ = sender.send(Err(failure)).inspect_err(|e| {
			tracing::error!("Error forwarding reject to caller: {:?}", e);
		});
	}
}

/// What the connection-handler loop should do after handling one event.
enum LoopAction {
	/// Keep looping.
	Continue,
	/// Stop looping with the given human-readable reason; the reason is
	/// forwarded to every pending waiter so callers can tell why their
	/// request was abandoned.
	Break(String),
}

/// Pick the next unused invoke-id, wrapping on u32 overflow. The
/// outstanding-requests semaphore already caps concurrent in-flight
/// requests, so collisions are not expected; the linear scan is just a
/// belt-and-suspenders guard against ever overwriting a live waiter.
fn next_free_invoke_id(
	counter: &mut u32,
	in_flight: &HashMap<u32, oneshot::Sender<ServiceResult>>,
) -> u32 {
	loop {
		let id = *counter;
		*counter = counter.wrapping_add(1);
		if !in_flight.contains_key(&id) {
			return id;
		}
	}
}

/// Prepare a request for sending.
/// This function will prepare the request for sending by encoding it and adding
/// the invoke ID.
fn prepare_request(
	invoke_id: u32,
	request: ConfirmedServiceRequest,
) -> Result<Vec<u8>, MmsClientError> {
	let request =
		MMSpdu::confirmed_RequestPDU(ConfirmedRequestPDU::new(Unsigned32(invoke_id), request));
	ber::encode(&request).context(EncodeRequest)
}

/// Make a bitstring from the data.
/// This function will make a bitstring from the data by truncating it to the
/// length of the data.
#[must_use]
fn make_bitstring(data: &[u8], length: usize) -> BitString {
	let mut bitstring = BitString::from_slice(data);
	bitstring.truncate(length);
	bitstring
}

#[allow(missing_docs)]
/// MMS client errors
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
	#[snafu(display("Service failure: {:?}", failure))]
	ServiceFailed {
		failure: ServiceFailure,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("Request timed out after {timeout:?}"))]
	RequestTimeout {
		timeout: Duration,
		#[snafu(implicit)]
		context: Box<SpanTraceWrapper>,
	},
	#[snafu(display("MMS connection handler is no longer accepting requests"))]
	ConnectionGone {
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
	/// Get the context of the MMS client error.
	#[must_use]
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
			MmsClientError::ReceiveResponse { context, .. } => context,
			MmsClientError::DataAccessError { context, .. } => context,
			MmsClientError::VisibleStringConversion { context, .. } => context,
			MmsClientError::ServiceFailed { context, .. } => context,
			MmsClientError::RequestTimeout { context, .. } => context,
			MmsClientError::ConnectionGone { context } => context,
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

#[allow(clippy::print_stdout, clippy::expect_used)]
#[cfg(test)]
mod tests {
	use rust_telemetry::config::OtelConfig;

	use super::*;
	use crate::mms::MmsObjectClass;

	#[tokio::test]
	async fn test_get_logical_devices() -> Result<(), MmsClientError> {
		let _g = rust_telemetry::init_otel!(&OtelConfig::for_tests());
		if let Err(e) = async {
			let config = ClientConfig::default();
			println!("Connecting to server...");
			let client = MmsClient::connect(&config, Box::new(TestReportCallback)).await?;
			println!("Getting logical devices...");
			let devices = client
				.get_name_list(
					MmsObjectClass::Domain as u8,
					GetNameListRequestObjectScope::vmdSpecific(()),
				)
				.await?;
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
			println!("Starting to read file {}...", directory[0]);
			let fd = client.file_open(vec![directory[0].clone()], None).await?.frsm_id.0;
			println!("File descriptor: {:?}", fd);
			println!("Reading file...");
			let data = client.file_read(fd).await?;
			println!("Data: {:?}", String::from_utf8(data).expect("Invalid UTF-8"));
			println!("Closing file...");
			client.file_close(fd).await?;
			println!("File closed");
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
				println!("Number of entries: {}", file_dir_response.list_of_directory_entry.len());
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

	#[test]
	fn test_next_free_invoke_id_skips_in_flight() {
		// If id 5 is already in flight, the counter should skip it on its
		// next pass and hand back 6 instead.
		let mut counter: u32 = 5;
		let (tx, _rx) = oneshot::channel();
		let mut in_flight: HashMap<u32, oneshot::Sender<ServiceResult>> = HashMap::new();
		in_flight.insert(5, tx);
		let id = next_free_invoke_id(&mut counter, &in_flight);
		assert_eq!(id, 6);
		// Counter advanced past the collision.
		assert_eq!(counter, 7);
	}

	#[test]
	fn test_next_free_invoke_id_wraps_around() {
		// The counter must wrap cleanly at u32::MAX instead of overflowing.
		let mut counter = u32::MAX;
		let in_flight: HashMap<u32, oneshot::Sender<ServiceResult>> = HashMap::new();
		let id = next_free_invoke_id(&mut counter, &in_flight);
		assert_eq!(id, u32::MAX);
		assert_eq!(counter, 0);
	}

	struct TestReportCallback;

	#[async_trait::async_trait]
	impl ReportCallback for TestReportCallback {
		async fn on_report(&self, report: Report) {
			tracing::debug!("Report: {:?}", report);
		}
	}
}
