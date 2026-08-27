//! Example client for the IEC61850 protocol.
//!
//! Connects to a server, loads the model, reads a dataset, enables a report
//! control block, and reconnects from a **separate task** after
//! [`iec61850::ClientCallback::on_disconnected`]. Do not call
//! [`iec61850::Iec61850Client::reconnect`] from that callback: it runs on the
//! MMS handler task. Ignore [`iec61850::DisconnectReason::Replaced`] so a
//! reconnect of a still-live association is not treated as a drop.
//!
//! Expects a server on localhost:102 (override via [`iec61850::ClientConfig`])
//! with a dataset and a report control block. Drop the server while this
//! example is waiting to see reconnect.

use std::{sync::Arc, time::Duration};

use iec61850::{
	ClientCallback, ClientConfig, DisconnectReason, Iec61850Client,
	iec61850::{
		rcb::{OptionalFields, TriggerOptions},
		report::Report,
	},
};
use snafu::{ResultExt, Whatever};
use tokio::sync::watch;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
	EnvFilter, Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<(), Whatever> {
	let filter = EnvFilter::from("debug");
	let layer = tracing_subscriber::fmt::layer().with_filter(filter);
	tracing_subscriber::registry()
		.with(layer)
		//needed to get the tracing_error working
		.with(ErrorLayer::default().with_filter(EnvFilter::from("debug")))
		.init();

	let config = ClientConfig::default();
	let (connected_tx, connected_rx) = watch::channel(false);

	let client = Arc::new(
		Iec61850Client::new(config.clone(), ExampleCallback { connected: connected_tx })
			.await
			.whatever_context("Failed to create client")?,
	);

	let model = client.model();
	tracing::info!("Model: {model:#}");

	let mut dataset = None;
	let mut rcb = None;
	for ld in &model.logical_devices {
		for ln in &ld.logical_nodes {
			if dataset.is_none() {
				let ds = ln.datasets.values().next().cloned();
				if ds.is_some() {
					dataset = ds;
				}
			}
			if rcb.is_none() {
				let report = ln.reports.values().next().cloned();
				if report.is_some() {
					rcb = report;
				}
			}
			if dataset.is_some() && rcb.is_some() {
				break;
			}
		}
	}

	if let Some(dataset) = &dataset {
		let data = client
			.read_dataset(&dataset.path.as_str().into())
			.await
			.whatever_context("Failed to read dataset")?;
		tracing::info!("Data: {data:#?}");
	}

	let dataset_path = dataset.as_ref().map(|d| d.path.clone());
	let rcb_path = rcb.as_ref().map(|r| r.path.clone());

	if let Some(path) = &rcb_path {
		enable_reports(&client, path, dataset_path.as_deref())
			.await
			.whatever_context("Failed to enable reports")?;
	}

	let supervisor = tokio::spawn(reconnect_supervisor(
		Arc::clone(&client),
		config,
		connected_rx,
		rcb_path.clone(),
		dataset_path.clone(),
	));

	tracing::info!("Waiting for reports (stop the IED to observe reconnect)");
	tokio::time::sleep(Duration::from_secs(1)).await;

	if let Some(path) = &rcb_path {
		client
			.set_rcb_enabled(&path.as_str().into(), false)
			.await
			.whatever_context("Failed to set report control block enabled")?;
		client
			.set_rcb_trigger_options(&path.as_str().into(), vec![TriggerOptions::DataChange])
			.await
			.whatever_context("Failed to set report control block trigger options")?;
	}

	let data = client
		.read_data_from_ld("SampleIEDDevice1", &["DGEN1$ST$Mod", "DGEN1$MX$TotWh"])
		.await
		.whatever_context("Failed to read data")?;
	tracing::info!("Data: {data:#?}");

	supervisor.abort();
	Ok(())
}

/// Re-enable reporting after connect or reconnect. The crate does not restore
/// RCB state on [`Iec61850Client::reconnect`].
async fn enable_reports(
	client: &Iec61850Client,
	rcb_path: &str,
	dataset_path: Option<&str>,
) -> Result<(), iec61850::iec61850::Iec61850ClientError> {
	let rcb_path = rcb_path.into();

	let report = client.get_rcb(&rcb_path).await?;
	tracing::info!("Report control block: {report:#?}");

	if let Some(dataset) = dataset_path {
		client.set_rcb_dataset(&rcb_path, dataset).await?;
	}
	client.set_rcb_integrity_period(&rcb_path, 1000).await?;
	client.set_rcb_buffer_time(&rcb_path, 1000).await?;
	client
		.set_rcb_trigger_options(
			&rcb_path,
			vec![TriggerOptions::DataChange, TriggerOptions::Integrity],
		)
		.await?;
	client
		.set_rcb_optional_fields(
			&rcb_path,
			vec![OptionalFields::SequenceNumber, OptionalFields::DataReference],
		)
		.await?;
	client.set_rcb_enabled(&rcb_path, true).await?;
	client.set_rcb_gi(&rcb_path, true).await?;
	Ok(())
}

/// Watches association state and reconnects only after a drop.
async fn reconnect_supervisor(
	client: Arc<Iec61850Client>,
	config: ClientConfig,
	mut connected: watch::Receiver<bool>,
	rcb_path: Option<String>,
	dataset_path: Option<String>,
) {
	loop {
		if connected.changed().await.is_err() {
			break;
		}
		if *connected.borrow_and_update() {
			tracing::info!("Association up");
			continue;
		}

		tracing::warn!("Association down; reconnecting");
		let mut delay = Duration::from_secs(1);
		loop {
			match client.reconnect(&config).await {
				Ok(()) => {
					if let Some(path) = &rcb_path
						&& let Err(error) =
							enable_reports(&client, path, dataset_path.as_deref()).await
					{
						tracing::error!("Failed to restore reports: {error}");
					}
					break;
				}
				Err(error) => {
					tracing::error!("Reconnect failed: {error}");
					tokio::time::sleep(delay).await;
					delay = (delay * 2).min(Duration::from_secs(30));
				}
			}
		}
	}
}

/// Signals association changes to the reconnect supervisor.
///
/// Do **not** call [`Iec61850Client::reconnect`] from these methods.
struct ExampleCallback {
	/// `true` while an MMS association is up.
	connected: watch::Sender<bool>,
}

#[async_trait::async_trait]
impl ClientCallback for ExampleCallback {
	async fn on_report(&self, report: Report) {
		// TO see the report change the filter to debug or this tracing level to info
		tracing::debug!("Report: {:?}", report);
	}

	async fn on_connected(&self) {
		tracing::info!("Connection started");
		let _ = self.connected.send(true);
	}

	async fn on_disconnected(&self, reason: DisconnectReason) {
		tracing::info!("Connection stopped: {reason}");
		// `reconnect` on a still-open association closes the old one with
		// `Replaced`. Skip it so the supervisor does not treat our own
		// reconnect as another drop. After an unexpected drop the handler
		// is already gone, so reconnect does not fire this.
		if matches!(reason, DisconnectReason::Replaced | DisconnectReason::Closed) {
			return;
		}
		let _ = self.connected.send(false);
	}
}
