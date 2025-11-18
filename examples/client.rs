//! Example client for the IEC61850 protocol.
//! This example will connect to a IEC61850 server and read the data model from
//! the server. Them it will read a dataset, configures a rcb and starts
//! receiving reports. Finally it will some data from the logical device.
//!
//! This example is expecting a server running on localhost:120 with the
//! IEC61850 model loaded that has a dataset and a report control block.

use iec61850::{
	ClientConfig, Iec61850Client,
	iec61850::{
		rcb::{OptionalFields, TriggerOptions},
		report::Report,
	},
	mms::ReportCallback,
};
use snafu::{ResultExt, Whatever};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
	EnvFilter, Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _,
};

#[tokio::main]
async fn main() -> Result<(), Whatever> {
	let filter = EnvFilter::from("info");
	let layer = tracing_subscriber::fmt::layer().with_filter(filter);
	tracing_subscriber::registry()
		.with(layer)
		//needed to get the tracing_error working
		.with(ErrorLayer::default().with_filter(EnvFilter::from("debug")))
		.init();

	let client = Iec61850Client::new(ClientConfig::default(), Box::new(TestReportCallback))
		.await
		.whatever_context("Failed to create client")?;

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
		let data =
			client.read_dataset(&dataset.path).await.whatever_context("Failed to read dataset")?;
		tracing::info!("Data: {data:#?}");
	}

	if let Some(rcb) = rcb {
		let split_path = rcb.path.split('/').collect::<Vec<&str>>();
		let ld = split_path[0];
		let rcb = split_path[1];

		let report =
			client.get_rcb(ld, rcb).await.whatever_context("Failed to get report control block")?;
		tracing::info!("Report control block: {report:#?}");

		if let Some(dataset) = &dataset {
			client
				.set_rcb_dataset(ld, rcb, &dataset.path)
				.await
				.whatever_context("Failed to set report control block dataset")?;
		}
		client
			.set_rcb_integrity_period(ld, rcb, 1000)
			.await
			.whatever_context("Failed to set report control block integrity period")?;
		client
			.set_rcb_buffer_time(ld, rcb, 1000)
			.await
			.whatever_context("Failed to set report control block buffer time")?;
		client
			.set_rcb_trigger_options(
				ld,
				rcb,
				vec![TriggerOptions::DataChange, TriggerOptions::Integrity],
			)
			.await
			.whatever_context("Failed to set report control block trigger options")?;
		client
			.set_rcb_optional_fields(
				ld,
				rcb,
				vec![OptionalFields::SequenceNumber, OptionalFields::DataReference],
			)
			.await
			.whatever_context("Failed to set report control block optional fields")?;
		client
			.set_rcb_enabled(ld, rcb, true)
			.await
			.whatever_context("Failed to set report control block enabled")?;
		client
			.set_rcb_gi(ld, rcb, true)
			.await
			.whatever_context("Failed to set report control block GI")?;

		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		client
			.set_rcb_enabled(ld, rcb, false)
			.await
			.whatever_context("Failed to set report control block enabled")?;
		client
			.set_rcb_trigger_options(ld, rcb, vec![TriggerOptions::DataChange])
			.await
			.whatever_context("Failed to set report control block trigger options")?;
	}

	let data = client
		.read_data_from_ld("SampleIEDDevice1", &["DGEN1$ST$Mod", "DGEN1$MX$TotWh"])
		.await
		.whatever_context("Failed to read data")?;
	tracing::info!("Data: {data:#?}");

	Ok(())
}

/// A test report callback that will print the report to the console.
struct TestReportCallback;

#[async_trait::async_trait]
impl ReportCallback for TestReportCallback {
	async fn on_report(&self, report: Report) {
		// TO see the report change the filter to debug or this tracing level to info
		tracing::debug!("Report: {:?}", report);
	}
}
