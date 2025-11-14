use rasn::prelude::VisibleString;
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use tracing::instrument;

pub mod data;
pub mod rcb;
pub mod report;

use crate::{
	iec61850::{
		data::Iec61850Data,
		rcb::{OptionalFields, ReportControlBlock, ReportControlBlockError, TriggerOptions},
	},
	mms::{
		ClientConfig, MmsObjectClass,
		ans1::mms::asn1::*,
		client::{MmsClient, MmsClientError},
	},
};
pub struct Iec61850Client {
	client: MmsClient,
}

impl Iec61850Client {
	pub async fn new(config: ClientConfig) -> Result<Self, Iec61850ClientError> {
		Ok(Self { client: MmsClient::connect(&config).await? })
	}

	#[instrument(skip(self))]
	pub async fn get_logical_devices(&self) -> Result<Vec<String>, Iec61850ClientError> {
		self.client
			.get_name_list(
				MmsObjectClass::Domain as u8,
				GetNameListRequestObjectScope::vmdSpecific(()),
			)
			.await
			.map_err(Into::into)
	}
	#[instrument(skip(self))]
	pub async fn get_logical_nodes(
		&self,
		logical_device: &str,
	) -> Result<Vec<String>, Iec61850ClientError> {
		self.client
			.get_name_list(
				MmsObjectClass::NamedVariable as u8,
				GetNameListRequestObjectScope::domainSpecific(to_identifier(logical_device)?),
			)
			.await
			.map_err(Into::into)
			.map(|nodes| nodes.into_iter().filter(|node| !node.contains("$")).collect())
	}

	#[instrument(skip(self))]
	pub async fn get_report_control_blocks(
		&self,
		logical_device: &str,
	) -> Result<Vec<String>, Iec61850ClientError> {
		self.client
			.get_name_list(
				MmsObjectClass::NamedVariable as u8,
				GetNameListRequestObjectScope::domainSpecific(to_identifier(logical_device)?),
			)
			.await
			.map_err(Into::into)
			.map(|nodes| {
				nodes
					.into_iter()
					.filter(|node| {
						let mut parts = node.splitn(4, '$');
						matches!(
							(parts.next(), parts.next(), parts.next(), parts.next()),
							(Some(_), Some("BR" | "RP"), Some(_), None)
						)
					})
					.collect()
			})
	}

	/// Get the datasets in a logical device.
	/// If logical_device is None, the datasets are association datasets.
	/// If logical_device is Some, the datasets are logical device datasets.
	#[instrument(skip(self))]
	pub async fn get_datasets(
		&self,
		logical_device: Option<&str>,
	) -> Result<Vec<String>, Iec61850ClientError> {
		let scope = if let Some(ld) = logical_device {
			GetNameListRequestObjectScope::domainSpecific(to_identifier(ld)?)
		} else {
			GetNameListRequestObjectScope::aaSpecific(())
		};
		self.client
			.get_name_list(MmsObjectClass::NamedVariableList as u8, scope)
			.await
			.map_err(Into::into)
	}
	/// Get the variables in a dataset.
	/// If logical_device is None, the dataset is an association dataset.
	/// If logical_device is Some, the dataset is a logical device dataset.
	#[instrument(skip(self))]
	pub async fn get_dataset(
		&self,
		dataset: &str,
		logical_device: Option<&str>,
	) -> Result<Vec<String>, Iec61850ClientError> {
		let object_name = if let Some(ld) = logical_device {
			ObjectNameDomainSpecific::new(to_identifier(ld)?, to_identifier(dataset)?).into()
		} else {
			ObjectName::aa_specific(to_identifier(dataset)?)
		};

		self.client
			.get_named_variable_list_attributes(object_name)
			.await
			.map(|response| {
				response
					.list_of_variable
					.0
					.into_iter()
					.map(|variable| {
						let VariableSpecification::name(name) = variable.variable_specification;
						name.to_string()
					})
					.collect()
			})
			.map_err(Into::into)
	}
	#[instrument(skip(self))]
	pub async fn get_data_definition(
		&self,
		logical_device: &str,
		logical_node: &str,
	) -> Result<TypeSpecification, Iec61850ClientError> {
		let object_name = ObjectName::domain_specific(ObjectNameDomainSpecific::new(
			to_identifier(logical_device)?,
			to_identifier(logical_node)?,
		));
		let response = self.client.get_variable_access_attributes(object_name).await?;

		Ok(response.type_specification)
	}
	pub async fn create_dataset(
		&self,
		path: &str,
		entries: Vec<String>,
	) -> Result<(), Iec61850ClientError> {
		// Association dataset can have elements from multiple logical devices while
		// dataset inside a logical device can only have elements from that logical
		// device.
		let (variable_list_name, logical_device) = if path.starts_with("@") {
			(ObjectName::aa_specific(to_identifier(path.trim_start_matches("@"))?), None)
		} else {
			let split_path = path.split('/').collect::<Vec<&str>>();
			if split_path.len() != 2 {
				return InvalidPath.fail();
			}
			let logical_device = split_path[0];
			let logical_node = split_path[1];
			(
				ObjectName::domain_specific(ObjectNameDomainSpecific::new(
					to_identifier(logical_device)?,
					to_identifier(logical_node)?,
				)),
				Some(logical_device),
			)
		};

		let variables = entries
			.iter()
			.map(|entry| {
				let split_path = entry.split('/').collect::<Vec<&str>>();
				if split_path.len() != 2 || logical_device.is_some_and(|ld| ld != split_path[0]) {
					return InvalidPath.fail();
				}
				Ok(AnonymousVariableDefs::new(
					ObjectName::domain_specific(ObjectNameDomainSpecific::new(
						to_identifier(split_path[0])?,
						to_identifier(split_path[1])?,
					))
					.into(),
					None,
				))
			})
			.collect::<Result<Vec<_>, _>>()?;

		self.client.define_named_variable_list(variable_list_name, variables).await?;
		Ok(())
	}

	async fn read_dataset(&self, dataset: &str) -> Result<Vec<Iec61850Data>, Iec61850ClientError> {
		let object_name = if dataset.starts_with("@") {
			ObjectName::aa_specific(to_identifier(dataset.trim_start_matches("@"))?)
		} else {
			let split_path = dataset.split('/').collect::<Vec<&str>>();
			if split_path.len() != 2 {
				return InvalidPath.fail();
			}
			ObjectName::domain_specific(ObjectNameDomainSpecific::new(
				to_identifier(split_path[0])?,
				to_identifier(split_path[1])?,
			))
		};

		self.client
			// TODO: Changing from false to true will break stuff. Investigate why.
			.read(VariableAccessSpecification::variableListName(object_name), false)
			.await
			.map_err(Into::into)
			.map(|data| data.into_iter().map(|d| d.into()).collect())
	}

	async fn get_report_control_block(
		&self,
		logical_device: &str,
		report_control_block: &str,
	) -> Result<ReportControlBlock, Iec61850ClientError> {
		let object_name = ObjectName::domain_specific(ObjectNameDomainSpecific::new(
			to_identifier(logical_device)?,
			to_identifier(report_control_block)?,
		));
		let mut data: Vec<Iec61850Data> = self
			.client
			.read(
				VariableAccessSpecification::listOfVariable(VariableDefs(vec![
					AnonymousVariableDefs::new(VariableSpecification::name(object_name), None),
				])),
				false,
			)
			.await?
			.into_iter()
			.map(|d| d.into())
			.collect();

		match data.pop().context(InvalidDataLength)? {
			Iec61850Data::Structure(data) => {
				ReportControlBlock::from_data(report_control_block.to_owned(), data)
					.context(CreateReportControlBlock)
			}
			_ => InvalidData.fail(),
		}
	}

	pub async fn set_data_value(
		&self,
		path: &str,
		data: Iec61850Data,
	) -> Result<(), Iec61850ClientError> {
		let split_path = path.split('/').collect::<Vec<&str>>();
		if split_path.len() != 2 {
			return InvalidPath.fail();
		}

		let variable_access_specification = VariableDefs(vec![AnonymousVariableDefs::new(
			VariableSpecification::name(ObjectName::domain_specific(
				ObjectNameDomainSpecific::new(
					to_identifier(split_path[0])?,
					to_identifier(split_path[1])?,
				),
			)),
			None,
		)])
		.into();

		let list_of_data = vec![data.into()];

		self.client.write(variable_access_specification, list_of_data).await.map_err(Into::into)
	}
	pub async fn set_report_control_block_gi(
		&self,
		logical_device: &str,
		report_control_block: &str,
		gi: bool,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Bool(gi);
		self.set_data_value(&format!("{logical_device}/{report_control_block}$GI"), data).await
	}
	pub async fn set_report_control_block_enabled(
		&self,
		logical_device: &str,
		report_control_block: &str,
		enabled: bool,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Bool(enabled);
		self.set_data_value(&format!("{logical_device}/{report_control_block}$RptEna"), data).await
	}

	pub async fn set_report_control_block_dataset(
		&self,
		logical_device: &str,
		report_control_block: &str,
		dataset: &str,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::String(dataset.trim_start_matches("@").to_owned());
		self.set_data_value(&format!("{logical_device}/{report_control_block}$DatSet"), data).await
	}
	pub async fn set_report_control_block_integrity_period(
		&self,
		logical_device: &str,
		report_control_block: &str,
		integrity_period: u32,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Unsigned(integrity_period);
		self.set_data_value(&format!("{logical_device}/{report_control_block}$IntgPd"), data).await
	}
	pub async fn set_report_control_block_buffer_time(
		&self,
		logical_device: &str,
		report_control_block: &str,
		buffer_time: u32,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Unsigned(buffer_time);
		self.set_data_value(&format!("{logical_device}/{report_control_block}$BufTm"), data).await
	}
	pub async fn set_report_control_block_trigger_options(
		&self,
		logical_device: &str,
		report_control_block: &str,
		trigger_options: Vec<TriggerOptions>,
	) -> Result<(), Iec61850ClientError> {
		self.set_data_value(
			&format!("{logical_device}/{report_control_block}$TrgOps"),
			trigger_options.into(),
		)
		.await
	}
	pub async fn set_report_control_block_optional_fields(
		&self,
		logical_device: &str,
		report_control_block: &str,
		optional_fields: Vec<OptionalFields>,
	) -> Result<(), Iec61850ClientError> {
		self.set_data_value(
			&format!("{logical_device}/{report_control_block}$OptFlds"),
			optional_fields.into(),
		)
		.await
	}
}

fn to_identifier<T: AsRef<str>>(value: T) -> Result<Identifier, Iec61850ClientError> {
	Ok(Identifier(
		VisibleString::from_iso646_bytes(value.as_ref().as_bytes())
			.context(ConvertToVisibleString)?,
	))
}

impl std::fmt::Display for ObjectName {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ObjectName::vmd_specific(name) => write!(f, "{}", name.0),
			ObjectName::domain_specific(name) => {
				write!(f, "{}/{}", name.domain_id.0, name.item_id.0)
			}
			ObjectName::aa_specific(name) => write!(f, "{}", name.0),
		}
	}
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum Iec61850ClientError {
	/// Error converting to visible string.
	ConvertToVisibleString { source: rasn::error::strings::PermittedAlphabetError },
	/// Invalid variable path format. Expected: <logical_device>/<logical_node>
	InvalidPath,
	/// Error on the MMS client.
	Client { source: MmsClientError },
	/// Invalid data.
	InvalidData,
	/// Invalid data length.
	InvalidDataLength,
	/// Error creating report control block.
	CreateReportControlBlock { source: ReportControlBlockError },
}

impl From<MmsClientError> for Iec61850ClientError {
	fn from(error: MmsClientError) -> Self {
		Iec61850ClientError::Client { source: error }
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use rust_telemetry::config::OtelConfig;

	use super::*;

	#[tokio::test]
	async fn test_get_logical_nodes() -> Result<(), Iec61850ClientError> {
		let _g = rust_telemetry::init_otel!(&OtelConfig::for_tests());
		let client = Iec61850Client::new(ClientConfig::default()).await?;
		let devices = client.get_logical_devices().await?;
		println!("Devices: {:?}", devices);
		let mut map = HashMap::new();
		for device in devices {
			let nodes = client.get_logical_nodes(&device).await?;
			// println!("Nodes: {nodes:?}");
			map.insert(device, nodes);
			// for node in nodes {
			//     let data_definition = client.get_data_definition(&device,
			// &node).await?;     println!("Data definition: {:#?}",
			// data_definition); }
		}
		let (device, nodes) = map.iter().next().unwrap();
		let node = nodes.iter().next().unwrap();
		client
			.create_dataset(
				"@MyAssociationDataSet",
				vec![
					format!("{device}/MMXU2$MX$TotW$mag$f"),
					format!("{device}/DGEN1$ST$GnOpSt$stVal"),
				],
			)
			.await?;
		let datasets = client.get_datasets(Some(device)).await?;
		println!("Datasets: {datasets:?}");
		let dataset = client.get_dataset(&datasets[0], Some(device)).await?;
		println!("Dataset: {dataset:?}");
		let dataset_name = format!("{device}/{}", datasets[0]);
		let data = client.read_dataset(&dataset_name).await?;
		println!("Data: {data:?}");
		println!("Data: {:?}", data[0]);
		let report_control_blocks = client.get_report_control_blocks(device).await?;
		println!("Report control blocks: {report_control_blocks:?}");
		let report_control_block =
			client.get_report_control_block(device, &report_control_blocks[0]).await?;
		println!("Report control block: {report_control_block:?}");
		client
			.set_report_control_block_dataset(device, &report_control_blocks[0], &dataset_name)
			.await?;
		println!("Set dataset");
		client
			.set_report_control_block_integrity_period(device, &report_control_blocks[0], 1000)
			.await?;
		println!("Set integrity period");
		client
			.set_report_control_block_buffer_time(device, &report_control_blocks[0], 1000)
			.await?;
		println!("Set buffer time");
		client
			.set_report_control_block_trigger_options(
				device,
				&report_control_blocks[0],
				vec![TriggerOptions::DataChange, TriggerOptions::Integrity, TriggerOptions::Gi],
			)
			.await?;
		println!("Set trigger options");
		client
			.set_report_control_block_optional_fields(
				device,
				&report_control_blocks[0],
				vec![
					OptionalFields::SequenceNumber,
					OptionalFields::ReportTimestamp,
					OptionalFields::ReasonForTransmission,
					OptionalFields::DataSetName,
					OptionalFields::BufferOverflow,
					OptionalFields::EntryID,
					OptionalFields::ConfigurationRevision,
				],
			)
			.await?;
		println!("Set optional fields");
		client.set_report_control_block_enabled(device, &report_control_blocks[0], true).await?;
		println!("Set enabled");
		client.set_report_control_block_gi(device, &report_control_blocks[0], true).await?;
		println!("Set GI");

		tokio::time::sleep(std::time::Duration::from_secs(10)).await;
		Ok(())
	}
}
