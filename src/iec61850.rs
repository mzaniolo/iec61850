//! IEC 61850 client implementation.

use std::{collections::HashMap, fmt, str::Utf8Error};

use rasn::prelude::VisibleString;
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use tracing::instrument;

pub mod data;
pub mod model;
pub mod rcb;
pub mod report;

use crate::{
	iec61850::{
		data::{Iec61850Data, Iec61850DataError},
		model::{IedModel, LogicalDevice, LogicalNode},
		rcb::{OptionalFields, ReportControlBlock, ReportControlBlockError, TriggerOptions},
	},
	mms::{
		ClientConfig, MmsObjectClass, ReportCallback,
		ans1::mms::asn1::*,
		client::{MmsClient, MmsClientError},
	},
};

/// An IEC 61850 client.
#[derive(Debug)]
pub struct Iec61850Client {
	/// The MMS client.
	client: MmsClient,
	/// The IEC 61850 model.
	ied_model: IedModel,
}

impl Iec61850Client {
	/// Create a new IEC 61850 client and load the model from the ied.
	pub async fn new(
		config: ClientConfig,
		report_callback: Box<dyn ReportCallback + Send + Sync>,
	) -> Result<Self, Iec61850ClientError> {
		let mut client = Self {
			client: MmsClient::connect(&config, report_callback).await?,
			ied_model: IedModel::default(),
		};
		client.reload_ied_model().await?;
		Ok(client)
	}

	/// Reload the model from the ied
	pub async fn reload_ied_model(&mut self) -> Result<(), Iec61850ClientError> {
		let model = self.get_ied_model().await?;
		self.ied_model = model;
		Ok(())
	}

	/// Get the IED model.
	#[must_use]
	pub const fn model(&self) -> &IedModel {
		&self.ied_model
	}

	/// Get the IED model from the ied.
	#[instrument(skip(self))]
	async fn get_ied_model(&self) -> Result<IedModel, Iec61850ClientError> {
		let mut logical_devices = self
			.get_logical_devices_names()
			.await?
			.into_iter()
			.map(LogicalDevice::new)
			.collect::<Vec<_>>();

		for ld in &mut logical_devices {
			let mut logical_nodes = self
				.get_logical_nodes_names(&ld.name)
				.await?
				.into_iter()
				.map(|ln| LogicalNode::new(ln, &ld.name))
				.collect::<Vec<_>>();

			// Build the logical node tree.
			for ln in &mut logical_nodes {
				ln.parse_nodes(self.get_data_definition(&ld.name, &ln.name).await?);
			}

			// TODO: Rethink this to optimize memory allocation.
			ld.logical_nodes.extend(logical_nodes);

			let reports = self.get_rcbs(&ld.name).await?;
			let mut report_rcbs = Vec::new();
			for report in reports {
				let rcb = self.get_rcb(&(&ld.name, &report).into()).await?;
				report_rcbs.push((report, rcb));
			}
			ld.add_reports(report_rcbs).context(Model)?;

			let datasets = self.get_datasets(Some(&ld.name)).await?;
			let mut dataset_entries = HashMap::new();
			for dataset in datasets {
				let entries = self.get_dataset(&dataset, Some(&ld.name)).await?;
				dataset_entries.insert(dataset, entries);
			}
			ld.add_datasets(dataset_entries).context(Model)?;
		}
		Ok(IedModel { logical_devices })
	}

	/// Get the names of the logical devices.
	#[instrument(skip(self))]
	pub async fn get_logical_devices_names(&self) -> Result<Vec<String>, Iec61850ClientError> {
		self.client
			.get_name_list(
				MmsObjectClass::Domain as u8,
				GetNameListRequestObjectScope::vmdSpecific(()),
			)
			.await
			.map_err(Into::into)
	}

	/// Get the names of the logical nodes in a logical device.
	#[instrument(skip(self))]
	pub async fn get_logical_nodes_names(
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

	/// Get the data definition of a logical node.
	#[instrument(skip(self))]
	async fn get_data_definition(
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

	/// Create a dataset.
	/// If path starts with @, the dataset is an association dataset.
	/// If path does not start with @, the dataset is a logical device dataset
	/// and the path needs to be like <logical_device>/<dataset_path>.
	pub async fn create_dataset(
		&self,
		path: &ObjectPath,
		entries: Vec<String>,
	) -> Result<(), Iec61850ClientError> {
		let path_str = path.to_string();
		// Association dataset can have elements from multiple logical devices while
		// dataset inside a logical device can only have elements from that logical
		// device.
		let (variable_list_name, logical_device) = if path_str.starts_with("@") {
			(ObjectName::aa_specific(to_identifier(path_str.trim_start_matches("@"))?), None)
		} else {
			let path = path.get_split_path()?;
			(
				ObjectName::domain_specific(ObjectNameDomainSpecific::new(
					to_identifier(path.0)?,
					to_identifier(path.1)?,
				)),
				Some(path.0),
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

	/// Read a dataset.
	pub async fn read_dataset(
		&self,
		dataset: &ObjectPath,
	) -> Result<Vec<Iec61850Data>, Iec61850ClientError> {
		let dataset_str = dataset.to_string();
		let object_name = if dataset_str.starts_with("@") {
			ObjectName::aa_specific(to_identifier(dataset_str.trim_start_matches("@"))?)
		} else {
			let path = dataset.get_split_path()?;
			ObjectName::domain_specific(ObjectNameDomainSpecific::new(
				to_identifier(path.0)?,
				to_identifier(path.1)?,
			))
		};

		self.client
			// TODO: Changing from false to true will break stuff. Investigate why.
			.read(VariableAccessSpecification::variableListName(object_name), false)
			.await?
			.into_iter()
			.map(TryInto::try_into)
			.collect::<Result<_, Iec61850DataError>>()
			.context(ConvertDataToMmsData)
	}

	/// Set the data value of a path.
	pub async fn set_data_value(
		&self,
		path: &ObjectPath,
		data: Iec61850Data,
	) -> Result<(), Iec61850ClientError> {
		let path = path.get_split_path()?;

		let variable_access_specification = VariableDefs(vec![AnonymousVariableDefs::new(
			VariableSpecification::name(ObjectName::domain_specific(
				ObjectNameDomainSpecific::new(to_identifier(path.0)?, to_identifier(path.1)?),
			)),
			None,
		)])
		.into();

		let list_of_data = vec![data.try_into().context(ConvertDataToMmsData)?];

		self.client.write(variable_access_specification, list_of_data).await.map_err(Into::into)
	}

	/// Get all the report control blocks in a logical device.
	#[instrument(skip(self))]
	pub async fn get_rcbs(&self, logical_device: &str) -> Result<Vec<String>, Iec61850ClientError> {
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

	/// Get a report control block by its path in a logical device.
	#[instrument(skip(self))]
	pub async fn get_rcb(
		&self,
		path: &ObjectPath,
	) -> Result<ReportControlBlock, Iec61850ClientError> {
		let (logical_device, report_control_block) = path.get_split_path()?;
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
			.map(TryInto::try_into)
			.collect::<Result<_, Iec61850DataError>>()
			.context(ConvertDataToMmsData)?;

		match data.pop().context(InvalidDataLength)? {
			Iec61850Data::Structure(data) => {
				ReportControlBlock::from_data(report_control_block.to_owned(), data)
					.context(CreateReportControlBlock)
			}
			_ => InvalidData.fail(),
		}
	}

	/// Set the GI of a report control block.
	#[instrument(skip(self))]
	pub async fn set_rcb_gi(&self, path: &ObjectPath, gi: bool) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Bool(gi);
		self.set_data_value(&format!("{path}$GI").into(), data).await
	}

	/// Set the enabled state of a report control block.
	#[instrument(skip(self))]
	pub async fn set_rcb_enabled(
		&self,
		path: &ObjectPath,
		enabled: bool,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Bool(enabled);
		self.set_data_value(&format!("{path}$RptEna").into(), data).await
	}

	/// Set the dataset of a report control block.
	#[instrument(skip(self))]
	pub async fn set_rcb_dataset(
		&self,
		path: &ObjectPath,
		dataset: &str,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::String(dataset.trim_start_matches("@").to_owned());
		self.set_data_value(&format!("{path}$DatSet").into(), data).await
	}

	/// Set the integrity period of a report control block.
	#[instrument(skip(self))]
	pub async fn set_rcb_integrity_period(
		&self,
		path: &ObjectPath,
		integrity_period: u32,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Unsigned(integrity_period);
		self.set_data_value(&format!("{path}$IntgPd").into(), data).await
	}

	/// Set the buffer time of a report control block.
	#[instrument(skip(self))]
	pub async fn set_rcb_buffer_time(
		&self,
		path: &ObjectPath,
		buffer_time: u32,
	) -> Result<(), Iec61850ClientError> {
		let data = Iec61850Data::Unsigned(buffer_time);
		self.set_data_value(&format!("{path}$BufTm").into(), data).await
	}

	/// Set the trigger options of a report control block.
	#[instrument(skip(self))]
	pub async fn set_rcb_trigger_options(
		&self,
		path: &ObjectPath,
		trigger_options: Vec<TriggerOptions>,
	) -> Result<(), Iec61850ClientError> {
		self.set_data_value(&format!("{path}$TrgOps").into(), trigger_options.into()).await
	}

	/// Set the optional fields of a report control block.
	#[instrument(skip(self))]
	pub async fn set_rcb_optional_fields(
		&self,
		path: &ObjectPath,
		optional_fields: Vec<OptionalFields>,
	) -> Result<(), Iec61850ClientError> {
		self.set_data_value(&format!("{path}$OptFlds").into(), optional_fields.into()).await
	}

	/// Read data from a logical device.
	pub async fn read_data_from_ld(
		&self,
		logical_device: &str,
		path: &[&str],
	) -> Result<Vec<Iec61850Data>, Iec61850ClientError> {
		let variable_defs = VariableDefs(
			path.iter()
				.map(|p| {
					Ok(AnonymousVariableDefs::new(
						VariableSpecification::name(ObjectName::domain_specific(
							ObjectNameDomainSpecific::new(
								to_identifier(logical_device)?,
								to_identifier(p)?,
							),
						)),
						None,
					))
				})
				.collect::<Result<Vec<_>, Iec61850ClientError>>()?,
		);

		self.client
			.read(variable_defs.into(), false)
			.await?
			.into_iter()
			.map(TryInto::try_into)
			.collect::<Result<_, Iec61850DataError>>()
			.context(ConvertDataToMmsData)
	}

	/// Read single data from a path.
	/// The path is in the format <logical_device>/<logical_node>.
	pub async fn read_data(&self, path: &str) -> Result<Vec<Iec61850Data>, Iec61850ClientError> {
		let path = split_path(path)?;
		self.read_data_from_ld(path.0, &[path.1]).await
	}

	/// Read a directory from the IED
	pub async fn get_directory(&self, path: &str) -> Result<Vec<String>, Iec61850ClientError> {
		self.client
			.file_directory(Some(vec![path.to_owned()]))
			.await?
			.iter()
			.map(|d| {
				Ok(d.file_name
					.0
					.iter()
					.map(|f| str::from_utf8(&f.0).context(ConvertToString))
					.collect::<Result<Vec<_>, _>>()?
					.join("/"))
			})
			.collect::<Result<Vec<_>, _>>()
	}

	/// Reads a file from the ied
	pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, Iec61850ClientError> {
		let file_id = self.client.file_open(vec![path.to_owned()], None).await?.frsm_id.0;
		let file = self.client.file_read(file_id).await?;
		self.client.file_close(file_id).await?;
		Ok(file)
	}
}

/// Convert a string to an identifier.
fn to_identifier<T: AsRef<str>>(value: T) -> Result<Identifier, Iec61850ClientError> {
	Ok(Identifier(
		VisibleString::from_iso646_bytes(value.as_ref().as_bytes())
			.context(ConvertToVisibleString)?,
	))
}

/// Split a path into a logical device and a logical node.
fn split_path(path: &str) -> Result<(&str, &str), Iec61850ClientError> {
	let split_path = path.split('/').collect::<Vec<&str>>();
	if split_path.len() != 2 {
		return InvalidPath.fail();
	}
	Ok((split_path[0], split_path[1]))
}

impl fmt::Display for ObjectName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ObjectName::vmd_specific(name) => write!(f, "{}", name.0),
			ObjectName::domain_specific(name) => {
				write!(f, "{}/{}", name.domain_id.0, name.item_id.0)
			}
			ObjectName::aa_specific(name) => write!(f, "{}", name.0),
		}
	}
}

#[allow(missing_docs)]
/// The error type for the IEC 61850 client.
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
	/// Error converting data to MMS data.
	ConvertDataToMmsData { source: Iec61850DataError },
	/// Error creating the IED model.
	Model { source: model::ModelError },
	/// Error converting to string
	ConvertToString { source: Utf8Error },
}

impl From<MmsClientError> for Iec61850ClientError {
	fn from(error: MmsClientError) -> Self {
		Iec61850ClientError::Client { source: error }
	}
}

/// A path to an object in the IED.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ObjectPath {
	/// A full path to an object in the IED.
	FullPath(String),
	/// A path to an object in a logical device.
	FromLogicalDevice {
		/// The name of the logical device.
		logical_device: String,
		/// The path to the object in the logical device.
		path: String,
	},
}

impl ObjectPath {
	/// Split a path into a logical device and a logical node.
	fn get_split_path(&self) -> Result<(&str, &str), Iec61850ClientError> {
		match self {
			Self::FullPath(path) => {
				let split_path = path.split('/').collect::<Vec<&str>>();
				if split_path.len() != 2 {
					return InvalidPath.fail();
				}
				Ok((split_path[0], split_path[1]))
			}
			Self::FromLogicalDevice { logical_device, path } => Ok((logical_device, path)),
		}
	}
}

impl From<&str> for ObjectPath {
	fn from(value: &str) -> Self {
		Self::FullPath(value.to_owned())
	}
}

impl From<String> for ObjectPath {
	fn from(value: String) -> Self {
		Self::FullPath(value)
	}
}

impl<T, U> From<(T, U)> for ObjectPath
where
	T: Into<String>,
	U: Into<String>,
{
	fn from((logical_device, path): (T, U)) -> Self {
		Self::FromLogicalDevice { logical_device: logical_device.into(), path: path.into() }
	}
}

impl fmt::Display for ObjectPath {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::FullPath(path) => write!(f, "{}", path),
			Self::FromLogicalDevice { logical_device, path } => {
				write!(f, "{}/{}", logical_device, path)
			}
		}
	}
}
