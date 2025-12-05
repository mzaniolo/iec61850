//! IEC61850 ied model.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use snafu::{OptionExt as _, Snafu};

use crate::{iec61850::rcb::ReportControlBlock, mms::ans1::mms::asn1::TypeSpecification};

/// A dataset in the IEC61850 ied model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
	/// The name of the dataset.
	pub name: String,
	/// The path of the dataset.
	#[serde(skip)]
	pub path: String,
	/// The entries in the dataset.
	pub entries: Vec<String>,
}

/// A report control block in the IEC61850 ied model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
	/// The name of the report.
	pub name: String,
	/// The path of the report.
	#[serde(skip)]
	pub path: String,
	/// Whether the report is buffered.
	pub buffered: bool,
	/// The dataset of the report.
	pub rcb: ReportControlBlock,
}

/// An IEC61850 ied model.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IedModel {
	/// The logical devices in the ied model.
	pub logical_devices: Vec<LogicalDevice>,
}

/// A logical device in the IEC61850 ied model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalDevice {
	/// The name of the logical device.
	pub name: String,
	/// The logical nodes in the logical device.
	pub logical_nodes: Vec<LogicalNode>,
}

impl LogicalDevice {
	/// Create a new logical device.
	#[must_use]
	pub const fn new(name: String) -> Self {
		Self { name, logical_nodes: Vec::new() }
	}
}

/// A logical node in the IEC61850 ied model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalNode {
	/// The name of the logical node.
	pub name: String,
	/// The path of the logical node.
	#[serde(skip)]
	pub path: String,
	/// The datasets in the logical node.
	pub datasets: HashMap<String, Dataset>,
	/// The reports in the logical node.
	pub reports: HashMap<String, Report>,
	/// The nodes in the logical node.
	pub nodes: Vec<Node>,
}

impl LogicalNode {
	/// Create a new logical node.
	#[must_use]
	pub fn new(name: String, logical_device: &str) -> Self {
		Self {
			path: format!("{logical_device}/{name}"),
			name,
			datasets: HashMap::new(),
			reports: HashMap::new(),
			nodes: Vec::new(),
		}
	}
}

/// A node in the IEC61850 ied model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Node {
	/// A data attribute.
	DataAttribute {
		/// The name of the data attribute.
		name: String,
		/// The path of the data attribute.
		#[serde(skip)]
		path: String,
		/// The type of the data attribute.
		r#type: String,
	},
	/// A data object.
	DataObject {
		/// The name of the data object.
		name: String,
		/// The path of the data object.
		#[serde(skip)]
		path: String,
		/// The nodes in the data object.
		nodes: Vec<Node>,
	},
}

impl LogicalDevice {
	/// Add reports to the logical device.
	pub fn add_reports(
		&mut self,
		reports: Vec<(String, ReportControlBlock)>,
	) -> Result<(), ModelError> {
		for (report, rcb) in reports {
			let buffered = report.contains("BR");
			let ln_name =
				report.split_once("$").with_context(|| InvalidReport { report: report.clone() })?.0;
			let ln = self
				.logical_nodes
				.iter_mut()
				.find(|ln| ln.name == ln_name)
				.with_context(|| LogicalNodeNotFound { ln_name })?;
			ln.reports.insert(
				report.clone(),
				Report { path: format!("{}/{}", self.name, report), name: report, buffered, rcb },
			);
		}
		Ok(())
	}

	/// Add datasets to the logical device.
	pub fn add_datasets(
		&mut self,
		datasets: HashMap<String, Vec<String>>,
	) -> Result<(), ModelError> {
		for (dataset_name, entries) in datasets {
			let ln_name = dataset_name
				.split_once("$")
				.with_context(|| InvalidDataset { dataset: dataset_name.clone() })?
				.0;
			let ln = self
				.logical_nodes
				.iter_mut()
				.find(|ln| ln.name == ln_name)
				.with_context(|| LogicalNodeNotFound { ln_name })?;
			ln.datasets.insert(
				dataset_name.clone(),
				Dataset {
					path: format!("{}/{}", self.name, dataset_name),
					name: dataset_name,
					entries,
				},
			);
		}
		Ok(())
	}
}

impl LogicalNode {
	/// Parse the nodes in the logical node.
	pub fn parse_nodes(&mut self, data_definition: TypeSpecification) {
		match data_definition {
			TypeSpecification::structure(structure) => {
				for component in structure.components.0 {
					let name =
						component.component_name.map(|id| id.0.to_string()).unwrap_or_default();

					// BR and RP are special nodes that represent report control blocks.
					if name == "BR" || name == "RP" {
						tracing::debug!("Found BR or RP node. Skipping...");
						continue;
					}

					let path = format!("{}${name}", self.path);

					let sub_node = Node::to_nodes(name, path, component.component_type);
					self.nodes.push(sub_node);
				}
			}
			_ => tracing::info!("Unexpected data definition: {:#?}", data_definition),
		}
	}
}

impl Node {
	/// Convert the type specification to a node.
	pub fn to_nodes(name: String, path: String, value: TypeSpecification) -> Self {
		match value {
			TypeSpecification::array(array) => {
				let mut node = Self::to_nodes(name, path, array.element_type);
				match node {
					Self::DataAttribute { ref mut r#type, .. } => {
						*r#type = format!("[{}]", r#type);
					}
					Self::DataObject { .. } => {
						tracing::debug!("Found array node. Adding new node...");
					}
				}
				node
			}
			TypeSpecification::structure(structure) => {
				let mut sub_nodes = Vec::new();
				for component in structure.components.0 {
					let name =
						component.component_name.map(|id| id.0.to_string()).unwrap_or_default();
					let path = format!("{path}${name}");

					let sub_node = Self::to_nodes(name, path, component.component_type);
					sub_nodes.push(sub_node);
				}
				Self::DataObject { name, path, nodes: sub_nodes }
			}
			TypeSpecification::bool(_) => {
				Self::DataAttribute { name, path, r#type: "bool".to_owned() }
			}
			TypeSpecification::bit_string(_) => {
				Self::DataAttribute { name, path, r#type: "bit_string".to_owned() }
			}
			TypeSpecification::integer(_) => {
				Self::DataAttribute { name, path, r#type: "integer".to_owned() }
			}
			TypeSpecification::unsigned(_) => {
				Self::DataAttribute { name, path, r#type: "unsigned".to_owned() }
			}
			TypeSpecification::floating_point(_) => {
				Self::DataAttribute { name, path, r#type: "floating_point".to_owned() }
			}
			TypeSpecification::octet_string(_) => {
				Self::DataAttribute { name, path, r#type: "octet_string".to_owned() }
			}
			TypeSpecification::visible_string(_) => {
				Self::DataAttribute { name, path, r#type: "visible_string".to_owned() }
			}
			TypeSpecification::binary_time(_) => {
				Self::DataAttribute { name, path, r#type: "binary_time".to_owned() }
			}
			TypeSpecification::mMSString(_) => {
				Self::DataAttribute { name, path, r#type: "mMSString".to_owned() }
			}
			TypeSpecification::utc_time(_) => {
				Self::DataAttribute { name, path, r#type: "utc_time".to_owned() }
			}
		}
	}
}

impl std::fmt::Display for IedModel {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		if f.alternate() {
			write!(f, "{}", serde_json::to_string_pretty(self).unwrap_or_default())
		} else {
			write!(f, "{}", serde_json::to_string(self).unwrap_or_default())
		}
	}
}

#[allow(missing_docs)]
/// The error type for the IEC61850 ied model.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum ModelError {
	#[snafu(display("Invalid report path: {}", report))]
	InvalidReport { report: String },
	#[snafu(display("Logical node not found: {}", ln_name))]
	LogicalNodeNotFound { ln_name: String },
	#[snafu(display("Invalid dataset path: {}", dataset))]
	InvalidDataset { dataset: String },
	#[snafu(display("Dataset not found: {}", dataset_name))]
	DatasetNotFound { dataset_name: String },
}
