use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use snafu::{OptionExt as _, Snafu};

use crate::mms::ans1::mms::asn1::TypeSpecification;

// TODO: Fix it
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
	pub name: String,
	#[serde(skip)]
	pub path: String,
	pub entries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
	pub name: String,
	#[serde(skip)]
	pub path: String,
	pub buffered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IedModel {
	pub logical_devices: Vec<LogicalDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalDevice {
	pub name: String,
	pub logical_nodes: Vec<LogicalNode>,
}

impl LogicalDevice {
	#[must_use]
	pub fn new(name: String) -> Self {
		Self { name, logical_nodes: Vec::new() }
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalNode {
	pub name: String,
	#[serde(skip)]
	pub path: String,
	pub datasets: HashMap<String, Dataset>,
	pub reports: HashMap<String, Report>,
	pub nodes: Vec<Node>,
}

impl LogicalNode {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Node {
	Leaf {
		name: String,
		#[serde(skip)]
		path: String,
		r#type: String,
	},
	Node {
		name: String,
		#[serde(skip)]
		path: String,
		nodes: Vec<Node>,
	},
}

impl LogicalDevice {
	pub fn add_reports(&mut self, reports: Vec<String>) -> Result<(), ModelError> {
		for report in reports {
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
				Report { path: format!("{}/{}", self.name, report), name: report, buffered },
			);
		}
		Ok(())
	}

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
	pub fn to_nodes(name: String, path: String, value: TypeSpecification) -> Self {
		match value {
			TypeSpecification::array(array) => {
				let mut node = Self::to_nodes(name, path, array.element_type);
				match node {
					Self::Leaf { ref mut r#type, .. } => {
						*r#type = format!("[{}]", r#type);
					}
					Self::Node { .. } => {
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
				Self::Node { name, path, nodes: sub_nodes }
			}
			TypeSpecification::bool(_) => Self::Leaf { name, path, r#type: "bool".to_string() },
			TypeSpecification::bit_string(_) => {
				Self::Leaf { name, path, r#type: "bit_string".to_string() }
			}
			TypeSpecification::integer(_) => {
				Self::Leaf { name, path, r#type: "integer".to_string() }
			}
			TypeSpecification::unsigned(_) => {
				Self::Leaf { name, path, r#type: "unsigned".to_string() }
			}
			TypeSpecification::floating_point(_) => {
				Self::Leaf { name, path, r#type: "floating_point".to_string() }
			}
			TypeSpecification::octet_string(_) => {
				Self::Leaf { name, path, r#type: "octet_string".to_string() }
			}
			TypeSpecification::visible_string(_) => {
				Self::Leaf { name, path, r#type: "visible_string".to_string() }
			}
			TypeSpecification::binary_time(_) => {
				Self::Leaf { name, path, r#type: "binary_time".to_string() }
			}
			TypeSpecification::mMSString(_) => {
				Self::Leaf { name, path, r#type: "mMSString".to_string() }
			}
			TypeSpecification::utc_time(_) => {
				Self::Leaf { name, path, r#type: "utc_time".to_string() }
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
