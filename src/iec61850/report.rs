use snafu::{OptionExt as _, ResultExt as _, Snafu};
use time::OffsetDateTime;

use super::{
	data::Iec61850Data,
	rcb::{OptionalFields, TriggerOptions},
};
use crate::{
	iec61850::data::{Bitstring, Iec61850DataError},
	mms::ans1::mms::asn1::{AccessResult, DataAccessError, InformationReport},
};

#[derive(Debug, Clone)]
pub struct Report {
	pub id: String,
	pub optional_fields: Vec<OptionalFields>,
	pub sequence_number: Option<u32>,
	pub time_of_entry: Option<OffsetDateTime>,
	pub dataset: Option<String>,
	pub buffer_overflow: Option<bool>,
	pub entry_id: Option<Vec<u8>>,
	pub configuration_revision: Option<u32>,
	pub sub_sequence_number: Option<u32>,
	pub more_segments_follows: Option<bool>,
	pub inclusion: Bitstring,
	pub data_reference: Option<Vec<String>>,
	pub values: Vec<Iec61850Data>,
	pub reason_for_transmission: Option<Vec<Vec<TriggerOptions>>>,
}

impl TryFrom<InformationReport> for Report {
	type Error = ReportError;
	fn try_from(value: InformationReport) -> Result<Self, Self::Error> {
		let values = value
			.list_of_access_result
			.into_iter()
			.map(|access_result| match access_result {
				AccessResult::success(data) => Ok(data.into()),
				AccessResult::failure(error) => Err(error),
			})
			.collect::<Result<Vec<Iec61850Data>, DataAccessError>>()
			.expect("Failed to convert access results to Iec61850Data");
		if values.len() < 3 {
			return Err(ReportError::InvalidReport);
		}
		let mut values_iter = values.into_iter();

		let id: String = values_iter
			.next()
			.context(MissingField { field: "id" })?
			.try_into()
			.context(InvalidConversion { field: "id" })?;

		let optional_fields: Vec<OptionalFields> = values_iter
			.next()
			.context(MissingField { field: "optional_fields" })?
			.try_into()
			.context(InvalidConversion { field: "optional_fields" })?;

		let mut sequence_number = None;
		if optional_fields.contains(&OptionalFields::SequenceNumber) {
			sequence_number = Some(
				values_iter
					.next()
					.context(MissingField { field: "sequence_number" })?
					.try_into()
					.context(InvalidConversion { field: "sequence_number" })?,
			);
		}

		let mut time_of_entry = None;
		if optional_fields.contains(&OptionalFields::ReportTimestamp) {
			time_of_entry = Some(
				values_iter
					.next()
					.context(MissingField { field: "time_of_entry" })?
					.try_into()
					.context(InvalidConversion { field: "time_of_entry" })?,
			);
		}
		let mut dataset = None;
		if optional_fields.contains(&OptionalFields::DataSetName) {
			dataset = Some(
				values_iter
					.next()
					.context(MissingField { field: "dataset" })?
					.try_into()
					.context(InvalidConversion { field: "dataset" })?,
			);
		}

		let mut buffer_overflow = None;
		if optional_fields.contains(&OptionalFields::BufferOverflow) {
			buffer_overflow = Some(
				values_iter
					.next()
					.context(MissingField { field: "buffer_overflow" })?
					.try_into()
					.context(InvalidConversion { field: "buffer_overflow" })?,
			);
		}

		let mut entry_id = None;
		if optional_fields.contains(&OptionalFields::EntryID) {
			entry_id = Some(
				values_iter
					.next()
					.context(MissingField { field: "entry_id" })?
					.try_into()
					.context(InvalidConversion { field: "entry_id" })?,
			);
		}

		let mut configuration_revision = None;
		if optional_fields.contains(&OptionalFields::ConfigurationRevision) {
			configuration_revision = Some(
				values_iter
					.next()
					.context(MissingField { field: "configuration_revision" })?
					.try_into()
					.context(InvalidConversion { field: "configuration_revision" })?,
			);
		}

		let mut sub_sequence_number = None;
		if optional_fields.contains(&OptionalFields::Segmentation) {
			sub_sequence_number = Some(
				values_iter
					.next()
					.context(MissingField { field: "sub_sequence_number" })?
					.try_into()
					.context(InvalidConversion { field: "sub_sequence_number" })?,
			);
		}

		let mut more_segments_follows = None;
		if optional_fields.contains(&OptionalFields::Segmentation) {
			more_segments_follows = Some(
				values_iter
					.next()
					.context(MissingField { field: "more_segments_follows" })?
					.try_into()
					.context(InvalidConversion { field: "more_segments_follows" })?,
			);
		}

		let inclusion: Bitstring = values_iter
			.next()
			.context(MissingField { field: "Inclusion-bitstring " })?
			.try_into()
			.context(InvalidConversion { field: "Inclusion-bitstring " })?;

		let meas_count = inclusion.bytes.iter().fold(0, |acc, x| acc + x.count_ones());

		let mut data_reference = None;
		if optional_fields.contains(&OptionalFields::DataReference) {
			let mut data_reference_data = Vec::new();
			for _ in 0..meas_count {
				data_reference_data.push(
					values_iter
						.next()
						.context(MissingField { field: "data_reference" })?
						.try_into()
						.context(InvalidConversion { field: "data_reference" })?,
				);
			}
			data_reference = Some(data_reference_data);
		}

		let mut values = Vec::new();
		for _ in 0..meas_count {
			values.push(values_iter.next().context(MissingField { field: "value" })?);
		}

		let mut reason_for_transmission = None;
		if optional_fields.contains(&OptionalFields::ReasonForTransmission) {
			let mut reason_for_transmission_data = Vec::new();
			for _ in 0..meas_count {
				reason_for_transmission_data.push(
					values_iter
						.next()
						.context(MissingField { field: "reason_for_transmission" })?
						.try_into()
						.context(InvalidConversion { field: "reason_for_transmission" })?,
				);
			}
			reason_for_transmission = Some(reason_for_transmission_data);
		}

		Ok(Self {
			id,
			optional_fields,
			sequence_number,
			time_of_entry,
			dataset,
			buffer_overflow,
			entry_id,
			configuration_revision,
			sub_sequence_number,
			more_segments_follows,
			inclusion,
			data_reference,
			values,
			reason_for_transmission,
		})
	}
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum ReportError {
	#[snafu(display("Invalid report"))]
	InvalidReport,
	#[snafu(display("Missing field: {}", field))]
	MissingField { field: String },
	#[snafu(display("Invalid conversion for field: {}", field))]
	InvalidConversion { field: String, source: Iec61850DataError },
}
