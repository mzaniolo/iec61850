//! IEC61850 report.

use snafu::{OptionExt as _, ResultExt as _, Snafu};
use time::OffsetDateTime;

use super::{
	data::Iec61850Data,
	rcb::{OptionalFields, TriggerOptions},
};
use crate::{
	iec61850::data::{Bitstring, Iec61850DataError},
	mms::asn1::mms::asn1::{AccessResult, DataAccessError, InformationReport},
};

/// A representation of a report.
#[derive(Debug, Clone)]
pub struct Report {
	/// The id of the report.
	pub id: String,
	/// The optional fields of the report.
	pub optional_fields: Vec<OptionalFields>,
	/// The sequence number of the report.
	pub sequence_number: Option<u32>,
	/// The time of entry of the report.
	pub time_of_entry: Option<OffsetDateTime>,
	/// The dataset of the report.
	pub dataset: Option<String>,
	/// The buffer overflow of the report.
	pub buffer_overflow: Option<bool>,
	/// The entry id of the report.
	pub entry_id: Option<Vec<u8>>,
	/// The configuration revision of the report.
	pub configuration_revision: Option<u32>,
	/// The sub sequence number of the report.
	pub sub_sequence_number: Option<u32>,
	/// The more segments follows of the report.
	pub more_segments_follows: Option<bool>,
	/// The inclusion of the report.
	pub inclusion: Bitstring,
	/// The data reference of the report.
	pub data_reference: Option<Vec<String>>,
	/// The values of the report.
	pub values: Vec<Iec61850Data>,
	/// The reason for transmission of the report.
	pub reason_for_transmission: Option<Vec<Vec<TriggerOptions>>>,
}

#[allow(clippy::too_many_lines)]
impl TryFrom<InformationReport> for Report {
	type Error = ReportError;
	fn try_from(value: InformationReport) -> Result<Self, Self::Error> {
		let values = value
			.list_of_access_result
			.into_iter()
			.map(|access_result| match access_result {
				AccessResult::success(data) => data.try_into().context(FailedToConvertData),
				AccessResult::failure(e) => {
					FailedToConvertAccessResults { data_access_error: e }.fail()
				}
			})
			.collect::<Result<Vec<Iec61850Data>, ReportError>>()?;

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

		let sequence_number = optional_fields
			.contains(&OptionalFields::SequenceNumber)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "sequence_number" })?
					.try_into()
					.context(InvalidConversion { field: "sequence_number" })
			})
			.transpose()?;

		let time_of_entry = optional_fields
			.contains(&OptionalFields::ReportTimestamp)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "time_of_entry" })?
					.try_into()
					.context(InvalidConversion { field: "time_of_entry" })
			})
			.transpose()?;

		let dataset = optional_fields
			.contains(&OptionalFields::DataSetName)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "dataset" })?
					.try_into()
					.context(InvalidConversion { field: "dataset" })
			})
			.transpose()?;

		let buffer_overflow = optional_fields
			.contains(&OptionalFields::BufferOverflow)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "buffer_overflow" })?
					.try_into()
					.context(InvalidConversion { field: "buffer_overflow" })
			})
			.transpose()?;

		let entry_id = optional_fields
			.contains(&OptionalFields::EntryID)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "entry_id" })?
					.try_into()
					.context(InvalidConversion { field: "entry_id" })
			})
			.transpose()?;

		let configuration_revision = optional_fields
			.contains(&OptionalFields::ConfigurationRevision)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "configuration_revision" })?
					.try_into()
					.context(InvalidConversion { field: "configuration_revision" })
			})
			.transpose()?;

		let sub_sequence_number = optional_fields
			.contains(&OptionalFields::Segmentation)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "sub_sequence_number" })?
					.try_into()
					.context(InvalidConversion { field: "sub_sequence_number" })
			})
			.transpose()?;

		let more_segments_follows = optional_fields
			.contains(&OptionalFields::Segmentation)
			.then(|| {
				values_iter
					.next()
					.context(MissingField { field: "more_segments_follows" })?
					.try_into()
					.context(InvalidConversion { field: "more_segments_follows" })
			})
			.transpose()?;

		let inclusion: Bitstring = values_iter
			.next()
			.context(MissingField { field: "Inclusion-bitstring " })?
			.try_into()
			.context(InvalidConversion { field: "Inclusion-bitstring " })?;

		let meas_count = inclusion.bytes.iter().fold(0, |acc, x| acc + x.count_ones());

		let data_reference = optional_fields
			.contains(&OptionalFields::DataReference)
			.then(|| {
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
				Ok(data_reference_data)
			})
			.transpose()?;

		let mut values = Vec::new();
		for _ in 0..meas_count {
			values.push(values_iter.next().context(MissingField { field: "value" })?);
		}

		let reason_for_transmission = optional_fields
			.contains(&OptionalFields::ReasonForTransmission)
			.then(|| {
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
				Ok(reason_for_transmission_data)
			})
			.transpose()?;

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

/// The error type for the report.
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum ReportError {
	#[snafu(display("Invalid report"))]
	InvalidReport,
	#[snafu(display("Missing field: {}", field))]
	MissingField {
		field: String,
	},
	#[snafu(display("Invalid conversion for field: {}", field))]
	InvalidConversion {
		field: String,
		source: Iec61850DataError,
	},

	#[snafu(display("Failed to convert access results to Iec61850Data: {data_access_error:?}"))]
	FailedToConvertAccessResults {
		data_access_error: DataAccessError,
	},
	FailedToConvertData {
		source: Iec61850DataError,
	},
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
	use rasn::types::{Integer, VisibleString};

	use super::*;
	use crate::{
		iec61850::data::Bitstring,
		mms::asn1::mms::asn1::{Data, Identifier, ObjectName, VariableAccessSpecification},
	};

	fn vstr(s: &str) -> VisibleString {
		VisibleString::from_iso646_bytes(s.as_bytes()).unwrap()
	}

	/// A report whose OptFlds only sets SequenceNumber must parse the fields
	/// in the expected order: RptID, OptFlds, [SeqNum], Inclusion, values.
	/// This locks the field-order logic against regressions.
	#[test]
	fn test_report_field_order() {
		// OptFlds with only the sequence-number bit set.
		let optflds: Data =
			Iec61850Data::from(vec![OptionalFields::SequenceNumber]).try_into().unwrap();
		// Inclusion bitstring with two bits set => two reported values.
		let inclusion: Data = Iec61850Data::BitString(Bitstring { bytes: vec![0x03], padding: 6 })
			.try_into()
			.unwrap();

		let results = vec![
			AccessResult::success(Data::visible_string(vstr("rcb01"))),
			AccessResult::success(optflds),
			AccessResult::success(Data::unsigned(Integer::from(42))),
			AccessResult::success(inclusion),
			AccessResult::success(Data::bool(true)),
			AccessResult::success(Data::bool(false)),
		];

		// The variable-access-specification is ignored by the parser.
		let spec = VariableAccessSpecification::variableListName(ObjectName::vmd_specific(
			Identifier(vstr("x")),
		));
		let report = Report::try_from(InformationReport::new(spec, results)).unwrap();

		assert_eq!(report.id, "rcb01");
		assert_eq!(report.optional_fields, vec![OptionalFields::SequenceNumber]);
		assert_eq!(report.sequence_number, Some(42));
		assert_eq!(report.time_of_entry, None);
		assert_eq!(report.dataset, None);
		assert_eq!(report.buffer_overflow, None);
		assert_eq!(report.values, vec![Iec61850Data::Bool(true), Iec61850Data::Bool(false)]);
		assert!(report.data_reference.is_none());
		assert!(report.reason_for_transmission.is_none());
	}

	/// A report with fewer than the minimum (id, optflds, inclusion) fields
	/// must be rejected.
	#[test]
	fn test_report_too_short_is_rejected() {
		let results = vec![AccessResult::success(Data::visible_string(vstr("rcb01")))];
		let spec = VariableAccessSpecification::variableListName(ObjectName::vmd_specific(
			Identifier(vstr("x")),
		));
		assert!(Report::try_from(InformationReport::new(spec, results)).is_err());
	}
}
