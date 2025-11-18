use serde::{Deserialize, Serialize};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use time::OffsetDateTime;

use crate::iec61850::data::{Bitstring, Iec61850Data, Iec61850DataError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportControlBlock {
	pub name: String,
	pub id: String,                           // Index 0
	pub enabled: bool,                        // Index 1
	pub dataset: String,                      // Index 2
	pub config_rev: u32,                      // Index 3
	pub optional_fields: Vec<OptionalFields>, // Index 4
	pub buffer_time: u32,                     // Index 5
	pub sequence_number: u32,                 // Index 6
	pub trigger_options: Vec<TriggerOptions>, // Index 7
	pub integrity_period: u32,                // Index 8
	pub gi: bool,                             // Index 9
	pub purge_buffer: bool,                   // Index 10
	pub entry_id: Vec<u8>,                    // Index 11
	pub time_of_entry: OffsetDateTime,        // Index 12
	pub reservation_time: i32,                // Index 13
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TriggerOptions {
	DataChange = 0x02,
	QualityChange = 0x04,
	DataUpdate = 0x08,
	Integrity = 0x10,
	Gi = 0x20,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum OptionalFields {
	SequenceNumber = 0x0002,
	ReportTimestamp = 0x0004,
	ReasonForTransmission = 0x0008,
	DataSetName = 0x0010,
	DataReference = 0x0020,
	BufferOverflow = 0x0040,
	EntryID = 0x0080,
	ConfigurationRevision = 0x0100,
	Segmentation = 0x0200,
}

impl ReportControlBlock {
	pub fn from_data(
		name: String,
		mut data: Vec<Iec61850Data>,
	) -> Result<Self, ReportControlBlockError> {
		Ok(Self {
			name,
			// The values come in a specific order
			reservation_time: data
				.pop()
				.context(MissingField { field: "reservation_time" })?
				.try_into()
				.context(InvalidConversion { field: "reservation_time" })?,
			time_of_entry: data
				.pop()
				.context(MissingField { field: "time_of_entry" })?
				.try_into()
				.context(InvalidConversion { field: "time_of_entry" })?,
			entry_id: data
				.pop()
				.context(MissingField { field: "entry_id" })?
				.try_into()
				.context(InvalidConversion { field: "entry_id" })?,
			purge_buffer: data
				.pop()
				.context(MissingField { field: "purge_buffer" })?
				.try_into()
				.context(InvalidConversion { field: "purge_buffer" })?,
			gi: data
				.pop()
				.context(MissingField { field: "gi" })?
				.try_into()
				.context(InvalidConversion { field: "gi" })?,
			integrity_period: data
				.pop()
				.context(MissingField { field: "integrity_period" })?
				.try_into()
				.context(InvalidConversion { field: "integrity_period" })?,
			trigger_options: data
				.pop()
				.context(MissingField { field: "trigger_options" })?
				.try_into()
				.context(InvalidConversion { field: "trigger_options" })?,
			sequence_number: data
				.pop()
				.context(MissingField { field: "sequence_number" })?
				.try_into()
				.context(InvalidConversion { field: "sequence_number" })?,
			buffer_time: data
				.pop()
				.context(MissingField { field: "buffer_time" })?
				.try_into()
				.context(InvalidConversion { field: "buffer_time" })?,
			optional_fields: data
				.pop()
				.context(MissingField { field: "optional_fields" })?
				.try_into()
				.context(InvalidConversion { field: "optional_fields" })?,
			config_rev: data
				.pop()
				.context(MissingField { field: "config_rev" })?
				.try_into()
				.context(InvalidConversion { field: "config_rev" })?,
			dataset: data
				.pop()
				.context(MissingField { field: "dataset" })?
				.try_into()
				.context(InvalidConversion { field: "dataset" })?,
			enabled: data
				.pop()
				.context(MissingField { field: "enabled" })?
				.try_into()
				.context(InvalidConversion { field: "enabled" })?,
			id: data
				.pop()
				.context(MissingField { field: "id" })?
				.try_into()
				.context(InvalidConversion { field: "id" })?,
		})
	}
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum ReportControlBlockError {
	#[snafu(display("Missing field: {}", field))]
	MissingField { field: String },
	#[snafu(display("Invalid conversion for field: {}", field))]
	InvalidConversion { field: String, source: Iec61850DataError },
}

impl TryFrom<Iec61850Data> for Vec<TriggerOptions> {
	type Error = Iec61850DataError;
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::BitString(value) => {
				let mut options = Vec::new();
				if value.len() != 1 {
					return Err(Iec61850DataError::InvalidConversion);
				}
				let option_byte = value.bytes[0];

				for option in [
					TriggerOptions::DataChange,
					TriggerOptions::QualityChange,
					TriggerOptions::DataUpdate,
					TriggerOptions::Integrity,
					TriggerOptions::Gi,
				] {
					if option_byte & option as u8 != 0 {
						options.push(option);
					}
				}
				Ok(options)
			}
			_ => Err(Iec61850DataError::InvalidConversion),
		}
	}
}

impl TryFrom<Iec61850Data> for Vec<OptionalFields> {
	type Error = Iec61850DataError;
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::BitString(value) => {
				let mut options = Vec::new();
				if value.len() != 2 {
					return Err(Iec61850DataError::InvalidConversion);
				}

				// The first 6 bits are padding
				let optional_fields = u16::from_le_bytes([value[0], value[1]]);

				for option in [
					OptionalFields::SequenceNumber,
					OptionalFields::ReportTimestamp,
					OptionalFields::ReasonForTransmission,
					OptionalFields::DataSetName,
					OptionalFields::DataReference,
					OptionalFields::BufferOverflow,
					OptionalFields::EntryID,
					OptionalFields::ConfigurationRevision,
					OptionalFields::Segmentation,
				] {
					if optional_fields & option as u16 != 0 {
						options.push(option);
					}
				}
				Ok(options)
			}
			_ => Err(Iec61850DataError::InvalidConversion),
		}
	}
}

impl From<Vec<TriggerOptions>> for Bitstring {
	fn from(value: Vec<TriggerOptions>) -> Self {
		Bitstring {
			bytes: vec![value.into_iter().fold(0u8, |byte, option| byte | option as u8)],
			padding: 2,
		}
	}
}

impl From<Vec<TriggerOptions>> for Iec61850Data {
	fn from(value: Vec<TriggerOptions>) -> Self {
		Iec61850Data::BitString(value.into())
	}
}

impl From<Vec<OptionalFields>> for Bitstring {
	fn from(value: Vec<OptionalFields>) -> Self {
		Bitstring {
			bytes: value
				.into_iter()
				.fold(0u16, |byte, option| byte | option as u16)
				.to_le_bytes()
				.to_vec(),
			padding: 6,
		}
	}
}

impl From<Vec<OptionalFields>> for Iec61850Data {
	fn from(value: Vec<OptionalFields>) -> Self {
		Iec61850Data::BitString(value.into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::iec61850::data::Bitstring;

	#[test]
	fn test_trigger_options() {
		// In the mms the bit 0 is the MSB. This is why we reverse the bits.
		let data = Bitstring { bytes: vec![0x4Cu8.reverse_bits()], padding: 2 };

		let options: Vec<TriggerOptions> =
			Iec61850Data::BitString(data.clone()).try_into().unwrap();
		assert_eq!(
			options,
			vec![TriggerOptions::DataChange, TriggerOptions::Integrity, TriggerOptions::Gi]
		);
		let bs: Bitstring = options.into();
		assert_eq!(bs, data);
	}

	#[test]
	fn test_optional_fields() {
		// In the mms the bit 0 is the MSB. This is why we reverse the bits and the
		// bytes.
		let data =
			Bitstring { bytes: vec![0x7bu8.reverse_bits(), 0x80u8.reverse_bits()], padding: 6 };
		let options: Vec<OptionalFields> =
			Iec61850Data::BitString(data.clone()).try_into().unwrap();
		assert_eq!(
			options,
			vec![
				OptionalFields::SequenceNumber,
				OptionalFields::ReportTimestamp,
				OptionalFields::ReasonForTransmission,
				OptionalFields::DataSetName,
				OptionalFields::BufferOverflow,
				OptionalFields::EntryID,
				OptionalFields::ConfigurationRevision,
			]
		);
		let bs: Bitstring = options.into();
		assert_eq!(bs, data);
	}
}
