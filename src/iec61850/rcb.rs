//! IEC61850 report control block.

use std::fmt;

use serde::{Deserialize, Serialize};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use time::OffsetDateTime;

use crate::iec61850::data::{Bitstring, Iec61850Data, Iec61850DataError};

/// A representation of a report control block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportControlBlock {
	/// A buffered report control block.
	Buffered(BufferedReportControlBlock),
	/// A unbuffered report control block.
	Unbuffered(UnbufferedReportControlBlock),
}

/// Positive BRCB `ResvTms` lifetime in seconds (`1..=i16::MAX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResvTmsDuration(i16);

impl ResvTmsDuration {
	/// Accept only values that IEC 61850-8-1 can encode as a positive `INT16`.
	pub fn new(seconds: u16) -> Result<Self, InvalidBrcbReservation> {
		match i16::try_from(seconds) {
			Ok(value) if value > 0 => Ok(Self(value)),
			_ => Err(InvalidBrcbReservation { seconds }),
		}
	}

	/// Seconds to write as `ResvTms`.
	#[must_use]
	pub const fn get(self) -> i16 {
		self.0
	}

	/// Construct from a positive `INT16` already known to be in range.
	#[must_use]
	pub const fn from_positive_i16(seconds: i16) -> Option<Self> {
		if seconds > 0 { Some(Self(seconds)) } else { None }
	}
}

/// BRCB `ResvTms` write (IEC 61850-8-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrcbReservation {
	/// Reserve for this many seconds (positive `INT16` on the wire).
	ForTime(ResvTmsDuration),
	/// `ResvTms = 0` — not reserved / release.
	Release,
	/// `ResvTms = -1` — reserved until this association ends.
	Association,
}

impl BrcbReservation {
	/// Timed reservation; fails if `seconds` is not in `1..=i16::MAX`.
	pub fn for_time(seconds: u16) -> Result<Self, InvalidBrcbReservation> {
		Ok(Self::ForTime(ResvTmsDuration::new(seconds)?))
	}

	/// Encode as the BRCB `ResvTms` `INT16` value.
	#[must_use]
	pub const fn to_resv_tms(self) -> i16 {
		match self {
			Self::Release => 0,
			Self::Association => -1,
			Self::ForTime(duration) => duration.get(),
		}
	}
}

/// `ResvTms` duration is not a valid positive `INT16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBrcbReservation {
	/// The value that was rejected.
	pub seconds: u16,
}

impl fmt::Display for InvalidBrcbReservation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "BRCB ResvTms duration {} must be in 1..={}", self.seconds, i16::MAX)
	}
}

impl std::error::Error for InvalidBrcbReservation {}

/// A  representation of a buffered report control block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferedReportControlBlock {
	/// The name of the report control block.
	pub name: String,
	/// The id of the report control block.
	pub id: String, // Index 0
	/// Whether the report control block is enabled.
	pub enabled: bool, // Index 1
	/// The dataset of the report control block.
	pub dataset: String, // Index 2
	/// The configuration revision of the report control block.
	pub config_rev: u32, // Index 3
	/// The optional fields of the report control block.
	pub optional_fields: Vec<OptionalFields>, // Index 4
	/// The buffer time of the report control block.
	pub buffer_time: u32, // Index 5
	/// The sequence number of the report control block.
	pub sequence_number: u32, // Index 6
	/// The trigger options of the report control block.
	pub trigger_options: Vec<TriggerOptions>, // Index 7
	/// The integrity period of the report control block.
	pub integrity_period: u32, // Index 8
	/// Whether the report control block is a global integrity report.
	pub gi: bool, // Index 9
	/// Whether the report control block is a purge buffer.
	pub purge_buffer: bool, // Index 10
	/// The entry id of the report control block.
	pub entry_id: Vec<u8>, // Index 11
	/// The time of entry of the report control block.
	pub time_of_entry: OffsetDateTime, // Index 12
	/// The reservation time of the report control block.
	pub reservation_time: i32, // Index 13
}

/// A  representation of a unbuffered report control block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbufferedReportControlBlock {
	/// The name of the report control block.
	pub name: String,
	/// The id of the report control block.
	pub id: String, // Index 0
	/// Whether the report control block is enabled.
	pub enabled: bool, // Index 1
	/// Whether the report control block is reserved.
	pub reservation: bool, // Index 2
	/// The dataset of the report control block.
	pub dataset: String, // Index 3
	/// The configuration revision of the report control block.
	pub config_rev: u32, // Index 4
	/// The optional fields of the report control block.
	pub optional_fields: Vec<OptionalFields>, // Index 5
	/// The buffer time of the report control block.
	pub buffer_time: u32, // Index 6
	/// The sequence number of the report control block.
	pub sequence_number: u32, // Index 7
	/// The trigger options of the report control block.
	pub trigger_options: Vec<TriggerOptions>, // Index 8
	/// The integrity period of the report control block.
	pub integrity_period: u32, // Index 9
	/// Whether the report control block is a global integrity report.
	pub gi: bool, // Index 10
}

/// A trigger option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TriggerOptions {
	/// The data change trigger option.
	DataChange = 0x02,
	/// The quality change trigger option.
	QualityChange = 0x04,
	/// The data update trigger option.
	DataUpdate = 0x08,
	/// The integrity trigger option.
	Integrity = 0x10,
	/// The general interrogation trigger option.
	Gi = 0x20,
}

/// A optional field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum OptionalFields {
	/// The sequence number optional field.
	SequenceNumber = 0x0002,
	/// The report timestamp optional field.
	ReportTimestamp = 0x0004,
	/// The reason for transmission optional field.
	ReasonForTransmission = 0x0008,
	/// The dataset name optional field.
	DataSetName = 0x0010,
	/// The data reference optional field.
	DataReference = 0x0020,
	/// The buffer overflow optional field.
	BufferOverflow = 0x0040,
	/// The entry id optional field.
	EntryID = 0x0080,
	/// The configuration revision optional field.
	ConfigurationRevision = 0x0100,
	/// The segmentation optional field.
	Segmentation = 0x0200,
}

impl BufferedReportControlBlock {
	/// Create a report control block from data.
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

impl UnbufferedReportControlBlock {
	/// Create a report control block from data.
	pub fn from_data(
		name: String,
		mut data: Vec<Iec61850Data>,
	) -> Result<Self, ReportControlBlockError> {
		Ok(Self {
			name,
			// The values come in a specific order
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
			reservation: data
				.pop()
				.context(MissingField { field: "reservation" })?
				.try_into()
				.context(InvalidConversion { field: "reservation" })?,
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

impl ReportControlBlock {
	/// Create a report control block from data.
	///
	/// A buffered RCB has 14 mandatory fields and an unbuffered RCB has 11.
	/// Both may carry a trailing optional `Owner` attribute (15 / 12 fields
	/// respectively); it is not modelled here, so it is dropped rather than
	/// failing the whole model load.
	pub fn from_data(
		name: String,
		mut data: Vec<Iec61850Data>,
	) -> Result<Self, ReportControlBlockError> {
		match data.len() {
			// Buffered, with optional trailing Owner.
			15 => {
				data.pop(); // Owner
				BufferedReportControlBlock::from_data(name, data).map(ReportControlBlock::Buffered)
			}
			14 => {
				BufferedReportControlBlock::from_data(name, data).map(ReportControlBlock::Buffered)
			}
			// Unbuffered, with optional trailing Owner.
			12 => {
				data.pop(); // Owner
				UnbufferedReportControlBlock::from_data(name, data)
					.map(ReportControlBlock::Unbuffered)
			}
			11 => UnbufferedReportControlBlock::from_data(name, data)
				.map(ReportControlBlock::Unbuffered),
			length => InvalidDataLength { length }.fail(),
		}
	}
	/// Get the dataset of the report control block.
	#[must_use]
	pub fn dataset(&self) -> &str {
		match self {
			ReportControlBlock::Buffered(buffered) => &buffered.dataset,
			ReportControlBlock::Unbuffered(unbuffered) => &unbuffered.dataset,
		}
	}
}

/// The error type for the report control block.
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum ReportControlBlockError {
	#[snafu(display("Missing field: {}", field))]
	MissingField { field: String },
	#[snafu(display("Invalid conversion for field: {}", field))]
	InvalidConversion { field: String, source: Iec61850DataError },
	#[snafu(display("Invalid data length for report control block. Length: {}", length))]
	InvalidDataLength { length: usize },
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
			bytes: vec![value.into_iter().fold(0_u8, |byte, option| byte | option as u8)],
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
				.fold(0_u16, |byte, option| byte | option as u16)
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

#[allow(clippy::unwrap_used, clippy::print_stdout)]
#[cfg(test)]
mod tests {
	use super::*;
	use crate::iec61850::data::Bitstring;

	#[test]
	fn test_trigger_options() {
		// In the mms the bit 0 is the MSB. This is why we reverse the bits.
		let data = Bitstring { bytes: vec![0x4C_u8.reverse_bits()], padding: 2 };

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
			Bitstring { bytes: vec![0x7b_u8.reverse_bits(), 0x80_u8.reverse_bits()], padding: 6 };
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

	/// The 11 mandatory fields of an unbuffered RCB, in wire order
	/// (id .. gi).
	fn unbuffered_rcb_fields() -> Vec<Iec61850Data> {
		vec![
			Iec61850Data::String("rcbID".to_owned()), // id
			Iec61850Data::Bool(true),                 // enabled
			Iec61850Data::Bool(false),                // reservation
			Iec61850Data::String("ds".to_owned()),    // dataset
			Iec61850Data::Unsigned(1),                // config_rev
			Iec61850Data::BitString(Bitstring { bytes: vec![0x00, 0x00], padding: 6 }), // opt_flds
			Iec61850Data::Unsigned(100),              // buffer_time
			Iec61850Data::Unsigned(0),                // seq_num
			Iec61850Data::BitString(Bitstring { bytes: vec![0x00], padding: 2 }), // trg_ops
			Iec61850Data::Unsigned(1000),             // intg_pd
			Iec61850Data::Bool(false),                // gi
		]
	}

	#[test]
	fn test_rcb_parses_without_owner() {
		assert!(matches!(
			ReportControlBlock::from_data("rcb".to_owned(), unbuffered_rcb_fields()),
			Ok(ReportControlBlock::Unbuffered(_))
		));
	}

	#[test]
	fn test_rcb_tolerates_trailing_owner() {
		// An extra trailing Owner attribute (12 fields) must still parse as
		// unbuffered rather than failing with InvalidDataLength.
		let mut with_owner = unbuffered_rcb_fields();
		with_owner.push(Iec61850Data::OctetString(vec![1, 2, 3]));
		assert!(matches!(
			ReportControlBlock::from_data("rcb".to_owned(), with_owner),
			Ok(ReportControlBlock::Unbuffered(_))
		));
	}

	#[test]
	fn brcb_reservation_encodes_resv_tms() {
		assert_eq!(BrcbReservation::Release.to_resv_tms(), 0);
		assert_eq!(BrcbReservation::Association.to_resv_tms(), -1);
		assert_eq!(BrcbReservation::for_time(60).unwrap().to_resv_tms(), 60);
		assert!(BrcbReservation::for_time(0).is_err());
		assert!(BrcbReservation::for_time(u16::MAX).is_err());
	}
}
