//! IEC61850 data types.

use num_traits::cast::ToPrimitive;
use rasn::{
	error::strings::PermittedAlphabetError,
	types::{BitString, FixedOctetString, Integer, OctetString, VisibleString},
};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use time::OffsetDateTime;
use tracing::instrument;

use crate::mms::ans1::mms::asn1::{Data, FloatingPoint, MMSString, TimeOfDay, UtcTime};

/// The offset between the MMS and the Unix epoch in milliseconds.
const MMS_TO_UNIX_EPOCH_OFFSET: i64 = 441_763_200_000;
/// The number of milliseconds in a day.
const MILLISECONDS_PER_DAY: i64 = 86_400_000;

/// The IEC61850 data types.
#[derive(Debug, Clone, PartialEq)]
pub enum Iec61850Data {
	/// An array of IEC61850 data types.
	Array(Vec<Iec61850Data>),
	/// A structure of IEC61850 data types.
	Structure(Vec<Iec61850Data>),
	/// A boolean value.
	Bool(bool),
	/// A bit string.
	BitString(Bitstring),
	/// An integer value.
	Integer(i32),
	/// An unsigned integer value.
	Unsigned(u32),
	/// A floating point value.
	FloatingPoint(f32),
	/// An octet string.
	OctetString(Vec<u8>),
	/// A visible string.
	String(String),
	/// A binary time.
	BinaryTime(OffsetDateTime),
	/// A MMS string.
	MMSString(String),
	/// A UTC time.
	UtcTime(OffsetDateTime),
}

/// A representation of a bit string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitstring {
	/// The bytes of the bit string.
	pub bytes: Vec<u8>,
	/// The padding of the bit string to complete the last byte.
	pub padding: u8,
}

impl From<BitString> for Bitstring {
	fn from(value: BitString) -> Self {
		let bytes = value
			.chunks(8)
			.map(|chunk| {
				let mut b = 0_u8;
				for (i, bit) in chunk.iter().enumerate() {
					if *bit {
						b |= 1 << i;
					}
				}
				b
			})
			.collect();
		let padding = (value.capacity() - value.len()) as u8;
		Self { bytes, padding }
	}
}

impl From<Bitstring> for BitString {
	fn from(value: Bitstring) -> Self {
		let mut bs = BitString::from_slice(
			&value.bytes.into_iter().map(u8::reverse_bits).collect::<Vec<u8>>(),
		);
		bs.truncate(bs.len() - value.padding as usize);
		bs
	}
}

impl AsRef<[u8]> for Bitstring {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

impl std::ops::Deref for Bitstring {
	type Target = [u8];
	fn deref(&self) -> &Self::Target {
		&self.bytes
	}
}

impl TryFrom<Data> for Iec61850Data {
	type Error = Iec61850DataError;
	fn try_from(value: Data) -> Result<Self, Self::Error> {
		Ok(match value {
			Data::array(value) => Iec61850Data::Array(
				value
					.into_iter()
					.map(TryInto::try_into)
					.collect::<Result<_, Iec61850DataError>>()?,
			),
			Data::structure(value) => Iec61850Data::Structure(
				value
					.into_iter()
					.map(TryInto::try_into)
					.collect::<Result<_, Iec61850DataError>>()?,
			),
			Data::bool(value) => Iec61850Data::Bool(value),
			Data::bit_string(value) => Iec61850Data::BitString(value.into()),
			Data::integer(value) => Iec61850Data::Integer(from_integer_to_i32(value)?),
			Data::unsigned(value) => Iec61850Data::Unsigned(from_unsigned_to_u32(value)?),
			Data::floating_point(value) => Iec61850Data::FloatingPoint(value.try_into()?),
			Data::octet_string(value) => {
				Iec61850Data::OctetString(from_octetstring_to_bytes(value))
			}
			Data::visible_string(value) => {
				Iec61850Data::String(from_visiblestring_to_string(value))
			}
			Data::binary_time(value) => Iec61850Data::BinaryTime(value.try_into()?),
			Data::mMSString(value) => Iec61850Data::MMSString(value.into()),
			Data::utc_time(value) => Iec61850Data::UtcTime(value.try_into()?),
		})
	}
}

/// A conversion from an IEC61850 data type to an MMS data type.
impl TryFrom<Iec61850Data> for Data {
	type Error = Iec61850DataError;
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		Ok(match value {
			Iec61850Data::Array(value) => Data::array(
				value
					.into_iter()
					.map(TryInto::try_into)
					.collect::<Result<_, Iec61850DataError>>()?,
			),
			Iec61850Data::Structure(value) => Data::structure(
				value
					.into_iter()
					.map(TryInto::try_into)
					.collect::<Result<_, Iec61850DataError>>()?,
			),
			Iec61850Data::Bool(value) => Data::bool(value),
			Iec61850Data::BitString(value) => Data::bit_string(BitString::from(value)),

			Iec61850Data::Integer(value) => Data::integer(value.into()),
			Iec61850Data::Unsigned(value) => Data::unsigned(value.into()),
			Iec61850Data::FloatingPoint(value) => Data::floating_point(value.into()),
			Iec61850Data::OctetString(value) => Data::octet_string(OctetString::from(value)),
			Iec61850Data::String(value) => Data::visible_string(
				VisibleString::from_iso646_bytes(value.as_bytes())
					.context(InvalidStringConversion)?,
			),
			Iec61850Data::BinaryTime(value) => Data::binary_time(value.into()),
			Iec61850Data::MMSString(value) => Data::mMSString(MMSString(
				VisibleString::from_iso646_bytes(value.as_bytes())
					.context(InvalidStringConversion)?,
			)),
			Iec61850Data::UtcTime(value) => Data::utc_time(value.into()),
		})
	}
}

impl TryFrom<FloatingPoint> for f32 {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: FloatingPoint) -> Result<Self, Self::Error> {
		// The first byte is the length of the exponent
		Ok(f32::from_le_bytes(*value.0.last_chunk().context(InvalidData)?))
	}
}
impl From<f32> for FloatingPoint {
	fn from(value: f32) -> Self {
		let bytes = value.to_le_bytes();
		FloatingPoint(OctetString::from([0, bytes[0], bytes[1], bytes[2], bytes[3]]))
	}
}

/// A conversion from an octet string to a vector of bytes.
#[instrument(level = "debug")]
fn from_octetstring_to_bytes(octet_string: OctetString) -> Vec<u8> {
	octet_string.to_vec()
}

/// A conversion from a visible string to a string.
#[instrument(level = "debug")]
fn from_visiblestring_to_string(visible_string: VisibleString) -> String {
	visible_string.to_string()
}

impl From<MMSString> for String {
	#[instrument(level = "debug")]
	fn from(value: MMSString) -> Self {
		value.0.to_string()
	}
}

impl TryFrom<UtcTime> for OffsetDateTime {
	type Error = Iec61850DataError;

	#[instrument(level = "debug")]
	fn try_from(value: UtcTime) -> Result<Self, Self::Error> {
		let seconds = i32::from_le_bytes(*value.0.first_chunk().context(MissingData)?);
		let milliseconds = i32::from_le_bytes([
			0,
			*value.0.get(4).context(MissingData)?,
			*value.0.get(5).context(MissingData)?,
			*value.0.get(6).context(MissingData)?,
		]) / 16777;

		//TODO: Fix it
		let quality = value.0.get(7).context(MissingData)?;
		let _leap_second_known = (quality & 0x80) != 0;
		let _clock_failure = (quality & 0x40) != 0;
		let _not_synchronized = (quality & 0x20) != 0;

		let timestamp = i64::from(seconds) * 1000 + i64::from(milliseconds);
		OffsetDateTime::from_unix_timestamp(timestamp).context(InvalidTimestamp)
	}
}

impl From<OffsetDateTime> for TimeOfDay {
	fn from(value: OffsetDateTime) -> Self {
		let mut buff = Vec::with_capacity(6);
		let milliseconds_from_unix_epoch =
			value.unix_timestamp() * 1000 + i64::from(value.millisecond());
		let mms_time = if milliseconds_from_unix_epoch > MMS_TO_UNIX_EPOCH_OFFSET {
			milliseconds_from_unix_epoch - MMS_TO_UNIX_EPOCH_OFFSET
		} else {
			0
		};

		buff.extend_from_slice(&u32::to_be_bytes((mms_time % MILLISECONDS_PER_DAY) as u32));
		buff.extend_from_slice(&u16::to_be_bytes((mms_time / MILLISECONDS_PER_DAY) as u16));
		TimeOfDay(OctetString::from(buff))
	}
}

impl From<OffsetDateTime> for UtcTime {
	fn from(value: OffsetDateTime) -> Self {
		let seconds = (value.unix_timestamp() as i32).to_le_bytes();
		let millisecond = value.millisecond();
		let seconds_fraction =
			i32::from((millisecond) * 16777 + ((millisecond * 216) / 1000)).to_le_bytes();

		//TODO: Fix it
		let quality = 0x00;
		UtcTime(FixedOctetString::from([
			seconds[0],
			seconds[1],
			seconds[2],
			seconds[3],
			seconds_fraction[0],
			seconds_fraction[1],
			seconds_fraction[2],
			quality,
		]))
	}
}

impl TryFrom<TimeOfDay> for OffsetDateTime {
	type Error = Iec61850DataError;

	#[instrument(level = "debug")]
	fn try_from(value: TimeOfDay) -> Result<Self, Self::Error> {
		let mut milliseconds = if value.0.len() == 6 {
			i64::from(u16::from_be_bytes([value.0[4], value.0[5]])) * MILLISECONDS_PER_DAY
				+ MMS_TO_UNIX_EPOCH_OFFSET
		} else {
			0
		};

		milliseconds +=
			i64::from(u32::from_be_bytes([value.0[0], value.0[1], value.0[2], value.0[3]]));

		Ok(OffsetDateTime::from_unix_timestamp(milliseconds / 1000).context(InvalidTimestamp)?
			+ time::Duration::milliseconds(milliseconds % 1000))
	}
}

/// A conversion from an Integer to an i32.
#[instrument(level = "debug")]
fn from_integer_to_i32(integer: Integer) -> Result<i32, Iec61850DataError> {
	integer.to_i32().context(InvalidData)
}

/// A conversion from an Integer to a u32.
#[instrument(level = "debug")]
fn from_unsigned_to_u32(unsigned: Integer) -> Result<u32, Iec61850DataError> {
	unsigned.to_u32().context(InvalidData)
}

impl TryFrom<Iec61850Data> for bool {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::Bool(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

impl TryFrom<Iec61850Data> for u32 {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::Unsigned(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

impl TryFrom<Iec61850Data> for i32 {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::Integer(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

impl TryFrom<Iec61850Data> for f32 {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::FloatingPoint(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

impl TryFrom<Iec61850Data> for Vec<u8> {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::OctetString(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

impl TryFrom<Iec61850Data> for Bitstring {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::BitString(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

impl TryFrom<Iec61850Data> for String {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::String(value) => Ok(value),
			Iec61850Data::MMSString(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

impl TryFrom<Iec61850Data> for OffsetDateTime {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: Iec61850Data) -> Result<Self, Self::Error> {
		match value {
			Iec61850Data::UtcTime(value) => Ok(value),
			Iec61850Data::BinaryTime(value) => Ok(value),
			_ => Err(Iec61850DataError::InvalidData),
		}
	}
}

#[allow(missing_docs)]
/// The error type for IEC61850 data types.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum Iec61850DataError {
	/// Invalid data.
	InvalidData,
	/// Invalid conversion.
	InvalidConversion,
	/// Invalid string conversion.
	InvalidStringConversion { source: PermittedAlphabetError },
	/// Missing data.
	MissingData,
	/// Invalid timestamp.
	InvalidTimestamp { source: time::error::ComponentRange },
}

#[allow(clippy::unwrap_used, clippy::print_stdout)]
#[cfg(test)]
mod tests {
	use time::format_description::well_known::Rfc3339;

	use super::*;

	#[test]
	fn test_from_utc_time_to_offset_date_time() {
		let utc_time = UtcTime(FixedOctetString::from([0, 0, 0, 0, 0, 0, 0, 0]));
		let offset_date_time = OffsetDateTime::try_from(utc_time).unwrap();
		assert_eq!(offset_date_time, OffsetDateTime::from_unix_timestamp(0).unwrap());
	}
	#[test]
	fn test_from_bitstring_to_bit_string() {
		let mut bs = BitString::from_slice(&[0x7b, 0x80]);
		bs.truncate(10);
		let bitstring: Bitstring = bs.clone().into();
		let bit_string = BitString::from(bitstring);
		assert_eq!(bs, bit_string);
	}

	#[test]
	fn test_from_bitstring_to_bit_string_single_byte() {
		let mut bs = BitString::from_slice(&[0x4c]);
		bs.truncate(6);
		println!("bs: {:?}", bs);
		let bitstring: Bitstring = bs.clone().into();
		println!("bitstring: {:?}", bitstring);
		let bit_string = BitString::from(bitstring);
		assert_eq!(bs, bit_string);
	}

	#[test]
	fn test_from_offset_date_time_to_binary_time() {
		// January 15, 2024 14:30:45.123 UTC
		let offset_date_time =
			OffsetDateTime::from_unix_timestamp_nanos(1_705_329_045_123_000_000).unwrap();
		println!("offset_date_time: {:?}", offset_date_time);
		let binary_time = TimeOfDay([0x03, 0x1D, 0x32, 0x83, 0x39, 0x20].into());
		println!("binary_time: {:?}", binary_time.0.to_vec());

		let from_binary_time: OffsetDateTime = binary_time.clone().try_into().unwrap();
		println!("from_binary_time: {:?}", from_binary_time);

		let from_offsetdatetime: TimeOfDay = offset_date_time.into();
		println!("from_offsetdatetime: {:?}", from_offsetdatetime.0.to_vec());

		assert_eq!(binary_time, offset_date_time.into());
		assert_eq!(offset_date_time, from_binary_time);
	}
	#[test]
	fn test_from_binary_time_to_offset_date_time() {
		let binary_time = TimeOfDay([0x03, 0x1b, 0xce, 0xc6, 0x3b, 0xbd].into());
		let offset_date_time: OffsetDateTime = binary_time.clone().try_into().unwrap();
		assert_eq!(
			offset_date_time,
			OffsetDateTime::parse("2025-11-14T14:29:14.054Z", &Rfc3339).unwrap()
		);
	}
}
