//! IEC61850 data types.

use num_traits::cast::ToPrimitive;
use rasn::{
	error::strings::PermittedAlphabetError,
	types::{BitString, FixedOctetString, Integer, OctetString, VisibleString},
};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use time::OffsetDateTime;
use tracing::instrument;

use crate::mms::asn1::mms::asn1::{Data, FloatingPoint, MMSString, TimeOfDay, UtcTime};

/// The offset between the MMS and the Unix epoch in milliseconds.
const MMS_TO_UNIX_EPOCH_OFFSET: i64 = 441_763_200_000;
/// The number of milliseconds in a day.
const MILLISECONDS_PER_DAY: i64 = 86_400_000;
/// IEEE-754 binary32 exponent width (MMS FloatingPoint format octet).
const IEEE754_SINGLE_EXPONENT_WIDTH: u8 = 8;
/// IEEE-754 binary64 exponent width (MMS FloatingPoint format octet).
const IEEE754_DOUBLE_EXPONENT_WIDTH: u8 = 11;

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
	///
	/// MMS may encode IEEE-754 binary32 or binary64; both are stored here as
	/// `f64`.
	FloatingPoint(f64),
	/// An octet string.
	OctetString(Vec<u8>),
	/// A visible string.
	String(String),
	/// A binary time.
	BinaryTime(OffsetDateTime),
	/// A MMS string.
	MMSString(String),
	/// A UTC time, with its associated TimeQuality.
	UtcTime(OffsetDateTime, TimeQuality),
}

/// The TimeQuality carried in the 8th octet of an IEC 61850 `UtcTime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeQuality {
	/// Whether a leap second is known to the time source.
	pub leap_second_known: bool,
	/// Whether the time source has a clock failure.
	pub clock_failure: bool,
	/// Whether the clock is not synchronized (the timestamp is not trusted).
	pub clock_not_synchronized: bool,
	/// Time accuracy: the number of significant bits of the fraction of a
	/// second (0..=24; the 5-bit field also encodes "unspecified" values).
	pub time_accuracy: u8,
}

impl From<u8> for TimeQuality {
	fn from(byte: u8) -> Self {
		Self {
			leap_second_known: byte & 0x80 != 0,
			clock_failure: byte & 0x40 != 0,
			clock_not_synchronized: byte & 0x20 != 0,
			time_accuracy: byte & 0x1F,
		}
	}
}

impl From<TimeQuality> for u8 {
	fn from(quality: TimeQuality) -> Self {
		(u8::from(quality.leap_second_known) << 7)
			| (u8::from(quality.clock_failure) << 6)
			| (u8::from(quality.clock_not_synchronized) << 5)
			| (quality.time_accuracy & 0x1F)
	}
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
		// Padding is the number of unused bits in the final byte, derived
		// from the logical bit length. `capacity()` is an allocation detail
		// and must not be used here (it can yield wrong padding or underflow
		// the `truncate` on the inverse conversion).
		let padding = ((8 - value.len() % 8) % 8) as u8;
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
			Data::utc_time(value) => {
				let quality = TimeQuality::from(*value.0.get(7).context(MissingData)?);
				Iec61850Data::UtcTime(value.try_into()?, quality)
			}
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
			Iec61850Data::UtcTime(value, quality) => Data::utc_time((value, quality).into()),
		})
	}
}

impl TryFrom<FloatingPoint> for f64 {
	type Error = Iec61850DataError;
	#[instrument(level = "debug")]
	fn try_from(value: FloatingPoint) -> Result<Self, Self::Error> {
		// MMS FloatingPoint (IEC 9506-2 14.4.2.2) is an OCTET STRING: the
		// first octet is the exponent width, the rest is the big-endian
		// IEEE-754 value. IEC 61850 uses binary32 (width 8) and binary64
		// (width 11).
		let bytes = value.0.as_ref();
		let exponent_width = *bytes.first().context(InvalidData)?;
		let value_bytes = bytes.get(1..).context(InvalidData)?;
		match (exponent_width, value_bytes.len()) {
			(IEEE754_SINGLE_EXPONENT_WIDTH, 4) => {
				let bits = value_bytes.first_chunk().context(InvalidData)?;
				Ok(f64::from(f32::from_be_bytes(*bits)))
			}
			(IEEE754_DOUBLE_EXPONENT_WIDTH, 8) => {
				let bits = value_bytes.first_chunk().context(InvalidData)?;
				Ok(f64::from_be_bytes(*bits))
			}
			_ => InvalidData.fail(),
		}
	}
}

impl From<f32> for FloatingPoint {
	fn from(value: f32) -> Self {
		let bytes = value.to_be_bytes();
		FloatingPoint(OctetString::from([
			IEEE754_SINGLE_EXPONENT_WIDTH,
			bytes[0],
			bytes[1],
			bytes[2],
			bytes[3],
		]))
	}
}

impl From<f64> for FloatingPoint {
	fn from(value: f64) -> Self {
		// Prefer binary32 when the value is exactly representable as f32 so
		// FLOAT32 attributes stay FLOAT32 on write. Otherwise emit binary64.
		#[allow(clippy::cast_possible_truncation)]
		let as_f32 = value as f32;
		if f64::from(as_f32).to_bits() == value.to_bits() {
			return as_f32.into();
		}
		let bytes = value.to_be_bytes();
		let mut encoded = Vec::with_capacity(9);
		encoded.push(IEEE754_DOUBLE_EXPONENT_WIDTH);
		encoded.extend_from_slice(&bytes);
		FloatingPoint(OctetString::from(encoded))
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
		// IEC 61850 UtcTime (8 octets, big-endian): 4 octets SecondSinceEpoch,
		// 3 octets FractionOfSecond (value / 2^24 of a second), 1 octet
		// TimeQuality.
		let seconds = u32::from_be_bytes(*value.0.first_chunk().context(MissingData)?);
		let fraction = u32::from_be_bytes([
			0,
			*value.0.get(4).context(MissingData)?,
			*value.0.get(5).context(MissingData)?,
			*value.0.get(6).context(MissingData)?,
		]);
		// fraction / 2^24 * 1000, as integer milliseconds.
		let milliseconds = (i64::from(fraction) * 1000) >> 24;

		// TODO: surface TimeQuality (leap-second-known, clock-failure,
		// not-synchronized); for now only validate the octet is present.
		let _quality = value.0.get(7).context(MissingData)?;

		Ok(OffsetDateTime::from_unix_timestamp(i64::from(seconds)).context(InvalidTimestamp)?
			+ time::Duration::milliseconds(milliseconds))
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
		(value, TimeQuality::default()).into()
	}
}

impl From<(OffsetDateTime, TimeQuality)> for UtcTime {
	fn from((value, quality): (OffsetDateTime, TimeQuality)) -> Self {
		// SecondSinceEpoch (big-endian) + FractionOfSecond (big-endian,
		// millisecond * 2^24 / 1000, 3 octets) + TimeQuality.
		let seconds = (value.unix_timestamp() as u32).to_be_bytes();
		let fraction = ((u64::from(value.millisecond()) << 24) / 1000) as u32;
		let fraction = fraction.to_be_bytes();

		UtcTime(FixedOctetString::from([
			seconds[0],
			seconds[1],
			seconds[2],
			seconds[3],
			fraction[1],
			fraction[2],
			fraction[3],
			quality.into(),
		]))
	}
}

impl TryFrom<TimeOfDay> for OffsetDateTime {
	type Error = Iec61850DataError;

	#[instrument(level = "debug")]
	fn try_from(value: TimeOfDay) -> Result<Self, Self::Error> {
		// Binary time: 4 octets milliseconds-since-midnight (big-endian),
		// optionally followed by 2 octets days-since-1984 (big-endian). Use
		// bounds-checked access so a short/malformed value errors instead of
		// panicking.
		let mut milliseconds =
			i64::from(u32::from_be_bytes(*value.0.first_chunk().context(MissingData)?));

		if value.0.len() == 6 {
			let days = u16::from_be_bytes([
				*value.0.get(4).context(MissingData)?,
				*value.0.get(5).context(MissingData)?,
			]);
			milliseconds += i64::from(days) * MILLISECONDS_PER_DAY + MMS_TO_UNIX_EPOCH_OFFSET;
		}

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

impl TryFrom<Iec61850Data> for f64 {
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
			Iec61850Data::UtcTime(value, _quality) => Ok(value),
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

#[allow(clippy::unwrap_used, clippy::print_stdout, clippy::float_cmp)]
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
	fn test_utc_time_big_endian_decode() {
		// 2021-01-01T00:00:00.500Z. SecondSinceEpoch = 1609459200 = 0x5FEE6600
		// (big-endian); FractionOfSecond for 500 ms = 500*2^24/1000 = 0x800000.
		let utc_time =
			UtcTime(FixedOctetString::from([0x5F, 0xEE, 0x66, 0x00, 0x80, 0x00, 0x00, 0x00]));
		let decoded: OffsetDateTime = utc_time.try_into().unwrap();
		assert_eq!(decoded, OffsetDateTime::parse("2021-01-01T00:00:00.500Z", &Rfc3339).unwrap());
	}

	#[test]
	fn test_utc_time_big_endian_round_trip() {
		let dt = OffsetDateTime::parse("2021-01-01T00:00:00.500Z", &Rfc3339).unwrap();
		let utc_time: UtcTime = dt.into();
		// Encoded form must be big-endian.
		assert_eq!(utc_time.0.to_vec(), vec![0x5F, 0xEE, 0x66, 0x00, 0x80, 0x00, 0x00, 0x00]);
		let back: OffsetDateTime = utc_time.try_into().unwrap();
		assert_eq!(back, dt);
	}

	#[test]
	fn test_time_quality_byte_round_trip() {
		let quality = TimeQuality {
			leap_second_known: true,
			clock_failure: false,
			clock_not_synchronized: true,
			time_accuracy: 10,
		};
		let byte: u8 = quality.into();
		assert_eq!(byte, 0x80 | 0x20 | 10);
		assert_eq!(TimeQuality::from(byte), quality);
	}

	#[test]
	fn test_utc_time_quality_surfaced() {
		use crate::mms::asn1::mms::asn1::Data;
		// Quality octet 0x60 = clock_failure | clock_not_synchronized.
		let utc = UtcTime(FixedOctetString::from([0x5F, 0xEE, 0x66, 0x00, 0x80, 0x00, 0x00, 0x60]));
		let data: Iec61850Data = Data::utc_time(utc).try_into().unwrap();
		let Iec61850Data::UtcTime(_, quality) = data else {
			panic!("expected UtcTime");
		};
		assert!(quality.clock_failure);
		assert!(quality.clock_not_synchronized);
		assert!(!quality.leap_second_known);
	}

	#[test]
	fn test_floating_point_big_endian() {
		// 1.0_f32 = 0x3F80_0000 (IEEE-754). MMS form prepends the exponent
		// width byte (8) and stores the value big-endian.
		let fp = FloatingPoint(OctetString::from(vec![0x08, 0x3F, 0x80, 0x00, 0x00]));
		let decoded: f64 = fp.try_into().unwrap();
		assert_eq!(decoded, 1.0);

		let encoded: FloatingPoint = 1.0_f32.into();
		assert_eq!(encoded.0.to_vec(), vec![0x08, 0x3F, 0x80, 0x00, 0x00]);

		// A second value to guard against accidental symmetry.
		let encoded: FloatingPoint = (-12.5_f32).into();
		assert_eq!(encoded.0.to_vec(), vec![0x08, 0xC1, 0x48, 0x00, 0x00]);
		let decoded: f64 = encoded.try_into().unwrap();
		assert_eq!(decoded, -12.5);
	}

	#[test]
	fn test_floating_point_binary64() {
		// 1.0_f64 = 0x3FF0_0000_0000_0000. Exponent width 11, 8 value octets.
		let fp = FloatingPoint(OctetString::from(vec![
			0x0B, 0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		]));
		let decoded: f64 = fp.try_into().unwrap();
		assert_eq!(decoded, 1.0);

		// A value that is not exactly representable as f32 must stay binary64.
		let value = 0.1_f64;
		let encoded: FloatingPoint = value.into();
		assert_eq!(encoded.0[0], IEEE754_DOUBLE_EXPONENT_WIDTH);
		assert_eq!(encoded.0.len(), 9);
		let decoded: f64 = encoded.try_into().unwrap();
		assert_eq!(decoded, value);
	}

	#[test]
	fn test_floating_point_rejects_unknown_width() {
		let fp = FloatingPoint(OctetString::from(vec![0x07, 0x3F, 0x80, 0x00, 0x00]));
		assert!(f64::try_from(fp).is_err());
	}
	#[test]
	fn test_from_bitstring_to_bit_string() {
		let mut bs = BitString::from_slice(&[0x7b, 0x80]);
		bs.truncate(10);
		let bitstring: Bitstring = bs.clone().into();
		// 10 logical bits => 6 bits of padding in the final byte.
		assert_eq!(bitstring.padding, 6);
		let bit_string = BitString::from(bitstring);
		assert_eq!(bs, bit_string);
	}

	#[test]
	fn test_time_of_day_short_input_errors_not_panics() {
		// Fewer than 4 octets must produce an error rather than panic on a
		// direct index.
		let short = TimeOfDay([0x00_u8, 0x01].into());
		assert!(OffsetDateTime::try_from(short).is_err());
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
