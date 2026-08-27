//! IEC 61850 control service structures (Oper / SBOw).
//!
//! Builds the common controllable CDC service attributes written over MMS for
//! Direct-operate and Select-before-operate. Callers supply `ctlVal` already
//! typed as [`Iec61850Data`]; this module packs origin, ctlNum, T, Test, and
//! Check around it.

use time::OffsetDateTime;

use crate::iec61850::data::{Bitstring, Iec61850Data, TimeQuality};

/// Originator category (`orCat`) per IEC 61850-7-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum OrCat {
	/// Not supported / not used.
	NotSupported = 0,
	/// Bay control.
	BayControl = 1,
	/// Station control.
	StationControl = 2,
	/// Remote control (default for this client).
	#[default]
	RemoteControl = 3,
	/// Automatic bay.
	AutomaticBay = 4,
	/// Automatic station.
	AutomaticStation = 5,
	/// Automatic remote.
	AutomaticRemote = 6,
	/// Maintenance.
	Maintenance = 7,
	/// Process.
	Process = 8,
}

/// Options for an Oper / SBOw write beyond `ctlVal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlOptions {
	/// IEC 61850 `Test` flag.
	pub test: bool,
	/// Synchrocheck bit of `Check`.
	pub synchrocheck: bool,
	/// Interlock-check bit of `Check`.
	pub interlock_check: bool,
	/// Originator category.
	pub or_cat: OrCat,
	/// Originator identity (`orIdent` OCTET STRING).
	pub or_ident: Vec<u8>,
	/// Control sequence number (`ctlNum`).
	pub ctl_num: u8,
}

impl Default for ControlOptions {
	fn default() -> Self {
		Self {
			test: false,
			synchrocheck: false,
			interlock_check: false,
			or_cat: OrCat::RemoteControl,
			or_ident: Vec::new(),
			ctl_num: 0,
		}
	}
}

impl ControlOptions {
	/// Build options with the given Test / Check flags (remote orCat).
	#[must_use]
	pub fn new(test: bool, synchrocheck: bool, interlock_check: bool) -> Self {
		Self { test, synchrocheck, interlock_check, ..Self::default() }
	}
}

/// Build the Oper / SBOw service structure (without optional `operTm`).
///
/// Field order (IEC 61850-7-3 common controllable service params, omitting
/// time-activated `operTm`):
/// `ctlVal`, `origin`, `ctlNum`, `T`, `Test`, `Check`.
#[must_use]
pub fn build_control_service_structure(
	ctl_val: Iec61850Data,
	options: &ControlOptions,
	timestamp: OffsetDateTime,
) -> Iec61850Data {
	let origin = Iec61850Data::Structure(vec![
		Iec61850Data::Integer(i32::from(options.or_cat as u8)),
		Iec61850Data::OctetString(options.or_ident.clone()),
	]);

	let time_quality = TimeQuality {
		leap_second_known: true,
		clock_failure: false,
		clock_not_synchronized: false,
		time_accuracy: 10,
	};

	Iec61850Data::Structure(vec![
		ctl_val,
		origin,
		Iec61850Data::Unsigned(u32::from(options.ctl_num)),
		Iec61850Data::UtcTime(timestamp, time_quality),
		Iec61850Data::Bool(options.test),
		Iec61850Data::BitString(check_bitstring(options.synchrocheck, options.interlock_check)),
	])
}

/// `Check` PACKED LIST: bit0 = synchrocheck, bit1 = interlock-check (2 used
/// bits).
fn check_bitstring(synchrocheck: bool, interlock_check: bool) -> Bitstring {
	let mut bits = 0_u8;
	if synchrocheck {
		bits |= 1 << 0;
	}
	if interlock_check {
		bits |= 1 << 1;
	}
	Bitstring { bytes: vec![bits], padding: 6 }
}

/// Append `$Oper` to a CO data-object reference (e.g. `LD/CSWI1$CO$Pos`).
#[must_use]
pub fn oper_path(co_reference: &str) -> String {
	format!("{co_reference}$Oper")
}

/// Append `$SBOw` to a CO data-object reference.
#[must_use]
pub fn sbow_path(co_reference: &str) -> String {
	format!("{co_reference}$SBOw")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn check_bits_encoding() {
		let none = check_bitstring(false, false);
		assert_eq!(none.bytes, vec![0]);
		assert_eq!(none.padding, 6);

		let sync = check_bitstring(true, false);
		assert_eq!(sync.bytes, vec![0x01]);

		let both = check_bitstring(true, true);
		assert_eq!(both.bytes, vec![0x03]);
	}

	#[test]
	fn control_structure_field_order() {
		let options = ControlOptions::new(true, true, false);
		let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("ts");
		let structure = build_control_service_structure(Iec61850Data::Bool(true), &options, ts);
		let Iec61850Data::Structure(fields) = structure else {
			panic!("expected structure");
		};
		assert_eq!(fields.len(), 6);
		assert_eq!(fields[0], Iec61850Data::Bool(true));
		let Iec61850Data::Structure(origin) = &fields[1] else {
			panic!("expected origin structure");
		};
		assert_eq!(origin[0], Iec61850Data::Integer(3));
		assert_eq!(origin[1], Iec61850Data::OctetString(vec![]));
		assert_eq!(fields[2], Iec61850Data::Unsigned(0));
		assert!(matches!(fields[3], Iec61850Data::UtcTime(_, _)));
		assert_eq!(fields[4], Iec61850Data::Bool(true));
		assert_eq!(fields[5], Iec61850Data::BitString(Bitstring { bytes: vec![0x01], padding: 6 }));
	}

	#[test]
	fn path_suffixes() {
		assert_eq!(oper_path("CTRL/CSWI1$CO$Pos"), "CTRL/CSWI1$CO$Pos$Oper");
		assert_eq!(sbow_path("CTRL/CSWI1$CO$Pos"), "CTRL/CSWI1$CO$Pos$SBOw");
	}
}
