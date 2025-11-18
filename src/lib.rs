//! IEC61850 protocol implementation in pure rust.
//!
//! This crate provides a client implementation for the IEC61850 protocol.
//! It is a pure rust implementation of the protocol and does not depend on
//! any external libraries.
//!
//! The implementation is based on the MMS stack protocol and the IEC61850
//! model.
//!
//! For an example of how to use the client see the examples folder.

pub mod iec61850;
pub mod mms;
pub use iec61850::Iec61850Client;
pub use mms::ClientConfig;
