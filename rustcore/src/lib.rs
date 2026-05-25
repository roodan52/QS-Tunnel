//! QS-Tunnel Rust Core — hot path implementations
//!
//! این کتابخانه از Go از طریق CGO فراخوانی میشه
//! همه توابع extern "C" هستن و با #[no_mangle] export میشن

#![allow(non_snake_case)]

mod proto;
mod reasm;
mod crypto;

pub use proto::*;
pub use reasm::*;
pub use crypto::*;
