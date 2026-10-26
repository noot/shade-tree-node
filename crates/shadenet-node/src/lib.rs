//! ShadeNet node (ADR 0014): a proof-gated egress node published as a Tor onion service.
//!
//! The binary is a thin shell: `main.rs` resolves a [`Config`] from the environment and
//! hands it to [`ShadeNode`], which owns every subsystem for the life of the process.
//! Wire formats follow `docs/WIRE-SPEC.md` section 6 and the refusal reasons the JavaScript
//! node emits, so existing clients need no change.

#![forbid(unsafe_op_in_unsafe_fn)]

mod chain;
mod config;
mod egress;
mod envelope;
mod error;
mod members;
mod node;
mod receipt;
mod roots;
mod rpc;
mod session;
mod slash;
mod spent;
mod tunnel;
mod verify;

pub use config::Config;
pub use error::Error;
pub use node::ShadeNode;
