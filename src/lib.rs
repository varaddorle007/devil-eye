//! Devil Eye library — authorized capture + modular assessment.

#![forbid(unsafe_code)]

pub mod audit;
pub mod banner;
pub mod bpf_lite;
pub mod capture;
pub mod cli;
pub mod console;
pub mod dashboard;
pub mod decode;
pub mod detect;
pub mod diff;
pub mod eve;
pub mod expr;
pub mod merge;
pub mod modules;
pub mod output;
pub mod packet;
pub mod report;
pub mod rules;
pub mod scope;
pub mod services;
pub mod session;
pub mod siem;
pub mod slice;
pub mod stats;
pub mod zeek;
