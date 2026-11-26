// Badang

#![allow(dead_code)]

pub mod analysis;
pub mod cli;
pub mod comms;
pub mod evasion;
#[cfg(feature = "gui")]
pub mod gui;
pub mod injection;
pub mod loader;
pub mod log;
pub mod obf;
pub mod payload;
pub mod pe;
pub mod persistence;
pub mod postex;
pub mod process;
#[allow(non_snake_case)]
pub mod resolve;
pub mod safety;
pub mod syscall;

#[cfg(test)]
mod tests;
