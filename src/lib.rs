// Badang — EDR Evasion Research Toolkit
// For authorized security research and red team use only.
// https://github.com/aimansam/badang

#![allow(dead_code)]

pub mod cli;
pub mod detect;
pub mod generate;
#[cfg(feature = "gui")]
pub mod gui;
pub mod injection;
pub mod log;
pub mod process;
pub mod payload;
pub mod safety;
pub mod syscall;
pub mod unhook;

#[cfg(test)]
mod tests;
