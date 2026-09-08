//! Subcommand implementations for the `flowplane` binary. Each module owns one subcommand's
//! clap `Args` struct and its `run` entry point; `main` only parses `Cli`/`Cmd` and dispatches.

pub mod bringup;
pub mod inspect;
pub mod serve;
pub mod tc_bringup;
