#![doc = include_str!("../README.md")]
pub mod action;
pub mod app;
pub mod event;
pub mod screens;
pub mod theme;
pub mod widgets;
pub use app::{update, view, App, ScreenId};
pub use event::{run, RunOutcome};
