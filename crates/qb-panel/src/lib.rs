//! The qberrypi front panel, "Drain": what the 480x320 screen shows and how
//! a tap works it. No I/O; the caller owns the framebuffer and the touch
//! device.
//!
//! A lane of name tiles runs along the top of the screen. A gate stands in
//! it: a refused name stops there, melts and drips into a funnel of dots
//! above the refused count. The slow figures (the blocked share, the clock
//! and the count) sit beside the lane, with the key that pauses blocking.
//! A pause and an alert take over the screen in a look of their own.
//!
//! [`drain::Drain`] is the scene, one `tick` a frame; [`drain::Stills`] holds
//! the figures; [`Painter`] keeps a frame between calls and repaints only
//! what changed, as RGB565 for the screen. [`touch`] maps taps to controls.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod drain;
pub mod format;
pub mod geometry;
mod rgb565;
pub mod rows;
pub mod state;
pub mod text;
pub mod touch;

pub use drain::{Fixture, Painter, drain_fixture};
pub use geometry::{HEIGHT, WIDTH};
pub use rgb565::rgba_to_rgb565;
pub use state::{Blocking, LaneWords, Share, TimeOfDay};
pub use touch::{Calibration, Control, Switch, TapTracker, TouchEvent, hit, to_screen};
