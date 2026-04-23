//! ANSI-colored origin tags. `[LOCAL]` is rendered in a tealish blue,
//! `[REMOTE]` in abrasive's gold/orange. The ESC sequence resets after
//! the tag so the rest of the line keeps whatever color cargo emitted.

pub const LOCAL: &str = "\x1b[38;2;100;200;220m[LOCAL]\x1b[0m";
pub const REMOTE: &str = "\x1b[38;2;232;185;49m[REMOTE]\x1b[0m";
