//! What the panel asks of the board itself and does to it: the control the panel is given for SYSTEM and
//! its readings, in the way `NamesControl` is the owner's names' and `DeviceControl` the devices'.
//!
//! **Wiring.** `wiring::LiveSystem` implements [`SystemControl`] over the update machinery
//! ([`crate::update::UpdateCtl`]) and the Wi-Fi's rejoin notify; `wiring::Slot` hands the panel that,
//! filled by init as soon as the slot is made (`Slot::fill_system`), so that the panel holds its control
//! from the start: the update view is wanted from the first frame, for a boot that is on trial. Until it
//! is filled, a restart is refused as not ready, a rejoin must wait a second, and the update machinery is
//! idle.
//!
//! **Reads** copy out and let go. [`SystemControl::readings`] reads `/proc` and `/sys` on the calling
//! thread, which is the panel's (never the runtime's): a few microseconds, every five seconds, only while
//! SYSTEM or one of its readings shows (spec §5.2). [`SystemControl::update_view`] is the update machinery's
//! own small lock, once a second.
//!
//! **Acts.** `rejoin` and `restart` carry out the two actions of spec §6.6 and refuse as it says: a rejoin
//! that lets a link go at most once a minute, and neither while an update is received or staged or on a trial. The
//! panel makes the two keys inert while an update is under way, but the refusal is here as well, in the one
//! place that knows. Neither carries a name, a label or an address, and what the panel logs of either is
//! that it was asked.

use crate::update::{self, Busy};
use crate::usage::Readings;

/// The seconds that a second rejoin is refused for, from the one before it.
pub const REJOIN_EVERY_SECS: u16 = 60;

/// A rejoin is asked for too soon after the last one: the seconds that are left, at least 1, counted up
/// (`REJOIN` shows `WAIT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RejoinWait(pub u16);

/// Why the board is not restarted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartRefused {
    /// An update is being received or staged, or this boot is on trial: a restart would cut it short.
    Updating,
    /// The system that restarts the board is not there yet to be asked.
    NotReady,
}

impl From<Busy> for RestartRefused {
    fn from(Busy: Busy) -> Self {
        Self::Updating
    }
}

/// Where the panel reads the board from, and what it does to it.
pub trait SystemControl: Send + Sync {
    /// Asks the Wi-Fi to let the link go and join again (spec §6.6): the link that is held ends at once and
    /// a hinted join follows. Refused while the last one that let a link go is less than [`REJOIN_EVERY_SECS`]
    /// old, with the seconds that are left. One that finds no link held (it is down, or being joined) lets
    /// nothing go, since the join that is under way or about to be is the one asked for: it is no refusal, and
    /// it is not charged the minute. Refused as well, as a wait of the whole minute that is charged to nobody,
    /// while an update is received or staged and while this boot is on trial: the link that carries it is
    /// not let go of. The house is without DNS for the few seconds of the join.
    fn rejoin(&self) -> Result<(), RejoinWait>;

    /// Asks for the board to restart, with the cause `Cause::Owner` (logged at INFO as the owner's own
    /// decision). Refused while an update is received or staged and while this boot is on trial. A restart
    /// that stands already is no refusal.
    fn restart(&self) -> Result<(), RestartRefused>;

    /// Where the update machinery stands: its state, the bytes received so far and the whole length, the
    /// trial's minimum time left, and how the last trial ended (spec §12.3, §12.5). One small lock.
    fn update_view(&self) -> update::View;

    /// The board's uptime, load, memory and heat, read now on the calling thread (spec §6.5).
    fn readings(&self) -> Readings;
}

/// A control for as long as nothing is there to be controlled: what the panel's own tests give it. Nothing
/// is restarted, a rejoin must wait, the update machinery is idle, and the readings are the running board's.
pub struct NoSystem;

impl SystemControl for NoSystem {
    fn rejoin(&self) -> Result<(), RejoinWait> {
        Err(RejoinWait(1))
    }

    fn restart(&self) -> Result<(), RestartRefused> {
        Err(RestartRefused::NotReady)
    }

    fn update_view(&self) -> update::View {
        update::UpdateCtl::off().view()
    }

    fn readings(&self) -> Readings {
        Readings::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stand_in_refuses_both_actions_and_knows_nothing() {
        let system: &dyn SystemControl = &NoSystem;
        assert_eq!(system.rejoin(), Err(RejoinWait(1)));
        assert_eq!(system.restart(), Err(RestartRefused::NotReady));
        let view = system.update_view();
        assert_eq!(
            (view.state, view.slot, view.received, view.length),
            ("idle", None, 0, 0)
        );
        assert_eq!(system.readings(), Readings::default());
    }

    #[test]
    fn a_busy_update_machinery_is_why_a_restart_is_refused() {
        assert_eq!(RestartRefused::from(Busy), RestartRefused::Updating);
    }
}
