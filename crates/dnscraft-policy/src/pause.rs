//! User-facing “Pause protection” (global and per-profile).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::error::{ConfigReason, PolicyError};
use crate::ids::ProfileId;

/// What to pause.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PauseScope {
    /// Every profile.
    Global,
    /// A single profile.
    Profile(ProfileId),
}

/// How long the pause lasts.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PauseUntil {
    /// Absolute duration from the moment [`PolicyEngine::pause`](crate::PolicyEngine::pause)
    /// is called (spec: 5 minutes or 1 hour; any positive duration is accepted).
    For(Duration),
    /// Stays paused until [`PolicyEngine::resume`](crate::PolicyEngine::resume).
    UntilResumed,
}

#[derive(Clone, Debug)]
enum Deadline {
    Until(SystemTime),
    UntilResumed,
}

impl Deadline {
    fn active(&self, now: SystemTime) -> bool {
        match self {
            Self::UntilResumed => true,
            Self::Until(t) => now < *t,
        }
    }
}

/// Mutable pause table (global + per profile).
#[derive(Debug, Default)]
pub(crate) struct PauseTable {
    global: Option<Deadline>,
    profiles: HashMap<ProfileId, Deadline>,
}

impl PauseTable {
    pub(crate) fn pause(
        &mut self,
        scope: PauseScope,
        until: PauseUntil,
        now: SystemTime,
        known_profiles: &[ProfileId],
    ) -> Result<(), PolicyError> {
        let deadline = match until {
            PauseUntil::UntilResumed => Deadline::UntilResumed,
            PauseUntil::For(d) => match now.checked_add(d) {
                Some(t) => Deadline::Until(t),
                // Overflow: treat as until-resumed rather than an already-expired deadline.
                None => Deadline::UntilResumed,
            },
        };
        match scope {
            PauseScope::Global => {
                self.global = Some(deadline);
                Ok(())
            }
            PauseScope::Profile(id) => {
                if !known_profiles.iter().any(|p| p == &id) {
                    return Err(PolicyError::InvalidConfig {
                        reason: ConfigReason::UnknownProfile {
                            id: Arc::from(id.as_str()),
                        },
                    });
                }
                self.profiles.insert(id, deadline);
                Ok(())
            }
        }
    }

    pub(crate) fn resume(&mut self, scope: PauseScope) {
        match scope {
            PauseScope::Global => {
                self.global = None;
            }
            PauseScope::Profile(id) => {
                self.profiles.remove(&id);
            }
        }
    }

    /// True when global or this profile's pause is still active at `now`.
    pub(crate) fn is_paused(&self, profile: &ProfileId, now: SystemTime) -> bool {
        if self.global.as_ref().is_some_and(|d| d.active(now)) {
            return true;
        }
        self.profiles.get(profile).is_some_and(|d| d.active(now))
    }

    /// Drops pauses for profile ids that are no longer present.
    pub(crate) fn retain_profiles(&mut self, known: &[ProfileId]) {
        self.profiles.retain(|id, _| known.iter().any(|k| k == id));
    }
}
