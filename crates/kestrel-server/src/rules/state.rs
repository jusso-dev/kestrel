//! Per-instance trigger state. `for` and `recover_for` are seconds.

use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerState {
    Ok,
    Pending {
        since: i64,
    },
    Problem {
        problem_id: Uuid,
        recover_since: Option<i64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Opened,
    Resolved,
    Acknowledged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub kind: EventKind,
    pub problem_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub state: TriggerState,
    pub event: Option<Fired>,
}

/// Advance one instance. `new_problem_id` is used only when a problem opens.
pub fn step(
    state: &TriggerState,
    firing: bool,
    now: i64,
    for_seconds: i64,
    recover_for: i64,
    new_problem_id: Uuid,
) -> Transition {
    let for_seconds = for_seconds.max(0);
    let recover_for = recover_for.max(0);
    match state {
        TriggerState::Ok => {
            if !firing {
                return stay(state);
            }
            if for_seconds == 0 {
                open(new_problem_id)
            } else {
                Transition {
                    state: TriggerState::Pending { since: now },
                    event: None,
                }
            }
        }
        TriggerState::Pending { since } => {
            if !firing {
                return Transition {
                    state: TriggerState::Ok,
                    event: None,
                };
            }
            if now.saturating_sub(*since) >= for_seconds {
                open(new_problem_id)
            } else {
                stay(state)
            }
        }
        TriggerState::Problem {
            problem_id,
            recover_since,
        } => {
            if firing {
                return Transition {
                    state: TriggerState::Problem {
                        problem_id: *problem_id,
                        recover_since: None,
                    },
                    event: None,
                };
            }
            if recover_for == 0 {
                return resolve(*problem_id);
            }
            match recover_since {
                None => Transition {
                    state: TriggerState::Problem {
                        problem_id: *problem_id,
                        recover_since: Some(now),
                    },
                    event: None,
                },
                Some(since) if now.saturating_sub(*since) >= recover_for => resolve(*problem_id),
                Some(_) => stay(state),
            }
        }
    }
}

fn stay(state: &TriggerState) -> Transition {
    Transition {
        state: state.clone(),
        event: None,
    }
}

fn open(problem_id: Uuid) -> Transition {
    Transition {
        state: TriggerState::Problem {
            problem_id,
            recover_since: None,
        },
        event: Some(Fired {
            kind: EventKind::Opened,
            problem_id,
        }),
    }
}

fn resolve(problem_id: Uuid) -> Transition {
    Transition {
        state: TriggerState::Ok,
        event: Some(Fired {
            kind: EventKind::Resolved,
            problem_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Uuid {
        Uuid::from_u128(42)
    }

    #[test]
    fn rules_disk_full_opens_after_for_and_resolves() {
        let pending = step(&TriggerState::Ok, true, 1_000, 60, 30, id());
        assert_eq!(pending.state, TriggerState::Pending { since: 1_000 });
        assert!(pending.event.is_none());
        let still = step(&pending.state, true, 1_030, 60, 30, id());
        assert!(matches!(still.state, TriggerState::Pending { .. }));
        let opened = step(&still.state, true, 1_060, 60, 30, id());
        assert_eq!(opened.event.unwrap().kind, EventKind::Opened);
        let held = step(&opened.state, false, 1_070, 60, 30, id());
        assert!(matches!(
            held.state,
            TriggerState::Problem {
                recover_since: Some(1_070),
                ..
            }
        ));
        let flapped = step(&held.state, true, 1_080, 60, 30, id());
        assert!(matches!(
            flapped.state,
            TriggerState::Problem {
                recover_since: None,
                ..
            }
        ));
        let recovering = step(&flapped.state, false, 1_090, 60, 30, id());
        let resolved = step(&recovering.state, false, 1_120, 60, 30, id());
        assert_eq!(resolved.event.unwrap().kind, EventKind::Resolved);
        assert_eq!(resolved.state, TriggerState::Ok);
    }

    #[test]
    fn rules_flap_before_for_does_not_open() {
        let pending = step(&TriggerState::Ok, true, 10, 60, 0, id());
        let cleared = step(&pending.state, false, 20, 60, 0, id());
        assert_eq!(cleared.state, TriggerState::Ok);
        assert!(cleared.event.is_none());
    }

    #[test]
    fn rules_restart_keeps_the_open_problem() {
        let problem_id = id();
        let state = TriggerState::Problem {
            problem_id,
            recover_since: None,
        };
        let again = step(&state, true, 500, 60, 30, Uuid::from_u128(99));
        assert!(again.event.is_none());
        match again.state {
            TriggerState::Problem {
                problem_id: kept, ..
            } => assert_eq!(kept, problem_id),
            other => panic!("unexpected {other:?}"),
        }
    }
}
