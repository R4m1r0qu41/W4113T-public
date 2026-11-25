//! The signing state machine (BP §12). Single source of truth for pipeline
//! ordering: the transition table below is the only way to move a lifecycle,
//! so no crate can express a pipeline that skips a required state.
//!
//! Every transition (and every rejected attempt) is auditable: callers pass
//! transitions to the audit log; this module only enforces legality.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Received,
    Validated,
    PermissionChecked,
    Decoded,
    Simulated,
    RiskEvaluated,
    PolicyEvaluated,
    UserReview,
    Authorized,
    Signed,
    Broadcast,
    Confirmed,
    // Terminal / failure states.
    Rejected,
    Blocked,
    Expired,
    Cancelled,
    SimulationFailed,
    PolicyDenied,
    SigningFailed,
    BroadcastFailed,
    Replaced,
    Dropped,
    Unknown,
}

use LifecycleState::*;

impl LifecycleState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Confirmed
                | Rejected
                | Blocked
                | Expired
                | Cancelled
                | SimulationFailed
                | PolicyDenied
                | SigningFailed
                | BroadcastFailed
                | Replaced
                | Dropped
                | Unknown
        )
    }

    /// The complete legal transition table. Nothing else moves a lifecycle.
    pub fn can_transition_to(self, next: LifecycleState) -> bool {
        // Emergency lock / explicit block: reachable from any pre-signature state.
        let blockable = matches!(
            self,
            Received
                | Validated
                | PermissionChecked
                | Decoded
                | Simulated
                | RiskEvaluated
                | PolicyEvaluated
                | UserReview
                | Authorized
        );
        if next == Blocked {
            return blockable;
        }
        match self {
            Received => matches!(next, Validated | Rejected),
            // Expiry can surface during the permission check (i.e. from
            // VALIDATED) or while the grant is held (from PERMISSION_CHECKED
            // / USER_REVIEW).
            Validated => matches!(next, PermissionChecked | Rejected | Expired),
            PermissionChecked => matches!(next, Decoded | Rejected | Expired),
            Decoded => matches!(next, Simulated | SimulationFailed),
            Simulated => matches!(next, RiskEvaluated),
            RiskEvaluated => matches!(next, PolicyEvaluated),
            PolicyEvaluated => matches!(next, UserReview | PolicyDenied),
            UserReview => matches!(next, Authorized | Rejected | Cancelled | Expired),
            Authorized => matches!(next, Signed | SigningFailed),
            Signed => matches!(next, Broadcast | BroadcastFailed),
            Broadcast => matches!(next, Confirmed | BroadcastFailed | Replaced | Dropped),
            // Terminal states are absorbing.
            _ => false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("illegal state transition {from:?} -> {to:?} for request {request_id}")]
pub struct IllegalTransition {
    pub request_id: Uuid,
    pub from: LifecycleState,
    pub to: LifecycleState,
}

/// One request's lifecycle. Constructed only at `Received`; there is no
/// constructor for a mid-pipeline lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lifecycle {
    request_id: Uuid,
    state: LifecycleState,
    history: Vec<(LifecycleState, DateTime<Utc>)>,
}

impl Lifecycle {
    pub fn start(request_id: Uuid) -> Self {
        Self {
            request_id,
            state: Received,
            history: vec![(Received, Utc::now())],
        }
    }

    pub fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub fn history(&self) -> &[(LifecycleState, DateTime<Utc>)] {
        &self.history
    }

    /// Advance or fail. The caller must audit both outcomes.
    pub fn advance(&mut self, to: LifecycleState) -> Result<(), IllegalTransition> {
        if self.state.can_transition_to(to) {
            self.state = to;
            self.history.push((to, Utc::now()));
            Ok(())
        } else {
            Err(IllegalTransition {
                request_id: self.request_id,
                from: self.state,
                to,
            })
        }
    }
}

pub const HAPPY_PATH: [LifecycleState; 12] = [
    Received,
    Validated,
    PermissionChecked,
    Decoded,
    Simulated,
    RiskEvaluated,
    PolicyEvaluated,
    UserReview,
    Authorized,
    Signed,
    Broadcast,
    Confirmed,
];

pub const ALL_STATES: [LifecycleState; 23] = [
    Received,
    Validated,
    PermissionChecked,
    Decoded,
    Simulated,
    RiskEvaluated,
    PolicyEvaluated,
    UserReview,
    Authorized,
    Signed,
    Broadcast,
    Confirmed,
    Rejected,
    Blocked,
    Expired,
    Cancelled,
    SimulationFailed,
    PolicyDenied,
    SigningFailed,
    BroadcastFailed,
    Replaced,
    Dropped,
    Unknown,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_is_legal_in_order() {
        let mut lc = Lifecycle::start(Uuid::new_v4());
        for s in HAPPY_PATH.iter().skip(1) {
            lc.advance(*s).unwrap();
        }
        assert_eq!(lc.state(), Confirmed);
        assert_eq!(lc.history().len(), 12);
    }

    #[test]
    fn cannot_skip_simulation_and_risk() {
        let mut lc = Lifecycle::start(Uuid::new_v4());
        lc.advance(Validated).unwrap();
        lc.advance(PermissionChecked).unwrap();
        lc.advance(Decoded).unwrap();
        // DECODED -> POLICY_EVALUATED must be illegal (skips SIMULATED, RISK_EVALUATED).
        assert!(lc.advance(PolicyEvaluated).is_err());
        assert_eq!(lc.state(), Decoded);
    }

    #[test]
    fn signing_unreachable_without_review() {
        let mut lc = Lifecycle::start(Uuid::new_v4());
        lc.advance(Validated).unwrap();
        assert!(lc.advance(Signed).is_err());
        assert!(lc.advance(Authorized).is_err());
    }

    #[test]
    fn terminal_states_are_absorbing() {
        for term in ALL_STATES.iter().filter(|s| s.is_terminal()) {
            for next in ALL_STATES {
                assert!(
                    !term.can_transition_to(next),
                    "{term:?} -> {next:?} must be illegal"
                );
            }
        }
    }

    #[test]
    fn blocked_reachable_only_pre_signature() {
        assert!(Received.can_transition_to(Blocked));
        assert!(UserReview.can_transition_to(Blocked));
        assert!(Authorized.can_transition_to(Blocked));
        assert!(!Signed.can_transition_to(Blocked));
        assert!(!Broadcast.can_transition_to(Blocked));
    }

    #[test]
    fn serde_uses_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&SimulationFailed).unwrap(),
            "\"SIMULATION_FAILED\""
        );
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_state() -> impl Strategy<Value = LifecycleState> {
        proptest::sample::select(ALL_STATES.to_vec())
    }

    proptest! {
        /// No random walk over advance() can reach SIGNED without having
        /// passed POLICY_EVALUATED, USER_REVIEW, and AUTHORIZED first.
        #[test]
        fn signed_requires_full_prefix(steps in proptest::collection::vec(arb_state(), 1..64)) {
            let mut lc = Lifecycle::start(Uuid::new_v4());
            for s in steps {
                let _ = lc.advance(s);
                if lc.state() == Signed {
                    let visited: Vec<_> = lc.history().iter().map(|(s, _)| *s).collect();
                    prop_assert!(visited.contains(&PolicyEvaluated));
                    prop_assert!(visited.contains(&UserReview));
                    prop_assert!(visited.contains(&Authorized));
                    prop_assert!(visited.contains(&Simulated));
                    prop_assert!(visited.contains(&RiskEvaluated));
                }
            }
        }

        /// advance() never leaves a terminal state.
        #[test]
        fn terminal_absorbing_under_random_walk(steps in proptest::collection::vec(arb_state(), 1..64)) {
            let mut lc = Lifecycle::start(Uuid::new_v4());
            let mut terminal_at: Option<LifecycleState> = None;
            for s in steps {
                let _ = lc.advance(s);
                if let Some(t) = terminal_at {
                    prop_assert_eq!(lc.state(), t);
                } else if lc.state().is_terminal() {
                    terminal_at = Some(lc.state());
                }
            }
        }
    }
}
