//! Escalation steps. A step is due at `opened_at + delay_s` and is skipped
//! once the problem is acknowledged or resolved.

use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationStep {
    pub step: u32,
    pub delay_s: i64,
    pub media_type_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueStep {
    pub step: u32,
    pub media_type_ids: Vec<Uuid>,
}

pub fn due_steps(
    opened_at: i64,
    now: i64,
    steps: &[EscalationStep],
    acknowledged: bool,
    resolved: bool,
    already_sent: &[u32],
) -> Vec<DueStep> {
    if acknowledged || resolved {
        return Vec::new();
    }
    let mut due = Vec::new();
    for step in steps {
        if already_sent.contains(&step.step) {
            continue;
        }
        if now >= opened_at.saturating_add(step.delay_s) {
            due.push(DueStep {
                step: step.step,
                media_type_ids: step.media_type_ids.clone(),
            });
        }
    }
    due.sort_by_key(|step| step.step);
    due
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steps() -> Vec<EscalationStep> {
        vec![
            EscalationStep {
                step: 1,
                delay_s: 0,
                media_type_ids: vec![Uuid::from_u128(1)],
            },
            EscalationStep {
                step: 2,
                delay_s: 60,
                media_type_ids: vec![Uuid::from_u128(2)],
            },
            EscalationStep {
                step: 3,
                delay_s: 120,
                media_type_ids: vec![Uuid::from_u128(3)],
            },
        ]
    }

    #[test]
    fn escalation_fires_in_order_and_stops_on_ack() {
        let steps = steps();
        let opened = 1_000;
        let first = due_steps(opened, opened, &steps, false, false, &[]);
        assert_eq!(
            first.iter().map(|step| step.step).collect::<Vec<_>>(),
            vec![1]
        );
        let second = due_steps(opened, opened + 60, &steps, false, false, &[1]);
        assert_eq!(
            second.iter().map(|step| step.step).collect::<Vec<_>>(),
            vec![2]
        );
        let third = due_steps(opened, opened + 120, &steps, false, false, &[1, 2]);
        assert_eq!(
            third.iter().map(|step| step.step).collect::<Vec<_>>(),
            vec![3]
        );
        assert!(due_steps(opened, opened + 120, &steps, true, false, &[1]).is_empty());
        assert!(due_steps(opened, opened + 120, &steps, false, true, &[1]).is_empty());
        let early = due_steps(opened, opened + 30, &steps, false, false, &[1]);
        assert!(early.is_empty());
    }
}
