//! Maintenance windows. Recurrence uses an RRULE and is evaluated in the
//! window's timezone so a weekly local time survives a DST change.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Window {
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub rrule: Option<String>,
    pub host_ids: Vec<Uuid>,
    pub group_ids: Vec<Uuid>,
    pub suppress_problems: bool,
}

pub fn notifications_suppressed(
    windows: &[Window],
    host_id: Option<Uuid>,
    group_id: Option<Uuid>,
    now: DateTime<Utc>,
) -> bool {
    windows
        .iter()
        .any(|window| covers(window, host_id, group_id, now))
}

pub fn problems_suppressed(
    windows: &[Window],
    host_id: Option<Uuid>,
    group_id: Option<Uuid>,
    now: DateTime<Utc>,
) -> bool {
    windows
        .iter()
        .any(|window| window.suppress_problems && covers(window, host_id, group_id, now))
}

fn covers(
    window: &Window,
    host_id: Option<Uuid>,
    group_id: Option<Uuid>,
    now: DateTime<Utc>,
) -> bool {
    let host_match = window.host_ids.is_empty() && window.group_ids.is_empty()
        || host_id.is_some_and(|id| window.host_ids.contains(&id))
        || group_id.is_some_and(|id| window.group_ids.contains(&id));
    if !host_match {
        return false;
    }
    if let Some(rule) = &window.rrule {
        return recurring_contains(window, rule, now);
    }
    now >= window.starts_at && now < window.ends_at
}

fn recurring_contains(window: &Window, rule: &str, now: DateTime<Utc>) -> bool {
    let duration = window.ends_at - window.starts_at;
    if duration <= Duration::zero() || now < window.starts_at {
        return false;
    }
    let definition = if rule.contains("DTSTART") {
        rule.to_string()
    } else {
        format!(
            "DTSTART:{}\nRRULE:{}",
            window.starts_at.format("%Y%m%dT%H%M%SZ"),
            rule.trim_start_matches("RRULE:")
        )
    };
    let Ok(recurrence) = definition.parse::<rrule::RRuleSet>() else {
        return false;
    };
    let lower = (now - duration).with_timezone(&rrule::Tz::UTC);
    let upper = now.with_timezone(&rrule::Tz::UTC);
    recurrence
        .after(lower)
        .before(upper)
        .all(1024)
        .dates
        .into_iter()
        .any(|start| now >= start.with_timezone(&Utc) && now < start.with_timezone(&Utc) + duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike};

    #[test]
    fn recurring_windows_obey_start_count_interval_and_cross_midnight() {
        let start = Utc.with_ymd_and_hms(2026, 10, 12, 23, 0, 0).unwrap();
        let window = Window {
            starts_at: start,
            ends_at: start + Duration::hours(2),
            rrule: Some("FREQ=WEEKLY;INTERVAL=2;COUNT=2;BYDAY=MO".into()),
            host_ids: vec![],
            group_ids: vec![],
            suppress_problems: true,
        };
        assert!(!notifications_suppressed(
            std::slice::from_ref(&window),
            None,
            None,
            start - Duration::weeks(2)
        ));
        assert!(notifications_suppressed(
            std::slice::from_ref(&window),
            None,
            None,
            start + Duration::hours(1)
        ));
        assert!(!notifications_suppressed(
            std::slice::from_ref(&window),
            None,
            None,
            start + Duration::hours(2)
        ));
        assert!(!notifications_suppressed(
            std::slice::from_ref(&window),
            None,
            None,
            start + Duration::weeks(1)
        ));
        assert!(notifications_suppressed(
            std::slice::from_ref(&window),
            None,
            None,
            start + Duration::weeks(2) + Duration::minutes(30)
        ));
        assert!(!notifications_suppressed(
            &[window],
            None,
            None,
            start + Duration::weeks(4)
        ));
    }

    #[test]
    fn escalation_maintenance_blocks_notifications() {
        let host = Uuid::from_u128(1);
        let window = Window {
            starts_at: Utc.with_ymd_and_hms(2026, 10, 14, 0, 0, 0).unwrap(),
            ends_at: Utc.with_ymd_and_hms(2026, 10, 14, 2, 0, 0).unwrap(),
            rrule: None,
            host_ids: vec![host],
            group_ids: vec![],
            suppress_problems: false,
        };
        let during = Utc.with_ymd_and_hms(2026, 10, 14, 1, 0, 0).unwrap();
        let after = Utc.with_ymd_and_hms(2026, 10, 14, 3, 0, 0).unwrap();
        assert!(notifications_suppressed(
            std::slice::from_ref(&window),
            Some(host),
            None,
            during
        ));
        assert!(!notifications_suppressed(
            std::slice::from_ref(&window),
            Some(host),
            None,
            after
        ));
        assert!(!problems_suppressed(&[window], Some(host), None, during));
    }

    #[test]
    fn escalation_weekly_maintenance_keeps_sydney_wall_clock_across_dst() {
        let host = Uuid::from_u128(1);
        let start = chrono_tz::Australia::Sydney
            .with_ymd_and_hms(2026, 9, 28, 9, 0, 0)
            .unwrap()
            .with_timezone(&Utc);
        let window = Window {
            starts_at: start,
            ends_at: start + Duration::hours(2),
            rrule: Some(
                "DTSTART;TZID=Australia/Sydney:20260928T090000\nRRULE:FREQ=WEEKLY;BYDAY=MO"
                    .to_string(),
            ),
            host_ids: vec![host],
            group_ids: vec![],
            suppress_problems: true,
        };
        let before = chrono_tz::Australia::Sydney
            .with_ymd_and_hms(2026, 9, 28, 9, 30, 0)
            .unwrap()
            .with_timezone(&Utc);
        let after = chrono_tz::Australia::Sydney
            .with_ymd_and_hms(2026, 10, 12, 9, 30, 0)
            .unwrap()
            .with_timezone(&Utc);
        let late = chrono_tz::Australia::Sydney
            .with_ymd_and_hms(2026, 10, 12, 12, 0, 0)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            before.with_timezone(&chrono_tz::Australia::Sydney).hour(),
            9
        );
        assert_eq!(after.with_timezone(&chrono_tz::Australia::Sydney).hour(), 9);
        assert_ne!(before, after);
        assert!(notifications_suppressed(
            std::slice::from_ref(&window),
            Some(host),
            None,
            before
        ));
        assert!(notifications_suppressed(
            std::slice::from_ref(&window),
            Some(host),
            None,
            after
        ));
        assert!(!notifications_suppressed(&[window], Some(host), None, late));
    }
}
