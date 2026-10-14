//! Maintenance windows. Recurrence uses an RRULE and is evaluated in the
//! window's timezone so a weekly local time survives a DST change.

use chrono::{DateTime, Datelike, Duration, TimeZone, Utc};
use chrono_tz::Tz;
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
    let Ok(parsed) = parse_weekly(rule) else {
        return false;
    };
    let duration = window.ends_at - window.starts_at;
    if duration <= Duration::zero() {
        return false;
    }
    let local_now = now.with_timezone(&parsed.tz);
    if !parsed.weekdays.contains(&local_now.weekday()) {
        return false;
    }
    let start = parsed
        .tz
        .with_ymd_and_hms(
            local_now.year(),
            local_now.month(),
            local_now.day(),
            parsed.hour,
            parsed.minute,
            parsed.second,
        )
        .single();
    let Some(start) = start else {
        return false;
    };
    let end = start + duration;
    local_now >= start && local_now < end
}

struct Weekly {
    tz: Tz,
    weekdays: Vec<chrono::Weekday>,
    hour: u32,
    minute: u32,
    second: u32,
}

fn parse_weekly(rule: &str) -> Result<Weekly, String> {
    let mut tz = chrono_tz::UTC;
    let mut hour = 0;
    let mut minute = 0;
    let mut second = 0;
    let mut weekdays = Vec::new();
    for line in rule.lines() {
        let line = line.trim();
        if let Some(start) = line.strip_prefix("DTSTART") {
            if let Some(zone) = start.strip_prefix(";TZID=") {
                let (name, time) = zone
                    .split_once(':')
                    .ok_or_else(|| "DTSTART is missing a time".to_string())?;
                tz = name
                    .parse()
                    .map_err(|_| format!("unknown timezone {name}"))?;
                (hour, minute, second) = parse_local_time(time)?;
            }
        }
        let body = line.strip_prefix("RRULE:").unwrap_or(line);
        if !body.contains("FREQ=") {
            continue;
        }
        let validated = if body.starts_with("FREQ=") {
            format!("DTSTART:20260101T000000Z\nRRULE:{body}")
        } else {
            body.to_string()
        };
        let _ = validated
            .parse::<rrule::RRuleSet>()
            .map_err(|err| format!("rrule: {err}"))?;
        for part in body.split(';') {
            if let Some(days) = part.strip_prefix("BYDAY=") {
                for day in days.split(',') {
                    weekdays.push(parse_day(day)?);
                }
            }
        }
    }
    if weekdays.is_empty() {
        return Err("RRULE is missing BYDAY".to_string());
    }
    Ok(Weekly {
        tz,
        weekdays,
        hour,
        minute,
        second,
    })
}

fn parse_local_time(value: &str) -> Result<(u32, u32, u32), String> {
    if value.len() < 15 {
        return Err("DTSTART time is too short".to_string());
    }
    let time = &value[9..];
    let hour: u32 = time
        .get(0..2)
        .ok_or("hour")?
        .parse()
        .map_err(|_| "hour".to_string())?;
    let minute: u32 = time
        .get(2..4)
        .ok_or("minute")?
        .parse()
        .map_err(|_| "minute".to_string())?;
    let second: u32 = time
        .get(4..6)
        .ok_or("second")?
        .parse()
        .map_err(|_| "second".to_string())?;
    Ok((hour, minute, second))
}

fn parse_day(day: &str) -> Result<chrono::Weekday, String> {
    Ok(match day {
        "MO" => chrono::Weekday::Mon,
        "TU" => chrono::Weekday::Tue,
        "WE" => chrono::Weekday::Wed,
        "TH" => chrono::Weekday::Thu,
        "FR" => chrono::Weekday::Fri,
        "SA" => chrono::Weekday::Sat,
        "SU" => chrono::Weekday::Sun,
        _ => return Err(format!("unknown weekday {day}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike};

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
