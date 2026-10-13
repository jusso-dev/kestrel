//! Wire types shared by agent and server. See ADR 0003.

/// One metric sample.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
    pub timestamp_ms: i64,
}

/// Nagios-compatible check state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Ok = 0,
    Warning = 1,
    Critical = 2,
    Unknown = 3,
}

impl CheckState {
    pub fn from_exit_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Warning,
            2 => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exit_codes_map() {
        assert_eq!(CheckState::from_exit_code(2), CheckState::Critical);
        assert_eq!(CheckState::from_exit_code(9), CheckState::Unknown);
    }
}
