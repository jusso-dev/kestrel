//! Server-side pollers. SNMP devices are operator-configured targets.

mod http;
mod runtime;
mod snmp;

pub(crate) use http::spawn as spawn_http;
pub(crate) use runtime::spawn;

pub use snmp::{
    snmp_templates, snmp_v3_security, BlockingPoller, PollError, SnmpPoller, SnmpTarget,
    TimeoutPool, DEFAULT_PERMITS, IF_TABLE, IF_X_TABLE,
};
