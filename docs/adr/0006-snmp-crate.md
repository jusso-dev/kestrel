# 0006 SNMP crate

SNMP polling uses [`snmp2`](https://crates.io/crates/snmp2) 0.4 with the `v3` feature.

The published 0.4 line does not have a `crypto-rust` feature. v3 authentication and privacy are implemented in that crate with OpenSSL: `AuthProtocol::Sha256` and interoperable `Cipher::Aes128`. v2c uses `SyncSession::new_v2c`. v3 uses `SyncSession::new_v3` with `Security::new` plus `with_auth_protocol` and `Auth::AuthPriv`, followed by `init()` to discover engine parameters and localize keys. Authenticated engine-state updates are retried at most twice.

Polling uses a semaphore (default 256 permits) and independent device schedules. Socket work runs on threads with 8 MiB stacks because upstream inline packet buffers and v3 initialization overflow a default Tokio stack in debug builds. A cancelled caller does not release its worker's permit until that bounded socket work actually exits. Socket timeouts and an absolute walk deadline prevent indefinite workers. Credentials are held in memory for the poll and stored encrypted with the same age key as notification secrets. They are not written to logs.

The IF-MIB walk starts at `1.3.6.1.2.1.2.2.1`. 64-bit interface counters come from ifXTable `1.3.6.1.2.1.31.1.1.1`.

`scripts/test-snmp.sh` creates an isolated simulator with random temporary credentials and verifies v2c and v3 SHA-256/AES128 get/walk requests against known interface names and 64-bit counters. It removes its container and credential files afterwards.
