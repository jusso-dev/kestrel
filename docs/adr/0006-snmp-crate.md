# 0006 SNMP crate

SNMP polling uses [`snmp2`](https://crates.io/crates/snmp2) 0.4 with the `v3` feature.

The published 0.4 line does not have a `crypto-rust` feature. v3 authentication and privacy are implemented in that crate with OpenSSL: `AuthProtocol::Sha256` and `Cipher::Aes256`. v2c uses `SyncSession::new_v2c`. v3 uses `SyncSession::new_v3` with `Security::new` plus `with_auth_protocol` and `Auth::AuthPriv`.

Polling runs on a semaphore (default 256 permits). A timed-out poll drops its permit so one device cannot stall the rest. Credentials are held in memory for the poll and stored encrypted with the same age key as notification secrets. They are not written to logs.

The IF-MIB walk starts at `1.3.6.1.2.1.2.2.1`. 64-bit interface counters come from ifXTable `1.3.6.1.2.1.31.1.1.1`.
