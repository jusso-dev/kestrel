# Triggers

Expressions are PromQL. The evaluator runs at least every 15 seconds. A series becomes a problem after it has been firing for `for` seconds, and it resolves after the recovery expression has been firing for `recover_for` seconds, or when the series disappears.

The tenant label is added by the server. Do not put a tenant matcher in a trigger.

## Examples

1. Disk above 90 percent: `kestrel_filesystem_used_ratio > 0.9`
2. Agent silent for three minutes: `time() - max_over_time(kestrel_agent_last_seen_timestamp[24h]) > 180`
3. Load above 8 (Unix hosts): `kestrel_load1 > 8`
4. Memory above 90 percent: `kestrel_memory_used_bytes / kestrel_memory_total_bytes > 0.9`
5. HTTP check down: `kestrel_http_up == 0`
6. Slow HTTP check: `kestrel_http_duration_seconds > 2`
7. Certificate expiry inside 14 days: `kestrel_tls_cert_expiry_timestamp_seconds - time() < 14 * 24 * 3600`
8. Check critical: `kestrel_check_state == 2`
9. SNMP device down: `snmp_up == 0`
10. Interface down: `snmp_if_oper_status == 2`

A built-in unreachable trigger uses example 2 for every agent.

Wrap gauges that stop reporting in a range function such as `max_over_time(...[24h])`. An instant query only looks back about five minutes, so a bare `kestrel_agent_last_seen_timestamp` disappears before a 180 second delay completes and the problem never opens. With the 24 hour range, a host that stays silent for more than a day drops out of the result and its problem resolves. Remove or disable a host that is gone for good.
