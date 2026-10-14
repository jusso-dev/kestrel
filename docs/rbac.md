# Roles

Every API route declares one of `Public`, `Agent` (mutual TLS), or `User(permission)`. A route without an entry in that table is a compile failure of the router.

| Permission | owner | admin | operator | viewer |
| --- | --- | --- | --- | --- |
| Read APIs (hosts, problems, metrics, audit, templates, maintenance) | yes | yes | yes | yes |
| Acknowledge a problem, write a dashboard, write OTLP | yes | yes | yes | no |
| Change hosts, triggers, users, media, templates | yes | yes | no | no |
| Tenant administration and MSP grants | yes | no | no | no |

`owner` and `admin` see every host group in the tenant. `operator` and `viewer` may be limited to one host group. Scoped metric queries add `host=~"a|b"` on the server. The client cannot set `tenant`; the proxy replaces any client `tenant` matcher with the session tenant.

A viewer calling a write route receives 403. A missing session receives 401.
