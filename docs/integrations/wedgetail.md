# Wedgetail

Kestrel forwards events outbound to an operator-configured Wedgetail push ingest URL. It does not open a listener for Wedgetail.

The request matches Wedgetail's push ingest:

- `POST {base}/v1/{stream}`
- `Authorization: Bearer wgi_<keyId>_<secret>`
- Body is NDJSON. One JSON object per line. A JSON array is also accepted by Wedgetail.

Problem events use OCSF Detection Finding, class uid 2004. API writes use OCSF API Activity, class uid 6003. Delivery failures are retried on `forward_jobs` and do not block the notifier.

Configure the URL and bearer token in the forwarder settings. Tests use a local fake and never call a real Wedgetail deployment.

Example:

```json
{"class_uid":2004,"class_name":"Detection Finding","finding_info":{"title":"Disk space is low"}}
```
