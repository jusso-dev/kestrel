#!/usr/bin/env python3
"""Official Python OTel SDK acceptance test against an isolated Kestrel stack.

Install requirements-otlp.txt into a venv. Set KESTREL_TEST_DATABASE_URL to the
same disposable database used by the running server. Run with --endpoint and
--ca-file; add --expect-dropped-label user_id when that drop rule is configured.
The test creates an expiring private token and deletes its temporary SQL rows.
Metric samples are tagged with a unique run and remain subject to VM retention.
"""

import argparse
import hashlib
import json
import os
import secrets
import ssl
import time
import urllib.parse
import urllib.request
import uuid

import psycopg
from opentelemetry import metrics
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.metrics import Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="https://127.0.0.1:8443")
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--tenant", default="00000000-0000-0000-0000-000000000001")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--expect-dropped-label")
    args = parser.parse_args()
    if not args.endpoint.startswith("https://") or args.timeout <= 0:
        parser.error("endpoint must use HTTPS and timeout must be positive")
    run, user, token_id = uuid.uuid4().hex, uuid.uuid4(), uuid.uuid4()
    token = "kst_" + secrets.token_urlsafe(32)
    context = ssl.create_default_context(cafile=args.ca_file)
    provider = None
    with psycopg.connect(os.environ["KESTREL_TEST_DATABASE_URL"], autocommit=True) as db:
        try:
            with db.transaction():
                db.execute(
                    "INSERT INTO users(id,tenant_id,email,password_hash,role) VALUES(%s,%s,%s,%s,%s)",
                    (user, args.tenant, run + "@sdk.example.test", "no-password-login", "owner"),
                )
                db.execute(
                    "INSERT INTO api_tokens(id,tenant_id,user_id,name,token_hash,expires_at) "
                    "VALUES(%s,%s,%s,%s,%s,now()+interval '10 minutes')",
                    (token_id, args.tenant, user, "sdk-validation", hashlib.sha256(token.encode()).hexdigest()),
                )
            exporter = OTLPMetricExporter(
                endpoint=args.endpoint.rstrip("/") + "/v1/metrics",
                certificate_file=args.ca_file,
                headers={"Authorization": "Bearer " + token},
            )
            reader = PeriodicExportingMetricReader(exporter, export_interval_millis=60000)
            provider = MeterProvider(metric_readers=[reader])
            metrics.set_meter_provider(provider)
            meter = metrics.get_meter("kestrel-sdk-acceptance")
            attributes = {"demo_run": run, "user_id": "must-be-dropped"}
            meter.create_counter("kestrel_sdk_demo_requests").add(7, attributes)
            meter.create_observable_gauge(
                "kestrel_sdk_demo_temperature", callbacks=[lambda options: [Observation(42, attributes)]]
            )
            meter.create_histogram("kestrel_sdk_demo_duration_seconds").record(0.2, attributes)
            assert provider.force_flush(), "SDK force_flush failed"
            expected = {
                "kestrel_sdk_demo_requests": 7,
                "kestrel_sdk_demo_temperature": 42,
                "kestrel_sdk_demo_duration_seconds_count": 1,
                "kestrel_sdk_demo_duration_seconds_sum": 0.2,
                "kestrel_sdk_demo_duration_seconds_bucket": 1,
            }
            deadline = time.monotonic() + args.timeout
            while expected and time.monotonic() < deadline:
                for name, value in list(expected.items()):
                    query = name + '{demo_run="' + run + '"}'
                    request = urllib.request.Request(
                        args.endpoint.rstrip("/") + "/api/v1/metrics/query?"
                        + urllib.parse.urlencode({"query": query}),
                        headers={"Authorization": "Bearer " + token},
                    )
                    with urllib.request.urlopen(request, context=context, timeout=10) as response:
                        series = json.load(response).get("series", [])
                    if not series:
                        continue
                    assert any(point[1] == value for item in series for point in item["points"]), name
                    if args.expect_dropped_label:
                        assert all(
                            key != args.expect_dropped_label
                            for item in series for key, _ in item["labels"]
                        ), "configured drop rule was not applied"
                    del expected[name]
                if expected:
                    time.sleep(0.25)
            assert not expected, "SDK series never became queryable: " + ", ".join(expected)
            print("Official OTel SDK: authenticated protobuf export and counter/gauge/histogram queries passed")
        finally:
            if provider is not None:
                provider.shutdown()
            with db.transaction():
                db.execute("DELETE FROM api_tokens WHERE id=%s", (token_id,))
                db.execute("DELETE FROM audit_log WHERE user_id=%s", (user,))
                db.execute("DELETE FROM users WHERE id=%s", (user,))


if __name__ == "__main__":
    main()
