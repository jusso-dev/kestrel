#!/usr/bin/env python3
"""Validate exported synthetic events with the official pinned OCSF service.

Usage: cargo run -p kestrel-server --example ocsf | python3 deploy/tests/validate_ocsf.py
The service receives the supplied events. Use synthetic fixtures for this check.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import urllib.request

BASE = "https://schema.ocsf.io/1.1.0"
ENDPOINT = BASE + "/api/v2/validate"


def request_json(url, event=None):
    data = None if event is None else json.dumps(event).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read(1_048_577)
    if len(body) > 1_048_576:
        raise ValueError("official validator response exceeds 1 MiB")
    return json.loads(body)


def validate(event):
    result = request_json(ENDPOINT, event)
    if not isinstance(result, dict) or not all(
        key in result for key in ("errors", "warnings", "error_count", "warning_count")
    ):
        raise ValueError("unexpected official validator response")
    return {
        "class_uid": event.get("class_uid"),
        "activity_id": event.get("activity_id"),
        "severity_id": event.get("severity_id"),
        "result": result,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", nargs="?", default="-", help="JSON array file, or - for stdin")
    args = parser.parse_args()
    text = sys.stdin.read() if args.events == "-" else Path(args.events).read_text()
    events = json.loads(text)
    if not isinstance(events, list) or not events or not all(isinstance(e, dict) for e in events):
        raise ValueError("expected a nonempty JSON array of synthetic events")
    version = request_json(BASE + "/api/version")
    if version.get("version") != "1.1.0":
        raise ValueError("official service did not report OCSF 1.1.0")
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(validate, events))
    failed = any(
        entry["result"]["errors"] or entry["result"]["warnings"]
        or entry["result"]["error_count"] != 0 or entry["result"]["warning_count"] != 0
        for entry in results
    )
    print(json.dumps({
        "validator": ENDPOINT,
        "schema_version": version["version"],
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "passed": not failed,
        "events": results,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError) as error:
        print(f"OCSF validation failed: {error}", file=sys.stderr)
        sys.exit(1)
