#!/bin/sh
# Isolated SNMPv2c and SHA-256/AES128 authPriv acceptance. Fixture passwords
# are random, never printed, and removed with the temporary container/files.
set -eu
umask 077
context=${DOCKER_CONTEXT:-homelab}
bind=${SNMPSIM_BIND_ADDR:-127.0.0.1}
port=${SNMPSIM_PORT:-51161}
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
container=kestrel-snmpsim-$(date +%s)-$$
cleanup() { docker --context "$context" rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$scratch"; }
trap cleanup EXIT HUP INT TERM
export SNMPSIM_ADDR="$bind:$port"
export SNMPSIM_AUTH_FILE="$scratch/auth.json"
python3 - "$context" "$container" "$bind" "$port" "$scratch" <<'PY'
import json, os, secrets, subprocess, sys
context, container, bind, port, scratch = sys.argv[1:]
fixture = dict(addr=f'{bind}:{port}', user='kestrel-test', auth=secrets.token_urlsafe(24), privacy=secrets.token_urlsafe(24))
with open(os.path.join(scratch, 'auth.json'), 'w') as output:
    json.dump(fixture, output)
args = ['docker', '--context', context, 'create', '--name', container, '-p', f'{bind}:{port}:1161/udp', 'tandrup/snmpsim:latest', 'snmpsimd.py', '--process-user=nobody', '--process-group=nogroup', '--logging-method=null', '--cache-dir=/tmp/cache', '--data-dir=/tmp/fixtures', '--agent-udpv4-endpoint=0.0.0.0:1161', '--v3-user='+fixture['user'], '--v3-auth-proto=SHA256', '--v3-auth-key='+fixture['auth'], '--v3-priv-proto=AES128', '--v3-priv-key='+fixture['privacy']]
result = subprocess.run(args, capture_output=True)
if result.returncode:
    raise SystemExit('could not create isolated SNMP simulator')
PY
docker --context "$context" cp "$root/deploy/dev/snmp" "$container:/tmp/fixtures" >/dev/null
# snmp2 uses the standard empty v3 context. snmpsim selects data for that
# context by transport domain; retain `public` for the v2c community fixture.
for transport in 0 1; do
  docker --context "$context" cp "$root/deploy/dev/snmp/public.snmprec" "$container:/tmp/fixtures/1.3.6.1.6.1.1.$transport.snmprec" >/dev/null
done
docker --context "$context" start "$container" >/dev/null
sleep 2
cd "$root"
cargo test -p kestrel-server snmp_walks_snmpsim -- --ignored
cargo test -p kestrel-server snmp_v3_authpriv_snmpsim -- --ignored
