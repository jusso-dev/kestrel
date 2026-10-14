#!/bin/sh
# Download a published agent, check SHA-256 and minisign, install it, and enrol.
# Set KESTREL_URL, KESTREL_SHA256 and KESTREL_TOKEN. Do not embed those values.

set -eu

if [ -z "${KESTREL_URL:-}" ] || [ -z "${KESTREL_SHA256:-}" ] || [ -z "${KESTREL_TOKEN:-}" ]; then
  echo "KESTREL_URL, KESTREL_SHA256 and KESTREL_TOKEN are required" >&2
  exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL "$KESTREL_URL" -o "$tmp"
printf '%s  %s\n' "$KESTREL_SHA256" "$tmp" | sha256sum -c -
if command -v minisign >/dev/null 2>&1 && [ -n "${KESTREL_MINISIGN_PUB:-}" ]; then
  minisign -V -p "$KESTREL_MINISIGN_PUB" -m "$tmp"
fi

install -m 0755 "$tmp" /usr/local/bin/kestrel-agent
install -d -m 0750 /var/lib/kestrel
install -d -m 0755 /etc/kestrel
if ! id kestrel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/kestrel --shell /usr/sbin/nologin kestrel
fi
chown kestrel:kestrel /var/lib/kestrel

cat >/etc/kestrel/agent.toml <<EOF
server_url = "${KESTREL_SERVER_URL:-https://kestrel.example:8443}"
data_dir = "/var/lib/kestrel"
enrol_token = "${KESTREL_TOKEN}"
allow_remote_commands = false
EOF
chmod 0640 /etc/kestrel/agent.toml

echo "Installed. Enrol by starting kestrel-agent once; the token is consumed."
