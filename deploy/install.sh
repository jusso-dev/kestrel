#!/bin/sh
# Install a Linux release. Obtain the checksum from a trusted release channel.
set -eu
umask 077
die() { echo "kestrel installer: $*" >&2; exit 1; }
usage() { echo 'Usage: install.sh --token TOKEN --server https://SERVER --url https://RELEASE --sha256 SHA256 [--ca-file FILE] [--signature-url URL --minisign-pub FILE] [--no-start]'; }
token=${KESTREL_TOKEN:-}
server=${KESTREL_SERVER_URL:-}
url=${KESTREL_URL:-}
sha256=${KESTREL_SHA256:-}
signature_url=${KESTREL_SIGNATURE_URL:-}
pubkey=${KESTREL_MINISIGN_PUB:-}
ca_file=${KESTREL_CA_FILE:-}
start=true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --no-start) start=false; shift ;;
    --token|--server|--url|--sha256|--signature-url|--minisign-pub|--ca-file)
      [ "$#" -ge 2 ] || die "missing value for $1"
      case "$1" in
        --token) token=$2 ;; --server) server=$2 ;; --url) url=$2 ;;
        --sha256) sha256=$2 ;; --signature-url) signature_url=$2 ;;
        --minisign-pub) pubkey=$2 ;;
        --ca-file) ca_file=$2 ;;
      esac
      shift 2 ;;
    *) die 'unknown argument; use --help' ;;
  esac
done
[ "$(uname -s)" = Linux ] || die 'use the signed macOS pkg or Windows MSI on this platform'
[ "$(id -u)" -eq 0 ] || die 'run as root'
[ -n "$token" ] || die '--token is required'
# Refuse TOML control characters and delimiters before writing credentials.
case "$token$server" in *[![:print:]]*|*'"'*|*\\*) die 'token/server contains invalid configuration characters' ;; esac
case "$server" in https://?*) ;; *) die '--server must be an HTTPS URL' ;; esac
case "$url" in https://?*) ;; *) die '--url must be an HTTPS URL' ;; esac
[ "${#sha256}" -eq 64 ] || die '--sha256 must contain 64 hexadecimal characters'
case "$sha256" in *[!0-9a-fA-F]*) die 'invalid SHA-256' ;; esac
[ -z "$ca_file" ] || [ -f "$ca_file" ] || die '--ca-file must name the trusted server CA certificate'
if [ -n "$pubkey$signature_url" ]; then
  [ -n "$pubkey" ] && [ -f "$pubkey" ] || die '--minisign-pub must name a public key file'
  case "$signature_url" in https://?*) ;; *) die '--signature-url must be HTTPS' ;; esac
  command -v minisign >/dev/null 2>&1 || die 'minisign is required for signature verification'
fi
for tool in curl sha256sum install useradd getent; do
  command -v "$tool" >/dev/null 2>&1 || die "required command missing: $tool"
done
if "$start"; then
  command -v systemctl >/dev/null 2>&1 || die 'systemd is required; use --no-start for manual startup'
fi
[ ! -e /etc/kestrel/agent.toml ] || die 'agent.toml already exists; preserve the enrolment identity when upgrading'
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl --proto '=https' --proto-redir '=https' -fsSL "$url" -o "$tmp/kestrel-agent"
printf '%s  %s\n' "$sha256" "$tmp/kestrel-agent" | sha256sum -c - >/dev/null
if [ -n "$pubkey" ]; then
  curl --proto '=https' --proto-redir '=https' -fsSL "$signature_url" -o "$tmp/kestrel-agent.minisig"
  minisign -V -p "$pubkey" -m "$tmp/kestrel-agent" -x "$tmp/kestrel-agent.minisig"
fi
if ! id kestrel >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/kestrel --shell /usr/sbin/nologin kestrel
fi
getent group kestrel >/dev/null || die 'the kestrel account must have a kestrel group'
install -d -m 0750 -o kestrel -g kestrel /var/lib/kestrel
install -d -m 0750 -o root -g kestrel /etc/kestrel
install -m 0755 "$tmp/kestrel-agent" /usr/local/bin/kestrel-agent
cat >"$tmp/agent.toml" <<EOF
server_url = "$server"
data_dir = "/var/lib/kestrel"
enrol_token = "$token"
allow_remote_commands = false
EOF
install -m 0640 -o root -g kestrel "$tmp/agent.toml" /etc/kestrel/agent.toml
if [ -n "$ca_file" ]; then
  install -m 0640 -o root -g kestrel "$ca_file" /etc/kestrel/bootstrap-ca.crt
  printf '\nbootstrap_ca_path = "/etc/kestrel/bootstrap-ca.crt"\n' >> /etc/kestrel/agent.toml
fi
install -d -m 0755 /etc/systemd/system
cat > /etc/systemd/system/kestrel-agent.service <<'EOF'
[Unit]
Description=Kestrel monitoring agent
Wants=network-online.target
After=network-online.target

[Service]
User=kestrel
Group=kestrel
ExecStart=/usr/local/bin/kestrel-agent --config /etc/kestrel/agent.toml
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/kestrel

[Install]
WantedBy=multi-user.target
EOF
if "$start"; then
  systemctl daemon-reload
  systemctl enable --now kestrel-agent.service
  systemctl is-active --quiet kestrel-agent.service
  echo 'Installed and started kestrel-agent. Enrolment occurs on first connection.'
else
  echo 'Installed kestrel-agent. Start the service to enrol.'
fi
