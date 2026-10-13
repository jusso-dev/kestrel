# ADR 0001: Rust agent and server, push model over mTLS

Status: Accepted

## Decision

Agent and server are written in Rust. Agents push to the server over mutually authenticated TLS. The server never connects into agents.

## Reasons

Memory safety for software that runs as a privileged-ish daemon on every host. Push works through NAT and firewalls, needs no inbound ports on hosts, and pairs naturally with an offline buffer. Nagios-style polling of agents is a common source of exposure.
