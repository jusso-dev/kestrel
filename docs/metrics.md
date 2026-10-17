# Metrics

`kestrel_filesystem_used_ratio{mount,device,fstype}` is the fraction of filesystem space unavailable to the agent, between zero and one.

Built-in collectors in `kestrel-checks` emit Prometheus-style series. A name
ending in `_total` is a counter: it only goes up, and the server computes the
rate. Everything else is a gauge. Sample timestamps are the `now_ms` value
passed to `Collector::collect`, not the host clock, so tests can supply a
fake clock.

The default interval is 30 seconds. The first CPU sample after a process
start can be `0` because sysinfo computes usage from the delta between two
refreshes. Collectors do not sleep inside a tick.

Pseudo filesystems `tmpfs`, `overlay`, `squashfs`, `proc` and `sysfs` are
skipped unless the filesystem collector is built with pseudo filesystems
included. Zero-sized mounts are skipped.

## Availability

| Metric | Type | Linux | Windows | macOS |
|---|---|---|---|---|
| `kestrel_cpu_usage_ratio` | gauge | yes | yes | yes |
| `kestrel_memory_used_bytes` | gauge | yes | yes | yes |
| `kestrel_memory_available_bytes` | gauge | yes | yes | yes |
| `kestrel_memory_total_bytes` | gauge | yes | yes | yes |
| `kestrel_swap_used_bytes` | gauge | yes | yes | yes |
| `kestrel_swap_total_bytes` | gauge | yes | yes | yes |
| `kestrel_load1` | gauge | yes | unavailable | yes |
| `kestrel_load5` | gauge | yes | unavailable | yes |
| `kestrel_load15` | gauge | yes | unavailable | yes |
| `kestrel_filesystem_free_bytes` | gauge | yes | yes | yes |
| `kestrel_filesystem_size_bytes` | gauge | yes | yes | yes |
| `kestrel_disk_read_bytes_total` | counter | yes | yes, fixed volumes | unavailable |
| `kestrel_disk_written_bytes_total` | counter | yes | yes, fixed volumes | unavailable |
| `kestrel_network_receive_bytes_total` | counter | yes | yes | yes |
| `kestrel_network_transmit_bytes_total` | counter | yes | yes | yes |
| `kestrel_network_receive_packets_total` | counter | yes | yes | yes |
| `kestrel_network_transmit_packets_total` | counter | yes | yes | yes |
| `kestrel_network_receive_errors_total` | counter | yes | yes | yes |
| `kestrel_network_transmit_errors_total` | counter | yes | yes | yes |
| `kestrel_uptime_seconds` | gauge | yes | yes | yes |
| `kestrel_agent_memory_bytes` | gauge | yes | yes | yes |
| `kestrel_agent_cpu_usage_ratio` | gauge | yes | yes | yes |
| `kestrel_agent_buffer_dropped_total` | counter | yes | yes | yes |
| `kestrel_process_count` | gauge | yes | yes | yes |
| `kestrel_process_cpu_ratio` | gauge | yes | yes | yes |
| `kestrel_process_memory_bytes` | gauge | yes | yes | yes |
| `kestrel_service_up` | gauge | yes, systemd | yes, SCM | yes, launchd |

Load averages are a Unix interface. sysinfo 0.32 does not expose per-disk byte
counters. Linux reads `/proc/diskstats` (the kernel counts 512-byte sectors).
Windows queries `IOCTL_DISK_PERFORMANCE` on each fixed volume. A volume the
process cannot open is skipped. macOS disk IO is unavailable with sysinfo
0.32.

`kestrel_filesystem_free_bytes` is the space still available to unprivileged
writes (`available_space`), not the raw free count that includes root-reserved
blocks.

`kestrel_agent_cpu_usage_ratio` follows sysinfo: `1.0` is 100 percent of one
CPU, so the value can exceed 1 on a busy process.

## CPU

`kestrel_cpu_usage_ratio{cpu}` is a ratio from 0 to 1. `cpu="total"` is the
mean across CPUs. Other values of `cpu` are the zero-based index (`"0"`,
`"1"`, and so on).

## Memory and swap

| Metric | Unit | Labels |
|---|---|---|
| `kestrel_memory_used_bytes` | bytes | none |
| `kestrel_memory_available_bytes` | bytes | none |
| `kestrel_memory_total_bytes` | bytes | none |
| `kestrel_swap_used_bytes` | bytes | none |
| `kestrel_swap_total_bytes` | bytes | none |

## Load

Unix only. `kestrel_load1`, `kestrel_load5` and `kestrel_load15` are the 1, 5
and 15 minute load averages. No labels.

## Filesystem

| Metric | Unit | Labels |
|---|---|---|
| `kestrel_filesystem_free_bytes` | bytes | `mount`, `device`, `fstype` |
| `kestrel_filesystem_size_bytes` | bytes | `mount`, `device`, `fstype` |

Example: `kestrel_filesystem_free_bytes{mount="/",device="sda1",fstype="ext4"}`.
On Windows `mount` looks like `C:\`.

## Disk IO

| Metric | Unit | Labels |
|---|---|---|
| `kestrel_disk_read_bytes_total` | bytes | `device` |
| `kestrel_disk_written_bytes_total` | bytes | `device` |

On Linux, `device` is the name from `/proc/diskstats` for a mounted disk when
that name matches, otherwise the whole-disk devices. On Windows, `device` is
the mount point without a trailing slash, such as `C:`.

## Network

Counters, labelled with `iface` (for example `eth0` or `Ethernet`).

| Metric | Unit |
|---|---|
| `kestrel_network_receive_bytes_total` | bytes |
| `kestrel_network_transmit_bytes_total` | bytes |
| `kestrel_network_receive_packets_total` | packets |
| `kestrel_network_transmit_packets_total` | packets |
| `kestrel_network_receive_errors_total` | errors |
| `kestrel_network_transmit_errors_total` | errors |

Example: `kestrel_network_receive_bytes_total{iface="eth0"}`.

## Uptime

`kestrel_uptime_seconds` is how long the host has been up, in seconds. No labels.

## Agent

| Metric | Unit | Labels |
|---|---|---|
| `kestrel_agent_memory_bytes` | bytes | none |
| `kestrel_agent_cpu_usage_ratio` | ratio | none |
| `kestrel_agent_buffer_dropped_total` | batches | none |

`kestrel_agent_memory_bytes` and `kestrel_agent_cpu_usage_ratio` describe the
process that is running the collectors. `kestrel_agent_buffer_dropped_total`
is an absolute counter of batches discarded because the on-disk buffer was
over `buffer_max_mb`. The shipper stamps the current total onto each flushed
batch. The value is kept in the buffer state file, so a restart does not
zero the counter.

## Processes

`ProcessCollector` is separate from the always-on host collectors. It groups
processes by name and publishes the busiest ones.

| Metric | Unit | Labels |
|---|---|---|
| `kestrel_process_count` | processes | `name` |
| `kestrel_process_cpu_ratio` | ratio | `name`, `pid` |
| `kestrel_process_memory_bytes` | bytes | `name`, `pid` |

`kestrel_process_count` is how many processes share that name. A collector
built with a configured name list also emits `0` when none of them are
running. The CPU and memory series are the top 10 processes on the host, not
only the configured names. `1.0` is 100 percent of one CPU, and the value can
exceed 1. The first CPU sample after a process start can be `0`.

## Services

`kestrel_service_up{name}` is `1` when the named service is running and `0`
when it is stopped or not installed. The collector reads the live state on
every tick, so a stop shows up on the next interval.

| Platform | Source |
|---|---|
| Linux | systemd `ActiveState` of `active`, via the system bus. A name with no dot gets a `.service` suffix. |
| Windows | Service Control Manager state `Running`. |
| macOS | `launchctl print system/<name>` reports `state = running`. |

Windows Event Log and journald are not collected.
