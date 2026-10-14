//! Disk read and write counters.
//!
//! Linux reads `/proc/diskstats` (sectors are 512 bytes, per the kernel ABI)
//! and keeps the mounted-disk list from sysinfo. Windows asks each fixed
//! volume for `IOCTL_DISK_PERFORMANCE`. macOS has no equivalent in sysinfo
//! 0.32, so this collector returns no series there.

#[cfg(any(target_os = "linux", windows))]
use crate::metrics::{DISK_READ_BYTES_TOTAL, DISK_WRITTEN_BYTES_TOTAL};
#[cfg(any(target_os = "linux", windows))]
use crate::sample;
use crate::{CollectError, Collector, Sample, DEFAULT_INTERVAL};
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::time::Duration;
use sysinfo::Disks;

pub struct DiskIoCollector {
    disks: Disks,
    interval: Duration,
}

impl DiskIoCollector {
    pub fn new() -> Self {
        Self {
            disks: Disks::new_with_refreshed_list(),
            interval: DEFAULT_INTERVAL,
        }
    }
}

impl Default for DiskIoCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, target_os = "linux"))]
pub(crate) struct DiskStat {
    pub name: String,
    pub read_bytes: u64,
    pub written_bytes: u64,
}

/// Parse Linux `/proc/diskstats`. Loop, ram and floppy devices are dropped.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn parse_diskstats(text: &str) -> Vec<DiskStat> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let name = cols[2];
        if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("fd") {
            continue;
        }
        let read_sectors = cols[5].parse::<u64>().unwrap_or(0);
        let write_sectors = cols[9].parse::<u64>().unwrap_or(0);
        out.push(DiskStat {
            name: name.to_string(),
            read_bytes: read_sectors.saturating_mul(512),
            written_bytes: write_sectors.saturating_mul(512),
        });
    }
    out
}

#[cfg(target_os = "linux")]
fn device_key(name: &str) -> &str {
    name.trim().trim_start_matches("/dev/").trim()
}

impl Collector for DiskIoCollector {
    fn name(&self) -> &str {
        "diskio"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        self.disks.refresh();
        #[cfg(target_os = "linux")]
        {
            self.collect_linux(now_ms)
        }
        #[cfg(windows)]
        {
            self.collect_windows(now_ms)
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = (now_ms, &self.disks);
            Ok(Vec::new())
        }
    }
}

impl DiskIoCollector {
    #[cfg(target_os = "linux")]
    fn collect_linux(&self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        let text = std::fs::read_to_string("/proc/diskstats")
            .map_err(|err| CollectError::new(format!("read /proc/diskstats: {err}")))?;
        let stats = parse_diskstats(&text);
        let mounted: BTreeSet<String> = self
            .disks
            .list()
            .iter()
            .map(|disk| device_key(&disk.name().to_string_lossy()).to_string())
            .collect();
        let matched = stats.iter().any(|stat| mounted.contains(&stat.name));
        let mut samples = Vec::new();
        for stat in &stats {
            if matched && !mounted.contains(&stat.name) {
                continue;
            }
            if !matched && is_partition(&stat.name) {
                continue;
            }
            push_disk(
                &mut samples,
                &stat.name,
                stat.read_bytes,
                stat.written_bytes,
                now_ms,
            );
        }
        Ok(samples)
    }

    #[cfg(windows)]
    fn collect_windows(&self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        let mut samples = Vec::new();
        for disk in self.disks.list() {
            if disk.is_removable() {
                continue;
            }
            let Some((read, written)) = volume_io(disk.mount_point()) else {
                continue;
            };
            let device = disk.mount_point().to_string_lossy();
            let device = device.trim_end_matches(['\\', '/']);
            if device.is_empty() {
                continue;
            }
            push_disk(&mut samples, device, read, written, now_ms);
        }
        Ok(samples)
    }
}

#[cfg(any(target_os = "linux", windows))]
fn push_disk(samples: &mut Vec<Sample>, device: &str, read: u64, written: u64, now_ms: i64) {
    let labels = [("device", device)];
    samples.push(sample(DISK_READ_BYTES_TOTAL, &labels, read as f64, now_ms));
    samples.push(sample(
        DISK_WRITTEN_BYTES_TOTAL,
        &labels,
        written as f64,
        now_ms,
    ));
}

/// Whole-disk names (`sda`, `nvme0n1`) are kept. Partition names are not,
/// when we have to fall back to the raw diskstats list.
#[cfg(any(test, target_os = "linux"))]
fn is_partition(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix("nvme") {
        return rest.contains('p');
    }
    if name.starts_with("mmcblk") {
        return name.contains('p');
    }
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
    base != name
        && (base.starts_with("sd")
            || base.starts_with("vd")
            || base.starts_with("hd")
            || base.starts_with("xvd"))
}

#[cfg(windows)]
fn volume_io(mount: &std::path::Path) -> Option<(u64, u64)> {
    let text = mount.to_string_lossy();
    let letter = text.chars().next()?;
    if !letter.is_ascii_alphabetic() {
        return None;
    }
    let path = format!(r"\\.\{letter}:");
    let mut wide: Vec<u16> =
        std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(&path)).collect();
    wide.push(0);
    unsafe { query_disk_performance(wide.as_ptr()) }
}

#[cfg(windows)]
unsafe fn query_disk_performance(path: *const u16) -> Option<(u64, u64)> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    const OPEN_EXISTING: u32 = 3;
    const IOCTL_DISK_PERFORMANCE: u32 = 0x0007_0020;

    // Zero access is enough for this ioctl and works without elevation.
    // Safety: `path` is a caller-provided null-terminated wide string. The
    // handle is owned and closed by `OwnedHandle`.
    let raw = CreateFileW(
        path,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        std::ptr::null_mut(),
        OPEN_EXISTING,
        0,
        0,
    );
    if raw == -1 {
        return None;
    }
    let handle = OwnedHandle::from_raw_handle(raw as *mut std::ffi::c_void);
    let mut buf = [0u8; 128];
    let mut returned = 0u32;
    let ok = DeviceIoControl(
        handle.as_raw_handle() as isize,
        IOCTL_DISK_PERFORMANCE,
        std::ptr::null(),
        0,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut returned,
        std::ptr::null_mut(),
    );
    if ok == 0 || returned < 16 {
        return None;
    }
    let read = i64::from_le_bytes(buf[0..8].try_into().ok()?);
    let written = i64::from_le_bytes(buf[8..16].try_into().ok()?);
    Some((u64::try_from(read).ok()?, u64::try_from(written).ok()?))
}

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut core::ffi::c_void,
        disposition: u32,
        flags: u32,
        template: isize,
    ) -> isize;
    fn DeviceIoControl(
        handle: isize,
        code: u32,
        input: *const u8,
        input_len: u32,
        output: *mut u8,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diskstats_parser_converts_sectors_and_skips_loop() {
        let text = "\
   8       0 sda 100 0 2000 0 50 0 800 0 0 0 0 0
   8       1 sda1 10 0 100 0 5 0 40 0 0 0 0 0
   7       0 loop0 1 0 8 0 0 0 0 0 0 0 0 0
 259       0 nvme0n1 1 0 4 0 1 0 2 0 0 0 0 0
";
        let stats = parse_diskstats(text);
        assert_eq!(
            stats,
            vec![
                DiskStat {
                    name: "sda".to_string(),
                    read_bytes: 2000 * 512,
                    written_bytes: 800 * 512,
                },
                DiskStat {
                    name: "sda1".to_string(),
                    read_bytes: 100 * 512,
                    written_bytes: 40 * 512,
                },
                DiskStat {
                    name: "nvme0n1".to_string(),
                    read_bytes: 4 * 512,
                    written_bytes: 2 * 512,
                },
            ]
        );
        assert!(is_partition("sda1"));
        assert!(!is_partition("sda"));
        assert!(is_partition("nvme0n1p1"));
        assert!(!is_partition("nvme0n1"));
    }
}
