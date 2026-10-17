//! Mounted filesystem capacity. Pseudo filesystems are skipped unless asked for.

use crate::metrics::{FILESYSTEM_FREE_BYTES, FILESYSTEM_SIZE_BYTES, FILESYSTEM_USED_RATIO};
use crate::{sample, CollectError, Collector, Sample, DEFAULT_INTERVAL};
use std::time::{Duration, Instant};
use sysinfo::Disks;

const PSEUDO_FS: &[&str] = &["tmpfs", "overlay", "squashfs", "proc", "sysfs"];

pub struct FilesystemCollector {
    disks: Disks,
    include_pseudo: bool,
    interval: Duration,
    last_discovery: Instant,
}

impl FilesystemCollector {
    pub fn new() -> Self {
        Self::with_pseudo(false)
    }

    pub fn with_pseudo(include_pseudo: bool) -> Self {
        Self {
            disks: Disks::new_with_refreshed_list(),
            include_pseudo,
            interval: DEFAULT_INTERVAL,
            last_discovery: Instant::now(),
        }
    }
}

impl Default for FilesystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// `true` when this filesystem type should be reported.
pub fn include_filesystem(fs_type: &str, include_pseudo: bool) -> bool {
    if include_pseudo {
        return true;
    }
    !PSEUDO_FS
        .iter()
        .any(|pseudo| fs_type.eq_ignore_ascii_case(pseudo))
}

impl Collector for FilesystemCollector {
    fn name(&self) -> &str {
        "filesystem"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn collect(&mut self, now_ms: i64) -> Result<Vec<Sample>, CollectError> {
        // Mount discovery can be expensive (especially with network mounts).
        // Keep the normal metric tick cheap while detecting hotplug within a minute.
        if self.last_discovery.elapsed() >= Duration::from_secs(60) {
            self.disks.refresh_list();
            self.last_discovery = Instant::now();
        }
        self.disks.refresh();
        let mut samples = Vec::new();
        for disk in self.disks.list() {
            let fs_type = disk.file_system().to_string_lossy();
            if !include_filesystem(&fs_type, self.include_pseudo) {
                continue;
            }
            let size = disk.total_space();
            if size == 0 {
                continue;
            }
            let mount = disk.mount_point().to_string_lossy();
            if mount.is_empty() {
                continue;
            }
            let device = disk.name().to_string_lossy();
            let labels = [
                ("mount", mount.as_ref()),
                ("device", device.as_ref()),
                ("fstype", fs_type.as_ref()),
            ];
            samples.push(sample(
                FILESYSTEM_FREE_BYTES,
                &labels,
                disk.available_space() as f64,
                now_ms,
            ));
            samples.push(sample(FILESYSTEM_SIZE_BYTES, &labels, size as f64, now_ms));
            samples.push(sample(
                FILESYSTEM_USED_RATIO,
                &labels,
                1.0 - disk.available_space().min(size) as f64 / size as f64,
                now_ms,
            ));
        }
        Ok(samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_filesystems_are_skipped_unless_configured() {
        for fs in ["tmpfs", "TMPFS", "overlay", "squashfs", "proc", "sysfs"] {
            assert!(!include_filesystem(fs, false), "{fs}");
            assert!(include_filesystem(fs, true), "{fs}");
        }
        assert!(include_filesystem("ext4", false));
        assert!(include_filesystem("NTFS", false));
        assert!(include_filesystem("apfs", false));
    }
}
