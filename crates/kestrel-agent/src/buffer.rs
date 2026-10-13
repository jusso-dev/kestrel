//! On-disk segment log for batches that have not been acknowledged.
//!
//! Each segment is `seg-<first-seq:020>.kb`. A frame is a little-endian `u64`
//! sequence, a little-endian `u32` payload length, and the `encode_batch`
//! bytes. Segments roll at 8 MiB. The directory stays within `max_bytes` by
//! dropping the oldest batches and rewriting the segment that held them.
//! Data files are fsynced when a segment rolls and at least once a second
//! while the buffer is dirty, not on every append.

use kestrel_proto::encode_batch;
use kestrel_proto::v1::Batch;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Roll a segment once it reaches this size.
pub const SEGMENT_ROLL_BYTES: u64 = 8 * 1024 * 1024;

const HEADER: u64 = 12;
const STATE_FILE: &str = "state.json";

/// Length-prefixed batches under `dir`, capped at `max_bytes`.
pub struct Buffer {
    pub dir: PathBuf,
    pub max_bytes: u64,
    segment_limit: u64,
    sync_interval: Duration,
    next_seq: u64,
    acked_through: u64,
    dropped: u64,
    segments: Vec<Segment>,
    open: Option<OpenSegment>,
    last_sync: Instant,
    dirty: bool,
    #[cfg(test)]
    syncs: u64,
}

#[derive(Clone, Copy)]
struct Frame {
    seq: u64,
    offset: u64,
    len: u64,
}

struct Segment {
    first_seq: u64,
    path: PathBuf,
    len: u64,
    frames: Vec<Frame>,
}

struct OpenSegment {
    first_seq: u64,
    file: File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Persisted {
    next_seq: u64,
    acked_through: u64,
    dropped: u64,
}

impl Default for Persisted {
    fn default() -> Self {
        Self {
            next_seq: 1,
            acked_through: 0,
            dropped: 0,
        }
    }
}

impl Buffer {
    /// Open or create the segment log in `dir`.
    pub fn open(dir: impl Into<PathBuf>, max_bytes: u64) -> io::Result<Self> {
        Self::open_with(
            dir.into(),
            max_bytes,
            SEGMENT_ROLL_BYTES,
            Duration::from_secs(1),
        )
    }

    fn open_with(
        dir: PathBuf,
        max_bytes: u64,
        segment_limit: u64,
        sync_interval: Duration,
    ) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        recover_partial_rewrites(&dir)?;
        let persisted = load_state(&dir.join(STATE_FILE));
        let mut segments = Vec::new();
        let mut repaired = false;
        let mut paths = segment_paths(&dir)?;
        paths.sort();
        for path in paths {
            let (frames, len, torn) = parse_segment(&path)?;
            if torn {
                repaired = true;
            }
            if frames.is_empty() {
                let _ = fs::remove_file(&path);
                repaired = true;
                continue;
            }
            let first_seq = frames[0].seq;
            segments.push(Segment {
                first_seq,
                path,
                len,
                frames,
            });
        }
        let max_seen = segments
            .iter()
            .flat_map(|segment| segment.frames.iter().map(|frame| frame.seq))
            .max()
            .unwrap_or(0);
        let mut next_seq = persisted.next_seq.max(1);
        if max_seen >= next_seq {
            next_seq = max_seen.saturating_add(1);
        }
        let mut buffer = Self {
            dir,
            max_bytes,
            segment_limit,
            sync_interval,
            next_seq,
            acked_through: persisted.acked_through,
            dropped: persisted.dropped,
            segments,
            open: None,
            last_sync: Instant::now(),
            dirty: repaired,
            #[cfg(test)]
            syncs: 0,
        };
        buffer.drop_fully_acked()?;
        buffer.reopen_tail()?;
        if buffer.stored_bytes() > buffer.max_bytes {
            buffer.enforce_cap()?;
        } else if repaired {
            buffer.sync()?;
        }
        Ok(buffer)
    }

    /// Assign the next sequence, append `batch`, and enforce the size cap.
    pub fn append(&mut self, batch: &Batch) -> io::Result<()> {
        let mut owned = batch.clone();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        owned.seq = seq;
        let payload = encode_batch(&owned);
        let payload_len = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "batch payload exceeds u32")
        })?;
        let frame_len = HEADER + u64::from(payload_len);
        if self.needs_roll(frame_len) {
            self.roll()?;
        }
        if self.open.is_none() {
            self.start_segment(seq)?;
        }
        self.write_frame(seq, &payload)?;
        let dropped_before = self.dropped;
        self.enforce_cap()?;
        if self.dropped > dropped_before {
            tracing::warn!(
                dropped = self.dropped,
                stored_bytes = self.stored_bytes(),
                max_bytes = self.max_bytes,
                "dropped oldest batches to stay within the buffer cap"
            );
        }
        self.dirty = true;
        self.sync_if_due()?;
        Ok(())
    }

    /// The oldest unacknowledged frame, as `(seq, encode_batch bytes)`.
    pub fn peek(&mut self) -> io::Result<Option<(u64, Vec<u8>)>> {
        let Some((first_seq, frame)) = self.head_frame() else {
            return Ok(None);
        };
        let payload = self.read_payload(first_seq, &frame)?;
        Ok(Some((frame.seq, payload)))
    }

    /// Drop the head frame when `seq` matches it.
    ///
    /// A crash before the next fsync leaves the frame in place, so the
    /// shipper sends it again. The server dedupes on `agent_id` and `seq`.
    pub fn ack(&mut self, seq: u64) -> io::Result<()> {
        let Some((_, head)) = self.head_frame() else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "buffer is empty"));
        };
        if head.seq != seq {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ack seq {seq} is not the buffer head {}", head.seq),
            ));
        }
        self.acked_through = seq;
        self.drop_fully_acked()?;
        self.dirty = true;
        self.sync_if_due()?;
        Ok(())
    }

    /// Batches discarded because the log was over [`Self::max_bytes`].
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Bytes currently occupied by segment files.
    pub fn stored_bytes(&self) -> u64 {
        self.segments.iter().map(|segment| segment.len).sum()
    }

    /// Fsync the open segment and the state file.
    pub fn sync(&mut self) -> io::Result<()> {
        if let Some(open) = &self.open {
            open.file.sync_all()?;
        }
        self.write_state()?;
        self.last_sync = Instant::now();
        self.dirty = false;
        #[cfg(test)]
        {
            self.syncs += 1;
        }
        Ok(())
    }

    /// Fsync when the buffer is dirty and the sync interval has elapsed.
    pub fn poll_sync(&mut self) -> io::Result<()> {
        self.sync_if_due()
    }

    fn sync_if_due(&mut self) -> io::Result<()> {
        if self.dirty && self.last_sync.elapsed() >= self.sync_interval {
            self.sync()?;
        }
        Ok(())
    }

    fn needs_roll(&self, frame_len: u64) -> bool {
        let Some(open) = &self.open else {
            return false;
        };
        let Some(segment) = self.segment(open.first_seq) else {
            return false;
        };
        segment.len > 0 && segment.len.saturating_add(frame_len) > self.segment_limit
    }

    fn roll(&mut self) -> io::Result<()> {
        if let Some(open) = self.open.take() {
            open.file.sync_all()?;
        }
        Ok(())
    }

    fn start_segment(&mut self, seq: u64) -> io::Result<()> {
        let path = self.dir.join(format!("seg-{seq:020}.kb"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        self.segments.push(Segment {
            first_seq: seq,
            path,
            len: 0,
            frames: Vec::new(),
        });
        self.open = Some(OpenSegment {
            first_seq: seq,
            file,
        });
        Ok(())
    }

    fn write_frame(&mut self, seq: u64, payload: &[u8]) -> io::Result<()> {
        let first_seq = self
            .open
            .as_ref()
            .map(|open| open.first_seq)
            .ok_or_else(|| io::Error::other("no open segment"))?;
        let offset = self
            .segment(first_seq)
            .map(|segment| segment.len)
            .ok_or_else(|| io::Error::other("open segment is not indexed"))?;
        let header = header_bytes(seq, payload.len());
        let write_result = (|| -> io::Result<()> {
            let open = self
                .open
                .as_mut()
                .ok_or_else(|| io::Error::other("no open segment"))?;
            open.file.seek(SeekFrom::Start(offset))?;
            open.file.write_all(&header)?;
            open.file.write_all(payload)?;
            Ok(())
        })();
        if let Err(err) = write_result {
            if let Some(open) = &self.open {
                let _ = open.file.set_len(offset);
            }
            return Err(err);
        }
        let len = HEADER + payload.len() as u64;
        let segment = self
            .segment_mut(first_seq)
            .ok_or_else(|| io::Error::other("open segment is not indexed"))?;
        segment.frames.push(Frame { seq, offset, len });
        segment.len = offset + len;
        Ok(())
    }

    fn enforce_cap(&mut self) -> io::Result<()> {
        if self.stored_bytes() <= self.max_bytes {
            return Ok(());
        }
        self.compact_acked_prefixes()?;
        while self.stored_bytes() > self.max_bytes {
            let before = self.stored_bytes();
            self.drop_oldest_excess()?;
            if self.stored_bytes() >= before {
                return Err(io::Error::other("buffer remained over its cap"));
            }
        }
        self.sync()?;
        Ok(())
    }

    fn drop_oldest_excess(&mut self) -> io::Result<()> {
        if self.segments.is_empty() {
            return Err(io::Error::other("buffer over cap with no segments"));
        }
        if self.segments[0].frames.is_empty() {
            return self.remove_segment(0);
        }
        let excess = self.stored_bytes().saturating_sub(self.max_bytes);
        let seg_len = self.segments[0].len;
        if seg_len <= excess {
            self.mark_dropped_prefix(0, self.segments[0].frames.len());
            return self.remove_segment(0);
        }
        let count = self.prefix_covering(0, excess).max(1);
        self.mark_dropped_prefix(0, count);
        self.rewrite_keeping(0, count)
    }

    fn prefix_covering(&self, index: usize, excess: u64) -> usize {
        let mut freed = 0u64;
        for (i, frame) in self.segments[index].frames.iter().enumerate() {
            freed += frame.len;
            if freed >= excess {
                return i + 1;
            }
        }
        self.segments[index].frames.len()
    }

    fn mark_dropped_prefix(&mut self, index: usize, count: usize) {
        let count = count.min(self.segments[index].frames.len());
        for frame in &self.segments[index].frames[..count] {
            if frame.seq > self.acked_through {
                self.dropped += 1;
            }
            self.acked_through = self.acked_through.max(frame.seq);
        }
    }

    fn compact_acked_prefixes(&mut self) -> io::Result<()> {
        while let Some(segment) = self.segments.first() {
            let keep = segment
                .frames
                .iter()
                .position(|frame| frame.seq > self.acked_through)
                .unwrap_or(segment.frames.len());
            if keep == 0 {
                break;
            }
            if keep >= segment.frames.len() {
                self.remove_segment(0)?;
                continue;
            }
            self.rewrite_keeping(0, keep)?;
            break;
        }
        Ok(())
    }

    fn drop_fully_acked(&mut self) -> io::Result<()> {
        while self.segments.first().is_some_and(|segment| {
            segment
                .frames
                .iter()
                .all(|frame| frame.seq <= self.acked_through)
        }) {
            self.remove_segment(0)?;
        }
        Ok(())
    }

    fn rewrite_keeping(&mut self, index: usize, keep_from: usize) -> io::Result<()> {
        if keep_from == 0 {
            return Ok(());
        }
        if keep_from >= self.segments[index].frames.len() {
            return self.remove_segment(index);
        }
        let first_seq = self.segments[index].first_seq;
        let frames = self.segments[index].frames[keep_from..].to_vec();
        let mut kept = Vec::new();
        for frame in frames {
            let payload = self.read_payload(first_seq, &frame)?;
            kept.push((frame.seq, payload));
        }
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.first_seq == first_seq)
        {
            self.open = None;
        }
        let path = self.segments[index].path.clone();
        let new_path = path.with_extension("kb.new");
        let mut new_frames = Vec::new();
        let mut offset = 0u64;
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&new_path)?;
            for (seq, payload) in &kept {
                let header = header_bytes(*seq, payload.len());
                file.write_all(&header)?;
                file.write_all(payload)?;
                let len = HEADER + payload.len() as u64;
                new_frames.push(Frame {
                    seq: *seq,
                    offset,
                    len,
                });
                offset += len;
            }
            file.sync_all()?;
        }
        fs::remove_file(&path)?;
        fs::rename(&new_path, &path)?;
        self.segments[index].frames = new_frames;
        self.segments[index].len = offset;
        if index + 1 == self.segments.len() && offset < self.segment_limit {
            self.reopen_tail()?;
        }
        Ok(())
    }

    fn remove_segment(&mut self, index: usize) -> io::Result<()> {
        let segment = self.segments.remove(index);
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.first_seq == segment.first_seq)
        {
            self.open = None;
        }
        match fs::remove_file(&segment.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn reopen_tail(&mut self) -> io::Result<()> {
        if self.open.is_some() {
            return Ok(());
        }
        let Some(segment) = self.segments.last() else {
            return Ok(());
        };
        if segment.len >= self.segment_limit {
            return Ok(());
        }
        let first_seq = segment.first_seq;
        let path = segment.path.clone();
        let len = segment.len;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.seek(SeekFrom::Start(len))?;
        self.open = Some(OpenSegment { first_seq, file });
        Ok(())
    }

    fn head_frame(&self) -> Option<(u64, Frame)> {
        for segment in &self.segments {
            for frame in &segment.frames {
                if frame.seq > self.acked_through {
                    return Some((segment.first_seq, *frame));
                }
            }
        }
        None
    }

    fn read_payload(&mut self, first_seq: u64, frame: &Frame) -> io::Result<Vec<u8>> {
        let start = frame.offset + HEADER;
        let len = usize::try_from(frame.len.saturating_sub(HEADER))
            .map_err(|_| io::Error::other("frame exceeds address space"))?;
        self.read_at(first_seq, start, len)
    }

    fn read_at(&mut self, first_seq: u64, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.with_file_mut(first_seq, |file| read_exact_at(file, offset, len))
    }

    fn with_file_mut<T>(
        &mut self,
        first_seq: u64,
        f: impl FnOnce(&mut File) -> io::Result<T>,
    ) -> io::Result<T> {
        if self
            .open
            .as_ref()
            .is_some_and(|open| open.first_seq == first_seq)
        {
            let open = self
                .open
                .as_mut()
                .ok_or_else(|| io::Error::other("open segment disappeared"))?;
            return f(&mut open.file);
        }
        let path = self
            .segment(first_seq)
            .map(|segment| segment.path.clone())
            .ok_or_else(|| io::Error::other("segment missing"))?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        f(&mut file)
    }

    fn segment(&self, first_seq: u64) -> Option<&Segment> {
        self.segments
            .iter()
            .find(|segment| segment.first_seq == first_seq)
    }

    fn segment_mut(&mut self, first_seq: u64) -> Option<&mut Segment> {
        self.segments
            .iter_mut()
            .find(|segment| segment.first_seq == first_seq)
    }

    fn write_state(&self) -> io::Result<()> {
        let persisted = Persisted {
            next_seq: self.next_seq,
            acked_through: self.acked_through,
            dropped: self.dropped,
        };
        let mut bytes = serde_json::to_vec(&persisted)
            .map_err(|err| io::Error::other(format!("buffer state: {err}")))?;
        bytes.push(b'\n');
        write_atomic(&self.dir.join(STATE_FILE), &bytes)
    }

    #[cfg(test)]
    pub(crate) fn pending_seqs(&self) -> Vec<u64> {
        self.segments
            .iter()
            .flat_map(|segment| segment.frames.iter().map(|frame| frame.seq))
            .filter(|seq| *seq > self.acked_through)
            .collect()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let _ = self.sync();
    }
}

fn header_bytes(seq: u64, payload_len: usize) -> [u8; HEADER as usize] {
    let mut header = [0u8; HEADER as usize];
    header[..8].copy_from_slice(&seq.to_le_bytes());
    let len = u32::try_from(payload_len).unwrap_or(u32::MAX);
    header[8..].copy_from_slice(&len.to_le_bytes());
    header
}

fn read_exact_at(file: &mut File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn parse_segment(path: &Path) -> io::Result<(Vec<Frame>, u64, bool)> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let file_len = file.metadata()?.len();
    let mut frames = Vec::new();
    let mut offset = 0u64;
    loop {
        if offset.saturating_add(HEADER) > file_len {
            break;
        }
        let header = read_exact_at(&mut file, offset, HEADER as usize)?;
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&header[..8]);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&header[8..]);
        let seq = u64::from_le_bytes(seq_bytes);
        let payload_len = u64::from(u32::from_le_bytes(len_bytes));
        let Some(total) = HEADER.checked_add(payload_len) else {
            break;
        };
        let Some(end) = offset.checked_add(total) else {
            break;
        };
        if end > file_len {
            break;
        }
        frames.push(Frame {
            seq,
            offset,
            len: total,
        });
        offset = end;
    }
    let torn = offset < file_len;
    if torn {
        file.set_len(offset)?;
        file.sync_all()?;
    }
    Ok((frames, offset, torn))
}

fn segment_paths(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("seg-") && name.ends_with(".kb") && !name.ends_with(".kb.new") {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

fn recover_partial_rewrites(dir: &Path) -> io::Result<()> {
    let mut partials = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        if let Some(stem) = name.strip_suffix(".kb.new") {
            partials.push((entry.path(), dir.join(format!("{stem}.kb"))));
        }
    }
    for (partial, dest) in partials {
        if dest.exists() {
            let _ = fs::remove_file(&partial);
        } else {
            fs::rename(&partial, &dest)?;
        }
    }
    Ok(())
}

fn load_state(path: &Path) -> Persisted {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Persisted::default(),
        Err(err) => {
            tracing::warn!(error = %err, "ignoring unreadable buffer state");
            return Persisted::default();
        }
    };
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        tracing::warn!(error = %err, "ignoring unreadable buffer state");
        Persisted::default()
    })
}

fn write_atomic(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = dest.with_extension("json.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match fs::rename(&tmp, dest) {
        Ok(()) => Ok(()),
        Err(err) => {
            if dest.exists() {
                fs::remove_file(dest)?;
                fs::rename(&tmp, dest)
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_proto::{decode_batch, v1, DEFAULT_MAX_DECOMPRESSED};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("kestrel-buffer-{label}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn batch(note: &str) -> v1::Batch {
        v1::Batch {
            agent_id: "agent-test".to_string(),
            seq: 0,
            samples: vec![v1::Sample {
                name: "kestrel_uptime_seconds".to_string(),
                labels: vec![],
                value: 1.0,
                timestamp_ms: 1,
            }],
            checks: vec![],
            logs: vec![v1::LogEvent {
                source: "test".to_string(),
                line: note.to_string(),
                timestamp_ms: 1,
                labels: vec![],
            }],
            inventory: None,
        }
    }

    fn decode_note(bytes: &[u8]) -> String {
        let decoded = decode_batch(bytes, DEFAULT_MAX_DECOMPRESSED).unwrap();
        decoded.logs[0].line.clone()
    }

    #[test]
    fn buffer_restart_keeps_unshipped_batches_in_order() {
        let dir = TempDir(scratch("restart"));
        {
            let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
            buffer.append(&batch("one")).unwrap();
            buffer.append(&batch("two")).unwrap();
            buffer.append(&batch("three")).unwrap();
            let (seq, bytes) = buffer.peek().unwrap().unwrap();
            assert_eq!(seq, 1);
            assert_eq!(decode_note(&bytes), "one");
            buffer.ack(1).unwrap();
        }
        let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
        let mut notes = Vec::new();
        while let Some((seq, bytes)) = buffer.peek().unwrap() {
            notes.push((seq, decode_note(&bytes)));
            buffer.ack(seq).unwrap();
        }
        assert_eq!(
            notes,
            vec![(2, "two".to_string()), (3, "three".to_string())]
        );
        assert!(buffer.peek().unwrap().is_none());
    }

    #[test]
    fn buffer_restart_without_ack_keeps_every_batch() {
        let dir = TempDir(scratch("noack"));
        {
            let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
            buffer.append(&batch("one")).unwrap();
            buffer.append(&batch("two")).unwrap();
        }
        let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
        assert_eq!(buffer.pending_seqs(), vec![1, 2]);
        let mut seqs = Vec::new();
        while let Some((seq, _)) = buffer.peek().unwrap() {
            seqs.push(seq);
            buffer.ack(seq).unwrap();
        }
        assert_eq!(seqs, vec![1, 2]);
    }

    #[test]
    fn buffer_overflow_drops_oldest_and_stays_within_cap() {
        let dir = TempDir(scratch("overflow"));
        let max_bytes = 2_048;
        let mut buffer = Buffer::open(&dir.0, max_bytes).unwrap();
        for i in 0..40 {
            let note = format!("{i:04}-{}", "k".repeat(180));
            buffer.append(&batch(&note)).unwrap();
            assert!(
                buffer.stored_bytes() <= max_bytes,
                "stored {} after append {i}",
                buffer.stored_bytes()
            );
        }
        assert!(
            buffer.dropped() > 0,
            "expected the cap to drop oldest batches"
        );
        let seqs = buffer.pending_seqs();
        assert!(!seqs.is_empty());
        assert!(seqs[0] > 1, "the oldest batch should have been dropped");
        assert_eq!(*seqs.last().unwrap(), 40);
        assert!(seqs.windows(2).all(|pair| pair[1] == pair[0] + 1));
        drop(buffer);
        let buffer = Buffer::open(&dir.0, max_bytes).unwrap();
        assert!(buffer.stored_bytes() <= max_bytes);
        assert!(buffer.dropped() > 0);
        assert_eq!(buffer.pending_seqs().last().copied(), Some(40));
    }

    #[test]
    fn buffer_drops_a_frame_larger_than_the_cap() {
        let dir = TempDir(scratch("huge"));
        let mut buffer = Buffer::open(&dir.0, 1).unwrap();
        buffer.append(&batch("too-big")).unwrap();
        assert_eq!(buffer.stored_bytes(), 0);
        assert!(buffer.dropped() >= 1);
        assert!(buffer.peek().unwrap().is_none());
    }

    #[test]
    fn buffer_truncates_a_torn_tail() {
        let dir = TempDir(scratch("torn"));
        let path = {
            let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
            buffer.append(&batch("kept")).unwrap();
            buffer.sync().unwrap();
            segment_paths(&dir.0).unwrap().into_iter().next().unwrap()
        };
        let complete = fs::metadata(&path).unwrap().len();
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[1, 2, 3, 4, 5]).unwrap();
        }
        let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
        let (seq, bytes) = buffer.peek().unwrap().unwrap();
        assert_eq!(seq, 1);
        assert_eq!(decode_note(&bytes), "kept");
        assert_eq!(fs::metadata(&path).unwrap().len(), complete);
    }

    #[test]
    fn buffer_does_not_fsync_every_append() {
        let dir = TempDir(scratch("sync"));
        let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
        buffer.sync_interval = Duration::from_secs(3600);
        let before = buffer.syncs;
        buffer.append(&batch("a")).unwrap();
        buffer.append(&batch("b")).unwrap();
        assert_eq!(buffer.syncs, before);
        buffer.sync_interval = Duration::ZERO;
        buffer.append(&batch("c")).unwrap();
        assert!(buffer.syncs > before);
    }

    #[test]
    fn buffer_rolls_segments() {
        let dir = TempDir(scratch("roll"));
        let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
        buffer.segment_limit = 400;
        for i in 0..12 {
            buffer
                .append(&batch(&format!("{i:02}-{}", "m".repeat(80))))
                .unwrap();
        }
        let files = segment_paths(&dir.0).unwrap();
        assert!(files.len() >= 2, "expected a roll, found {}", files.len());
    }

    #[test]
    fn buffer_rejects_ack_that_is_not_the_head() {
        let dir = TempDir(scratch("ack"));
        let mut buffer = Buffer::open(&dir.0, 8 * 1024 * 1024).unwrap();
        buffer.append(&batch("one")).unwrap();
        buffer.append(&batch("two")).unwrap();
        assert!(buffer.ack(2).is_err());
        assert_eq!(buffer.pending_seqs(), vec![1, 2]);
    }
}
