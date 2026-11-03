//! Tail configured log files.
//!
//! Rotation is an inode change or a shrink. Offsets live in
//! `data_dir/log_offsets.json` so a restart does not send the same lines
//! again. One tick returns at most 1000 lines, and each line is capped at
//! 8 KiB. A partial line at the live end of the file is held until a newline
//! arrives. A line longer than the cap is emitted as soon as the cap is
//! reached and the remainder is skipped, at most
//! [`MAX_LOG_SKIP_BYTES_PER_TICK`] bytes per tick, so an unterminated huge
//! line is never rescanned. Windows Event Log and journald are out of scope.

use kestrel_proto::v1::LogEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Lines returned from one [`LogTailer::poll`].
pub const MAX_LOG_LINES_PER_TICK: usize = 1000;
/// Bytes kept from one line. The rest of the line is discarded.
pub const MAX_LOG_LINE_BYTES: usize = 8 * 1024;
/// Bytes of an over-long line's remainder discarded in one tick.
pub const MAX_LOG_SKIP_BYTES_PER_TICK: u64 = 1024 * 1024;

const OFFSETS_FILE: &str = "log_offsets.json";

pub struct LogTailer {
    pub path: PathBuf,
    pub pattern: Option<Regex>,
    pub offset: u64,
    pub inode: u64,
    file: Option<File>,
    /// `true` once `offset` and `inode` came from a checkpoint or a poll.
    checkpoint: bool,
    max_lines: usize,
    /// `true` while discarding the rest of a line already emitted truncated.
    /// Not persisted: after a restart the remainder is read as a new line.
    skipping: bool,
}

#[derive(Debug)]
pub enum LogError {
    Io(std::io::Error),
    Pattern(String),
    Offset(String),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Pattern(err) => write!(f, "log pattern: {err}"),
            Self::Offset(err) => write!(f, "log offsets: {err}"),
        }
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Pattern(_) | Self::Offset(_) => None,
        }
    }
}

impl From<std::io::Error> for LogError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// One saved tail position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogOffset {
    pub path: String,
    pub offset: u64,
    pub inode: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct OffsetFile {
    files: Vec<LogOffset>,
}

impl LogTailer {
    pub fn open(path: impl Into<PathBuf>, pattern: Option<&str>) -> Result<Self, LogError> {
        Ok(Self {
            path: path.into(),
            pattern: compile_pattern(pattern)?,
            offset: 0,
            inode: 0,
            file: None,
            checkpoint: false,
            max_lines: MAX_LOG_LINES_PER_TICK,
            skipping: false,
        })
    }

    /// Continue a tail after a restart. When the file identity no longer
    /// matches, the next poll starts at the beginning of the replacement.
    pub fn restore(
        path: impl Into<PathBuf>,
        pattern: Option<&str>,
        offset: u64,
        inode: u64,
    ) -> Result<Self, LogError> {
        let mut tailer = Self::open(path, pattern)?;
        tailer.offset = offset;
        tailer.inode = inode;
        tailer.checkpoint = true;
        Ok(tailer)
    }

    #[cfg(test)]
    pub(crate) fn set_max_lines(&mut self, max_lines: usize) {
        self.max_lines = max_lines;
    }

    pub fn apply_saved_offsets(&mut self, saved: &[LogOffset]) {
        let key = path_key(&self.path);
        if let Some(found) = saved.iter().find(|row| row.path == key) {
            self.offset = found.offset;
            self.inode = found.inode;
            self.checkpoint = true;
            self.file = None;
            self.skipping = false;
        }
    }

    /// Read new matching lines. The returned events share `now_ms`.
    pub fn poll(&mut self, now_ms: i64) -> Result<Vec<LogEvent>, LogError> {
        let mut events = Vec::new();
        let source = path_key(&self.path);
        let mut remaining = self.max_lines;
        loop {
            if remaining == 0 {
                break;
            }
            if self.file.is_none() {
                match self.open_current()? {
                    Opened::Missing => break,
                    Opened::Ready => {}
                }
            }
            if self.path_was_rotated()? {
                let outcome = self.read_open(remaining, now_ms, &source, true, &mut events)?;
                remaining = remaining.saturating_sub(outcome.lines);
                if outcome.stop == ReadStop::Cap {
                    break;
                }
                let path_gone = self.path_is_missing()?;
                self.file = None;
                self.offset = 0;
                self.inode = 0;
                self.checkpoint = false;
                self.skipping = false;
                if path_gone {
                    break;
                }
                continue;
            }
            self.rewind_if_truncated()?;
            let _outcome = self.read_open(remaining, now_ms, &source, false, &mut events)?;
            break;
        }
        Ok(events)
    }

    fn open_current(&mut self) -> Result<Opened, LogError> {
        let mut file = match open_shared(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Opened::Missing),
            Err(err) => return Err(err.into()),
        };
        let id = file_id(&file)?;
        let len = file.metadata()?.len();
        if self.checkpoint && self.inode == id {
            if len < self.offset {
                self.offset = 0;
                self.skipping = false;
            }
        } else {
            self.offset = 0;
            self.inode = id;
            self.skipping = false;
        }
        self.checkpoint = true;
        file.seek(SeekFrom::Start(self.offset))?;
        self.file = Some(file);
        Ok(Opened::Ready)
    }

    fn path_was_rotated(&self) -> Result<bool, LogError> {
        let Some(file) = self.file.as_ref() else {
            return Ok(false);
        };
        let open_id = file_id(file)?;
        match file_id_of_path(&self.path) {
            Ok(path_id) => Ok(path_id != open_id),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(err) => Err(err.into()),
        }
    }

    fn path_is_missing(&self) -> Result<bool, LogError> {
        match file_id_of_path(&self.path) {
            Ok(_) => Ok(false),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(err) => Err(err.into()),
        }
    }

    fn rewind_if_truncated(&mut self) -> Result<(), LogError> {
        let Some(file) = self.file.as_ref() else {
            return Ok(());
        };
        if file.metadata()?.len() < self.offset {
            self.offset = 0;
            self.skipping = false;
        }
        Ok(())
    }

    fn read_open(
        &mut self,
        max_lines: usize,
        now_ms: i64,
        source: &str,
        emit_partial: bool,
        events: &mut Vec<LogEvent>,
    ) -> Result<ReadOutcome, LogError> {
        let pattern = self.pattern.clone();
        let file = self.file.as_mut().expect("read_open requires an open file");
        read_new_lines(
            file,
            &mut self.offset,
            &mut self.skipping,
            pattern.as_ref(),
            source,
            ReadLimits {
                max_lines,
                now_ms,
                emit_partial,
            },
            events,
        )
        .map_err(LogError::from)
    }
}

enum Opened {
    Ready,
    Missing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadStop {
    Eof,
    Cap,
}

struct ReadOutcome {
    stop: ReadStop,
    lines: usize,
}

struct ReadLimits {
    max_lines: usize,
    now_ms: i64,
    emit_partial: bool,
}

struct RawLine {
    bytes: Vec<u8>,
    consumed: u64,
    partial: bool,
    /// The line is longer than the cap and its remainder is still unread.
    oversized: bool,
}

fn compile_pattern(pattern: Option<&str>) -> Result<Option<Regex>, LogError> {
    match pattern {
        None | Some("") => Ok(None),
        Some(pattern) => Regex::new(pattern)
            .map(Some)
            .map_err(|err| LogError::Pattern(err.to_string())),
    }
}

pub fn path_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Load `data_dir/log_offsets.json`. A missing file is an empty checkpoint.
pub fn load_log_offsets(data_dir: &Path) -> Result<Vec<LogOffset>, LogError> {
    let path = data_dir.join(OFFSETS_FILE);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let parsed: OffsetFile = serde_json::from_str(&text)
        .map_err(|err| LogError::Offset(format!("could not parse {}: {err}", path.display())))?;
    Ok(parsed.files)
}

/// Write `data_dir/log_offsets.json` from the tailers' current positions.
pub fn save_log_offsets(data_dir: &Path, tailers: &[LogTailer]) -> Result<(), LogError> {
    std::fs::create_dir_all(data_dir)?;
    let mut files = Vec::new();
    for tailer in tailers {
        let path = path_key(&tailer.path);
        let row = LogOffset {
            path,
            offset: tailer.offset,
            inode: tailer.inode,
        };
        if let Some(existing) = files
            .iter_mut()
            .find(|saved: &&mut LogOffset| saved.path == row.path)
        {
            *existing = row;
        } else {
            files.push(row);
        }
    }
    let mut body = serde_json::to_vec_pretty(&OffsetFile { files })
        .map_err(|err| LogError::Offset(err.to_string()))?;
    body.push(b'\n');
    let dest = data_dir.join(OFFSETS_FILE);
    write_atomic(&dest, &body)?;
    Ok(())
}

fn write_atomic(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dest.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, dest) {
        Ok(()) => Ok(()),
        Err(err) => {
            if dest.exists() {
                std::fs::remove_file(dest)?;
                std::fs::rename(&tmp, dest)
            } else {
                Err(err)
            }
        }
    }
}

fn read_new_lines(
    file: &mut File,
    offset: &mut u64,
    skipping: &mut bool,
    pattern: Option<&Regex>,
    source: &str,
    limits: ReadLimits,
    events: &mut Vec<LogEvent>,
) -> std::io::Result<ReadOutcome> {
    file.seek(SeekFrom::Start(*offset))?;
    let mut lines = 0;
    while lines < limits.max_lines {
        if *skipping {
            let (consumed, found) = skip_to_newline(file, MAX_LOG_SKIP_BYTES_PER_TICK)?;
            *offset = offset.saturating_add(consumed);
            if !found {
                return Ok(ReadOutcome {
                    stop: ReadStop::Eof,
                    lines,
                });
            }
            *skipping = false;
        }
        match read_one_line(file, MAX_LOG_LINE_BYTES)? {
            None => {
                return Ok(ReadOutcome {
                    stop: ReadStop::Eof,
                    lines,
                });
            }
            Some(line) if line.partial && !limits.emit_partial => {
                file.seek(SeekFrom::Start(*offset))?;
                return Ok(ReadOutcome {
                    stop: ReadStop::Eof,
                    lines,
                });
            }
            Some(line) => {
                *offset = offset.saturating_add(line.consumed);
                *skipping = line.oversized;
                lines += 1;
                let text = String::from_utf8_lossy(&line.bytes).into_owned();
                let matches = match pattern {
                    Some(regex) => regex.is_match(&text),
                    None => true,
                };
                if matches {
                    events.push(LogEvent {
                        source: source.to_string(),
                        line: text,
                        timestamp_ms: limits.now_ms,
                        labels: Vec::new(),
                    });
                }
            }
        }
    }
    Ok(ReadOutcome {
        stop: ReadStop::Cap,
        lines,
    })
}

/// Read one line. `partial` is set when EOF arrives before a newline.
/// The file cursor is left at the first byte that was not consumed.
fn read_one_line(file: &mut File, max_bytes: usize) -> std::io::Result<Option<RawLine>> {
    let mut kept = Vec::new();
    let mut consumed = 0u64;
    let mut chunk = [0u8; 8192];
    loop {
        let filled = file.read(&mut chunk)?;
        if filled == 0 {
            if consumed == 0 {
                return Ok(None);
            }
            return Ok(Some(RawLine {
                bytes: kept,
                consumed,
                partial: true,
                oversized: false,
            }));
        }
        for (index, byte) in chunk[..filled].iter().enumerate() {
            if *byte != b'\n' && kept.len() >= max_bytes {
                // Stop at the cap instead of scanning to the newline, which
                // may be arbitrarily far away or not written yet.
                let unread = i64::try_from(filled - index).unwrap_or(0);
                file.seek(SeekFrom::Current(-unread))?;
                return Ok(Some(RawLine {
                    bytes: kept,
                    consumed,
                    partial: false,
                    oversized: true,
                }));
            }
            consumed += 1;
            if *byte == b'\n' {
                let unread = filled - (index + 1);
                if unread > 0 {
                    let unread = i64::try_from(unread).unwrap_or(0);
                    file.seek(SeekFrom::Current(-unread))?;
                }
                if kept.last() == Some(&b'\r') {
                    kept.pop();
                }
                return Ok(Some(RawLine {
                    bytes: kept,
                    consumed,
                    partial: false,
                    oversized: false,
                }));
            }
            kept.push(*byte);
        }
    }
}

/// Discard bytes up to and including the next newline, reading at most
/// `budget` bytes. Returns the bytes consumed and whether the newline was found.
/// The file cursor is left at the first byte that was not consumed.
fn skip_to_newline(file: &mut File, budget: u64) -> std::io::Result<(u64, bool)> {
    let mut consumed = 0u64;
    let mut chunk = [0u8; 8192];
    while consumed < budget {
        let want = usize::try_from((budget - consumed).min(chunk.len() as u64)).unwrap_or(0);
        let filled = file.read(&mut chunk[..want])?;
        if filled == 0 {
            break;
        }
        if let Some(index) = chunk[..filled].iter().position(|byte| *byte == b'\n') {
            let unread = i64::try_from(filled - (index + 1)).unwrap_or(0);
            if unread > 0 {
                file.seek(SeekFrom::Current(-unread))?;
            }
            return Ok((consumed + index as u64 + 1, true));
        }
        consumed += filled as u64;
    }
    Ok((consumed, false))
}

fn open_shared(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn file_id_of_path(path: &Path) -> std::io::Result<u64> {
    let file = open_shared(path)?;
    file_id(&file)
}

#[cfg(unix)]
fn file_id(file: &File) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.ino())
}

#[cfg(windows)]
fn file_id(file: &File) -> std::io::Result<u64> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Filetime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: Filetime,
        last_access_time: Filetime,
        last_write_time: Filetime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    const _: () = assert!(std::mem::size_of::<ByHandleFileInformation>() == 52);

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }

    // Safety: the handle comes from an open `File`. `info` is a local struct
    // whose layout matches `BY_HANDLE_FILE_INFORMATION`.
    let mut info = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let index = (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low);
    let mixed = index ^ u64::from(info.volume_serial_number).wrapping_mul(0x9E37_79B1_85EB_CA87);
    Ok(if mixed == 0 { 1 } else { mixed })
}

#[cfg(not(any(unix, windows)))]
fn file_id(file: &File) -> std::io::Result<u64> {
    let _ = file;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "kestrel-logs-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn event_lines(events: &[LogEvent]) -> Vec<&str> {
        events.iter().map(|event| event.line.as_str()).collect()
    }

    #[test]
    fn logs_rotation_does_not_lose_or_duplicate_lines() {
        let scratch = Scratch::new("rotate");
        let path = scratch.path().join("app.log");
        std::fs::write(&path, "one\ntwo\nthree").unwrap();
        let mut tailer = LogTailer::open(&path, None).unwrap();
        tailer.set_max_lines(1);
        let now = 1_700_000_000_000;
        let first = tailer.poll(now).unwrap();
        assert_eq!(event_lines(&first), ["one"]);
        assert_eq!(first[0].timestamp_ms, now);
        assert_eq!(first[0].source, path_key(&path));

        let rotated = scratch.path().join("app.log.1");
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "four\n").unwrap();

        tailer.set_max_lines(MAX_LOG_LINES_PER_TICK);
        let next = tailer.poll(now + 1).unwrap();
        assert_eq!(event_lines(&next), ["two", "three", "four"]);
        assert!(tailer.poll(now + 2).unwrap().is_empty());
    }

    #[test]
    fn logs_truncation_restarts_at_the_beginning() {
        let scratch = Scratch::new("truncate");
        let path = scratch.path().join("app.log");
        std::fs::write(&path, "alpha\nbeta\n").unwrap();
        let mut tailer = LogTailer::open(&path, None).unwrap();
        assert_eq!(event_lines(&tailer.poll(1).unwrap()), ["alpha", "beta"]);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        use std::io::Write;
        file.write_all(b"gamma\n").unwrap();
        drop(file);

        assert_eq!(event_lines(&tailer.poll(2).unwrap()), ["gamma"]);
        assert!(tailer.poll(3).unwrap().is_empty());
    }

    #[test]
    fn logs_line_and_size_caps_are_enforced() {
        let scratch = Scratch::new("caps");
        let path = scratch.path().join("app.log");
        let mut long = vec![b'A'; MAX_LOG_LINE_BYTES + 100];
        long.push(b'\n');
        long.extend_from_slice(b"tail\n");
        std::fs::write(&path, &long).unwrap();

        let mut tailer = LogTailer::open(&path, None).unwrap();
        let events = tailer.poll(1).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].line.len(), MAX_LOG_LINE_BYTES);
        assert!(events[0].line.chars().all(|ch| ch == 'A'));
        assert_eq!(events[1].line, "tail");
        assert!(tailer.poll(2).unwrap().is_empty());

        let many = scratch.path().join("many.log");
        let mut body = String::new();
        for index in 0..1005 {
            body.push_str(&format!("l{index}\n"));
        }
        std::fs::write(&many, body).unwrap();
        let mut tailer = LogTailer::open(&many, None).unwrap();
        let first = tailer.poll(3).unwrap();
        assert_eq!(first.len(), MAX_LOG_LINES_PER_TICK);
        assert_eq!(first[0].line, "l0");
        assert_eq!(first[999].line, "l999");
        let second = tailer.poll(4).unwrap();
        assert_eq!(
            event_lines(&second),
            ["l1000", "l1001", "l1002", "l1003", "l1004"]
        );
        assert!(tailer.poll(5).unwrap().is_empty());
    }

    #[test]
    fn logs_offsets_survive_restart_without_duplicates() {
        let scratch = Scratch::new("offsets");
        let path = scratch.path().join("app.log");
        std::fs::write(&path, "a\nb\n").unwrap();
        let mut tailer = LogTailer::open(&path, None).unwrap();
        assert_eq!(event_lines(&tailer.poll(1).unwrap()), ["a", "b"]);
        let inode = tailer.inode;
        let offset = tailer.offset;
        save_log_offsets(scratch.path(), std::slice::from_ref(&tailer)).unwrap();
        drop(tailer);

        let saved = load_log_offsets(scratch.path()).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].offset, offset);
        assert_eq!(saved[0].inode, inode);
        let mut resumed = LogTailer::restore(&path, None, saved[0].offset, saved[0].inode).unwrap();
        assert!(resumed.poll(2).unwrap().is_empty());

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"c\n").unwrap();
        drop(file);
        assert_eq!(event_lines(&resumed.poll(3).unwrap()), ["c"]);

        // A replacement file must be read from the start, not from the old offset.
        drop(resumed);
        let retired = scratch.path().join("app.log.old");
        std::fs::rename(&path, &retired).unwrap();
        std::fs::write(&path, "zzzzzzzz\n").unwrap();
        let mut replaced = LogTailer::restore(&path, None, offset, inode).unwrap();
        assert_eq!(event_lines(&replaced.poll(4).unwrap()), ["zzzzzzzz"]);
        assert!(replaced.poll(5).unwrap().is_empty());
    }

    #[test]
    fn logs_partial_line_is_held_until_the_newline() {
        let scratch = Scratch::new("partial");
        let path = scratch.path().join("app.log");
        std::fs::write(&path, "hello").unwrap();
        let mut tailer = LogTailer::open(&path, None).unwrap();
        assert!(tailer.poll(1).unwrap().is_empty());

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b" world\nnext\n").unwrap();
        drop(file);
        assert_eq!(
            event_lines(&tailer.poll(2).unwrap()),
            ["hello world", "next"]
        );
    }

    #[test]
    fn logs_pattern_skips_lines_that_do_not_match() {
        let scratch = Scratch::new("pattern");
        let path = scratch.path().join("app.log");
        std::fs::write(&path, "ok\nERROR boom\nfine\n").unwrap();
        let mut tailer = LogTailer::open(&path, Some("ERROR")).unwrap();
        assert_eq!(event_lines(&tailer.poll(1).unwrap()), ["ERROR boom"]);
        assert!(tailer.poll(2).unwrap().is_empty());

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"ERROR again\n").unwrap();
        drop(file);
        assert_eq!(event_lines(&tailer.poll(3).unwrap()), ["ERROR again"]);
        assert!(LogTailer::open(&path, Some("(")).is_err());
    }

    #[test]
    fn logs_unterminated_huge_line_is_emitted_once_and_not_rescanned() {
        let scratch = Scratch::new("huge-partial");
        let path = scratch.path().join("app.log");
        let size = MAX_LOG_SKIP_BYTES_PER_TICK * 2 + MAX_LOG_SKIP_BYTES_PER_TICK / 2;
        std::fs::write(&path, vec![b'X'; usize::try_from(size).unwrap()]).unwrap();
        let mut tailer = LogTailer::open(&path, None).unwrap();

        let first = tailer.poll(1).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].line.len(), MAX_LOG_LINE_BYTES);
        let cap = MAX_LOG_LINE_BYTES as u64;
        assert_eq!(tailer.offset, cap + MAX_LOG_SKIP_BYTES_PER_TICK);

        // Each tick discards at most the skip budget and never rescans.
        assert!(tailer.poll(2).unwrap().is_empty());
        assert_eq!(tailer.offset, cap + 2 * MAX_LOG_SKIP_BYTES_PER_TICK);
        assert!(tailer.poll(3).unwrap().is_empty());
        assert_eq!(tailer.offset, size);
        assert!(tailer.poll(4).unwrap().is_empty());
        assert_eq!(tailer.offset, size);

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"XXX\nnext\n").unwrap();
        drop(file);
        assert_eq!(event_lines(&tailer.poll(5).unwrap()), ["next"]);
    }

    #[test]
    fn logs_missing_offset_file_is_empty() {
        let scratch = Scratch::new("empty-offsets");
        assert!(load_log_offsets(scratch.path()).unwrap().is_empty());
    }

    #[test]
    fn logs_crlf_newlines_are_stripped() {
        let scratch = Scratch::new("crlf");
        let path = scratch.path().join("app.log");
        std::fs::write(&path, "a\r\nb\r\n").unwrap();
        let mut tailer = LogTailer::open(&path, None).unwrap();
        assert_eq!(event_lines(&tailer.poll(1).unwrap()), ["a", "b"]);
    }
}
