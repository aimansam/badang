// Badang — Shared logging sink
// Captures structured log output for both CLI (drain to stderr) and GUI (render in panel).

use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogLevel {
    Info,
    Step,
    Warning,
    Error,
    Detail,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    pub timestamp: Instant,
}

#[derive(Clone)]
pub struct LogSink {
    entries: Arc<Mutex<Vec<LogEntry>>>,
}

impl Default for LogSink {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSink {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log(&self, level: LogLevel, msg: impl Into<String>) {
        let entry = LogEntry {
            level,
            message: msg.into(),
            timestamp: Instant::now(),
        };
        self.entries.lock().unwrap().push(entry);
    }

    pub fn info(&self, msg: impl Into<String>) {
        self.log(LogLevel::Info, msg);
    }

    pub fn step(&self, msg: impl Into<String>) {
        self.log(LogLevel::Step, msg);
    }

    pub fn warning(&self, msg: impl Into<String>) {
        self.log(LogLevel::Warning, msg);
    }

    pub fn error(&self, msg: impl Into<String>) {
        self.log(LogLevel::Error, msg);
    }

    pub fn detail(&self, msg: impl Into<String>) {
        self.log(LogLevel::Detail, msg);
    }

    pub fn drain(&self) -> Vec<LogEntry> {
        let mut entries = self.entries.lock().unwrap();
        std::mem::take(&mut *entries)
    }

    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.entries.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_and_drain() {
        let sink = LogSink::new();
        sink.info("hello");
        sink.error("oops");
        let entries = sink.drain();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].level, LogLevel::Info);
        assert_eq!(entries[0].message, "hello");
        assert_eq!(entries[1].level, LogLevel::Error);
        assert_eq!(entries[1].message, "oops");
        assert!(sink.drain().is_empty());
    }

    #[test]
    fn test_snapshot_preserves() {
        let sink = LogSink::new();
        sink.step("[1/6] OpenProcess");
        let snap = sink.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(sink.snapshot().len(), 1);
    }

    #[test]
    fn test_clear() {
        let sink = LogSink::new();
        sink.info("a");
        sink.info("b");
        sink.clear();
        assert!(sink.snapshot().is_empty());
    }

    #[test]
    fn test_clone_shares_state() {
        let sink = LogSink::new();
        let clone = sink.clone();
        sink.info("from original");
        clone.info("from clone");
        assert_eq!(sink.snapshot().len(), 2);
    }

    #[test]
    fn test_default() {
        let sink = LogSink::default();
        assert!(sink.snapshot().is_empty());
    }
}
