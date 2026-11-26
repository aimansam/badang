use crate::log::LogSink;

pub fn send_recv(_host: &str, _data: &[u8], _log: &LogSink) -> Result<Vec<u8>, String> {
    Err("Name Resolution Channel is not yet implemented".to_string())
}
