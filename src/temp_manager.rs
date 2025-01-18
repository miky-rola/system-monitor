use std::fs;
use std::path::Path;
use std::io;
use walkdir::WalkDir;

pub struct TempCleanupStats {
    pub files_deleted: usize,
    pub bytes_freed: u64,
    pub errors: Vec<String>,
}

pub fn delete_temp_files(paths: &[&Path], older_than_days: Option<u64>) -> TempCleanupStats {
    let mut stats = TempCleanupStats {
        files_deleted: 0,
        bytes_freed: 0,
        errors: Vec::new(),
    };

    let current_time = std::time::SystemTime::now();
    
    for &path in paths {
        if !path.exists() {
            continue;
        }

        for entry in WalkDir::new(path)
            .min_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok()) {
                
            if let Ok(metadata) = entry.metadata() {
                if !metadata.is_file() {
                    continue;
                }

                // Check file age if specified
                if let Some(days) = older_than_days {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(duration) = current_time.duration_since(modified) {
                            if duration.as_secs() < days * 86400 {
                                continue;
                            }
                        }
                    }
                }

                // Try to delete the file
                match fs::remove_file(entry.path()) {
                    Ok(_) => {
                        stats.files_deleted += 1;
                        stats.bytes_freed += metadata.len();
                    },
                    Err(e) => {
                        stats.errors.push(format!(
                            "Failed to delete {}: {}",
                            entry.path().display(),
                            e
                        ));
                    }
                }
            }
        }
    }

    stats
}