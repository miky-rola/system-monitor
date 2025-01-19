use std::fs;
use std::path::Path;
// use std::io;
use walkdir::WalkDir;

pub struct TempCleanupStats {
    pub files_deleted: usize,
    pub bytes_freed: u64,
    pub errors: Vec<String>,
}

pub fn delete_temp_files(paths: &[&Path], min_days_old: u64) -> TempCleanupStats {
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

                if let Ok(modified) = metadata.modified() {
                    if let Ok(duration) = current_time.duration_since(modified) {
                        let days_old = duration.as_secs() / 86400;
                        
                        match min_days_old {
                            2 => if !(1..=2).contains(&days_old) { continue; },
                            5 => if !(3..=5).contains(&days_old) { continue; },
                            6 => if days_old < 6 { continue; },
                            _ => continue,
                        }

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
        }
    }

    stats
}