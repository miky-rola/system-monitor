use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

const MAX_REPORTED_ERRORS: usize = 50;

#[derive(Debug, Default, PartialEq)]
pub struct TempCleanupStats {
    pub files_deleted: usize,
    pub bytes_freed: u64,
    pub errors: Vec<String>,
    pub errors_omitted: usize,
}

impl TempCleanupStats {
    fn record_error(&mut self, message: String) {
        if self.errors.len() < MAX_REPORTED_ERRORS {
            self.errors.push(message);
        } else {
            self.errors_omitted += 1;
        }
    }
}

pub fn temp_roots() -> Vec<PathBuf> {
    let mut candidates = vec![
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ];
    candidates.extend(user_profile_temp_root());

    dedup_roots(candidates)
}

#[cfg(windows)]
fn user_profile_temp_root() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .ok()
        .map(|profile| PathBuf::from(profile).join("AppData").join("Local").join("Temp"))
}

#[cfg(not(windows))]
fn user_profile_temp_root() -> Option<PathBuf> {
    None
}

fn dedup_roots(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();

    for candidate in candidates {
        let Ok(canonical) = candidate.canonicalize() else {
            continue;
        };
        if !canonical.is_dir() || roots.iter().any(|root| canonical.starts_with(root)) {
            continue;
        }
        roots.retain(|root| !root.starts_with(&canonical));
        roots.push(canonical);
    }

    roots
}

pub fn delete_temp_files(paths: &[PathBuf], min_days_old: u64) -> TempCleanupStats {
    let mut stats = TempCleanupStats::default();
    let current_time = std::time::SystemTime::now();

    for path in paths {
        for entry in WalkDir::new(path)
            .min_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }

            let Ok(modified) = metadata.modified() else {
                continue;
            };
            let Ok(age) = current_time.duration_since(modified) else {
                continue;
            };
            let days_old = age.as_secs() / 86400;

            match min_days_old {
                2 => if !(1..=2).contains(&days_old) { continue; },
                5 => if !(3..=5).contains(&days_old) { continue; },
                6 => if days_old < 6 { continue; },
                _ => continue,
            }

            match fs::remove_file(entry.path()) {
                Ok(()) => {
                    stats.files_deleted += 1;
                    stats.bytes_freed = stats.bytes_freed.saturating_add(metadata.len());
                }
                Err(e) => stats.record_error(format!(
                    "Failed to delete {}: {e}",
                    entry.path().display()
                )),
            }
        }
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_roots_drops_missing_paths() {
        let roots = dedup_roots(vec![PathBuf::from("/nonexistent/temp/path")]);
        assert_eq!(roots, Vec::<PathBuf>::new());
    }

    #[test]
    fn dedup_roots_collapses_repeated_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let roots = dedup_roots(vec![path.clone(), path.clone()]);

        assert_eq!(roots, vec![path.canonicalize().unwrap()]);
    }

    #[test]
    fn dedup_roots_keeps_only_the_outermost_directory() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().canonicalize().unwrap();
        let child = parent.join("nested");
        fs::create_dir(&child).unwrap();

        assert_eq!(dedup_roots(vec![parent.clone(), child.clone()]), vec![parent.clone()]);
        assert_eq!(dedup_roots(vec![child, parent.clone()]), vec![parent]);
    }

    #[test]
    fn dedup_roots_keeps_unrelated_directories() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let first_path = first.path().canonicalize().unwrap();
        let second_path = second.path().canonicalize().unwrap();

        let roots = dedup_roots(vec![first_path.clone(), second_path.clone()]);

        assert_eq!(roots, vec![first_path, second_path]);
    }

    #[test]
    fn recorded_errors_are_capped() {
        let mut stats = TempCleanupStats::default();

        for i in 0..MAX_REPORTED_ERRORS + 10 {
            stats.record_error(format!("failure {i}"));
        }

        assert_eq!(stats.errors.len(), MAX_REPORTED_ERRORS);
        assert_eq!(stats.errors_omitted, 10);
        assert_eq!(stats.errors.last().unwrap(), "failure 49");
    }

    #[test]
    fn deleting_from_missing_path_reports_nothing() {
        let stats = delete_temp_files(&[PathBuf::from("/nonexistent/temp/path")], 6);
        assert_eq!(stats, TempCleanupStats::default());
    }

    #[test]
    fn recent_files_are_not_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fresh.tmp");
        fs::write(&file, b"data").unwrap();

        let stats = delete_temp_files(&[dir.path().to_path_buf()], 6);

        assert_eq!(stats, TempCleanupStats::default());
        assert!(file.exists());
    }
}
