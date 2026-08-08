use walkdir::WalkDir;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::path::PathBuf;
use std::time::SystemTime;
use sysinfo::{System, SystemExt, ProcessExt, DiskExt, CpuExt, NetworkExt, NetworksExt, ComponentExt};
use crate::types::{SystemMetrics, DiskMetrics, ProcessMetrics, TempFileMetrics, TempFileInfo, TemperatureMetrics, TemperatureReading, MetricsScope};

const MAX_LISTED_TEMP_FILES: usize = 500;

pub fn collect_system_metrics(sys: &mut System, scope: MetricsScope) -> SystemMetrics {
    let temp_files = collect_temp_files(scope);

    SystemMetrics {
        timestamp: std::time::Instant::now(),
        cpu_usage: sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect(),
        memory_usage: sys.used_memory(),
        memory_total: sys.total_memory(),
        swap_usage: sys.used_swap(),
        swap_total: sys.total_swap(),
        network_rx: sys.networks().iter().map(|(_, data)| data.received()).sum(),
        network_tx: sys.networks().iter().map(|(_, data)| data.transmitted()).sum(),
        disk_usage: collect_disk_metrics(sys),
        process_metrics: collect_process_metrics(sys),
        temp_files,
        temperature: collect_temperature_metrics(sys),
    }
}

fn collect_disk_metrics(sys: &mut System) -> HashMap<String, DiskMetrics> {
    let mut metrics = HashMap::new();

    for disk in sys.disks() {
        metrics.insert(
            disk.mount_point().to_string_lossy().to_string(),
            DiskMetrics {
                total: disk.total_space(),
                used: disk.total_space() - disk.available_space(),
                read_rate: 0.0,
                write_rate: 0.0,
            }
        );
    }

    metrics
}

pub fn collect_process_metrics(sys: &mut System) -> Vec<ProcessMetrics> {
    sys.processes()
        .values()
        .map(|process| ProcessMetrics {
            name: process.name().to_string(),
            pid: process.pid(),
            cpu_usage: process.cpu_usage(),
            memory_usage: process.memory(),
            disk_usage: 0,
        })
        .collect()
}

fn create_temp_reading(celsius: f32) -> TemperatureReading {
    TemperatureReading {
        celsius,
        fahrenheit: (celsius * 9.0 / 5.0) + 32.0,
    }
}

fn collect_temperature_metrics(sys: &mut System) -> TemperatureMetrics {
    let components = collect_temperature_components(sys);

    let cpu_temp = hottest(&components, &["cpu", "pacc", "eacc", "tdie", "soc"]);
    let gpu_temp = hottest(&components, &["gpu"]);

    TemperatureMetrics {
        cpu_temp,
        gpu_temp,
        components,
    }
}

#[cfg(target_os = "macos")]
fn collect_temperature_components(sys: &mut System) -> HashMap<String, TemperatureReading> {
    let hid: HashMap<String, TemperatureReading> = crate::temperature::read_sensors()
        .into_iter()
        .map(|(label, celsius)| (label, create_temp_reading(celsius)))
        .collect();
    if !hid.is_empty() {
        return hid;
    }

    let fallback = sysinfo_temperature_components(sys);
    if fallback.is_empty() {
        log::warn!("No temperature sensors available (IOKit HID and sysinfo both returned none)");
    } else {
        log::info!("IOKit HID returned no sensors; using sysinfo temperature components");
    }
    fallback
}

#[cfg(not(target_os = "macos"))]
fn collect_temperature_components(sys: &mut System) -> HashMap<String, TemperatureReading> {
    sysinfo_temperature_components(sys)
}

fn sysinfo_temperature_components(sys: &mut System) -> HashMap<String, TemperatureReading> {
    sys.refresh_components();
    sys.components()
        .iter()
        .map(|component| {
            (
                component.label().to_string(),
                create_temp_reading(component.temperature()),
            )
        })
        .collect()
}

fn hottest(
    components: &HashMap<String, TemperatureReading>,
    needles: &[&str],
) -> Option<TemperatureReading> {
    let max = components
        .iter()
        .filter(|(label, _)| label_contains_any(label, needles))
        .map(|(_, reading)| reading.celsius)
        .reduce(f32::max)?;
    Some(create_temp_reading(max))
}

fn label_contains_any(label: &str, needles: &[&str]) -> bool {
    let lower = label.to_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

pub fn collect_temp_files(scope: MetricsScope) -> TempFileMetrics {
    scan_temp_roots(&crate::temp_manager::temp_roots(), scope)
}

fn scan_temp_roots(roots: &[PathBuf], scope: MetricsScope) -> TempFileMetrics {
    match scope {
        MetricsScope::Full | MetricsScope::Summary => {}
        MetricsScope::Light => return TempFileMetrics::default(),
    }

    let mut metrics = TempFileMetrics::default();
    let mut largest: BinaryHeap<Reverse<(u64, String, Option<SystemTime>)>> = BinaryHeap::new();

    for root in roots {
        for entry in WalkDir::new(root)
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

            let size = metadata.len();
            metrics.total_size = metrics.total_size.saturating_add(size);
            metrics.file_count += 1;

            match scope {
                MetricsScope::Full => {
                    let smallest_listed = match largest.peek() {
                        Some(Reverse((listed_size, _, _))) => *listed_size,
                        None => 0,
                    };
                    if largest.len() == MAX_LISTED_TEMP_FILES {
                        if smallest_listed >= size {
                            continue;
                        }
                        largest.pop();
                    }

                    largest.push(Reverse((
                        size,
                        entry.path().to_string_lossy().into_owned(),
                        metadata.modified().ok(),
                    )));
                }
                MetricsScope::Summary | MetricsScope::Light => {}
            }
        }
    }

    match scope {
        MetricsScope::Full => {
            metrics.files_omitted = metrics.file_count - largest.len();
            metrics.files = largest
                .into_sorted_vec()
                .into_iter()
                .map(|Reverse((size, path, last_modified))| TempFileInfo {
                    path,
                    size,
                    last_modified,
                })
                .collect();
        }
        MetricsScope::Summary | MetricsScope::Light => {}
    }

    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn components(entries: &[(&str, f32)]) -> HashMap<String, TemperatureReading> {
        entries
            .iter()
            .map(|(label, celsius)| ((*label).to_string(), create_temp_reading(*celsius)))
            .collect()
    }

    #[test]
    fn temp_reading_converts_to_fahrenheit() {
        let reading = create_temp_reading(100.0);
        assert_eq!(reading.celsius, 100.0);
        assert_eq!(reading.fahrenheit, 212.0);
    }

    #[test]
    fn label_matching_is_case_insensitive() {
        assert!(label_contains_any("pACC MTR Temp Sensor1", &["pacc"]));
        assert!(label_contains_any("GPU MTR Temp", &["gpu"]));
        assert!(!label_contains_any("battery", &["cpu", "gpu"]));
    }

    #[test]
    fn hottest_picks_max_matching_sensor() {
        let comps = components(&[
            ("eACC MTR Temp", 55.0),
            ("pACC MTR Temp", 72.0),
            ("GPU MTR Temp", 48.0),
        ]);

        let cpu = hottest(&comps, &["cpu", "pacc", "eacc", "tdie", "soc"]).unwrap();
        assert_eq!(cpu.celsius, 72.0);

        let gpu = hottest(&comps, &["gpu"]).unwrap();
        assert_eq!(gpu.celsius, 48.0);
    }

    #[test]
    fn hottest_returns_none_without_match() {
        let comps = components(&[("battery", 30.0)]);
        assert!(hottest(&comps, &["cpu", "gpu"]).is_none());
    }

    fn temp_root_with_files() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("small.tmp"), vec![0u8; 10]).unwrap();
        std::fs::write(dir.path().join("large.tmp"), vec![0u8; 100]).unwrap();
        dir
    }

    #[test]
    fn light_scope_scans_nothing() {
        let dir = temp_root_with_files();

        let metrics = scan_temp_roots(&[dir.path().to_path_buf()], MetricsScope::Light);

        assert_eq!(metrics, TempFileMetrics::default());
    }

    #[test]
    fn summary_scope_counts_without_retaining_paths() {
        let dir = temp_root_with_files();

        let metrics = scan_temp_roots(&[dir.path().to_path_buf()], MetricsScope::Summary);

        assert_eq!(
            metrics,
            TempFileMetrics {
                total_size: 110,
                file_count: 2,
                files: Vec::new(),
                files_omitted: 0,
            }
        );
    }

    #[test]
    fn full_scope_retains_paths_largest_first() {
        let dir = temp_root_with_files();

        let metrics = scan_temp_roots(&[dir.path().to_path_buf()], MetricsScope::Full);

        assert_eq!(metrics.total_size, 110);
        assert_eq!(metrics.file_count, 2);
        assert_eq!(metrics.files_omitted, 0);
        assert_eq!(
            metrics.files.iter().map(|file| file.size).collect::<Vec<_>>(),
            vec![100, 10]
        );
        assert!(metrics.files[0].path.ends_with("large.tmp"));
    }

    #[test]
    fn full_scope_lists_only_the_largest_files() {
        let dir = tempfile::tempdir().unwrap();
        let file_count = MAX_LISTED_TEMP_FILES + 10;
        for size in 1..=file_count {
            std::fs::write(dir.path().join(format!("{size}.tmp")), vec![0u8; size]).unwrap();
        }

        let metrics = scan_temp_roots(&[dir.path().to_path_buf()], MetricsScope::Full);

        assert_eq!(metrics.file_count, file_count);
        assert_eq!(metrics.total_size, (file_count * (file_count + 1) / 2) as u64);
        assert_eq!(metrics.files.len(), MAX_LISTED_TEMP_FILES);
        assert_eq!(metrics.files_omitted, 10);
        assert_eq!(
            metrics.files.iter().map(|file| file.size).collect::<Vec<_>>(),
            (1..=file_count)
                .rev()
                .take(MAX_LISTED_TEMP_FILES)
                .map(|size| size as u64)
                .collect::<Vec<_>>()
        );
    }
}
