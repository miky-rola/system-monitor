use walkdir::WalkDir;
use std::collections::HashMap;
use std::path::PathBuf;
use sysinfo::{System, SystemExt, ProcessExt, DiskExt, CpuExt, NetworkExt, NetworksExt};
#[cfg(not(target_os = "macos"))]
use sysinfo::ComponentExt;
use crate::types::{SystemMetrics, DiskMetrics, ProcessMetrics, TempFileMetrics, TempFileInfo, TemperatureMetrics, TemperatureReading, MetricsScope};

pub fn collect_system_metrics(sys: &mut System, scope: MetricsScope) -> SystemMetrics {
    let temp_files = match scope {
        MetricsScope::Full => collect_temp_metrics(),
        MetricsScope::Light => TempFileMetrics { total_size: 0, files: Vec::new() },
    };

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

fn collect_process_metrics(sys: &mut System) -> Vec<ProcessMetrics> {
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
fn collect_temperature_components(_sys: &mut System) -> HashMap<String, TemperatureReading> {
    crate::temperature::read_sensors()
        .into_iter()
        .map(|(label, celsius)| (label, create_temp_reading(celsius)))
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn collect_temperature_components(sys: &mut System) -> HashMap<String, TemperatureReading> {
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

fn collect_temp_metrics() -> TempFileMetrics {
    let mut total_size = 0u64;
    let mut files = Vec::new();

    let temp_paths = vec![
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from(format!("{}\\AppData\\Local\\Temp",
            std::env::var("USERPROFILE").unwrap_or_default())),
    ];

    for temp_path in temp_paths {
        if !temp_path.exists() {
            continue;
        }

        for entry in WalkDir::new(temp_path)
            .min_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok()) {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        let size = metadata.len();
                        total_size += size;

                        files.push(TempFileInfo {
                            path: entry.path().to_string_lossy().into_owned(),
                            size,
                            last_modified: metadata.modified().ok(),
                        });
                    }
                }
            }
    }

    files.sort_by_key(|file| std::cmp::Reverse(file.size));

    TempFileMetrics {
        total_size,
        files,
    }
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
}
