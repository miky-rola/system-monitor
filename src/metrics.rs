use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;
use sysinfo::{System, SystemExt, ProcessExt, DiskExt, CpuExt, NetworkExt, NetworksExt};
use crate::types::{SystemMetrics, DiskMetrics, ProcessMetrics, TempFileMetrics, TempFileInfo};
use walkdir::WalkDir;

pub fn collect_system_metrics(sys: &System) -> SystemMetrics {
    SystemMetrics {
        timestamp: std::time::Instant::now(),
        cpu_usage: sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect(),
        memory_usage: sys.used_memory(),
        memory_total: sys.total_memory(),
        swap_usage: sys.used_swap(),
        network_rx: sys.networks().iter().map(|(_, data)| data.received()).sum(),
        network_tx: sys.networks().iter().map(|(_, data)| data.transmitted()).sum(),
        disk_usage: collect_disk_metrics(sys),
        process_metrics: collect_process_metrics(sys),
        temp_files: collect_temp_metrics(),
    }
}

fn collect_temp_metrics() -> TempFileMetrics {
    let mut total_size = 0u64;
    let mut files = Vec::new();

    let temp_paths = vec![
        std::env::temp_dir(),
        PathBuf::from("/tmp"),           // Unix/Linux
        PathBuf::from("/var/tmp"),       // Unix/Linux
        PathBuf::from(format!("{}\\AppData\\Local\\Temp", 
            std::env::var("USERPROFILE").unwrap_or_default())), // Windows
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

    // Sort files by size in descending order
    files.sort_by(|a, b| b.size.cmp(&a.size));

    TempFileMetrics {
        total_size,
        files,
    }
}

fn collect_disk_metrics(sys: &System) -> HashMap<String, DiskMetrics> {
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

fn collect_process_metrics(sys: &System) -> Vec<ProcessMetrics> {
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