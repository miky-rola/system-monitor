use std::time::Instant;
use std::collections::HashMap;
use sysinfo::Pid;

pub struct SystemMetrics {
    pub timestamp: Instant,
    pub cpu_usage: Vec<f32>,
    pub memory_usage: u64,
    pub memory_total: u64,
    pub swap_usage: u64, 
    pub network_rx: u64,
    pub network_tx: u64,
    pub disk_usage: HashMap<String, DiskMetrics>,
    pub process_metrics: Vec<ProcessMetrics>,
    pub temp_files: TempFileMetrics,
}

pub struct TempFileMetrics {
    pub total_size: u64,
    pub files: Vec<TempFileInfo>,
}

pub struct TempFileInfo {
    pub path: String,
    pub size: u64,
    pub last_modified: Option<std::time::SystemTime>,
}

pub struct DiskMetrics {
    pub total: u64,
    pub used: u64,
    pub read_rate: f64,
    pub write_rate: f64,
}

pub struct ProcessMetrics {
    pub name: String,
    pub pid: Pid,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub disk_usage: u64,
}

pub struct SecurityAnalysis {
    pub unusual_network_activity: Vec<String>,
    pub high_resource_usage: Vec<String>,
}

pub struct UsageTrend {
    pub average: f64,
    pub peak: f64,
    pub pattern: f64,
}

pub struct NetworkTrend {
    pub rx_rate: f64,
    pub tx_rate: f64,
}