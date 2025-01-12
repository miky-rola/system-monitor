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
    pub suspicious_processes: Vec<String>,
    pub suspicious_files: Vec<String>,
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