use sysinfo::{System, SystemExt, ProcessExt, NetworkExt};
use walkdir::WalkDir;
use std::path::Path;
use crate::types::{SystemMetrics, SecurityAnalysis};
use humansize::{format_size, BINARY};

pub fn perform_security_analysis(sys: &System, metrics_history: &[SystemMetrics]) -> SecurityAnalysis {
    let mut analysis = SecurityAnalysis {
        suspicious_processes: Vec::new(),
        suspicious_files: Vec::new(),
        unusual_network_activity: Vec::new(),
        high_resource_usage: Vec::new(),
    };

    // Process analysis
    for process in sys.processes().values() {
        let name = process.name().to_lowercase();
        if is_suspicious_process_name(&name) {
            analysis.suspicious_processes.push(format!(
                "{} (PID: {})", process.name(), process.pid()
            ));
        }

        if process.cpu_usage() > 90.0 || process.memory() > sys.total_memory() / 10 {
            analysis.high_resource_usage.push(format!(
                "{} (CPU: {:.1}%, Memory: {})",
                process.name(),
                process.cpu_usage(),
                format_size(process.memory() * 1024, BINARY)
            ));
        }
    }

    // File system analysis
    scan_suspicious_files(&mut analysis);

    // Network analysis
    let network_baseline = calculate_network_baseline(metrics_history);
    for (interface, data) in sys.networks() {
        let current_throughput = data.received() + data.transmitted();
        if current_throughput > network_baseline * 2 {
            analysis.unusual_network_activity.push(format!(
                "Interface {} shows unusual activity", interface
            ));
        }
    }

    analysis
}

fn scan_suspicious_files(analysis: &mut SecurityAnalysis) {
    let suspicious_extensions = [
        ".virus", ".malware", ".ransomware", ".encrypted",
        ".suspicious", ".backdoor", ".trojan", ".keylog"
    ];
    
    let suspicious_patterns = [
        "backdoor", "exploit", "hack", "crack", "steal",
        "keylog", "malicious", "virus", "trojan"
    ];

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let paths_to_scan = vec![
        home,
        "/tmp".to_string(),
        "/var/tmp".to_string(),
    ];

    for base_path in paths_to_scan {
        if !Path::new(&base_path).exists() {
            continue;
        }

        for entry in WalkDir::new(&base_path)
            .follow_links(false)
            .max_depth(4)  // Limit depth to prevent excessive scanning
            .into_iter()
            .filter_map(|e| e.ok()) {
                
            let path = entry.path();
            let file_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            let file_name_lower = file_name.to_lowercase();

            // Check for suspicious file extensions
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if suspicious_extensions.iter().any(|&s| ext.contains(s)) {
                    analysis.suspicious_files.push(format!(
                        "Suspicious extension: {}", path.display()
                    ));
                    continue;
                }
            }

            // Check for suspicious patterns in filename
            if suspicious_patterns.iter().any(|&pattern| file_name_lower.contains(pattern)) {
                analysis.suspicious_files.push(format!(
                    "Suspicious filename: {}", path.display()
                ));
                continue;
            }

            // Check file permissions and ownership
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = path.metadata() {
                    let mode = metadata.permissions().mode();
                    // Check for world-writable executables
                    if mode & 0o111 != 0 && mode & 0o002 != 0 {
                        analysis.suspicious_files.push(format!(
                            "World-writable executable: {}", path.display()
                        ));
                    }
                }
            }
        }
    }
}

pub fn generate_recommendations(
    metrics_history: &[SystemMetrics],
    security_analysis: &SecurityAnalysis
) -> Vec<String> {
    let mut recommendations = Vec::new();
    let last_metrics = metrics_history.last().unwrap();
    
    // Memory recommendations
    let memory_usage_percent = (last_metrics.memory_usage as f64 / last_metrics.memory_total as f64 * 100.0) as u64;
    if memory_usage_percent > 80 {
        recommendations.push("* Critical: High memory usage detected - Consider closing unused applications".to_string());
        recommendations.push("* Run memory diagnostics to check for memory leaks".to_string());
    }

    // CPU recommendations
    let high_cpu_cores: Vec<usize> = last_metrics.cpu_usage.iter()
        .enumerate()
        .filter(|(_, &usage)| usage > 90.0)
        .map(|(core, _)| core)
        .collect();

    if !high_cpu_cores.is_empty() {
        recommendations.push(format!(
            "* High CPU usage on cores {} - Check for CPU-intensive processes",
            high_cpu_cores.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")
        ));
    }

    // Security recommendations
    if !security_analysis.suspicious_processes.is_empty() {
        recommendations.push("* URGENT: Suspicious processes detected - Run full system scan".to_string());
        recommendations.push("* Review and terminate suspicious processes".to_string());
    }

    if !security_analysis.suspicious_files.is_empty() {
        recommendations.push("* Suspicious files detected:".to_string());
        recommendations.push("  - Run antivirus scan".to_string());
        recommendations.push("  - Check file permissions".to_string());
        recommendations.push("  - Review recently modified files".to_string());
    }

    if !security_analysis.unusual_network_activity.is_empty() {
        recommendations.push("* Unusual network activity detected - Check firewall settings".to_string());
        recommendations.push("* Monitor network connections for unauthorized access".to_string());
    }

    // Browser recommendations
    let process_metrics = &last_metrics.process_metrics;
    let browser_processes: Vec<_> = process_metrics.iter()
        .filter(|p| p.name.contains("chrome") || p.name.contains("firefox") || p.name.contains("msedge"))
        .collect();

    if browser_processes.iter().any(|p| p.memory_usage > 1024 * 1024 * 1024) {
        recommendations.push("* Browser memory usage is high:".to_string());
        recommendations.push("  - Consider reducing number of open tabs".to_string());
        recommendations.push("  - Check browser extensions for memory leaks".to_string());
    }

    // General maintenance recommendations
    recommendations.push("* Schedule regular system maintenance:".to_string());
    recommendations.push("  - Update system and application software".to_string());
    recommendations.push("  - Run disk cleanup and defragmentation".to_string());
    recommendations.push("  - Monitor system performance over time".to_string());
    recommendations.push("  - Regularly scan for suspicious files".to_string());

    recommendations
}

fn is_suspicious_process_name(name: &str) -> bool {
    let suspicious_patterns = [
        "cryptominer", "miner", "malware", "suspicious",
        "temp", "tmp", "hack", "crack", "keylog"
    ];
    suspicious_patterns.iter().any(|&pattern| name.contains(pattern))
}

fn calculate_network_baseline(metrics_history: &[SystemMetrics]) -> u64 {
    let total: u64 = metrics_history.iter()
        .map(|m| m.network_rx + m.network_tx)
        .sum();
    total / metrics_history.len() as u64
}