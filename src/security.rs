use sysinfo::{System, SystemExt, ProcessExt, NetworkExt};
use walkdir::WalkDir;
use std::path::Path;
use crate::types::{SystemMetrics, SecurityAnalysis};
use humansize::{format_size, BINARY};

pub fn perform_security_analysis(sys: &System, metrics_history: &[SystemMetrics]) -> SecurityAnalysis {
    let mut analysis = SecurityAnalysis {
        unusual_network_activity: Vec::new(),
        high_resource_usage: Vec::new(),
    };

    for process in sys.processes().values() {
        let name = process.name().to_lowercase();

        if process.cpu_usage() > 90.0 || process.memory() > sys.total_memory() / 10 {
            analysis.high_resource_usage.push(format!(
                "{} (CPU: {:.1}%, Memory: {})",
                process.name(),
                process.cpu_usage(),
                format_size(process.memory() * 1024, BINARY)
            ));
        }
    }

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

    if !security_analysis.unusual_network_activity.is_empty() {
        recommendations.push("* Unusual network activity detected - Check firewall settings".to_string());
        recommendations.push("* Monitor network connections for unauthorized access".to_string());
    }

    // Browser recommendations
    let process_metrics = &last_metrics.process_metrics;
    let browser_processes: Vec<_> = process_metrics.iter()
    .filter(|p| {
        let name = p.name.to_lowercase();
        name.contains("chrome") || 
        name.contains("chromium") ||
        name.contains("firefox") || 
        name.contains("librewolf") ||
        name.contains("waterfox") ||
        name.contains("msedge") || 
        name.contains("edge") ||
        name.contains("safari") ||
        name.contains("opera") ||
        name.contains("brave") ||
        name.contains("vivaldi") ||
        name.contains("tor") ||
        name.contains("palemoon") ||
        name.contains("seamonkey") ||
        name.contains("falkon") ||
        name.contains("konqueror") ||
        name.contains("epiphany") ||
        name.contains("midori") ||
        name.contains("qutebrowser") ||
        name.contains("iexplore") ||  // Internet Explorer
        name.contains("maxthon") ||
        name.contains("whale") ||     // Naver Whale
        name.contains("yandex")       // Yandex Browser
    })
    .collect();
    if browser_processes.iter().any(|p| p.memory_usage > 1024 * 1024 * 1024) {
        recommendations.push("* Browser memory usage is high:".to_string());
        recommendations.push("  - Consider reducing number of open tabs".to_string());
    }

    recommendations
}


fn calculate_network_baseline(metrics_history: &[SystemMetrics]) -> u64 {
    let total: u64 = metrics_history.iter()
        .map(|m| m.network_rx + m.network_tx)
        .sum();
    total / metrics_history.len() as u64
}