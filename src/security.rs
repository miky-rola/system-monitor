use sysinfo::{System, SystemExt, ProcessExt, NetworkExt, NetworksExt, ProcessStatus};
use crate::types::{SystemMetrics, SecurityAnalysis};
use crate::config::Config;
use humansize::{format_size, BINARY};

pub fn perform_security_analysis(sys: &System, metrics_history: &[SystemMetrics], config: &Config) -> SecurityAnalysis {
    let mut analysis = SecurityAnalysis {
        unusual_network_activity: Vec::new(),
        high_resource_usage: Vec::new(),
        zombie_processes: Vec::new(),
        swap_pressure: Vec::new(),
    };

    let memory_threshold_bytes = (sys.total_memory() as f64 * config.thresholds.memory_percent / 100.0) as u64;

    for process in sys.processes().values() {
        if f64::from(process.cpu_usage()) > config.thresholds.cpu_percent || process.memory() > memory_threshold_bytes {
            analysis.high_resource_usage.push(format!(
                "{} (CPU: {:.1}%, Memory: {})",
                process.name(),
                process.cpu_usage(),
                format_size(process.memory(), BINARY)
            ));
        }

        if process.status() == ProcessStatus::Zombie {
            analysis.zombie_processes.push(format!(
                "{} (PID: {})",
                process.name(),
                process.pid()
            ));
        }
    }

    let network_baseline = calculate_network_baseline(metrics_history);
    let current_total: u64 = sys.networks()
        .iter()
        .map(|(_, data)| data.received() + data.transmitted())
        .sum();
    if network_baseline > 0 && current_total > network_baseline * 2 {
        analysis.unusual_network_activity.push(format!(
            "Network throughput ({}) exceeds 2x baseline ({})",
            format_size(current_total, BINARY),
            format_size(network_baseline, BINARY)
        ));
    }

    if let Some(last) = metrics_history.last() {
        if last.swap_total > 0 {
            let swap_pct = last.swap_usage as f64 / last.swap_total as f64 * 100.0;
            if swap_pct > config.thresholds.swap_percent {
                analysis.swap_pressure.push(format!(
                    "Swap usage at {swap_pct:.0}% ({} / {})",
                    format_size(last.swap_usage, BINARY),
                    format_size(last.swap_total, BINARY)
                ));
            }
        }
    }

    analysis
}

pub fn generate_recommendations(
    metrics_history: &[SystemMetrics],
    security_analysis: &SecurityAnalysis,
    config: &Config,
) -> Vec<String> {
    let mut recommendations = Vec::new();
    let Some(last_metrics) = metrics_history.last() else {
        return recommendations;
    };

    let memory_usage_percent = last_metrics.memory_usage as f64 / last_metrics.memory_total as f64 * 100.0;
    if memory_usage_percent > config.thresholds.memory_percent {
        recommendations.push("* Critical: High memory usage detected - Consider closing unused applications".to_string());
        recommendations.push("* Run memory diagnostics to check for memory leaks".to_string());
    }

    let high_cpu_cores: Vec<usize> = last_metrics.cpu_usage.iter()
        .enumerate()
        .filter(|(_, &usage)| f64::from(usage) > config.thresholds.cpu_percent)
        .map(|(core, _)| core)
        .collect();

    if !high_cpu_cores.is_empty() {
        recommendations.push(format!(
            "* High CPU usage on cores {} - Check for CPU-intensive processes",
            high_cpu_cores.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
        ));
    }

    if !security_analysis.unusual_network_activity.is_empty() {
        recommendations.push("* Unusual network activity detected - Check firewall settings".to_string());
        recommendations.push("* Monitor network connections for unauthorized access".to_string());
    }

    if !security_analysis.swap_pressure.is_empty() {
        recommendations.push("* High swap usage detected - System may be thrashing".to_string());
        recommendations.push("  - Close unused applications or add more RAM".to_string());
    }

    let browser_threshold = (config.thresholds.browser_memory_mb * 1024.0 * 1024.0) as u64;
    let browser_processes: Vec<_> = last_metrics.process_metrics.iter()
        .filter(|p| {
            let name = p.name.to_lowercase();
            name.contains("chrome")
                || name.contains("chromium")
                || name.contains("firefox")
                || name.contains("librewolf")
                || name.contains("waterfox")
                || name.contains("msedge")
                || name.contains("edge")
                || name.contains("safari")
                || name.contains("opera")
                || name.contains("brave")
                || name.contains("vivaldi")
                || name.contains("tor")
                || name.contains("palemoon")
                || name.contains("seamonkey")
                || name.contains("falkon")
                || name.contains("konqueror")
                || name.contains("epiphany")
                || name.contains("midori")
                || name.contains("qutebrowser")
                || name.contains("iexplore")
                || name.contains("maxthon")
                || name.contains("whale")
                || name.contains("yandex")
        })
        .collect();

    if browser_processes.iter().any(|p| p.memory_usage > browser_threshold) {
        recommendations.push("* Browser memory usage is high:".to_string());
        recommendations.push("  - Consider reducing number of open tabs".to_string());
    }

    recommendations
}

fn calculate_network_baseline(metrics_history: &[SystemMetrics]) -> u64 {
    if metrics_history.is_empty() {
        return 0;
    }
    let total: u64 = metrics_history.iter()
        .map(|m| m.network_rx + m.network_tx)
        .sum();
    total / metrics_history.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;
    use std::time::Instant;

    fn make_metrics(cpu: f32, mem_used: u64, mem_total: u64) -> SystemMetrics {
        SystemMetrics {
            timestamp: Instant::now(),
            cpu_usage: vec![cpu],
            memory_usage: mem_used,
            memory_total: mem_total,
            swap_usage: 0,
            swap_total: 0,
            network_rx: 0,
            network_tx: 0,
            disk_usage: HashMap::new(),
            process_metrics: Vec::new(),
            temp_files: TempFileMetrics { total_size: 0, files: Vec::new() },
            temperature: TemperatureMetrics {
                cpu_temp: None,
                gpu_temp: None,
                components: HashMap::new(),
            },
        }
    }

    #[test]
    fn network_baseline_empty_history_returns_zero() {
        assert_eq!(calculate_network_baseline(&[]), 0);
    }

    #[test]
    fn network_baseline_single_entry() {
        let mut m = make_metrics(10.0, 50, 100);
        m.network_rx = 1000;
        m.network_tx = 500;
        assert_eq!(calculate_network_baseline(&[m]), 1500);
    }

    #[test]
    fn network_baseline_averages_across_history() {
        let mut m1 = make_metrics(10.0, 50, 100);
        m1.network_rx = 1000;
        m1.network_tx = 0;
        let mut m2 = make_metrics(10.0, 50, 100);
        m2.network_rx = 3000;
        m2.network_tx = 0;
        assert_eq!(calculate_network_baseline(&[m1, m2]), 2000);
    }

    #[test]
    fn generate_recommendations_empty_history_returns_empty() {
        let analysis = SecurityAnalysis {
            unusual_network_activity: Vec::new(),
            high_resource_usage: Vec::new(),
            zombie_processes: Vec::new(),
            swap_pressure: Vec::new(),
        };
        let config = Config::default();
        assert!(generate_recommendations(&[], &analysis, &config).is_empty());
    }

    #[test]
    fn swap_pressure_detected_when_high() {
        let mut m = make_metrics(10.0, 50, 100);
        m.swap_usage = 90;
        m.swap_total = 100;
        let config = Config::default();
        let analysis = SecurityAnalysis {
            unusual_network_activity: Vec::new(),
            high_resource_usage: Vec::new(),
            zombie_processes: Vec::new(),
            swap_pressure: vec!["Swap usage at 90%".to_string()],
        };
        let recs = generate_recommendations(&[m], &analysis, &config);
        assert!(recs.iter().any(|r| r.contains("swap")));
    }

    #[test]
    fn swap_pressure_not_triggered_when_no_swap() {
        let mut m = make_metrics(10.0, 50, 100);
        m.swap_total = 0;
        m.swap_usage = 0;
        let analysis = SecurityAnalysis {
            unusual_network_activity: Vec::new(),
            high_resource_usage: Vec::new(),
            zombie_processes: Vec::new(),
            swap_pressure: Vec::new(),
        };
        let config = Config::default();
        let recs = generate_recommendations(&[m], &analysis, &config);
        assert!(!recs.iter().any(|r| r.contains("swap")));
    }

    #[test]
    fn high_memory_triggers_recommendation() {
        let m = make_metrics(10.0, 90, 100);
        let analysis = SecurityAnalysis {
            unusual_network_activity: Vec::new(),
            high_resource_usage: Vec::new(),
            zombie_processes: Vec::new(),
            swap_pressure: Vec::new(),
        };
        let config = Config::default();
        let recs = generate_recommendations(&[m], &analysis, &config);
        assert!(recs.iter().any(|r| r.contains("High memory usage")));
    }

    #[test]
    fn browser_threshold_uses_config_value() {
        let mut m = make_metrics(10.0, 50, 100);
        m.process_metrics.push(ProcessMetrics {
            name: "chrome".to_string(),
            pid: sysinfo::Pid::from(1),
            cpu_usage: 1.0,
            memory_usage: 600 * 1024 * 1024,
            disk_usage: 0,
        });
        let analysis = SecurityAnalysis {
            unusual_network_activity: Vec::new(),
            high_resource_usage: Vec::new(),
            zombie_processes: Vec::new(),
            swap_pressure: Vec::new(),
        };
        let mut config = Config::default();
        config.thresholds.browser_memory_mb = 512.0;
        let recs = generate_recommendations(&[m], &analysis, &config);
        assert!(recs.iter().any(|r| r.contains("Browser memory")));
    }
}
