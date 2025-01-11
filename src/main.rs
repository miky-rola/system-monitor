use std::{time::{Duration, Instant}, thread, collections::HashMap};
use sysinfo::{System, SystemExt, ProcessExt, DiskExt, CpuExt, NetworkExt, NetworksExt};
use humansize::{format_size, BINARY};

struct SystemMetrics {
    timestamp: Instant,
    cpu_usage: Vec<f32>,
    memory_usage: u64,
    memory_total: u64,
    swap_usage: u64,
    network_rx: u64,
    network_tx: u64,
    disk_usage: HashMap<String, DiskMetrics>,
    process_metrics: Vec<ProcessMetrics>,
}

struct DiskMetrics {
    total: u64,
    used: u64,
    read_rate: f64,
    write_rate: f64,
}

struct ProcessMetrics {
    name: String,
    pid: sysinfo::Pid,
    cpu_usage: f32,
    memory_usage: u64,
    disk_usage: u64,
}

struct SecurityAnalysis {
    suspicious_processes: Vec<String>,
    suspicious_files: Vec<String>,
    unusual_network_activity: Vec<String>,
    high_resource_usage: Vec<String>,
}

fn main() {
    println!("Advanced System Performance Monitor Starting...\n");
    
    // Initialize system information
    let mut sys = System::new_all();
    let mut metrics_history: Vec<SystemMetrics> = Vec::new();
    let monitoring_duration = Duration::from_secs(30);
    let sample_interval = Duration::from_secs(5);
    let samples = (monitoring_duration.as_secs() / sample_interval.as_secs()) as usize;
    
    println!("Collecting system metrics over {} seconds...", monitoring_duration.as_secs());
    println!("Process Resource Monitor\n");
    
    // Initialize system information
    let mut sys = System::new_all();
    
    // Take first measurement
    sys.refresh_all();
    let initial_measurements: HashMap<sysinfo::Pid, f32> = sys.processes()
        .iter()
        .map(|(&pid, process)| (pid, process.cpu_usage()))
        .collect();
    
    // Wait for a short period to measure CPU usage
    thread::sleep(Duration::from_millis(500));
    
    sys.refresh_all();

    let mut processes: Vec<_> = sys.processes()
        .values()
        .collect();
    
    processes.sort_by(|a, b| b.memory().cmp(&a.memory()));

    println!("{:<40} {:>10} {:>15}", "Process Name", "CPU %", "Memory Usage");
    println!("{:-<67}", "");

    let mut grouped_processes: HashMap<String, (f32, u64)> = HashMap::new();
    
    for process in processes {
        let name = process.name().to_string();
        let cpu = process.cpu_usage() - initial_measurements.get(&process.pid()).unwrap_or(&0.0);
        let memory = process.memory();
        
        grouped_processes
            .entry(name)
            .and_modify(|(c, m)| {
                *c += cpu;
                *m += memory;
            })
            .or_insert((cpu, memory));
    }

    let mut grouped_vec: Vec<_> = grouped_processes.into_iter().collect();
    grouped_vec.sort_by(|a, b| b.1.1.cmp(&a.1.1));  // Sort by memory usage

    for (name, (cpu, memory)) in grouped_vec {
        if memory > 0 { 
            println!("{:<40} {:>10.1} {:>15}",
                name,
                cpu.max(0.0),  // Ensure CPU usage isn't negative
                format_size(memory * 1024, BINARY)
            );
        }
    }

    // Display system totals
    println!("\nSystem Totals:");
    println!("Total Memory: {}", format_size(sys.total_memory() * 1024, BINARY));
    println!("Used Memory:  {}", format_size(sys.used_memory() * 1024, BINARY));
    println!("Total CPU Usage: {:.1}%", 
        sys.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32
    );
    // Collect metrics over time
    for i in 0..samples {
        sys.refresh_all();
        metrics_history.push(collect_system_metrics(&sys));
        
        if i < samples - 1 {
            print!(".");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            thread::sleep(sample_interval);
        }
    }
    println!("\n");

    // Display comprehensive system analysis
    display_system_info(&sys);
    display_performance_analysis(&metrics_history);
    let security_analysis = perform_security_analysis(&sys, &metrics_history);
    display_security_analysis(&security_analysis);
    let recommendations = generate_recommendations(&metrics_history, &security_analysis);
    display_recommendations(&recommendations);
}

fn collect_system_metrics(sys: &System) -> SystemMetrics {
    SystemMetrics {
        timestamp: Instant::now(),
        cpu_usage: sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect(),
        memory_usage: sys.used_memory(),
        memory_total: sys.total_memory(),
        swap_usage: sys.used_swap(),
        network_rx: sys.networks().iter().map(|(_, data)| data.received()).sum(),
        network_tx: sys.networks().iter().map(|(_, data)| data.transmitted()).sum(),
        disk_usage: collect_disk_metrics(sys),
        process_metrics: collect_process_metrics(sys),
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
                read_rate: 0.0, // Would need multiple samples to calculate rate
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
            disk_usage: 0, // Simplified as disk_usage() might not be available in all versions
        })
        .collect()
}

fn display_system_info(sys: &System) {
    println!("=== System Information ===");
    println!("Device Name: {}", sys.host_name().unwrap_or_default());
    println!("System: {}", sys.long_os_version().unwrap_or_default());
    println!("OS: {} {}", sys.name().unwrap_or_default(), sys.os_version().unwrap_or_default());
    println!("Kernel: {}", sys.kernel_version().unwrap_or_default());
    println!("CPUs: {} (Physical), {} (Logical)", 
             sys.physical_core_count().unwrap_or_default(),
             sys.cpus().len());
}

fn display_performance_analysis(metrics_history: &[SystemMetrics]) {
    println!("\n=== Performance Analysis ===");
    
    let cpu_trend = analyze_cpu_trend(metrics_history);
    println!("\nCPU Usage Trends:");
    for (core, trend) in cpu_trend.iter().enumerate() {
        println!("Core {}: {:.2}% avg, Pattern: {}", 
                core, 
                trend.average, 
                classify_usage_pattern(trend.pattern));
    }

    let memory_trend = analyze_memory_trend(metrics_history);
    println!("\nMemory Usage:");
    println!("Average: {}", format_size(memory_trend.average as u64 * 1024, BINARY));
    println!("Peak: {}", format_size(memory_trend.peak as u64 * 1024, BINARY));
    println!("Pattern: {}", classify_usage_pattern(memory_trend.pattern));

    let network_trend = analyze_network_trend(metrics_history);
    println!("\nNetwork Activity:");
    println!("Avg Throughput: ↓{}ps, ↑{}ps",
             format_size(network_trend.rx_rate as u64, BINARY),
             format_size(network_trend.tx_rate as u64, BINARY));
}

fn display_security_analysis(analysis: &SecurityAnalysis) {
    println!("\n=== Security Analysis ===");
    
    if !analysis.suspicious_processes.is_empty() {
        println!("\nSuspicious Processes:");
        for process in &analysis.suspicious_processes {
            println!("- {}", process);
        }
    }

    if !analysis.unusual_network_activity.is_empty() {
        println!("\nUnusual Network Activity:");
        for activity in &analysis.unusual_network_activity {
            println!("- {}", activity);
        }
    }

    if !analysis.high_resource_usage.is_empty() {
        println!("\nHigh Resource Usage:");
        for usage in &analysis.high_resource_usage {
            println!("- {}", usage);
        }
    }
}

fn perform_security_analysis(sys: &System, metrics_history: &[SystemMetrics]) -> SecurityAnalysis {
    let mut analysis = SecurityAnalysis {
        suspicious_processes: Vec::new(),
        suspicious_files: Vec::new(),
        unusual_network_activity: Vec::new(),
        high_resource_usage: Vec::new(),
    };

    for process in sys.processes().values() {
        // Check for suspicious process names
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

fn generate_recommendations(
    metrics_history: &[SystemMetrics],
    security_analysis: &SecurityAnalysis
) -> Vec<String> {
    let mut recommendations = Vec::new();

    let last_metrics = metrics_history.last().unwrap();
    let memory_usage_percent = (last_metrics.memory_usage as f64 / last_metrics.memory_total as f64 * 100.0) as u64;

    if memory_usage_percent > 80 {
        recommendations.push("* Critical: High memory usage detected - Consider closing unused applications".to_string());
        recommendations.push("* Run memory diagnostics to check for memory leaks".to_string());
    }

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

    // Security Recommendations
    if !security_analysis.suspicious_processes.is_empty() {
        recommendations.push("* URGENT: Suspicious processes detected - Run full system scan".to_string());
        recommendations.push("* Review and terminate suspicious processes".to_string());
    }

    if !security_analysis.unusual_network_activity.is_empty() {
        recommendations.push("* Unusual network activity detected - Check firewall settings".to_string());
        recommendations.push("* Monitor network connections for unauthorized access".to_string());
    }

    let process_metrics = &last_metrics.process_metrics;
    let browser_processes: Vec<&ProcessMetrics> = process_metrics.iter()
        .filter(|p| p.name.contains("chrome") || p.name.contains("firefox") || p.name.contains("msedge"))
        .collect();

    if browser_processes.iter().any(|p| p.memory_usage > 1024 * 1024 * 1024) {
        recommendations.push("* Browser memory usage is high:".to_string());
        recommendations.push("  - Consider reducing number of open tabs".to_string());
        recommendations.push("  - Check browser extensions for memory leaks".to_string());
    }

    recommendations.push("* Schedule regular system maintenance:".to_string());
    recommendations.push("  - Update system and application software".to_string());
    recommendations.push("  - Run disk cleanup and defragmentation".to_string());
    recommendations.push("  - Monitor system performance over time".to_string());

    recommendations
}

fn display_recommendations(recommendations: &[String]) {
    println!("\n=== System Recommendations ===");
    for recommendation in recommendations {
        println!("{}", recommendation);
    }
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

fn classify_usage_pattern(pattern: f64) -> &'static str {
    match pattern {
        p if p < 0.2 => "Very Low",
        p if p < 0.4 => "Low",
        p if p < 0.6 => "Moderate",
        p if p < 0.8 => "High",
        _ => "Very High"
    }
}

struct UsageTrend {
    average: f64,
    peak: f64,
    pattern: f64,
}

fn analyze_cpu_trend(metrics_history: &[SystemMetrics]) -> Vec<UsageTrend> {
    let cpu_count = metrics_history[0].cpu_usage.len();
    let mut trends = Vec::with_capacity(cpu_count);

    for core in 0..cpu_count {
        let usages: Vec<f32> = metrics_history.iter()
            .map(|m| m.cpu_usage[core])
            .collect();

        let average = usages.iter().sum::<f32>() / usages.len() as f32;
        let peak = usages.iter().cloned().fold(0f32, f32::max);
        let pattern = calculate_usage_pattern(&usages);

        trends.push(UsageTrend {
            average: average as f64,
            peak: peak as f64,
            pattern,
        });
    }

    trends
}

fn analyze_memory_trend(metrics_history: &[SystemMetrics]) -> UsageTrend {
    let usages: Vec<u64> = metrics_history.iter()
        .map(|m| m.memory_usage)
        .collect();

    let average = usages.iter().sum::<u64>() / usages.len() as u64;
    let peak = usages.iter().cloned().max().unwrap_or(0);
    let pattern = calculate_usage_pattern(&usages.iter()
        .map(|&u| u as f32)
        .collect::<Vec<f32>>());

    UsageTrend {
        average: average as f64,
        peak: peak as f64,
        pattern,
    }
}

struct NetworkTrend {
    rx_rate: f64,
    tx_rate: f64,
}

fn analyze_network_trend(metrics_history: &[SystemMetrics]) -> NetworkTrend {
    let duration = metrics_history.last().unwrap().timestamp
        .duration_since(metrics_history[0].timestamp)
        .as_secs_f64();

    let total_rx: u64 = metrics_history.iter().map(|m| m.network_rx).sum();
    let total_tx: u64 = metrics_history.iter().map(|m| m.network_tx).sum();

    NetworkTrend {
        rx_rate: total_rx as f64 / duration,
        tx_rate: total_tx as f64 / duration,
    }
}

fn calculate_usage_pattern(values: &[f32]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let max = values.iter().cloned().fold(0f32, f32::max);
    let min = values.iter().cloned().fold(f32::MAX, f32::min);
    let avg = values.iter().sum::<f32>() / values.len() as f32;

    // Calculate volatility and trend
    let volatility = if max != min {
        (max - min) / avg
    } else {
        0.0
    };

    let mut trend = 0.0;
    for window in values.windows(2) {
        if window[1] > window[0] {
            trend += 1.0;
        } else if window[1] < window[0] {
            trend -= 1.0;
        }
    }
    trend /= (values.len() - 1) as f32;

    // Combine factors into a pattern score (0.0 to 1.0)
    ((volatility + trend.abs() + (avg / max)) / 3.0) as f64
}