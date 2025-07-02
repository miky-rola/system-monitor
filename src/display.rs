use std::collections::HashMap;
use sysinfo::{System, SystemExt, ProcessExt, CpuExt};
use humansize::{format_size, BINARY};
use crate::types::{SystemMetrics, SecurityAnalysis};
use crate::analysis::{analyze_cpu_trend, analyze_memory_trend, analyze_network_trend, classify_usage_pattern};

pub fn display_process_summary(sys: &mut System) {
    sys.refresh_all();
    let initial_measurements: HashMap<sysinfo::Pid, f32> = sys.processes()
        .iter()
        .map(|(&pid, process)| (pid, process.cpu_usage()))
        .collect();
    
    std::thread::sleep(std::time::Duration::from_millis(500));
    sys.refresh_all();

    let mut processes: Vec<_> = sys.processes().values().collect();
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
    grouped_vec.sort_by(|a, b| b.1.1.cmp(&a.1.1));

    for (name, (cpu, memory)) in grouped_vec {
        if memory > 0 {
            println!("{:<40} {:>10.1} {:>15}",
                name,
                cpu.max(0.0),
                format_size(memory, BINARY)
            );
        }
    }

    println!("\nSystem Totals:");
    println!("Total Memory: {}", format_size(sys.total_memory(), BINARY));
    println!("Used Memory:  {}", format_size(sys.used_memory(), BINARY));
    println!("Total CPU Usage: {:.1}%", 
        sys.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / sys.cpus().len() as f32
    );
}

pub fn display_system_info(sys: &System) {
    println!("=== System Information ===");
    println!("Device Name: {}", sys.host_name().unwrap_or_default());
    println!("System: {}", sys.long_os_version().unwrap_or_default());
    println!("OS: {} {}", sys.name().unwrap_or_default(), sys.os_version().unwrap_or_default());
    println!("Kernel: {}", sys.kernel_version().unwrap_or_default());
    println!("CPUs: {} (Physical), {} (Logical)", 
             sys.physical_core_count().unwrap_or_default(),
             sys.cpus().len());
}

pub fn display_temp_files(metrics: &SystemMetrics) {
    println!("\n=== Temporary Files Analysis ===");
    println!("Total Size: {}", format_size(metrics.temp_files.total_size, BINARY));
    println!("Total Files: {}", metrics.temp_files.files.len());
    
    if !metrics.temp_files.files.is_empty() {
        println!("\nAll Temporary Files:");
        println!("{:<10} {:<20} {}", "Size", "Last Modified", "Path");
        println!("{:-<80}", "");
        
        for file in &metrics.temp_files.files {
            let last_modified = file.last_modified
                .map(|time| {
                    time.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| {
                            let secs = d.as_secs();
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let diff = now - secs;
                            if diff < 3600 {
                                format!("{}m ago", diff / 60)
                            } else if diff < 86400 {
                                format!("{}h ago", diff / 3600)
                            } else {
                                format!("{}d ago", diff / 86400)
                            }
                        })
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .unwrap_or_else(|| "unknown".to_string());

            println!("{:<10} {:<20} {}", 
                format_size(file.size, BINARY),
                last_modified,
                file.path
            );
        }
    }
}

pub fn display_performance_analysis(metrics_history: &[SystemMetrics]) {
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
    println!("Average: {}", format_size(memory_trend.average as u64, BINARY));
    println!("Peak: {}", format_size(memory_trend.peak as u64, BINARY));
    println!("Pattern: {}", classify_usage_pattern(memory_trend.pattern));

    let network_trend = analyze_network_trend(metrics_history);
    println!("\nNetwork Activity:");
    println!("Avg Throughput: ↓{}ps, ↑{}ps",
             format_size(network_trend.rx_rate as u64, BINARY),
             format_size(network_trend.tx_rate as u64, BINARY));

    // Just show summary of temp files
    let latest_metrics = metrics_history.last().unwrap();
    println!("\nTemporary Files Summary:");
    println!("Total Size: {}", format_size(latest_metrics.temp_files.total_size, BINARY));
    println!("Total Files: {}", latest_metrics.temp_files.files.len());
    println!("Use 'show-temp-files' command to view detailed listing");
}

pub fn display_security_analysis(analysis: &SecurityAnalysis) {    

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

pub fn display_recommendations(recommendations: &[String]) {
    println!("\n=== System Recommendations ===");
    for recommendation in recommendations {
        println!("{}", recommendation);
    }
}

pub fn display_temperature_info(metrics: &SystemMetrics) {
    println!("\n=== Temperature Information ===");
    
    if let Some(cpu_temp) = &metrics.temperature.cpu_temp {
        println!("CPU Temperature: {:.1}°C / {:.1}°F", 
            cpu_temp.celsius, 
            cpu_temp.fahrenheit
        );
    }
    
    if let Some(gpu_temp) = &metrics.temperature.gpu_temp {
        println!("GPU Temperature: {:.1}°C / {:.1}°F", 
            gpu_temp.celsius, 
            gpu_temp.fahrenheit
        );
    }
    
    if !metrics.temperature.components.is_empty() {
        println!("\nAll Components:");
        for (label, temp) in &metrics.temperature.components {
            println!("{}: {:.1}°C / {:.1}°F", 
                label, 
                temp.celsius, 
                temp.fahrenheit
            );
        }
    }

    // Add temperature warnings if needed
    for (label, temp) in &metrics.temperature.components {
        if temp.celsius > 80.0 {
            println!("\n⚠️ WARNING: {} temperature is high ({:.1}°C / {:.1}°F)", 
                label, 
                temp.celsius, 
                temp.fahrenheit
            );
        }
    }
}