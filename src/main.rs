use std::path::Path;
use sysinfo::{System, SystemExt, ProcessExt, DiskExt, CpuExt};
use walkdir::WalkDir;
use humansize::{format_size, BINARY};

fn main() {
    println!("Advanced System Monitor Starting...\n");

    // Initialize system information
    let mut sys = System::new_all();
    sys.refresh_all();

    // Display System Name/Host Information
    println!("=== System Information ===");
    println!("Device Name: {}", sys.host_name().unwrap_or_default());
    if let Some(system_name) = sys.long_os_version() {
        println!("System: {}", system_name);
    }
    println!("OS: {} {}", sys.name().unwrap_or_default(), sys.os_version().unwrap_or_default());
    println!("Kernel: {}\n", sys.kernel_version().unwrap_or_default());

    // Display Memory Information with Warnings
    println!("=== Memory Information ===");
    let total_memory = sys.total_memory() * 1024; // Convert to bytes
    let used_memory = sys.used_memory() * 1024;
    let total_swap = sys.total_swap() * 1024;
    let used_swap = sys.used_swap() * 1024;
    let memory_usage_percent = (used_memory as f64 / total_memory as f64 * 100.0) as u64;

    println!("Total Memory: {}", format_size(total_memory, BINARY));
    println!("Used Memory: {} ({:?}%)", format_size(used_memory, BINARY), memory_usage_percent);
    println!("Total Swap: {}", format_size(total_swap, BINARY));
    println!("Used Swap: {}", format_size(used_swap, BINARY));
    
    // Memory usage warnings
    if memory_usage_percent > 80 {
        println!("\n⚠️ WARNING: High memory usage detected!");
    }

    // Display CPU Information with Process Attribution
    println!("\n=== CPU Information ===");
    println!("Number of CPUs: {}", sys.cpus().len());
    
    // Refresh processes to get current CPU usage
    sys.refresh_processes();
    let processes: Vec<_> = sys.processes().values().collect();
    
    for (i, cpu) in sys.cpus().iter().enumerate() {
        println!("CPU {}: {:.2}% usage", i, cpu.cpu_usage());
        
        // Find top process for this CPU
        let top_process = processes.iter()
            .max_by(|a, b| a.cpu_usage().partial_cmp(&b.cpu_usage()).unwrap());
        
        if let Some(process) = top_process {
            println!("  → Main process: {} (PID: {})", process.name(), process.pid());
        }
    }

    // Display Disk Information with Usage Warnings
    println!("\n=== Disk Information ===");
    for disk in sys.disks() {
        let total = disk.total_space();
        let available = disk.available_space();
        let used = total - available;
        let usage_percent = (used as f64 / total as f64 * 100.0) as u64;

        println!(
            "Mount point: {}, Total: {}, Used: {} ({:?}%)",
            disk.mount_point().to_string_lossy(),
            format_size(total, BINARY),
            format_size(used, BINARY),
            usage_percent
        );

        if usage_percent > 90 {
            println!("⚠️ WARNING: Low disk space on {}", disk.mount_point().to_string_lossy());
        }
    }

    // Display Process Information with Suspicious Activity Detection
    println!("\n=== Top 10 Processes by Memory Usage ===");
    let mut processes: Vec<_> = sys.processes().values().collect();
    processes.sort_by(|a, b| b.memory().cmp(&a.memory()));
    
    let mut suspicious_processes = Vec::new();
    
    // Define suspicious patterns
    let suspicious_patterns = vec![
        "cryptominer",
        "miner",
        "malware",
        "suspicious",
        "temp",
        "tmp",
    ];

    for process in processes.iter().take(10) {
        let memory_usage = process.memory() * 1024;
        println!(
            "Process: {}, PID: {}, Memory: {}",
            process.name(),
            process.pid(),
            format_size(memory_usage, BINARY)
        );

        // Check for suspicious memory usage
        if memory_usage > 1024 * 1024 * 1024 * 100 { // More than 100GB
            suspicious_processes.push(format!("{} (Excessive memory: {})", 
                process.name(), format_size(memory_usage, BINARY)));
        }

        // Check for suspicious process names
        for pattern in &suspicious_patterns {
            if process.name().to_lowercase().contains(pattern) {
                suspicious_processes.push(format!("{} (Suspicious name)", process.name()));
            }
        }
    }

    // Scan files in current directory with malware detection
    println!("\n=== File System Scan ===");
    let scan_results = scan_directory(".");
    println!(
        "Total files: {}\nTotal directories: {}\nTotal size: {}",
        scan_results.file_count,
        scan_results.dir_count,
        format_size(scan_results.total_size, BINARY)
    );

    // System Health Check Section
    println!("\n=== System Health Check ===");
    
    // Display suspicious processes if any
    if !suspicious_processes.is_empty() {
        println!("\n🚨 Suspicious Processes Detected:");
        for process in suspicious_processes {
            println!("- {}", process);
        }
    } else {
        println!("✅ No suspicious processes detected");
    }

    // Display suspicious files if any
    if !scan_results.suspicious_files.is_empty() {
        println!("\n⚠️ Potentially Suspicious Files Detected:");
        for file in scan_results.suspicious_files {
            println!("- {}", file);
        }
    } else {
        println!("✅ No suspicious files detected");
    }

    // Recommended Actions Based on System Analysis
    println!("\n=== Recommended Actions ===");
    let mut recommendations = Vec::new();

    if memory_usage_percent > 80 {
        recommendations.push("* Running a full antivirus scan");
    }

    let high_memory_processes: Vec<_> = processes.iter()
        .filter(|p| p.memory() * 1024 > 1024 * 1024 * 1024 * 50) // Over 50GB
        .collect();

    if !high_memory_processes.is_empty() {
        recommendations.push("* Investigating the browser processes using excessive memory");
        recommendations.push("* Checking for memory leaks in applications like VS Code and rust-analyzer");
    }

    recommendations.push("* Monitoring system performance over time to identify patterns");

    if !recommendations.is_empty() {
        println!("Recommended actions based on system analysis:");
        for rec in recommendations {
            println!("{}", rec);
        }
    } else {
        println!("✅ No immediate actions required");
    }
}

struct ScanResults {
    total_size: u64,
    file_count: u64,
    dir_count: u64,
    suspicious_files: Vec<String>,
}

fn scan_directory(start_path: &str) -> ScanResults {
    let mut results = ScanResults {
        total_size: 0,
        file_count: 0,
        dir_count: 0,
        suspicious_files: Vec::new(),
    };

    // Define suspicious file patterns
    let suspicious_extensions = vec![
        ".exe",
        ".dll",
        ".bat",
        ".tmp",
        ".vbs",
        ".scr",
    ];

    for entry in WalkDir::new(start_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                results.total_size += metadata.len();
                results.file_count += 1;

                // Check for suspicious files
                let path = entry.path().to_string_lossy();
                if suspicious_extensions.iter().any(|ext| path.to_lowercase().ends_with(ext)) 
                   && metadata.len() > 1024 * 1024 * 10 { // Files larger than 10MB
                    results.suspicious_files.push(path.to_string());
                }
            }
        } else if entry.file_type().is_dir() {
            results.dir_count += 1;
        }
    }

    results
}