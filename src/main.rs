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
    println!("Hostname: {}", sys.host_name().unwrap_or_default());
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
            println!("⚠️ WARNING: Unusually high memory usage detected for {}", process.name());
        }

        // Check for suspicious process names
        for pattern in &suspicious_patterns {
            if process.name().to_lowercase().contains(pattern) {
                println!("🚨 ALERT: Potentially suspicious process detected: {}", process.name());
            }
        }
    }

    // Scan files in current directory with malware detection
    println!("\n=== File System Scan ===");
    scan_directory(".");
}

fn scan_directory(start_path: &str) {
    let mut total_size: u64 = 0;
    let mut file_count = 0;
    let mut dir_count = 0;
    let mut suspicious_files = Vec::new();

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
                total_size += metadata.len();
                file_count += 1;

                // Check for suspicious files
                let path = entry.path().to_string_lossy();
                if suspicious_extensions.iter().any(|ext| path.to_lowercase().ends_with(ext)) 
                   && metadata.len() > 1024 * 1024 * 10 { // Files larger than 10MB
                    suspicious_files.push(path.to_string());
                }
            }
        } else if entry.file_type().is_dir() {
            dir_count += 1;
        }
    }

    println!(
        "Total files: {}\nTotal directories: {}\nTotal size: {}",
        file_count,
        dir_count,
        format_size(total_size, BINARY)
    );

    if !suspicious_files.is_empty() {
        println!("\n⚠️ Potentially suspicious files detected:");
        for file in suspicious_files {
            println!("- {}", file);
        }
    }
}