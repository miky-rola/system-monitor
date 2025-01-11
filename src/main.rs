use std::path::Path;
use sysinfo::{System, SystemExt, ProcessExt, DiskExt, CpuExt};
use walkdir::WalkDir;
use humansize::{format_size, BINARY};

fn main() {
    println!("System Monitor Starting...\n");

    let mut sys = System::new_all();
    sys.refresh_all();

    println!("=== Operating System Information ===");
    println!("OS: {} {}", sys.name().unwrap_or_default(), sys.os_version().unwrap_or_default());
    println!("Kernel: {}\n", sys.kernel_version().unwrap_or_default());

    println!("=== Memory Information ===");
    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();

    println!("Total Memory: {} GB", total_memory / 1024 / 1024);
    println!("Used Memory: {} GB", used_memory / 1024 / 1024);
    println!("Total Swap: {} GB", total_swap / 1024 / 1024);
    println!("Used Swap: {} GB\n", used_swap / 1024 / 1024);

    println!("=== CPU Information ===");
    println!("Number of CPUs: {}", sys.cpus().len());
    for (i, cpu) in sys.cpus().iter().enumerate() {
        println!("CPU {}: {:.2}% usage", i, cpu.cpu_usage());
    }
    println!();

    println!("=== Disk Information ===");
    for disk in sys.disks() {
        let total = disk.total_space();
        let used = total - disk.available_space();
        println!(
            "Mount point: {}, Total: {} GB, Used: {} GB",
            disk.mount_point().to_string_lossy(),
            total / 1024 / 1024 / 1024,
            used / 1024 / 1024 / 1024
        );
    }
    println!();

    println!("=== Top 10 Processes by Memory Usage ===");
    let mut processes: Vec<_> = sys.processes().values().collect();
    processes.sort_by(|a, b| b.memory().cmp(&a.memory()));
    for process in processes.iter().take(10) {
        println!(
            "Process: {}, PID: {}, Memory: {} MB",
            process.name(),
            process.pid(),
            process.memory() / 1024 / 1024
        );
    }
    println!();

    println!("=== File System Scan ===");
    scan_directory(".");
}

fn scan_directory(start_path: &str) {
    let mut total_size: u64 = 0;
    let mut file_count = 0;
    let mut dir_count = 0;

    for entry in WalkDir::new(start_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total_size += metadata.len();
                file_count += 1;
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
}