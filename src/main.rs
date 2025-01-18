use std::time::Duration;
use std::thread;
use std::env;
use std::path::Path;
use sysinfo::{System, SystemExt};
mod metrics;
mod analysis;
mod display;
mod security;
mod types;
mod temp_manager;

use metrics::collect_system_metrics;
use display::{
    display_system_info, 
    display_performance_analysis, 
    display_security_analysis,
    display_recommendations, 
    display_temp_files,
    display_temperature_info
};
use security::{perform_security_analysis, generate_recommendations};
use temp_manager::delete_temp_files;
use humansize::{format_size, BINARY};

const VERSION: &str = "1.2.0";

fn print_help() {
    println!("Advanced System Performance Monitor v{}\n", VERSION);
    println!("Usage:");
    println!("  cargo run [command]\n");
    println!("Available Commands:");
    println!("  help           - Show this help message");
    println!("  show-temp-files- Display detailed temporary file information");
    println!("  clean-temp     - Clean temporary files older than 7 days");
    println!("  monitor        - Run continuous monitoring (default)");
    println!("\nExamples:");
    println!("  cargo run");
    println!("  cargo run -- help");
    println!("  cargo run -- clean-temp");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str());

    // Handle help command first
    if matches!(command, Some("help") | Some("-h") | Some("--help")) {
        print_help();
        return;
    }

    println!("Advanced System Performance Monitor v{} Starting...\n", VERSION);
    
    let mut metrics_history = Vec::new();
    let monitoring_duration = Duration::from_secs(30);
    let sample_interval = Duration::from_secs(5);
    let samples = (monitoring_duration.as_secs() / sample_interval.as_secs()) as usize;
    
    // Initialize system information
    let mut sys = System::new_all();
    sys.refresh_all();

    match command {
        Some("show-temp-files") => {
            println!("Collecting temporary file information...");
            let metrics = collect_system_metrics(&sys);
            display_temp_files(&metrics);
        },
        Some("clean-temp") => {
            println!("\nCleaning temporary files...");
            let temp_dir = std::env::temp_dir();
            let temp_paths: Vec<&Path> = vec![
                temp_dir.as_path(),
                Path::new("/tmp"),
                Path::new("/var/tmp"),*
            ];
            let stats = delete_temp_files(
                &temp_paths,
                Some(2) // Delete files older than 7 days
            );
            println!("\nCleanup Results:");
            println!("Files Deleted: {}", stats.files_deleted);
            println!("Space Freed: {}", format_size(stats.bytes_freed, BINARY));
            
            if !stats.errors.is_empty() {
                println!("\nErrors encountered:");
                for error in &stats.errors {
                    println!("- {}", error);
                }
            }
        },
        _ => {
            println!("Collecting system metrics over {} seconds...", monitoring_duration.as_secs());
            display::display_process_summary(&mut sys);

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
            
            // Display temperature information
            if let Some(last_metrics) = metrics_history.last() {
                display_temperature_info(last_metrics);
            }

            // Security analysis and recommendations
            let security_analysis = perform_security_analysis(&sys, &metrics_history);
            display_security_analysis(&security_analysis);
            let recommendations = generate_recommendations(&metrics_history, &security_analysis);
            display_recommendations(&recommendations);

            println!("\nAvailable Commands:");
            println!("- View temporary files details:");
            println!("    cargo run -- show-temp-files");
            println!("- Clean temporary files:");
            println!("    cargo run -- clean-temp");
            println!("- Show this help:");
            println!("    cargo run -- help");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_initialization() {
        let sys = System::new_all();
        assert!(sys.total_memory() > 0);
    }

    #[test]
    fn test_metrics_collection() {
        let sys = System::new_all();
        let metrics = collect_system_metrics(&sys);
        assert!(!metrics.cpu_usage.is_empty());
        assert!(metrics.memory_total > 0);
    }
}