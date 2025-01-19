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
use std::io::{self, Write};

use metrics::collect_system_metrics;
use display::{
    display_system_info, 
    display_performance_analysis, 
    display_security_analysis,
    display_recommendations, 
    display_temp_files,
    display_temperature_info,
    display_process_summary
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
    println!("  help            - Show this help message");
    println!("  show-temp-files - Display detailed temporary file information");
    println!("  clean-temp      - Clean temporary files older than 7 days");
    println!("  monitor        - Run continuous monitoring (default)");
    println!("\nExamples:");
    println!("  cargo run");
    println!("  cargo run -- help");
    println!("  cargo run -- clean-temp");
    println!("  cargo run -- show-temp-files");
}

fn prompt_temp_file_age() -> Option<u64> {
    println!("\nChoose files to delete based on age:");
    println!("1. Recent files (1-2 days old)");
    println!("2. Moderately old files (3-5 days old)");
    println!("3. Old files (6+ days old)");
    println!("4. Cancel cleanup");
    
    print!("\nEnter your choice (1-4): ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    match input.trim() {
        "1" => {
            println!("Deleting files 1-2 days old...");
            Some(2)
        },
        "2" => {
            println!("Deleting files 3-5 days old...");
            Some(5)
        },
        "3" => {
            println!("Deleting files 6+ days old...");
            Some(6)
        },
        "4" => {
            println!("Cleanup cancelled.");
            None
        },
        _ => {
            println!("Invalid choice. Cleanup cancelled.");
            None
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str());

    if matches!(command, Some("help") | Some("-h") | Some("--help")) {
        print_help();
        return;
    }

    println!("Advanced System Performance Monitor v{} Starting...\n", VERSION);
    
    let mut metrics_history = Vec::new();
    let monitoring_duration = Duration::from_secs(30);
    let sample_interval = Duration::from_secs(5);
    let samples = (monitoring_duration.as_secs() / sample_interval.as_secs()) as usize;
    
    let mut sys = System::new_all();
    sys.refresh_components_list();

    match command {
        Some("show-temp-files") => {
            println!("Collecting temporary file information...");
            let metrics = collect_system_metrics(&mut sys);
            display_temp_files(&metrics);
        },
        Some("clean-temp") => {
            let days_threshold = match prompt_temp_file_age() {
                Some(days) => days,
                None => return,
            };
        
            println!("\nCleaning temporary files...");
            let temp_dir = std::env::temp_dir();
            let temp_paths: Vec<&Path> = vec![
                temp_dir.as_path(),
                Path::new("/tmp"),
                Path::new("/var/tmp"),
            ];
            
            let stats = delete_temp_files(
                &temp_paths,
                days_threshold
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
            display_process_summary(&mut sys);

            // Collect metrics over time
            for i in 0..samples {
                metrics_history.push(collect_system_metrics(&mut sys));
                
                if i < samples - 1 {
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                    thread::sleep(sample_interval);
                }
            }
            println!("\n");

            display_system_info(&sys);
            display_performance_analysis(&metrics_history);
            
            if let Some(last_metrics) = metrics_history.last() {
                display_temperature_info(last_metrics);
            }

            let security_analysis = perform_security_analysis(&mut sys, &metrics_history);
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