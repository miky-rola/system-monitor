use std::time::Duration;
use std::thread;
use std::env;
use sysinfo::{System, SystemExt};
mod metrics;
mod analysis;
mod display;
mod security;
mod types;

use metrics::collect_system_metrics;
use display::{display_system_info, display_performance_analysis, display_security_analysis, 
              display_recommendations, display_temp_files};
use security::{perform_security_analysis, generate_recommendations};

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str());

    println!("Advanced System Performance Monitor Starting...\n");
    
    let mut metrics_history = Vec::new();
    let monitoring_duration = Duration::from_secs(30);
    let sample_interval = Duration::from_secs(5);
    let samples = (monitoring_duration.as_secs() / sample_interval.as_secs()) as usize;
    
    println!("Collecting system metrics over {} seconds...", monitoring_duration.as_secs());
    
    // Initialize system information
    let mut sys = System::new_all();
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

    match command {
        Some("show-temp-files") => {
            display_temp_files(metrics_history.last().unwrap());
        },
        _ => {
            // Display regular system analysis
            display_system_info(&sys);
            display_performance_analysis(&metrics_history);
            let security_analysis = perform_security_analysis(&sys, &metrics_history);
            display_security_analysis(&security_analysis);
            let recommendations = generate_recommendations(&metrics_history, &security_analysis);
            display_recommendations(&recommendations);
            println!("\nTo view temporary files details, run:");
            println!("    cargo run -- show-temp-files");
            println!("    or");
            println!("    ./system-monitor show-temp-files (if using compiled executable)");
        }
    }
}