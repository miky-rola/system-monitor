use std::time::Duration;
use std::thread;
use std::path::Path;
use std::io::{self, Write};
use clap::{Parser, Subcommand};
use sysinfo::{System, SystemExt};

mod metrics;
mod analysis;
mod display;
mod security;
mod types;
mod temp_manager;
mod config;
mod notifications;
mod daemon;

use metrics::collect_system_metrics;
use types::MetricsScope;
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

#[derive(Parser)]
#[command(name = "system-monitor", version, about = "A lightweight cross-platform system monitoring tool with desktop notifications")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    #[arg(long, global = true)]
    no_notify: bool,

    #[arg(long, global = true)]
    interval: Option<u64>,
}

#[derive(Subcommand)]
enum Commands {
    Monitor,
    Daemon,
    ShowTempFiles,
    CleanTemp,
    Config,
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
        }
        "2" => {
            println!("Deleting files 3-5 days old...");
            Some(5)
        }
        "3" => {
            println!("Deleting files 6+ days old...");
            Some(6)
        }
        "4" => {
            println!("Cleanup cancelled.");
            None
        }
        _ => {
            println!("Invalid choice. Cleanup cancelled.");
            None
        }
    }
}

fn run_monitor(cfg: &config::Config) {
    let monitoring_duration = Duration::from_secs(cfg.monitoring.duration_secs);
    let sample_interval = Duration::from_secs(cfg.monitoring.sample_interval_secs);
    let samples = (monitoring_duration.as_secs() / sample_interval.as_secs()) as usize;

    let mut sys = System::new_all();
    #[cfg(target_os = "macos")]
    sys.refresh_all();
    #[cfg(not(target_os = "macos"))]
    sys.refresh_components_list();

    println!("Collecting system metrics over {} seconds...", monitoring_duration.as_secs());
    display_process_summary(&mut sys);

    let mut metrics_history = Vec::new();
    for i in 0..samples {
        metrics_history.push(collect_system_metrics(&mut sys, MetricsScope::Full));

        if i < samples - 1 {
            print!(".");
            io::stdout().flush().unwrap();
            thread::sleep(sample_interval);
        }
    }
    println!("\n");

    display_system_info(&sys);
    display_performance_analysis(&metrics_history);

    if let Some(last_metrics) = metrics_history.last() {
        display_temperature_info(last_metrics, cfg);
    }

    let security_analysis = perform_security_analysis(&sys, &metrics_history, cfg);
    display_security_analysis(&security_analysis);
    let recommendations = generate_recommendations(&metrics_history, &security_analysis, cfg);
    display_recommendations(&recommendations);

    if cfg.notifications.enabled {
        if let Some(last_metrics) = metrics_history.last() {
            let mut notifier = notifications::NotificationManager::new(cfg.notifications.cooldown_secs);
            notifier.check_and_notify(last_metrics, cfg);
        }
    }

    println!("\nAvailable Commands:");
    println!("  system-monitor show-temp-files");
    println!("  system-monitor clean-temp");
    println!("  system-monitor daemon");
    println!("  system-monitor config");
}

fn run_show_temp_files() {
    let mut sys = System::new_all();
    #[cfg(target_os = "macos")]
    sys.refresh_all();
    #[cfg(not(target_os = "macos"))]
    sys.refresh_components_list();

    println!("Collecting temporary file information...");
    let metrics = collect_system_metrics(&mut sys, MetricsScope::Full);
    display_temp_files(&metrics);
}

fn run_clean_temp() {
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

    let stats = delete_temp_files(&temp_paths, days_threshold);

    println!("\nCleanup Results:");
    println!("Files Deleted: {}", stats.files_deleted);
    println!("Space Freed: {}", format_size(stats.bytes_freed, BINARY));

    if !stats.errors.is_empty() {
        println!("\nErrors encountered:");
        for error in &stats.errors {
            println!("- {error}");
        }
    }
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let mut cfg = config::load(cli.config.as_deref());
    if cli.no_notify {
        cfg.notifications.enabled = false;
    }
    if let Some(interval) = cli.interval {
        cfg.daemon.check_interval_secs = interval;
    }

    println!("Advanced System Performance Monitor v{} Starting...\n", env!("CARGO_PKG_VERSION"));

    match cli.command {
        None | Some(Commands::Monitor) => run_monitor(&cfg),
        Some(Commands::Daemon) => daemon::run_daemon(&cfg),
        Some(Commands::ShowTempFiles) => run_show_temp_files(),
        Some(Commands::CleanTemp) => run_clean_temp(),
        Some(Commands::Config) => config::display_config(&cfg),
    }
}
