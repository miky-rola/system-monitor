use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{System, SystemExt};
use crate::config::Config;
use crate::metrics::collect_system_metrics;
use crate::notifications::NotificationManager;
use crate::types::MetricsScope;

pub fn run_daemon(config: &Config) {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set signal handler");

    log::info!(
        "Daemon started, checking every {}s",
        config.daemon.check_interval_secs,
    );
    println!(
        "Monitoring system every {}s. Press Ctrl+C to stop.",
        config.daemon.check_interval_secs,
    );

    let mut sys = System::new_all();
    #[cfg(target_os = "macos")]
    sys.refresh_all();
    #[cfg(not(target_os = "macos"))]
    sys.refresh_components_list();

    let mut notification_manager = NotificationManager::new(config.notifications.cooldown_secs);
    let interval = Duration::from_secs(config.daemon.check_interval_secs);

    while running.load(Ordering::SeqCst) {
        sys.refresh_all();
        let metrics = collect_system_metrics(&mut sys, MetricsScope::Light);

        let avg_cpu = metrics.cpu_usage.iter().sum::<f32>() / metrics.cpu_usage.len() as f32;
        let mem_percent = (metrics.memory_usage as f64 / metrics.memory_total as f64 * 100.0) as u64;
        log::debug!("CPU: {avg_cpu:.1}%, Memory: {mem_percent}%");

        notification_manager.check_and_notify(&metrics, config);

        std::thread::sleep(interval);
    }

    println!("Daemon stopped.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;
    use std::time::Instant;

    fn make_test_metrics(cpu: f32, mem_used: u64, mem_total: u64) -> SystemMetrics {
        SystemMetrics {
            timestamp: Instant::now(),
            cpu_usage: vec![cpu],
            memory_usage: mem_used,
            memory_total: mem_total,
            swap_usage: 0,
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
    fn notification_manager_tracks_state_across_calls() {
        let config = Config::default();
        let mut manager = NotificationManager::new(config.notifications.cooldown_secs);

        let low_metrics = make_test_metrics(10.0, 30, 100);
        manager.check_and_notify(&low_metrics, &config);
        assert!(manager.last_sent_times().is_empty());

        let high_metrics = make_test_metrics(95.0, 90, 100);
        manager.check_and_notify(&high_metrics, &config);
        assert!(!manager.last_sent_times().is_empty());
    }

    #[test]
    fn daemon_config_defaults_are_sensible() {
        let config = Config::default();
        assert_eq!(config.daemon.check_interval_secs, 60);
        assert!(config.notifications.enabled);
        assert_eq!(config.notifications.cooldown_secs, 300);
    }
}
