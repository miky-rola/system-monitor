use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;
use sysinfo::{System, SystemExt};
use crate::config::Config;
use crate::metrics::collect_system_metrics;
use crate::notifications::NotificationManager;
use crate::security::{perform_security_analysis, generate_recommendations};
use crate::types::{MetricsScope, SystemMetrics};

enum LoopControl {
    Continue,
    Stop,
}

fn wait_for_shutdown(shutdown: &Receiver<()>, timeout: Duration) -> LoopControl {
    match shutdown.recv_timeout(timeout) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => LoopControl::Stop,
        Err(RecvTimeoutError::Timeout) => LoopControl::Continue,
    }
}

pub fn run_daemon(config: &Config) {
    let (signal_sender, shutdown) = mpsc::channel();

    ctrlc::set_handler(move || {
        let _ = signal_sender.send(());
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
    let max_history = 10;
    let mut metrics_history: Vec<SystemMetrics> = Vec::with_capacity(max_history);

    loop {
        sys.refresh_all();
        let metrics = collect_system_metrics(&mut sys, MetricsScope::Light);

        let avg_cpu = metrics.cpu_usage.iter().sum::<f32>() / metrics.cpu_usage.len() as f32;
        let mem_percent = metrics.memory_usage as f64 / metrics.memory_total as f64 * 100.0;
        log::debug!("CPU: {avg_cpu:.1}%, Memory: {mem_percent:.0}%");

        metrics_history.push(metrics);
        if metrics_history.len() > max_history {
            metrics_history.remove(0);
        }

        notification_manager.check_and_notify(metrics_history.last().unwrap(), config);

        let security_analysis = perform_security_analysis(&sys, &metrics_history, config);
        let recommendations = generate_recommendations(&metrics_history, &security_analysis, config);

        for finding in &security_analysis.zombie_processes {
            log::warn!("Zombie process: {finding}");
        }
        for finding in &security_analysis.unusual_network_activity {
            log::warn!("Network: {finding}");
        }
        for finding in &security_analysis.swap_pressure {
            log::warn!("Swap: {finding}");
        }
        for rec in &recommendations {
            log::info!("Recommendation: {rec}");
        }

        match wait_for_shutdown(&shutdown, interval) {
            LoopControl::Stop => break,
            LoopControl::Continue => {}
        }
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
            swap_total: 0,
            network_rx: 0,
            network_tx: 0,
            disk_usage: HashMap::new(),
            process_metrics: Vec::new(),
            temp_files: TempFileMetrics::default(),
            temperature: TemperatureMetrics {
                cpu_temp: None,
                gpu_temp: None,
                components: HashMap::new(),
            },
        }
    }

    #[test]
    fn a_signal_stops_the_loop_without_waiting_for_the_interval() {
        let (sender, receiver) = mpsc::channel();
        sender.send(()).unwrap();

        let waited = Instant::now();
        let control = wait_for_shutdown(&receiver, Duration::from_secs(60));

        assert!(matches!(control, LoopControl::Stop));
        assert!(waited.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_dropped_sender_stops_the_loop() {
        let (sender, receiver) = mpsc::channel::<()>();
        drop(sender);

        assert!(matches!(
            wait_for_shutdown(&receiver, Duration::from_secs(60)),
            LoopControl::Stop
        ));
    }

    #[test]
    fn the_loop_continues_when_no_signal_arrives() {
        let (_sender, receiver) = mpsc::channel::<()>();

        assert!(matches!(
            wait_for_shutdown(&receiver, Duration::from_millis(10)),
            LoopControl::Continue
        ));
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
