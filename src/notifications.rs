use std::collections::HashMap;
use std::time::Instant;
use crate::config::Config;
use crate::types::SystemMetrics;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AlertKind {
    Cpu,
    Memory,
    Temperature,
    Disk,
}

pub struct NotificationManager {
    last_sent: HashMap<AlertKind, Instant>,
    previous_state: HashMap<AlertKind, bool>,
    cooldown_secs: u64,
}

impl NotificationManager {
    pub fn new(cooldown_secs: u64) -> Self {
        Self {
            last_sent: HashMap::new(),
            previous_state: HashMap::new(),
            cooldown_secs,
        }
    }

    pub fn check_and_notify(&mut self, metrics: &SystemMetrics, config: &Config) {
        if !config.notifications.enabled {
            return;
        }

        let alerts = self.evaluate_alerts(metrics, config);

        for (kind, is_alerting) in alerts {
            let was_alerting = self.previous_state.get(&kind).copied().unwrap_or(false);
            self.previous_state.insert(kind.clone(), is_alerting);

            if is_alerting && self.should_notify(&kind, was_alerting) {
                let (title, body) = alert_message(&kind, metrics, config);
                self.send_notification(&title, &body, kind);
            }
        }
    }

    fn evaluate_alerts(&self, metrics: &SystemMetrics, config: &Config) -> Vec<(AlertKind, bool)> {
        let mut alerts = Vec::new();

        if config.notifications.cpu_alert {
            let avg_cpu = metrics.cpu_usage.iter().sum::<f32>() / metrics.cpu_usage.len() as f32;
            alerts.push((AlertKind::Cpu, f64::from(avg_cpu) > config.thresholds.cpu_percent));
        }

        if config.notifications.memory_alert {
            let memory_percent = metrics.memory_usage as f64 / metrics.memory_total as f64 * 100.0;
            alerts.push((AlertKind::Memory, memory_percent > config.thresholds.memory_percent));
        }

        if config.notifications.temperature_alert {
            let max_temp = metrics.temperature.components.values()
                .map(|r| r.celsius)
                .fold(0.0_f32, f32::max);
            alerts.push((AlertKind::Temperature, f64::from(max_temp) > config.thresholds.temperature_celsius));
        }

        if config.notifications.disk_alert {
            let any_disk_high = metrics.disk_usage.values().any(|d| {
                if d.total == 0 { return false; }
                let percent = d.used as f64 / d.total as f64 * 100.0;
                percent > config.thresholds.disk_percent
            });
            alerts.push((AlertKind::Disk, any_disk_high));
        }

        alerts
    }

    fn should_notify(&self, kind: &AlertKind, was_alerting: bool) -> bool {
        if !was_alerting {
            return true;
        }

        match self.last_sent.get(kind) {
            Some(last) => last.elapsed().as_secs() >= self.cooldown_secs,
            None => true,
        }
    }

    #[cfg(test)]
    pub fn last_sent_times(&self) -> &HashMap<AlertKind, Instant> {
        &self.last_sent
    }

    fn send_notification(&mut self, title: &str, body: &str, kind: AlertKind) {
        match notify_rust::Notification::new()
            .summary(title)
            .body(body)
            .show()
        {
            Ok(_) => log::info!("Notification sent: {title}"),
            Err(e) => log::warn!("Failed to send notification: {e}"),
        }
        self.last_sent.insert(kind, Instant::now());
    }
}

fn alert_message(kind: &AlertKind, metrics: &SystemMetrics, config: &Config) -> (String, String) {
    match kind {
        AlertKind::Cpu => {
            let avg = metrics.cpu_usage.iter().sum::<f32>() / metrics.cpu_usage.len() as f32;
            (
                "High CPU Usage".to_string(),
                format!("Average CPU at {avg:.1}% (threshold: {}%)", config.thresholds.cpu_percent),
            )
        }
        AlertKind::Memory => {
            let percent = metrics.memory_usage as f64 / metrics.memory_total as f64 * 100.0;
            (
                "High Memory Usage".to_string(),
                format!("Memory at {percent:.0}% (threshold: {:.0}%)", config.thresholds.memory_percent),
            )
        }
        AlertKind::Temperature => {
            let max_temp = metrics.temperature.components.values()
                .map(|r| r.celsius)
                .fold(0.0_f32, f32::max);
            (
                "High Temperature".to_string(),
                format!("Temperature at {max_temp:.1}°C (threshold: {}°C)", config.thresholds.temperature_celsius),
            )
        }
        AlertKind::Disk => {
            (
                "High Disk Usage".to_string(),
                format!("Disk usage exceeds {}%", config.thresholds.disk_percent),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;

    fn make_metrics(cpu: f32, memory_usage: u64, memory_total: u64) -> SystemMetrics {
        SystemMetrics {
            timestamp: Instant::now(),
            cpu_usage: vec![cpu],
            memory_usage,
            memory_total,
            swap_usage: 0,
            swap_total: 0,
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

    fn default_config() -> Config {
        Config::default()
    }

    #[test]
    fn no_alerts_when_below_thresholds() {
        let manager = NotificationManager::new(300);
        let metrics = make_metrics(10.0, 40, 100);
        let config = default_config();

        let alerts = manager.evaluate_alerts(&metrics, &config);
        assert!(alerts.iter().all(|(_, alerting)| !alerting));
    }

    #[test]
    fn high_cpu_triggers_alert() {
        let manager = NotificationManager::new(300);
        let metrics = make_metrics(95.0, 40, 100);
        let config = default_config();

        let alerts = manager.evaluate_alerts(&metrics, &config);
        let cpu_alert = alerts.iter().find(|(k, _)| *k == AlertKind::Cpu);
        assert_eq!(cpu_alert, Some(&(AlertKind::Cpu, true)));
    }

    #[test]
    fn high_memory_triggers_alert() {
        let manager = NotificationManager::new(300);
        let metrics = make_metrics(10.0, 85, 100);
        let config = default_config();

        let alerts = manager.evaluate_alerts(&metrics, &config);
        let mem_alert = alerts.iter().find(|(k, _)| *k == AlertKind::Memory);
        assert_eq!(mem_alert, Some(&(AlertKind::Memory, true)));
    }

    #[test]
    fn disabled_notifications_produces_no_alerts_on_check() {
        let mut manager = NotificationManager::new(300);
        let metrics = make_metrics(95.0, 90, 100);
        let mut config = default_config();
        config.notifications.enabled = false;

        manager.check_and_notify(&metrics, &config);
        assert!(manager.last_sent.is_empty());
    }

    #[test]
    fn disabled_cpu_alert_skips_cpu() {
        let manager = NotificationManager::new(300);
        let metrics = make_metrics(95.0, 40, 100);
        let mut config = default_config();
        config.notifications.cpu_alert = false;

        let alerts = manager.evaluate_alerts(&metrics, &config);
        assert!(!alerts.iter().any(|(k, _)| *k == AlertKind::Cpu));
    }

    #[test]
    fn should_notify_on_first_transition() {
        let manager = NotificationManager::new(300);
        assert!(manager.should_notify(&AlertKind::Cpu, false));
    }

    #[test]
    fn should_not_notify_during_cooldown() {
        let mut manager = NotificationManager::new(300);
        manager.last_sent.insert(AlertKind::Cpu, Instant::now());
        assert!(!manager.should_notify(&AlertKind::Cpu, true));
    }

    #[test]
    fn custom_thresholds_respected() {
        let manager = NotificationManager::new(300);
        let metrics = make_metrics(80.0, 60, 100);
        let mut config = default_config();
        config.thresholds.cpu_percent = 70.0;
        config.thresholds.memory_percent = 50.0;

        let alerts = manager.evaluate_alerts(&metrics, &config);

        let cpu_alert = alerts.iter().find(|(k, _)| *k == AlertKind::Cpu);
        assert_eq!(cpu_alert, Some(&(AlertKind::Cpu, true)));

        let mem_alert = alerts.iter().find(|(k, _)| *k == AlertKind::Memory);
        assert_eq!(mem_alert, Some(&(AlertKind::Memory, true)));
    }

    #[test]
    fn high_temperature_triggers_alert() {
        let manager = NotificationManager::new(300);
        let mut metrics = make_metrics(10.0, 40, 100);
        metrics.temperature.components.insert(
            "CPU".to_string(),
            TemperatureReading { celsius: 95.0, fahrenheit: 203.0 },
        );
        let config = default_config();

        let alerts = manager.evaluate_alerts(&metrics, &config);
        let temp_alert = alerts.iter().find(|(k, _)| *k == AlertKind::Temperature);
        assert_eq!(temp_alert, Some(&(AlertKind::Temperature, true)));
    }

    #[test]
    fn high_disk_triggers_alert() {
        let manager = NotificationManager::new(300);
        let mut metrics = make_metrics(10.0, 40, 100);
        metrics.disk_usage.insert("/".to_string(), DiskMetrics {
            total: 1000,
            used: 950,
            read_rate: 0.0,
            write_rate: 0.0,
        });
        let config = default_config();

        let alerts = manager.evaluate_alerts(&metrics, &config);
        let disk_alert = alerts.iter().find(|(k, _)| *k == AlertKind::Disk);
        assert_eq!(disk_alert, Some(&(AlertKind::Disk, true)));
    }

    #[test]
    fn alert_message_formats_correctly() {
        let metrics = make_metrics(95.0, 85, 100);
        let config = default_config();

        let (title, body) = alert_message(&AlertKind::Cpu, &metrics, &config);
        assert_eq!(title, "High CPU Usage");
        assert!(body.contains("95.0%"));
        assert!(body.contains("90%"));

        let (title, body) = alert_message(&AlertKind::Memory, &metrics, &config);
        assert_eq!(title, "High Memory Usage");
        assert!(body.contains("85%"));
        assert!(body.contains("80%"), "body was: {body}");
    }
}
