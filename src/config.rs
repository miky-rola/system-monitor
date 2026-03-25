use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct Config {
    pub monitoring: MonitoringConfig,
    pub thresholds: ThresholdConfig,
    pub notifications: NotificationConfig,
    pub daemon: DaemonConfig,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct MonitoringConfig {
    pub duration_secs: u64,
    pub sample_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct ThresholdConfig {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub temperature_celsius: f64,
    pub disk_percent: f64,
    pub swap_percent: f64,
    pub browser_memory_mb: f64,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub cpu_alert: bool,
    pub memory_alert: bool,
    pub temperature_alert: bool,
    pub disk_alert: bool,
    pub cooldown_secs: u64,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct DaemonConfig {
    pub check_interval_secs: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            duration_secs: 30,
            sample_interval_secs: 5,
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            cpu_percent: 90.0,
            memory_percent: 80.0,
            temperature_celsius: 80.0,
            disk_percent: 90.0,
            swap_percent: 80.0,
            browser_memory_mb: 1024.0,
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cpu_alert: true,
            memory_alert: true,
            temperature_alert: true,
            disk_alert: true,
            cooldown_secs: 300,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 60,
        }
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("system-monitor").join("config.toml"))
}

pub fn load(path: Option<&Path>) -> Config {
    let config_path = path
        .map(PathBuf::from)
        .or_else(default_config_path);

    let Some(config_path) = config_path else {
        return Config::default();
    };

    let Ok(contents) = std::fs::read_to_string(&config_path) else {
        return Config::default();
    };

    toml::from_str(&contents).unwrap_or_else(|e| {
        log::warn!("Failed to parse config at {}: {e}", config_path.display());
        Config::default()
    })
}

pub fn display_config(config: &Config) {
    println!("Config file location: {}", default_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown".to_string()));
    println!();
    println!("[monitoring]");
    println!("  duration_secs = {}", config.monitoring.duration_secs);
    println!("  sample_interval_secs = {}", config.monitoring.sample_interval_secs);
    println!();
    println!("[thresholds]");
    println!("  cpu_percent = {}", config.thresholds.cpu_percent);
    println!("  memory_percent = {}", config.thresholds.memory_percent);
    println!("  temperature_celsius = {}", config.thresholds.temperature_celsius);
    println!("  disk_percent = {}", config.thresholds.disk_percent);
    println!("  swap_percent = {}", config.thresholds.swap_percent);
    println!("  browser_memory_mb = {}", config.thresholds.browser_memory_mb);
    println!();
    println!("[notifications]");
    println!("  enabled = {}", config.notifications.enabled);
    println!("  cpu_alert = {}", config.notifications.cpu_alert);
    println!("  memory_alert = {}", config.notifications.memory_alert);
    println!("  temperature_alert = {}", config.notifications.temperature_alert);
    println!("  disk_alert = {}", config.notifications.disk_alert);
    println!("  cooldown_secs = {}", config.notifications.cooldown_secs);
    println!();
    println!("[daemon]");
    println!("  check_interval_secs = {}", config.daemon.check_interval_secs);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_has_expected_values() {
        let config = Config::default();

        assert_eq!(config, Config {
            monitoring: MonitoringConfig {
                duration_secs: 30,
                sample_interval_secs: 5,
            },
            thresholds: ThresholdConfig {
                cpu_percent: 90.0,
                memory_percent: 80.0,
                temperature_celsius: 80.0,
                disk_percent: 90.0,
                swap_percent: 80.0,
                browser_memory_mb: 1024.0,
            },
            notifications: NotificationConfig {
                enabled: true,
                cpu_alert: true,
                memory_alert: true,
                temperature_alert: true,
                disk_alert: true,
                cooldown_secs: 300,
            },
            daemon: DaemonConfig {
                check_interval_secs: 60,
            },
        });
    }

    #[test]
    fn partial_toml_fills_missing_fields_with_defaults() {
        let toml_content = r#"
[thresholds]
cpu_percent = 75.0
"#;
        let config: Config = toml::from_str(toml_content).unwrap();

        assert_eq!(config.thresholds.cpu_percent, 75.0);
        assert_eq!(config.thresholds.memory_percent, 80.0);
        assert_eq!(config.monitoring, MonitoringConfig::default());
        assert_eq!(config.notifications, NotificationConfig::default());
        assert_eq!(config.daemon, DaemonConfig::default());
    }

    #[test]
    fn full_toml_parses_all_fields() {
        let toml_content = r#"
[monitoring]
duration_secs = 60
sample_interval_secs = 10

[thresholds]
cpu_percent = 75.0
memory_percent = 70.0
temperature_celsius = 85.0
disk_percent = 95.0
swap_percent = 80.0
browser_memory_mb = 1024.0

[notifications]
enabled = false
cpu_alert = false
memory_alert = true
temperature_alert = false
disk_alert = true
cooldown_secs = 600

[daemon]
check_interval_secs = 120
"#;
        let config: Config = toml::from_str(toml_content).unwrap();

        assert_eq!(config, Config {
            monitoring: MonitoringConfig {
                duration_secs: 60,
                sample_interval_secs: 10,
            },
            thresholds: ThresholdConfig {
                cpu_percent: 75.0,
                memory_percent: 70.0,
                temperature_celsius: 85.0,
                disk_percent: 95.0,
                swap_percent: 80.0,
                browser_memory_mb: 1024.0,
            },
            notifications: NotificationConfig {
                enabled: false,
                cpu_alert: false,
                memory_alert: true,
                temperature_alert: false,
                disk_alert: true,
                cooldown_secs: 600,
            },
            daemon: DaemonConfig {
                check_interval_secs: 120,
            },
        });
    }

    #[test]
    fn missing_file_returns_defaults() {
        let config = load(Some(Path::new("/nonexistent/path/config.toml")));
        assert_eq!(config, Config::default());
    }

    #[test]
    fn invalid_toml_returns_defaults() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"this is not valid toml {{{").unwrap();

        let config = load(Some(tmpfile.path()));
        assert_eq!(config, Config::default());
    }

    #[test]
    fn valid_file_parses_correctly() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, r#"
[daemon]
check_interval_secs = 30
"#).unwrap();

        let config = load(Some(tmpfile.path()));
        assert_eq!(config.daemon.check_interval_secs, 30);
        assert_eq!(config.monitoring, MonitoringConfig::default());
    }
}
