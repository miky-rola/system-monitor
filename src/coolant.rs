use std::process::Command;
use sysinfo::PidExt;
use crate::config::CoolantConfig;
use crate::types::ProcessMetrics;

const CRITICAL_PROCESSES: &[&str] = &[
    "kernel_task",
    "launchd",
    "windowserver",
    "systemd",
    "init",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "system",
];

const MIN_CPU_PERCENT: f32 = 1.0;

pub struct CoolantReport {
    pub cooled: Vec<String>,
    pub errors: Vec<String>,
}

pub fn select_targets<'a>(
    processes: &'a [ProcessMetrics],
    cfg: &CoolantConfig,
) -> Vec<&'a ProcessMetrics> {
    let self_pid = std::process::id();
    let mut candidates: Vec<&ProcessMetrics> = processes
        .iter()
        .filter(|process| {
            let pid = process.pid.as_u32();
            let name = process.name.to_lowercase();
            process.cpu_usage > MIN_CPU_PERCENT
                && pid != self_pid
                && pid != 0
                && pid != 1
                && !CRITICAL_PROCESSES.contains(&name.as_str())
        })
        .collect();
    candidates.sort_by(|a, b| b.cpu_usage.total_cmp(&a.cpu_usage));
    candidates.truncate(cfg.top_processes);
    candidates
}

pub fn lower_priority(pid: sysinfo::Pid, nice_level: i32) -> Result<(), String> {
    let raw = pid.as_u32();

    #[cfg(unix)]
    let output = {
        // Coolant only lowers priority; clamp so a negative value can't raise it.
        let level = nice_level.clamp(0, 19);
        Command::new("renice")
            .args([level.to_string(), "-p".to_string(), raw.to_string()])
            .output()
    };

    #[cfg(windows)]
    let output = {
        let _ = nice_level;
        Command::new("powershell")
            .args([
                "-NoProfile".to_string(),
                "-Command".to_string(),
                format!("(Get-Process -Id {raw}).PriorityClass='Idle'"),
            ])
            .output()
    };

    match output {
        Ok(result) if result.status.success() => Ok(()),
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let message = stderr.trim();
            if message.is_empty() {
                Err(format!("exited with {}", result.status))
            } else {
                Err(message.to_string())
            }
        }
        Err(error) => Err(error.to_string()),
    }
}

pub fn apply_coolant(targets: &[&ProcessMetrics], cfg: &CoolantConfig) -> CoolantReport {
    let mut cooled = Vec::new();
    let mut errors = Vec::new();

    for target in targets {
        let label = format!("{} (pid {})", target.name, target.pid.as_u32());
        match lower_priority(target.pid, cfg.nice_level) {
            Ok(()) => cooled.push(label),
            Err(error) => errors.push(format!("{label}: {error}")),
        }
    }

    CoolantReport { cooled, errors }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(name: &str, pid: usize, cpu_usage: f32) -> ProcessMetrics {
        ProcessMetrics {
            name: name.to_string(),
            pid: sysinfo::Pid::from(pid),
            cpu_usage,
            memory_usage: 0,
            disk_usage: 0,
        }
    }

    fn target_pids(targets: &[&ProcessMetrics]) -> Vec<u32> {
        targets.iter().map(|process| process.pid.as_u32()).collect()
    }

    fn config(top_processes: usize) -> CoolantConfig {
        CoolantConfig {
            enabled: true,
            top_processes,
            nice_level: 15,
        }
    }

    #[test]
    fn selects_top_cpu_processes_in_descending_order() {
        let processes = vec![
            process("light", 100, 5.0),
            process("hottest", 101, 90.0),
            process("medium", 102, 40.0),
        ];

        let targets = select_targets(&processes, &config(2));

        assert_eq!(target_pids(&targets), vec![101, 102]);
    }

    #[test]
    fn skips_processes_below_cpu_floor() {
        let processes = vec![
            process("idle", 200, 0.5),
            process("busy", 201, 12.0),
        ];

        let targets = select_targets(&processes, &config(5));

        assert_eq!(target_pids(&targets), vec![201]);
    }

    #[test]
    fn excludes_critical_processes_and_low_pids() {
        let processes = vec![
            process("launchd", 50, 99.0),
            process("WindowServer", 51, 95.0),
            process("init", 0, 80.0),
            process("kernel_task", 1, 70.0),
            process("user-app", 300, 60.0),
        ];

        let targets = select_targets(&processes, &config(10));

        assert_eq!(target_pids(&targets), vec![300]);
    }

    #[test]
    fn excludes_our_own_process() {
        let self_pid = std::process::id() as usize;
        let processes = vec![
            process("system-monitor", self_pid, 99.0),
            process("other", self_pid + 1, 50.0),
        ];

        let targets = select_targets(&processes, &config(10));

        assert_eq!(target_pids(&targets), vec![(self_pid + 1) as u32]);
    }
}
