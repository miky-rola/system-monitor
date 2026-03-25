# System Monitor

A lightweight, cross-platform system monitoring tool with desktop notifications. Monitors CPU, memory, disk, temperature, and network — alerting you when something needs attention.

## Install

### Homebrew (macOS / Linux)

```bash
brew tap miky-rola/tap
brew install system-monitor
```

### Download binary

Grab the latest release for your platform from [GitHub Releases](https://github.com/miky-rola/system-monitor/releases).

### Cargo

```bash
cargo install system-monitor
```

### Build from source

```bash
git clone https://github.com/miky-rola/system-monitor
cd system-monitor
cargo build --release
```

## Usage

### One-shot monitoring (default)

```bash
system-monitor
```

Collects system metrics over 30 seconds and prints a full report: CPU trends, memory usage, temperature, security analysis, and recommendations.

### Daemon mode

```bash
system-monitor daemon
```

Runs continuously in the background, checking your system every 60 seconds. Sends desktop notifications when CPU, memory, temperature, or disk usage exceeds your configured thresholds.

### All commands

```
system-monitor                  Run one-shot monitoring (default)
system-monitor monitor          Same as above
system-monitor daemon           Run as continuous background monitor
system-monitor show-temp-files  List temporary files with sizes and ages
system-monitor clean-temp       Interactively clean temp files by age
system-monitor config           Show current configuration and config path
```

### Global flags

```
--config <path>    Use a custom config file
--no-notify        Disable desktop notifications
--interval <secs>  Override daemon check interval
```

## Configuration

System monitor works out of the box with sensible defaults. To customize, create a config file:

| Platform | Path |
|----------|------|
| Linux    | `~/.config/system-monitor/config.toml` |
| macOS    | `~/Library/Application Support/system-monitor/config.toml` |
| Windows  | `%APPDATA%\system-monitor\config.toml` |

See [config.example.toml](config.example.toml) for all options. Key defaults:

| Setting | Default |
|---------|---------|
| CPU alert threshold | 90% |
| Memory alert threshold | 80% |
| Temperature warning | 80°C |
| Disk alert threshold | 90% |
| Daemon check interval | 60s |
| Notification cooldown | 5 min |

## Running as a service

### macOS (launchd)

```bash
cp service/com.mikyrola.system-monitor.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.mikyrola.system-monitor.plist
```

Or with Homebrew: `brew services start system-monitor`

### Linux (systemd)

```bash
cp service/system-monitor.service ~/.config/systemd/user/
systemctl --user enable --now system-monitor
```

### Windows

See [service/README-windows.md](service/README-windows.md).

## Features

- Real-time CPU, memory, network, disk, and temperature monitoring
- Desktop notifications with configurable thresholds and cooldowns
- Process analysis with grouping by name
- Security anomaly detection (unusual network activity, high resource usage)
- Temporary file management (list, clean by age)
- Daemon mode for continuous background monitoring
- Cross-platform: macOS, Linux, Windows

## Example output

![System Monitor Screenshot 1](https://res.cloudinary.com/dxbz61zly/image/upload/v1736711345/Screenshot_2025-01-12_193745_nmffv9.png)

![System Monitor Screenshot 2](https://res.cloudinary.com/dxbz61zly/image/upload/v1736711377/Screenshot_2025-01-12_194048_jofbyg.png)

## Project structure

```
src/
├── main.rs           Entry point and CLI
├── config.rs         Configuration loading and defaults
├── daemon.rs         Continuous monitoring loop
├── notifications.rs  Desktop notification delivery
├── metrics.rs        System metrics collection
├── analysis.rs       Trend analysis and pattern detection
├── security.rs       Security analysis and recommendations
├── display.rs        Output formatting
├── types.rs          Type definitions
└── temp_manager.rs   Temporary file management
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Write tests first, then implement
4. Run `cargo test && cargo clippy -- -D warnings`
5. Submit a Pull Request

## License

MIT - see [LICENSE](LICENSE)

## Contact

Miky Rola - mikyrola8@gmail.com
Project Link: https://github.com/miky-rola/system-monitor
