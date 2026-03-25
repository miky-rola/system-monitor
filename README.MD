# System Monitor

A lightweight, cross-platform system monitoring tool that runs in the background and alerts you when something needs attention. Like having a sysadmin watching your machine 24/7.

## Why not just use top or htop?

| | `top` | `htop` | `system-monitor` |
|---|---|---|---|
| CPU / memory / disk | per-process only | per-process only | per-process + system-wide trends |
| Trend analysis | - | - | tracks patterns over time (increasing, volatile, steady) |
| Anomaly detection | - | - | flags unusual network activity and resource spikes |
| Desktop notifications | - | - | alerts you when thresholds are breached |
| Background daemon | - | - | runs silently, no terminal needed |
| Temperature monitoring | - | - | CPU/GPU temps with configurable warnings |
| Temp file cleanup | - | - | find and clean old temp files by age |
| Recommendations | - | - | actionable suggestions based on system state |
| Runtime dependencies | pre-installed | ncurses | none — single static binary |
| Requires terminal open | yes | yes | no — daemon mode runs in background |

`top` and `htop` show you what's happening **right now**. system-monitor tells you **what's wrong and what to do about it**.

## Quick install

**macOS / Linux (Homebrew):**
```bash
brew tap miky-rola/tap && brew install system-monitor && brew services start system-monitor
```

**Cargo:**
```bash
cargo install system-monitor-rs
system-monitor daemon
```

**Linux (binary):**
```bash
curl -L https://github.com/miky-rola/system-monitor/releases/latest/download/system-monitor-linux-x86_64.tar.gz | tar xz && sudo mv system-monitor-linux-x86_64 /usr/local/bin/system-monitor
```

**macOS Apple Silicon (binary):**
```bash
curl -L https://github.com/miky-rola/system-monitor/releases/latest/download/system-monitor-macos-aarch64.tar.gz | tar xz && sudo mv system-monitor-macos-aarch64 /usr/local/bin/system-monitor
```

**Windows:** Download from [GitHub Releases](https://github.com/miky-rola/system-monitor/releases) and add to PATH.

## Upgrade

**Homebrew:**
```bash
brew update && brew upgrade system-monitor && brew services restart system-monitor
```

**Cargo:**
```bash
cargo install system-monitor-rs --force
```

**Binary:** Re-run the install command above — it always pulls the latest release.

### Build from source

```bash
git clone https://github.com/miky-rola/system-monitor && cd system-monitor && cargo build --release
```

## Usage

```bash
system-monitor                  # Full system report (30s collection)
system-monitor daemon           # Background monitor with notifications
system-monitor show-temp-files  # List temp files with sizes and ages
system-monitor clean-temp       # Interactively clean temp files by age
system-monitor config           # Show config path and current settings
```

### Global flags

```
--config <path>    Use a custom config file
--no-notify        Disable desktop notifications
--interval <secs>  Override daemon check interval
```

## Running as a service

**macOS (Homebrew):**
```bash
brew services start system-monitor
```

**macOS (manual):**
```bash
cp service/com.mikyrola.system-monitor.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.mikyrola.system-monitor.plist
```

**Linux (systemd):**
```bash
cp service/system-monitor.service ~/.config/systemd/user/
systemctl --user enable --now system-monitor
```

**Windows:** See [service/README-windows.md](service/README-windows.md).

## Configuration

Works out of the box. To customize, create a config file:

| Platform | Path |
|----------|------|
| Linux    | `~/.config/system-monitor/config.toml` |
| macOS    | `~/Library/Application Support/system-monitor/config.toml` |
| Windows  | `%APPDATA%\system-monitor\config.toml` |

See [config.example.toml](config.example.toml) for all options. Defaults:

| Setting | Default |
|---------|---------|
| CPU alert threshold | 90% |
| Memory alert threshold | 80% |
| Temperature warning | 80°C |
| Disk alert threshold | 90% |
| Daemon check interval | 60s |
| Notification cooldown | 5 min |

## Example output

![System Monitor Screenshot 1](https://res.cloudinary.com/dxbz61zly/image/upload/v1736711345/Screenshot_2025-01-12_193745_nmffv9.png)

![System Monitor Screenshot 2](https://res.cloudinary.com/dxbz61zly/image/upload/v1736711377/Screenshot_2025-01-12_194048_jofbyg.png)

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
