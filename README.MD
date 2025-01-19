# System Performance Monitor

A comprehensive system monitoring tool written in Rust that provides detailed analysis of system performance, security, and resource usage.

## Features

- **Real-time System Monitoring**
  - CPU usage per core
  - Memory usage and trends
  - Network activity monitoring
  - Disk usage statistics
  - Temporary file analysis and management

- **Process Analysis**
  - Detailed process resource usage
  - Process grouping by name
  - Memory and CPU usage tracking
  - Browser memory analysis

- **Security Analysis**
  - Unusual network activity monitoring
  - Resource usage anomaly detection
  - High CPU/Memory usage alerts
  - Browser resource monitoring

- **Performance Analysis**
  - CPU usage trends and patterns
  - Memory usage patterns
  - Network throughput analysis
  - System resource utilization trends
  - Temperature trend analysis

## Requirements

- Rust 1.70.0 or higher
- Linux, macOS, or Windows operating system

## Installation

1. Clone the repository:
```bash
git clone https://github.com/miky-rola/system-monitor
cd system-monitor
```

2. Build the project:
```bash
cargo build --release
```

3. Run the binary:
```bash
./target/release/system-monitor
```

## Usage

### Basic Monitoring
Run without arguments to start comprehensive system monitoring:
```bash
cargo run
```

### Available Commands
```bash
cargo run -- [command]

Commands:
  help            - Show help message
  show-temp-files - Display detailed temporary file information
  clean-temp      - Clean temporary files with age selection
  monitor         - Run continuous monitoring (default)
```

### Temporary File Management
The clean-temp command now offers interactive age selection:
- Recent files (1-2 days old)
- Moderately old files (3-5 days old)
- Old files (6+ days old)
- Option to cancel cleanup

Example output:
```
=== System Information ===
Device Name: hostname
System: Ubuntu 22.04 LTS
CPUs: 8 (Physical), 16 (Logical)

=== Performance Analysis ===
CPU Usage Trends:
Core 0: 45.2% avg, Pattern: Moderate
Memory Usage:
Average: 8.2 GB
Peak: 12.1 GB
Pattern: Moderate

=== Temperature Information ===
CPU Temperature: 65.0°C / 149.0°F
GPU Temperature: 71.2°C / 160.2°F

=== System Recommendations ===
* Schedule regular system maintenance
* Monitor browser memory usage
* Check high temperature components
```

## Example outputs
![System Monitor Screenshot 1](https://res.cloudinary.com/dxbz61zly/image/upload/v1736711345/Screenshot_2025-01-12_193745_nmffv9.png)

![System Monitor Screenshot 2](https://res.cloudinary.com/dxbz61zly/image/upload/v1736711377/Screenshot_2025-01-12_194048_jofbyg.png)

## Project Structure

```
src/
├── main.rs         # Entry point and program flow
├── types.rs        # Type definitions
├── metrics.rs      # System metrics collection
├── analysis.rs     # Data analysis
├── security.rs     # Security analysis
├── display.rs      # Output formatting and display
└── temp_manager.rs # Temporary file management
```

## Configuration

The monitor runs with the following default settings:
- Monitoring duration: 30 seconds
- Sample interval: 5 seconds
- CPU usage threshold: 90%
- Memory usage threshold: 80%
- Network baseline: 2x average throughput
- Temperature warning threshold: 80°C

## Development

### Building from Source

1. Install Rust and Cargo:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Clone and build:
```bash
git clone https://github.com/miky-rola/system-monitor
cd system-monitor
cargo build
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a Pull Request

## Dependencies

- [sysinfo](https://crates.io/crates/sysinfo) - System information gathering
- [humansize](https://crates.io/crates/humansize) - Human-readable size formatting
- [walkdir](https://crates.io/crates/walkdir) - Directory traversal for temp file management

## Contact

Miky Rola - mikyrola8@gmail.com
Project Link: https://github.com/miky-rola/system-monitor