# System Performance Monitor

A comprehensive system monitoring tool written in Rust that provides detailed analysis of system performance, security, and resource usage.

## Features

- **Real-time System Monitoring**
  - CPU usage per core
  - Memory usage and trends
  - Network activity monitoring
  - Disk usage statistics

- **Process Analysis**
  - Detailed process resource usage
  - Process grouping by name
  - Memory and CPU usage tracking

- **Security Analysis**
  - Unusual network activity monitoring
  - Resource usage anomaly detection

- **Performance Analysis**
  - CPU usage trends and patterns
  - Memory usage patterns
  - Network throughput analysis
  - System resource utilization trends

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

Simply run the program and it will:
1. Display current process resource usage
2. Collect system metrics for 30 seconds
3. Analyze system performance
4. Provide security analysis
5. Generate system recommendations

Example output:
```
=== System Information ===
Device Name: hostname
System: Ubuntu 22.04 LTS
CPUs: 8 (Physical), 16 (Logical)

=== Performance Analysis ===
CPU Usage Trends:
Core 0: 45.2% avg, Pattern: Moderate
...


=== System Recommendations ===
* Schedule regular system maintenance:
  - Update system and application software
  - Monitor system performance over time
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
└── display.rs      # Output formatting and display
```

## Configuration

The monitor runs with the following default settings:
- Monitoring duration: 30 seconds
- Sample interval: 5 seconds
- CPU usage threshold: 90%
- Memory usage threshold: 80%
- Network baseline: 2x average throughput

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

## Acknowledgments

- [sysinfo](https://crates.io/crates/sysinfo) - System information gathering
- [humansize](https://crates.io/crates/humansize) - Human-readable size formatting
- [walkdir](https://crates.io/crates/walkdir)- scanning

## Contact

Miky Rola - mikyrola8@gmail.com
Project Link:https://github.com/miky-rola/system-monitor