use crate::types::{SystemMetrics, UsageTrend, NetworkTrend, };

pub fn analyze_cpu_trend(metrics_history: &[SystemMetrics]) -> Vec<UsageTrend> {
    let cpu_count = metrics_history[0].cpu_usage.len();
    let mut trends = Vec::with_capacity(cpu_count);

    for core in 0..cpu_count {
        let usages: Vec<f32> = metrics_history.iter()
            .map(|m| m.cpu_usage[core])
            .collect();

        let average = usages.iter().sum::<f32>() / usages.len() as f32;
        let peak = usages.iter().cloned().fold(0f32, f32::max);
        let pattern = calculate_usage_pattern(&usages);

        trends.push(UsageTrend {
            average: average as f64,
            peak: peak as f64,
            pattern,
        });
    }

    trends
}

pub fn analyze_memory_trend(metrics_history: &[SystemMetrics]) -> UsageTrend {
    let usages: Vec<u64> = metrics_history.iter()
        .map(|m| m.memory_usage)
        .collect();

    let average = usages.iter().sum::<u64>() / usages.len() as u64;
    let peak = usages.iter().cloned().max().unwrap_or(0);
    let pattern = calculate_usage_pattern(&usages.iter()
        .map(|&u| u as f32)
        .collect::<Vec<f32>>());

    UsageTrend {
        average: average as f64,
        peak: peak as f64,
        pattern,
    }
}

pub fn analyze_network_trend(metrics_history: &[SystemMetrics]) -> NetworkTrend {
    let duration = metrics_history.last().unwrap().timestamp
        .duration_since(metrics_history[0].timestamp)
        .as_secs_f64();

    let total_rx: u64 = metrics_history.iter().map(|m| m.network_rx).sum();
    let total_tx: u64 = metrics_history.iter().map(|m| m.network_tx).sum();

    NetworkTrend {
        rx_rate: total_rx as f64 / duration,
        tx_rate: total_tx as f64 / duration,
    }
}

pub fn classify_usage_pattern(pattern: f64) -> &'static str {
    match pattern {
        p if p < 0.2 => "Very Low",
        p if p < 0.4 => "Low",
        p if p < 0.6 => "Moderate",
        p if p < 0.8 => "High",
        _ => "Very High"
    }
}

fn calculate_usage_pattern(values: &[f32]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let max = values.iter().cloned().fold(0f32, f32::max);
    let min = values.iter().cloned().fold(f32::MAX, f32::min);
    let avg = values.iter().sum::<f32>() / values.len() as f32;

    let volatility = if max != min {
        (max - min) / avg
    } else {
        0.0
    };

    let mut trend = 0.0;
    for window in values.windows(2) {
        if window[1] > window[0] {
            trend += 1.0;
        } else if window[1] < window[0] {
            trend -= 1.0;
        }
    }
    trend /= (values.len() - 1) as f32;

    ((volatility + trend.abs() + (avg / max)) / 3.0) as f64
}