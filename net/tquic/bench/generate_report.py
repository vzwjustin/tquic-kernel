#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
TQUIC Benchmark Report Generator

Generates an HTML report with charts from benchmark JSON results.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Target metrics
TARGET_METRICS = {
    'throughput_gbps': 9.0,
    'multipath_efficiency': 0.95,
    'failover_ms': 100,
    'memory_kb': 64,
    'connection_rtt': 1,
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TQUIC Performance Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --primary-color: #2563eb;
            --success-color: #16a34a;
            --warning-color: #ca8a04;
            --error-color: #dc2626;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, var(--primary-color), #1d4ed8);
            color: white;
            padding: 40px 20px;
            text-align: center;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}

        header .subtitle {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card {{
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 24px;
            border: 1px solid var(--border-color);
        }}

        .card h2 {{
            font-size: 1.25rem;
            margin-bottom: 16px;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .metric {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid var(--border-color);
        }}

        .metric:last-child {{
            border-bottom: none;
        }}

        .metric-label {{
            font-weight: 500;
            color: #64748b;
        }}

        .metric-value {{
            font-size: 1.5rem;
            font-weight: 700;
        }}

        .metric-value.pass {{
            color: var(--success-color);
        }}

        .metric-value.fail {{
            color: var(--error-color);
        }}

        .metric-value.warn {{
            color: var(--warning-color);
        }}

        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
        }}

        .status-badge.pass {{
            background: #dcfce7;
            color: var(--success-color);
        }}

        .status-badge.fail {{
            background: #fee2e2;
            color: var(--error-color);
        }}

        .chart-container {{
            position: relative;
            height: 300px;
            margin-top: 20px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: #f1f5f9;
            font-weight: 600;
            color: #475569;
        }}

        tr:hover {{
            background: #f8fafc;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--card-bg);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid var(--border-color);
        }}

        .summary-card .value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
        }}

        .summary-card .label {{
            color: #64748b;
            margin-top: 8px;
        }}

        footer {{
            text-align: center;
            padding: 40px 20px;
            color: #64748b;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }}

        .percentile-bar {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .percentile-bar .bar {{
            flex-grow: 1;
            height: 8px;
            background: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
        }}

        .percentile-bar .bar-fill {{
            height: 100%;
            background: var(--primary-color);
            border-radius: 4px;
        }}

        @media (max-width: 768px) {{
            header h1 {{
                font-size: 1.75rem;
            }}

            .grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <h1>TQUIC Performance Report</h1>
        <p class="subtitle">Generated: {timestamp}</p>
    </header>

    <div class="container">
        <!-- Summary Cards -->
        <div class="summary-grid">
            {summary_cards}
        </div>

        <!-- Target Metrics -->
        <div class="card" style="margin-bottom: 30px;">
            <h2>Target Metrics Comparison</h2>
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Target</th>
                        <th>Actual</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {target_metrics_rows}
                </tbody>
            </table>
        </div>

        <div class="grid">
            <!-- Throughput Results -->
            {throughput_card}

            <!-- Latency Results -->
            {latency_card}

            <!-- Connection Results -->
            {connection_card}

            <!-- Failover Results -->
            {failover_card}
        </div>

        <!-- Charts -->
        <div class="grid">
            <div class="card">
                <h2>Throughput by Packet Size</h2>
                <div class="chart-container">
                    <canvas id="throughputChart"></canvas>
                </div>
            </div>

            <div class="card">
                <h2>Latency Distribution</h2>
                <div class="chart-container">
                    <canvas id="latencyChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Scheduler Comparison -->
        {scheduler_card}
    </div>

    <footer>
        <p>TQUIC Kernel Module Performance Benchmarks</p>
        <p>Report generated by generate_report.py</p>
    </footer>

    <script>
        // Throughput Chart
        {throughput_chart_js}

        // Latency Chart
        {latency_chart_js}
    </script>
</body>
</html>
"""


def load_json_file(path):
    """Load a JSON file if it exists."""
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return None
    return None


def format_value(value, unit='', decimals=2):
    """Format a numeric value with unit."""
    if value is None:
        return 'N/A'
    if isinstance(value, float):
        return f'{value:.{decimals}f}{unit}'
    return f'{value}{unit}'


def check_threshold(value, target, higher_is_better=True):
    """Check if a value meets the target threshold."""
    if value is None:
        return 'warn'
    if higher_is_better:
        return 'pass' if value >= target else 'fail'
    else:
        return 'pass' if value <= target else 'fail'


def generate_summary_cards(data):
    """Generate HTML for summary cards."""
    cards = []

    # Throughput
    if data.get('throughput'):
        results = data['throughput'].get('results', [])
        if results:
            max_gbps = max(r.get('gbps', 0) for r in results)
            cards.append(f'''
            <div class="summary-card">
                <div class="value">{max_gbps:.2f}</div>
                <div class="label">Max Throughput (Gbps)</div>
            </div>
            ''')

    # Latency
    if data.get('latency'):
        lat = data['latency'].get('latency', {})
        p99 = lat.get('p99_us', 0)
        cards.append(f'''
        <div class="summary-card">
            <div class="value">{p99:.1f}</div>
            <div class="label">P99 Latency (us)</div>
        </div>
        ''')

    # Connections
    if data.get('connections'):
        conn = data['connections'].get('connections', {})
        cps = conn.get('cps', 0)
        cards.append(f'''
        <div class="summary-card">
            <div class="value">{cps:.0f}</div>
            <div class="label">Connections/sec</div>
        </div>
        ''')

    # Failover
    if data.get('failover'):
        fail = data['failover'].get('failover', {})
        failover_ms = fail.get('failover_time_ms', 0)
        cards.append(f'''
        <div class="summary-card">
            <div class="value">{failover_ms:.1f}</div>
            <div class="label">Failover Time (ms)</div>
        </div>
        ''')

    return '\n'.join(cards)


def generate_target_metrics_rows(data):
    """Generate HTML table rows for target metrics."""
    rows = []

    # Throughput
    throughput_val = None
    if data.get('throughput'):
        results = data['throughput'].get('results', [])
        if results:
            throughput_val = max(r.get('gbps', 0) for r in results)

    status = check_threshold(throughput_val, TARGET_METRICS['throughput_gbps'])
    rows.append(f'''
    <tr>
        <td>Single-path Throughput</td>
        <td>&gt;{TARGET_METRICS['throughput_gbps']} Gbps</td>
        <td>{format_value(throughput_val, ' Gbps')}</td>
        <td><span class="status-badge {status}">{status.upper()}</span></td>
    </tr>
    ''')

    # Failover time
    failover_val = None
    if data.get('failover'):
        failover_val = data['failover'].get('failover', {}).get('failover_time_ms')

    status = check_threshold(failover_val, TARGET_METRICS['failover_ms'], higher_is_better=False)
    rows.append(f'''
    <tr>
        <td>Failover Time</td>
        <td>&lt;{TARGET_METRICS['failover_ms']} ms</td>
        <td>{format_value(failover_val, ' ms')}</td>
        <td><span class="status-badge {status}">{status.upper()}</span></td>
    </tr>
    ''')

    # Memory per connection
    memory_val = None
    if data.get('connections'):
        memory_val = data['connections'].get('connections', {}).get('memory_per_conn_kb')

    status = check_threshold(memory_val, TARGET_METRICS['memory_kb'], higher_is_better=False)
    rows.append(f'''
    <tr>
        <td>Memory per Connection</td>
        <td>&lt;{TARGET_METRICS['memory_kb']} KB</td>
        <td>{format_value(memory_val, ' KB')}</td>
        <td><span class="status-badge {status}">{status.upper()}</span></td>
    </tr>
    ''')

    return '\n'.join(rows)


def generate_throughput_card(data):
    """Generate HTML for throughput results card."""
    if not data:
        return '<div class="card"><h2>Throughput</h2><p>No data available</p></div>'

    results = data.get('results', [])
    if not results:
        return '<div class="card"><h2>Throughput</h2><p>No results</p></div>'

    rows = []
    for r in results:
        status = check_threshold(r.get('gbps', 0), TARGET_METRICS['throughput_gbps'])
        rows.append(f'''
        <tr>
            <td>{r.get('packet_size', 'N/A')} B</td>
            <td class="{status}">{r.get('gbps', 0):.3f} Gbps</td>
            <td>{r.get('pps', 0):,}</td>
            <td>{r.get('cpu_percent', 0):.1f}%</td>
        </tr>
        ''')

    return f'''
    <div class="card">
        <h2>Throughput Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Packet Size</th>
                    <th>Throughput</th>
                    <th>Packets/sec</th>
                    <th>CPU Usage</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    '''


def generate_latency_card(data):
    """Generate HTML for latency results card."""
    if not data:
        return '<div class="card"><h2>Latency</h2><p>No data available</p></div>'

    lat = data.get('latency', {})

    return f'''
    <div class="card">
        <h2>Latency Results</h2>
        <div class="metric">
            <span class="metric-label">Average RTT</span>
            <span class="metric-value">{lat.get('rtt_avg_us', 0):.2f} us</span>
        </div>
        <div class="metric">
            <span class="metric-label">Min RTT</span>
            <span class="metric-value">{lat.get('rtt_min_us', 0):.2f} us</span>
        </div>
        <div class="metric">
            <span class="metric-label">Max RTT</span>
            <span class="metric-value">{lat.get('rtt_max_us', 0):.2f} us</span>
        </div>
        <div class="metric">
            <span class="metric-label">Jitter</span>
            <span class="metric-value">{lat.get('jitter_us', 0):.2f} us</span>
        </div>
        <div class="metric">
            <span class="metric-label">P50</span>
            <span class="metric-value">{lat.get('p50_us', 0):.2f} us</span>
        </div>
        <div class="metric">
            <span class="metric-label">P95</span>
            <span class="metric-value">{lat.get('p95_us', 0):.2f} us</span>
        </div>
        <div class="metric">
            <span class="metric-label">P99</span>
            <span class="metric-value">{lat.get('p99_us', 0):.2f} us</span>
        </div>
        <div class="metric">
            <span class="metric-label">P99.9</span>
            <span class="metric-value">{lat.get('p999_us', 0):.2f} us</span>
        </div>
    </div>
    '''


def generate_connection_card(data):
    """Generate HTML for connection results card."""
    if not data:
        return '<div class="card"><h2>Connections</h2><p>No data available</p></div>'

    conn = data.get('connections', {})
    mem_status = check_threshold(
        conn.get('memory_per_conn_kb'),
        TARGET_METRICS['memory_kb'],
        higher_is_better=False
    )

    return f'''
    <div class="card">
        <h2>Connection Results</h2>
        <div class="metric">
            <span class="metric-label">Connections/sec</span>
            <span class="metric-value">{conn.get('cps', 0):.0f}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Total Connections</span>
            <span class="metric-value">{conn.get('total', 0):,}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Successful</span>
            <span class="metric-value pass">{conn.get('successful', 0):,}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Failed</span>
            <span class="metric-value fail">{conn.get('failed', 0):,}</span>
        </div>
        <div class="metric">
            <span class="metric-label">0-RTT Rate</span>
            <span class="metric-value">{conn.get('zero_rtt_rate', 0)*100:.1f}%</span>
        </div>
        <div class="metric">
            <span class="metric-label">Memory per Connection</span>
            <span class="metric-value {mem_status}">{conn.get('memory_per_conn_kb', 0):.2f} KB</span>
        </div>
        <div class="metric">
            <span class="metric-label">Avg Setup Time</span>
            <span class="metric-value">{conn.get('avg_setup_time_us', 0):.2f} us</span>
        </div>
    </div>
    '''


def generate_failover_card(data):
    """Generate HTML for failover results card."""
    if not data:
        return '<div class="card"><h2>Failover</h2><p>No data available</p></div>'

    fail = data.get('failover', {})
    status = check_threshold(
        fail.get('failover_time_ms'),
        TARGET_METRICS['failover_ms'],
        higher_is_better=False
    )

    return f'''
    <div class="card">
        <h2>Failover Results</h2>
        <div class="metric">
            <span class="metric-label">Failover Time</span>
            <span class="metric-value {status}">{fail.get('failover_time_ms', 0):.2f} ms</span>
        </div>
        <div class="metric">
            <span class="metric-label">Recovery Time</span>
            <span class="metric-value">{fail.get('recovery_time_ms', 0):.2f} ms</span>
        </div>
        <div class="metric">
            <span class="metric-label">Packets Lost</span>
            <span class="metric-value">{fail.get('packets_lost', 0):,}</span>
        </div>
        <div class="metric">
            <span class="metric-label">BW During Failover</span>
            <span class="metric-value">{fail.get('bandwidth_during_failover', 0):.3f} Gbps</span>
        </div>
        <div class="metric">
            <span class="metric-label">Iterations</span>
            <span class="metric-value">{fail.get('iterations', 0)}</span>
        </div>
    </div>
    '''


def generate_scheduler_card(data):
    """Generate HTML for scheduler comparison card."""
    if not data:
        return ''

    results = data.get('scheduler_results', [])
    if not results:
        return ''

    rows = []
    for r in results:
        rows.append(f'''
        <tr>
            <td>{r.get('algorithm', 'N/A')}</td>
            <td>{r.get('throughput_gbps', 0):.3f} Gbps</td>
            <td>{r.get('scheduling_overhead_us', 0):.3f} us</td>
            <td>{r.get('fairness_index', 0):.4f}</td>
        </tr>
        ''')

    return f'''
    <div class="card" style="grid-column: 1 / -1;">
        <h2>Scheduler Comparison</h2>
        <table>
            <thead>
                <tr>
                    <th>Algorithm</th>
                    <th>Throughput</th>
                    <th>Overhead</th>
                    <th>Fairness Index</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    '''


def generate_throughput_chart_js(data):
    """Generate JavaScript for throughput chart."""
    if not data:
        return '// No throughput data'

    results = data.get('results', [])
    if not results:
        return '// No throughput results'

    labels = [str(r.get('packet_size', 0)) for r in results]
    gbps = [r.get('gbps', 0) for r in results]

    return f'''
    new Chart(document.getElementById('throughputChart'), {{
        type: 'bar',
        data: {{
            labels: {json.dumps(labels)},
            datasets: [{{
                label: 'Throughput (Gbps)',
                data: {json.dumps(gbps)},
                backgroundColor: 'rgba(37, 99, 235, 0.8)',
                borderColor: 'rgba(37, 99, 235, 1)',
                borderWidth: 1
            }}, {{
                label: 'Target',
                data: {json.dumps([TARGET_METRICS['throughput_gbps']] * len(results))},
                type: 'line',
                borderColor: 'rgba(220, 38, 38, 0.8)',
                borderDash: [5, 5],
                fill: false,
                pointRadius: 0
            }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{
                y: {{
                    beginAtZero: true,
                    title: {{
                        display: true,
                        text: 'Gbps'
                    }}
                }},
                x: {{
                    title: {{
                        display: true,
                        text: 'Packet Size (bytes)'
                    }}
                }}
            }}
        }}
    }});
    '''


def generate_latency_chart_js(data):
    """Generate JavaScript for latency chart."""
    if not data:
        return '// No latency data'

    lat = data.get('latency', {})

    percentiles = ['p50', 'p95', 'p99', 'p99.9']
    values = [
        lat.get('p50_us', 0),
        lat.get('p95_us', 0),
        lat.get('p99_us', 0),
        lat.get('p999_us', 0)
    ]

    return f'''
    new Chart(document.getElementById('latencyChart'), {{
        type: 'bar',
        data: {{
            labels: {json.dumps(percentiles)},
            datasets: [{{
                label: 'Latency (us)',
                data: {json.dumps(values)},
                backgroundColor: [
                    'rgba(34, 197, 94, 0.8)',
                    'rgba(234, 179, 8, 0.8)',
                    'rgba(249, 115, 22, 0.8)',
                    'rgba(220, 38, 38, 0.8)'
                ],
                borderWidth: 1
            }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            scales: {{
                y: {{
                    beginAtZero: true,
                    title: {{
                        display: true,
                        text: 'Microseconds'
                    }}
                }}
            }}
        }}
    }});
    '''


def generate_report(results_dir):
    """Generate the HTML report from benchmark results."""
    results_path = Path(results_dir)

    # Load all result files
    data = {
        'throughput': load_json_file(results_path / 'throughput.json'),
        'latency': load_json_file(results_path / 'latency.json'),
        'connections': load_json_file(results_path / 'connections.json'),
        'failover': load_json_file(results_path / 'failover.json'),
        'scheduler': load_json_file(results_path / 'scheduler.json'),
        'config': load_json_file(results_path / 'config.json'),
    }

    # Generate timestamp
    config = data.get('config', {})
    timestamp = config.get('timestamp', datetime.now().isoformat())

    # Generate HTML components
    html = HTML_TEMPLATE.format(
        timestamp=timestamp,
        summary_cards=generate_summary_cards(data),
        target_metrics_rows=generate_target_metrics_rows(data),
        throughput_card=generate_throughput_card(data.get('throughput')),
        latency_card=generate_latency_card(data.get('latency')),
        connection_card=generate_connection_card(data.get('connections')),
        failover_card=generate_failover_card(data.get('failover')),
        scheduler_card=generate_scheduler_card(data.get('scheduler')),
        throughput_chart_js=generate_throughput_chart_js(data.get('throughput')),
        latency_chart_js=generate_latency_chart_js(data.get('latency')),
    )

    return html


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <results_directory>", file=sys.stderr)
        sys.exit(1)

    results_dir = sys.argv[1]

    if not os.path.isdir(results_dir):
        print(f"Error: {results_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    html = generate_report(results_dir)
    print(html)


if __name__ == '__main__':
    main()
