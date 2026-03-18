# netprobe User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Command-Line Options](#command-line-options)
4. [TUI Dashboard](#tui-dashboard)
5. [Probe Types](#probe-types)
6. [Anomaly Detection](#anomaly-detection)
7. [Logging and Output](#logging-and-output)
8. [Examples](#examples)
9. [Troubleshooting](#troubleshooting)

---

## Introduction

netprobe is a comprehensive network quality monitoring tool designed for network administrators, DevOps engineers, and anyone who needs to diagnose network connectivity issues. It provides continuous multi-layer network diagnostics through an interactive terminal UI or in quiet mode for background monitoring.

### Key Capabilities

- **Multi-layer monitoring**: ICMP, DNS, TCP, TLS, and HTTP in a single tool
- **Real-time visualization**: Interactive dashboard with live metrics
- **Historical analysis**: Ring buffer stores up to 3600 samples for trend analysis
- **Structured logging**: JSONL format for programmatic analysis
- **Anomaly detection**: Automatic identification of network issues

---

## Getting Started

### Basic Usage

The simplest way to use netprobe is to provide a target host:

```bash
netprobe example.com
```

This starts monitoring with default settings:
- ICMP ping every 1000ms
- DNS resolution every 30 seconds
- TCP/TLS/HTTP probe every 10 seconds
- Traceroute every 60 seconds

### Monitoring an IP Address

```bash
netprobe 1.1.1.1
```

When monitoring an IP, netprobe will attempt reverse DNS lookup to display the hostname.

### Quiet Mode

For background monitoring without the TUI:

```bash
netprobe example.com -q
```

In quiet mode, netprobe logs to a JSONL file and outputs informational messages to stderr.

---

## Command-Line Options

### Target Specification

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target host (domain or IP address) | Required |

### Port and Path Options

| Option | Description | Default |
|--------|-------------|---------|
| `--port <PORT>` | TCP/HTTP port to probe | 443 |
| `--http-path <PATH>` | HTTP path for healthcheck | / |
| `--no-http` | Disable HTTP(S) probing | false |
| `--no-tls` | Use plain HTTP instead of HTTPS | false |

### Interval Options

| Option | Description | Default |
|--------|-------------|---------|
| `--interval-icmp <MS>` | ICMP ping interval in milliseconds | 1000 |
| `--interval-dns <SEC>` | DNS resolve interval in seconds | 30 |
| `--interval-tcp <SEC>` | TCP/HTTP probe interval in seconds | 10 |
| `--interval-trace <SEC>` | Traceroute interval in seconds | 60 |

### Timeout Options

| Option | Description | Default |
|--------|-------------|---------|
| `--timeout-icmp <MS>` | ICMP probe timeout in milliseconds | 2000 |
| `--timeout-tcp <MS>` | TCP connect timeout in milliseconds | 5000 |
| `--timeout-dns <MS>` | DNS resolution timeout in milliseconds | 5000 |
| `--timeout-http <MS>` | HTTP response timeout in milliseconds | 10000 |
| `--timeout-trace <MS>` | Traceroute timeout in milliseconds | 30000 |

### Other Options

| Option | Description | Default |
|--------|-------------|---------|
| `--log <PATH>` | Path to JSONL log file | Auto-generated |
| `--dns-server <IP>` | Explicit DNS server to use | System default |
| `--history <N>` | Ring buffer history size in samples | 3600 |
| `-q, --quiet` | Quiet mode (no TUI, only logging) | false |
| `-h, --help` | Print help information | - |
| `-V, --version` | Print version information | - |

---

## TUI Dashboard

The Terminal User Interface provides a comprehensive real-time view of all network metrics.

### Layout

The dashboard is organized into several panels:

```
+----------------------------------------------------------+
| Header: Target info, resolved IP, MOS grade, uptime      |
+----------------------------------------------------------+
| Ping Panel: Sparkline, current RTT, loss%, jitter        |
+----------------------------------------------------------+
| DNS Panel: Last resolution time, TTL, server, IPs        |
+----------------------------------------------------------+
| TCP/TLS/HTTP Panel: Connect, handshake, TTFB, status     |
+----------------------------------------------------------+
| Traceroute Panel: Hop-by-hop path visualization          |
+----------------------------------------------------------+
| Events Panel | Logs Panel: Anomalies and log messages    |
+----------------------------------------------------------+
| Footer: Keyboard shortcuts and status                    |
+----------------------------------------------------------+
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit netprobe |
| `t` | Force immediate traceroute |
| `r` | Reset statistics |
| `n` / `p` | Switch to next/previous IP address |
| `Tab` | Cycle focus between panels |
| `↑` / `↓` | Scroll focused panel |
| `?` | Toggle help popup |
| `Esc` | Close help popup |

### Panel Navigation

When the TUI starts, the Logs panel is focused. Press `Tab` to cycle through:
1. Logs Panel
2. Traceroute Panel
3. Events Panel

Use `↑` and `↓` to scroll within the focused panel. Press `n` or `p` to switch between resolved IP addresses (useful for hosts with multiple A/AAAA records).

### MOS Grade Interpretation

The header displays a MOS (Mean Opinion Score) grade indicating overall connection quality:

| Grade | MOS Range | Quality |
|-------|-----------|---------|
| A | 4.0 - 4.5 | Excellent |
| B | 3.5 - 4.0 | Good |
| C | 3.0 - 3.5 | Fair |
| D | 2.5 - 3.0 | Poor |
| F | < 2.5 | Very Poor |

MOS is calculated based on RTT, jitter, and packet loss.

---

## Probe Types

### ICMP Ping

The ICMP probe measures network latency and packet loss:

- **RTT (Round-Trip Time)**: Time for a packet to travel to target and back
- **Jitter**: Variation in RTT between consecutive packets
- **Packet Loss**: Percentage of packets that did not receive a response
- **TTL (Time To Live)**: Hop count from target to your machine

ICMP Strategy:
- **Unprivileged**: Uses SOCK_DGRAM + IPPROTO_ICMP (preferred, no root needed)
- **Raw**: Uses SOCK_RAW (requires root on most systems)
- **Subprocess**: Falls back to system `ping` command

### DNS Resolution

The DNS probe tracks name resolution performance:

- **Resolve Time**: Time to complete DNS lookup
- **TTL**: Time-to-live of DNS record
- **DNS Server**: Server used for resolution
- **IP Addresses**: All resolved IP addresses for the target

### TCP Connection

Measures TCP three-way handshake time:

- **Connect Time**: Time to establish TCP connection
- **Status**: Ok, Refused, Timeout, or Reset

### TLS Handshake

Analyzes TLS/SSL connection establishment:

- **Handshake Time**: Time to complete TLS handshake
- **Version**: TLS protocol version (e.g., TLSv1.3)
- **Cipher**: Negotiated cipher suite
- **Certificate Subject**: CN from certificate
- **Certificate Issuer**: Certificate authority
- **Certificate SAN**: Subject Alternative Names
- **Certificate Expiry**: Expiration date and days remaining

### HTTP Probe

Tests HTTP/HTTPS endpoint availability:

- **TTFB (Time To First Byte)**: Time until first byte of response
- **Total Time**: Complete request/response time
- **Status Code**: HTTP response code (200, 404, 500, etc.)

### Traceroute

Maps the network path to the target:

- **Hop Number**: Position in the route
- **IP Address**: Router IP at this hop
- **RTT**: Round-trip time to this hop
- **Hostname**: Reverse DNS lookup of the hop

Traceroute requires elevated privileges (raw sockets).

---

## Anomaly Detection

netprobe automatically detects and reports network anomalies:

### Detected Events

| Event | Description | Severity |
|-------|-------------|----------|
| `rtt_spike` | RTT significantly above baseline | Warning |
| `jitter_spike` | Jitter significantly above baseline | Warning |
| `loss_burst` | Multiple consecutive packets lost | Critical |
| `dns_change` | DNS resolution returned different IPs | Info |
| `cert_expiry_warning` | TLS certificate expiring soon | Warning/Critical |
| `http_error` | HTTP error response (4xx/5xx) | Critical |
| `tcp_refused` | TCP connection refused | Critical |
| `route_change` | Traceroute path changed | Warning |
| `hop_rtt_anomaly` | Hop RTT significantly changed | Warning |

### Event Details

Each event includes:
- **Timestamp**: When the event occurred
- **Severity**: Info, Warning, or Critical
- **Value**: Measured value that triggered the event
- **Threshold**: Expected/normal value
- **Sigma**: Number of standard deviations from mean
- **Message**: Human-readable description

---

## Logging and Output

### JSONL Log Format

netprobe outputs structured logs in JSON Lines format (one JSON object per line). Each line has a `type` field indicating the record type.

#### Record Types

**session_start** - Emitted when monitoring begins:
```json
{
  "type": "session_start",
  "ts": "2026-03-18T14:00:00Z",
  "target": "example.com",
  "resolved_target": "example.com",
  "traceroute_available": true,
  "config": {
    "port": 443,
    "interval_icmp_ms": 1000,
    "interval_dns_sec": 30,
    "interval_tcp_sec": 10,
    "interval_trace_sec": 60,
    "history_size": 3600,
    "icmp_strategy": "unprivileged"
  }
}
```

**session_end** - Emitted when monitoring ends:
```json
{
  "type": "session_end",
  "ts": "2026-03-18T16:15:39Z",
  "target": "example.com",
  "duration_sec": 8139,
  "summary": {
    "icmp_sent": 8139,
    "icmp_received": 8115,
    "loss_pct": 0.29,
    "rtt_avg_ms": 18.7,
    "rtt_p95_ms": 32.4,
    "uptime_pct": 99.71,
    "mos": 4.3,
    "grade": "A",
    "events_total": 7
  }
}
```

**icmp** - Individual ping result:
```json
{
  "type": "icmp",
  "ts": "2026-03-18T14:23:05.123Z",
  "target": "1.1.1.1",
  "seq": 8142,
  "rtt_ms": 14.2,
  "ttl": 56,
  "status": "ok"
}
```

**dns** - DNS resolution result:
```json
{
  "type": "dns",
  "ts": "2026-03-18T14:23:30.001Z",
  "target": "example.com",
  "resolve_ms": 4.2,
  "ips": ["1.1.1.1", "1.0.0.1"],
  "ttl_secs": 286,
  "server": "192.168.1.1",
  "status": "ok"
}
```

**tcp** - TCP connection result:
```json
{
  "type": "tcp",
  "ts": "2026-03-18T14:23:35.050Z",
  "target": "1.1.1.1",
  "port": 443,
  "connect_ms": 15.1,
  "status": "ok"
}
```

**tls** - TLS handshake result:
```json
{
  "type": "tls",
  "ts": "2026-03-18T14:23:35.065Z",
  "target": "1.1.1.1",
  "port": 443,
  "handshake_ms": 42.3,
  "version": "TLSv1.3",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "cert_subject": "CN=one.one.one.one",
  "cert_issuer": "CN=DigiCert",
  "cert_san": ["one.one.one.one", "1.1.1.1"],
  "cert_expiry": "2026-06-15T00:00:00Z",
  "cert_days_remaining": 89,
  "status": "ok"
}
```

**http** - HTTP probe result:
```json
{
  "type": "http",
  "ts": "2026-03-18T14:23:35.130Z",
  "target": "1.1.1.1",
  "port": 443,
  "path": "/",
  "ttfb_ms": 78.4,
  "total_ms": 82.1,
  "status_code": 200,
  "status": "ok"
}
```

**traceroute** - Traceroute result:
```json
{
  "type": "traceroute",
  "ts": "2026-03-18T14:24:05.200Z",
  "target": "1.1.1.1",
  "hops": [
    {"hop": 1, "ip": "192.168.1.1", "rtt_ms": 1.2, "host": "router.local"},
    {"hop": 2, "ip": "10.0.0.1", "rtt_ms": 4.1},
    {"hop": 4, "ip": "1.1.1.1", "rtt_ms": 14.2, "host": "one.one.one.one"}
  ],
  "hop_count": 4,
  "status": "ok"
}
```

**event** - Detected anomaly:
```json
{
  "type": "event",
  "ts": "2026-03-18T14:22:51Z",
  "target": "1.1.1.1",
  "event": "rtt_spike",
  "severity": "warning",
  "value": 47.1,
  "threshold": 32.4,
  "sigma": 3.2,
  "message": "RTT spike: 47.1ms (3.2σ above mean)"
}
```

### Log File Location

By default, netprobe creates a log file named:
```
netprobe-<target>-<timestamp>.jsonl
```

Use `--log <path>` to specify a custom location.

### Analyzing Logs

Process logs with jq:

```bash
# View all ICMP records
jq 'select(.type == "icmp")' netprobe-*.jsonl

# Calculate average RTT
jq -s '[.[] | select(.type == "icmp" and .rtt_ms) | .rtt_ms] | add / length' netprobe-*.jsonl

# Find all events
jq 'select(.type == "event")' netprobe-*.jsonl

# View session summary
jq 'select(.type == "session_end") | .summary' netprobe-*.jsonl
```

---

## Examples

### Basic Monitoring

```bash
# Monitor a website
netprobe google.com

# Monitor a DNS server
netprobe 1.1.1.1

# Monitor with custom intervals
netprobe example.com --interval-icmp 500 --interval-dns 60
```

### HTTP Service Monitoring

```bash
# Monitor API health endpoint
netprobe api.example.com --port 8080 --http-path /health

# Monitor without TLS (plain HTTP)
netprobe internal.local --no-tls --port 80

# Monitor with longer HTTP timeout
netprobe slow-api.example.com --timeout-http 30000
```

### Background Monitoring

```bash
# Quiet mode with custom log file
netprobe production-db.internal -q --log /var/log/netprobe/db.jsonl

# Run in background (Linux/macOS)
nohup netprobe api.example.com -q --log /var/log/netprobe/api.jsonl &
```

### Troubleshooting Scenarios

```bash
# ICMP only (no HTTP/TLS)
netprobe problematic-host.com --no-http

# Faster ICMP for quick diagnosis
netprobe unstable-host.com --interval-icmp 200

# Custom DNS server for resolution testing
netprobe example.com --dns-server 8.8.8.8

# Extended timeouts for slow networks
netprobe remote-site.com --timeout-icmp 5000 --timeout-tcp 10000
```

### Certificate Monitoring

```bash
# Check certificate details
netprobe example.com --interval-tcp 5

# Then watch the TLS panel for:
# - Certificate expiry date
# - Days remaining
# - Issuer information
# - Subject Alternative Names
```

---

## Troubleshooting

### Traceroute Unavailable

**Symptom**: Traceroute panel shows "unavailable"

**Solution**:
- Linux: Run with sudo or set capabilities: `sudo setcap cap_net_raw+ep ./netprobe`
- macOS: Run with sudo
- Windows: Traceroute uses `tracert.exe` and does not require elevated privileges

### ICMP Not Working

**Symptom**: All pings timeout

**Possible causes**:
1. Firewall blocking ICMP
2. Target not responding to ping
3. Network unreachable

**Solutions**:
- Check firewall rules
- Try TCP probe instead: `netprobe target --no-http`
- Verify network connectivity with system ping

### DNS Resolution Failing

**Symptom**: DNS panel shows errors

**Solutions**:
- Specify custom DNS server: `--dns-server 8.8.8.8`
- Check DNS timeout: `--timeout-dns 10000`
- Verify target domain exists

### TLS/HTTP Errors

**Symptom**: TLS or HTTP probe failing

**Possible causes**:
1. Port closed or wrong
2. Certificate expired or invalid
3. HTTP path doesn't exist
4. TLS version mismatch

**Solutions**:
- Verify port: `--port 443`
- Check HTTP path: `--http-path /health`
- Use plain HTTP: `--no-tls`
- Check certificate with: `openssl s_client -connect target:443`

### High Resource Usage

**Symptom**: CPU or memory usage is high

**Solutions**:
- Reduce history size: `--history 1000`
- Increase probe intervals
- Use quiet mode: `-q`

### TUI Display Issues

**Symptom**: Garbled or incorrect display

**Solutions**:
- Ensure terminal supports Unicode
- Try different terminal emulator
- Check terminal size (minimum 80x24 recommended)
- Disable mouse support in terminal settings if needed

---

## Best Practices

1. **Use appropriate intervals**: Don't set ICMP intervals too low (< 200ms) to avoid network flooding
2. **Monitor from multiple locations**: Run netprobe from different networks for comprehensive analysis
3. **Log to persistent storage**: Use `--log` to save data for historical analysis
4. **Set up alerting**: Process JSONL logs with external tools for alerting
5. **Regular certificate checks**: Monitor TLS certificates with appropriate TCP intervals
6. **Privilege management**: Use capabilities on Linux instead of running as root
