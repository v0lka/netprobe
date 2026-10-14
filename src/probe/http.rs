//! HTTP healthcheck prober

use crate::probe::ProbeError;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

/// Result of an HTTP probe
#[derive(Debug, Clone)]
pub struct HttpResult {
    pub ttfb_ms: f64,
    pub total_ms: f64,
    pub status_code: u16,
}

/// Hard cap for the status-line/header read buffer. A legitimate status line
/// and its headers never approach this size; anything larger is garbage.
const MAX_STATUS_LINE_BUFFER: usize = 8 * 1024;

/// Perform an HTTP GET request with TTFB (Time To First Byte) measurement
/// Sends a minimal HTTP/1.1 GET request and measures:
/// - TTFB: Time until the first byte of the response is received
/// - Total time: Time until the status line is fully parsed
pub async fn http_probe<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    timeout_duration: Duration,
) -> Result<HttpResult, ProbeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();

    // RFC 7230 §5.4: an IPv6 literal must be bracketed in the Host header,
    // otherwise the raw `:` characters parse as a bogus host:port pair.
    let host_header = match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_ipv6() => format!("[{}]", ip),
        _ => host.to_string(),
    };

    // Build minimal HTTP/1.1 GET request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_header
    );

    // Send the request with timeout
    timeout(timeout_duration, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::SocketError(format!("Failed to send HTTP request: {}", e)))?;

    // Flush to ensure data is sent
    timeout(timeout_duration, stream.flush())
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::SocketError(format!("Failed to flush: {}", e)))?;

    // Measure TTFB - time until first byte received
    let mut first_byte_buffer = [0u8; 1];
    timeout(timeout_duration, stream.read_exact(&mut first_byte_buffer))
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::SocketError(format!("Failed to read first byte: {}", e)))?;

    let ttfb_elapsed = start.elapsed();
    let ttfb_ms = ttfb_elapsed.as_secs_f64() * 1000.0;

    // Read until the status line is terminated ("\r\n" seen). The whole phase
    // is bounded by a single overall deadline (the same timeout as the
    // request/TTFB) and a hard buffer cap, so a peer that trickles bytes
    // forever can neither grow the buffer unboundedly nor stall the probe.
    let mut buffer = vec![first_byte_buffer[0]];
    let mut temp_buffer = [0u8; 1024];

    // Returns whether the status line was terminated; `false` means the
    // connection closed mid-status-line (a truncated response).
    let read_status_line = async {
        loop {
            match stream.read(&mut temp_buffer).await {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buffer[..n]);
                    // Check if we have the full status line
                    if buffer.windows(2).any(|w| w == b"\r\n") {
                        return Ok(true);
                    }
                    // Reject oversized/garbage responses instead of buffering forever
                    if buffer.len() > MAX_STATUS_LINE_BUFFER {
                        return Err(ProbeError::ParseError(
                            "Response exceeded status-line buffer limit".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(ProbeError::SocketError(format!("Read error: {}", e)));
                }
            }
        }
    };

    // Only a terminated status line is parsed: parsing a truncated one could
    // fabricate a bogus status code (e.g. "HTTP/1.1 5" → 5).
    let status_line_terminated = match timeout(timeout_duration, read_status_line).await {
        Ok(outcome) => outcome?,
        // Overall deadline elapsed without a complete status line: the attempt
        // is a timeout. The TTFB captured above is discarded with the failed
        // attempt, like any other probe error.
        Err(_) => return Err(ProbeError::Timeout),
    };
    if !status_line_terminated {
        return Err(ProbeError::ParseError(
            "Connection closed before the status line was complete".to_string(),
        ));
    }

    let total_elapsed = start.elapsed();
    let total_ms = total_elapsed.as_secs_f64() * 1000.0;

    // Parse the status line to extract status code
    let status_code = parse_status_line(&buffer)?;

    Ok(HttpResult {
        ttfb_ms,
        total_ms,
        status_code,
    })
}

/// Parse HTTP status line to extract status code
/// Status line format: "HTTP/1.1 200 OK\r\n" or "HTTP/1.1 404 Not Found\r\n"
pub fn parse_status_line(data: &[u8]) -> Result<u16, ProbeError> {
    // Convert to string, handling potential invalid UTF-8
    let response = String::from_utf8_lossy(data);

    // Find the first line (status line)
    let status_line = response
        .lines()
        .next()
        .ok_or_else(|| ProbeError::ParseError("Empty response".to_string()))?;

    // Parse status line: "HTTP/1.1 200 OK"
    // Split by whitespace and get the second part (status code)
    let parts: Vec<&str> = status_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(ProbeError::ParseError(format!(
            "Invalid status line format: {}",
            status_line
        )));
    }

    // The status code is the second element
    let status_code: u16 = parts[1]
        .parse()
        .map_err(|e| ProbeError::ParseError(format!("Failed to parse status code: {}", e)))?;

    Ok(status_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status_line_ok() {
        let data = b"HTTP/1.1 200 OK\r\n";
        let status = parse_status_line(data).unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn test_parse_status_line_not_found() {
        let data = b"HTTP/1.1 404 Not Found\r\n";
        let status = parse_status_line(data).unwrap();
        assert_eq!(status, 404);
    }

    #[test]
    fn test_parse_status_line_redirect() {
        let data = b"HTTP/1.1 301 Moved Permanently\r\n";
        let status = parse_status_line(data).unwrap();
        assert_eq!(status, 301);
    }

    #[test]
    fn test_parse_status_line_server_error() {
        let data = b"HTTP/1.1 500 Internal Server Error\r\n";
        let status = parse_status_line(data).unwrap();
        assert_eq!(status, 500);
    }

    #[test]
    fn test_parse_status_line_with_headers() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n";
        let status = parse_status_line(data).unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn test_parse_status_line_http10() {
        let data = b"HTTP/1.0 200 OK\r\n";
        let status = parse_status_line(data).unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn test_parse_status_line_invalid() {
        let data = b"Invalid response\r\n";
        let result = parse_status_line(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_status_line_empty() {
        let data = b"";
        let result = parse_status_line(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_http_result_structure() {
        let result = HttpResult {
            ttfb_ms: 78.4,
            total_ms: 82.1,
            status_code: 200,
        };

        assert_eq!(result.ttfb_ms, 78.4);
        assert_eq!(result.total_ms, 82.1);
        assert_eq!(result.status_code, 200);
    }
}
