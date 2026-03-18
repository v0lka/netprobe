//! Probe modules for network monitoring

use std::error::Error;
use std::fmt;

pub mod dns;
pub mod http;
pub mod icmp;
pub mod tcp;
pub mod tls;
pub mod traceroute;

/// Error types for probe operations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ProbeError {
    Timeout,
    SocketError(String),
    PermissionDenied,
    ParseError(String),
    Other(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Timeout => write!(f, "Operation timed out"),
            ProbeError::SocketError(msg) => write!(f, "Socket error: {}", msg),
            ProbeError::PermissionDenied => write!(f, "Permission denied"),
            ProbeError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ProbeError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for ProbeError {}

/// ICMP probing strategy used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpStrategy {
    /// Unprivileged ICMP socket (SOCK_DGRAM + IPPROTO_ICMP)
    Unprivileged,
    /// Raw ICMP socket (SOCK_RAW)
    Raw,
    /// Subprocess fallback (ping command)
    Subprocess,
}

impl fmt::Display for IcmpStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpStrategy::Unprivileged => write!(f, "unprivileged"),
            IcmpStrategy::Raw => write!(f, "raw"),
            IcmpStrategy::Subprocess => write!(f, "subprocess"),
        }
    }
}
