// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

//! Small helpers shared by the flowplane `serve` gRPC bind path.

/// Extract the unix-socket path from a `--addr` value, or `None` for a `host:port` TCP address.
///
/// Accepts the grpc-go dial forms `unix:///abs/path` and `unix:/abs/path` (and the bare
/// `unix://relative`), so the same `--addr` string works for the Rust server here and the Go
/// clients that dial it. A value without a `unix:` scheme (e.g. `127.0.0.1:1337`) returns `None`.
pub fn uds_path(addr: &str) -> Option<&str> {
    addr.strip_prefix("unix://")
        .or_else(|| addr.strip_prefix("unix:"))
}

#[cfg(test)]
mod tests {
    use super::uds_path;

    #[test]
    fn parses_uds_and_tcp_forms() {
        // grpc-go's canonical absolute form: authority empty, leading slash preserved.
        assert_eq!(
            uds_path("unix:///run/flowplane/dataplane.sock"),
            Some("/run/flowplane/dataplane.sock")
        );
        // Single-slash form.
        assert_eq!(
            uds_path("unix:/run/flowplane/dataplane.sock"),
            Some("/run/flowplane/dataplane.sock")
        );
        // TCP addresses are not unix sockets.
        assert_eq!(uds_path("127.0.0.1:1337"), None);
        assert_eq!(uds_path("[::1]:1337"), None);
    }
}
