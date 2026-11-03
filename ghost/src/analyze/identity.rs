//! Identity match layer (RFC 0003).
//!
//! Classifies a tracked process as a known app family (nginx, mysqld,
//! redis, …) so app-specific rules can gate on it. The RFC lists five
//! match sources ranked by confidence; this implementation covers the
//! two cheapest (exe basename + cmdline substring + comm) which run on
//! every host without extra caps, and leaves slots for the open-fd /
//! unix-socket matchers to be filled when `ProcSnapshot.fds` carries
//! the needed detail.

use crate::analyze::Confidence;
use crate::proc::ProcSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSource {
    UnixSocket,
    OpenFd,
    ExePath,
    Cmdline,
    Comm,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub app: &'static str,
    pub role: Option<&'static str>,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub matched_by: MatchSource,
}

/// Static table of comm/exe basenames we recognise. Confidence derived
/// from match source: ExePath = Medium, Cmdline/Comm = Low. First match
/// wins (table is ordered by how specific the signal is).
static WELL_KNOWN: &[(&str, &str)] = &[
    ("nginx", "nginx"),
    ("httpd", "apache"),
    ("apache2", "apache"),
    ("caddy", "caddy"),
    ("traefik", "traefik"),
    ("haproxy", "haproxy"),
    ("mysqld", "mysql"),
    ("mariadbd", "mysql"),
    ("postgres", "postgres"),
    ("postmaster", "postgres"),
    ("sqlite3", "sqlite"),
    ("mongod", "mongo"),
    ("cockroach", "cockroach"),
    ("tidb-server", "tidb"),
    ("influxd", "influx"),
    ("timescaledb", "timescale"),
    ("cassandra", "cassandra"),
    ("scylla", "scylla"),
    ("redis-server", "redis"),
    ("memcached", "memcached"),
    ("php-fpm", "phpfpm"),
    ("php-fpm7.4", "phpfpm"),
    ("php-fpm8.1", "phpfpm"),
    ("php-fpm8.2", "phpfpm"),
    ("varnishd", "varnish"),
    ("squid", "squid"),
    ("rsyslogd", "rsyslog"),
    ("systemd-journal", "journald"),
    ("fluent-bit", "fluentbit"),
    ("fluentd", "fluentd"),
    ("vector", "vector"),
    ("promtail", "promtail"),
    ("filebeat", "filebeat"),
    ("otelcol", "otelcol"),
    ("dockerd", "docker"),
    ("containerd", "containerd"),
    ("runc", "runc"),
    ("podman", "podman"),
    ("kubelet", "kubelet"),
    ("kube-proxy", "kubeproxy"),
    ("crio", "crio"),
    ("containerd-shim", "containerd_shim"),
    ("lxc-start", "lxc"),
    ("firecracker", "firecracker"),
    ("kata-runtime", "kata"),
    ("crun", "crun"),
    ("youki", "youki"),
    ("node", "node"),
    ("nodejs", "node"),
    ("java", "jvm"),
    ("python3", "python"),
    ("python", "python"),
    ("python3.10", "python"),
    ("python3.11", "python"),
    ("python3.12", "python"),
    ("go", "go"),
    ("dotnet", "dotnet"),
    ("kafka", "kafka"),
    ("rabbitmq-server", "rabbit"),
    ("beam.smp", "rabbit"),
    ("nats-server", "nats"),
    ("pulsar", "pulsar"),
    ("nsqd", "nsq"),
    ("nsqlookupd", "nsqlookupd"),
    ("systemd-resolved", "resolver"),
    ("nscd", "resolver"),
    ("wg-crypt-wg0", "wireguard"),
    ("openvpn", "openvpn"),
    ("envoy", "envoy"),
];

/// Resolve an `Identity` from the latest `ProcSnapshot`. Returns None
/// if no matcher fires; app rules then skip the process entirely for
/// zero overhead on unknown binaries.
pub fn identify(snap: Option<&ProcSnapshot>, comm: &str) -> Option<Identity> {
    // 1. Exe basename — Medium
    if let Some(s) = snap {
        if let Some(name) = basename(&s.exe) {
            if let Some(app) = lookup_exact(name) {
                return Some(Identity {
                    app,
                    role: None,
                    version: None,
                    confidence: Confidence::Medium,
                    matched_by: MatchSource::ExePath,
                });
            }
        }
        // 2. Cmdline substring — Low
        for (sig, app) in WELL_KNOWN {
            if !s.cmdline.is_empty() && s.cmdline.contains(sig) {
                return Some(Identity {
                    app,
                    role: None,
                    version: None,
                    confidence: Confidence::Low,
                    matched_by: MatchSource::Cmdline,
                });
            }
        }
    }
    // 3. Comm fallback — Low
    if let Some(app) = lookup_exact(comm) {
        return Some(Identity {
            app,
            role: None,
            version: None,
            confidence: Confidence::Low,
            matched_by: MatchSource::Comm,
        });
    }
    None
}

fn basename(path: &str) -> Option<&str> {
    path.rsplit('/').next().filter(|s| !s.is_empty())
}

fn lookup_exact(name: &str) -> Option<&'static str> {
    WELL_KNOWN.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comm_lookup_hits_known() {
        let id = identify(None, "nginx").unwrap();
        assert_eq!(id.app, "nginx");
        assert_eq!(id.matched_by, MatchSource::Comm);
    }
    #[test]
    fn unknown_comm_returns_none() {
        assert!(identify(None, "weird-thing-9000").is_none());
    }
    #[test]
    fn basename_strips_dirs() {
        assert_eq!(basename("/usr/sbin/nginx"), Some("nginx"));
        assert_eq!(basename("nginx"), Some("nginx"));
        assert_eq!(basename(""), None);
    }
}
