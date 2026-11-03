# RFC 0003: Application-specific analyzer rules (210)

**Status:** Proposal (not yet implemented)
**Depends on:** RFC 0001 (PR #3) + RFC 0002 (PR #4) landed.
**Scope:** This PR tracks the proposal only. Implementation lands in a single follow-up PR once the design is accepted.

## Motivation

The 50 general rules from RFCs 0001/0002 see **what** a process is doing (CPU-bound, lock-contended, I/O-heavy, …). The next leap is seeing **who** it is and **why it's doing that**. If ghost can look at a process and say "that's **nginx**, and it's taking a DDoS because `connect_timeout_wall + connection_reset_storm + fork_storm + rss_climb_steady` are all firing at once with a worker-pool shape" — the operator skips twenty minutes of googling.

**210 application rules**, grouped by product family. Each rule has an identity signal (comm / exe / cmdline / open-fd / unix-socket) plus one or more behavioural signals it watches, and emits a diagnosis with product-specific vocabulary and remediation hints.

## Decisions baked in (confirmed from review)

| Decision | Value |
|---|---|
| Rule count | **210** (one PR; no trimming) |
| Identity matching | **All signals, in order of best match confidence**: unix-socket path → open-fd fingerprint → exe basename → cmdline substring → comm regex. First match with `Confidence::High` wins; weaker matchers only confirm. |
| Version detection | **Allowed, opt-in via config.** Off by default; when `[identity] version_probe = true`, ghost spawns `<exe> --version` once per detected pid, caches result for the process lifetime, 500 ms timeout, abort on any non-zero exit without logging. |
| Grouping | **One PR for all 210** (not split by family) |
| Prerequisites | RFC 0001 engine + RFC 0002 samplers; no new engine or sampler work here |

## Design (unchanged from RFC 0001/0002)

- Same `Rule` trait.
- Same `AppState` input + samplers from RFC 0002.
- Same TUI / CLI surfaces (analyze screen, `ghost analyze` subcommand, config schema).
- New: `IdentityMatcher` layer runs first per tick; app-rules only evaluate when identity hits.

## Identity match contract

Match order (highest-confidence first; search stops as soon as a `High` match hits):

| Order | Source | Example | Confidence yielded |
|---|---|---|---|
| 1 | **unix-socket path** on an open fd | `/var/run/postgresql/.s.PGSQL.5432` → postgres | High |
| 2 | **open-fd fingerprint** (specific file paths) | fd pointing at `/var/lib/mysql/ibdata1` → mysqld | High |
| 3 | **exe basename** (readlink `/proc/<pid>/exe`) | `/usr/sbin/nginx` → nginx | Medium |
| 4 | **cmdline substring** | `-c /etc/redis/redis.conf` → redis-server | Medium |
| 5 | **comm regex** | `kafka` → kafka JVM wrapper | Low |

Rust shape:

```rust
pub struct Identity {
    pub app: &'static str,          // "nginx"
    pub role: Option<&'static str>, // "master" | "worker"
    pub version: Option<String>,    // populated by opt-in probe
    pub confidence: Confidence,
    pub matched_by: MatchSource,    // UnixSocket | OpenFd | ExePath | Cmdline | Comm
}

pub trait IdentityMatcher: Send + Sync {
    fn app(&self) -> &'static str;
    fn probe(&self, snap: &ProcSnapshot, hints: &MatchHints) -> Option<Identity>;
}
```

An `Identity` cache on `AppState` keyed by pid persists the match for the process lifetime (invalidated on `target_gone`), so the N-rules-for-one-process overhead is amortised.

## Version detection

**Opt-in only.** Config:
```toml
[identity]
version_probe = true          # default: false
version_probe_timeout_ms = 500
```

Semantics:
- Fires once per pid, after the first identity match reaches `Medium` or higher.
- Spawns `<exe> --version` (or app-specific variant: `postgres -V`, `nginx -v`, `redis-server --version`, …) via `std::process::Command` with the configured timeout.
- Captured stderr+stdout; parsed with a per-app regex into semver.
- Failure is silent: no logging, cache the "unknown version" state so we don't re-probe.
- Rules may condition on `identity.version >= X.Y` to catch bugs/behaviours that only exist in specific versions.

## Rule catalogue (210)

Full ids below, grouped by family. Each will land as `ghost/src/analyze/apps/<family>/<rule>.rs`.

### A. Web servers (30)

**nginx (8)** — `nginx_worker_starved`, `nginx_upstream_stuck`, `nginx_ssl_handshake_storm`, `nginx_rate_limit_tripping`, `nginx_log_flush_stall`, `nginx_reload_quiescence`, `nginx_cache_miss_storm`, `nginx_shm_zone_full`
**apache httpd (8)** — `httpd_prefork_saturation`, `httpd_worker_mpm_thrash`, `httpd_mod_php_bottleneck`, `httpd_modsec_block_storm`, `httpd_slow_client_wall`, `httpd_keepalive_exhaustion`, `httpd_graceful_restart_drag`, `httpd_fcgi_stuck`
**litespeed / openlitespeed (4)** — `lsws_lsapi_pool_pressure`, `lsws_connect_backlog`, `lsws_cache_rebuild`, `lsws_qos_tripping`
**caddy (4)** — `caddy_autocert_wall`, `caddy_admin_api_flood`, `caddy_reverse_proxy_stuck`, `caddy_config_reload_quiescence`
**traefik (3)** — `traefik_routing_rebuild_pressure`, `traefik_dynamic_config_churn`, `traefik_backend_marker_flapping`
**haproxy (3)** — `haproxy_backend_down`, `haproxy_queue_climb`, `haproxy_check_timeout_storm`

### B. Databases (40)

**MySQL / MariaDB (12)** — `mysql_innodb_row_lock_wait`, `mysql_buffer_pool_pressure`, `mysql_slow_query_log_flood`, `mysql_replication_lag`, `mysql_deadlock_loop`, `mysql_open_table_cache_miss`, `mysql_temp_disk_spill`, `mysql_binlog_fsync_wall`, `mysql_aria_pwrite_stall`, `mysql_galera_flow_control`, `mysql_thread_pool_full`, `mysql_ibtmp_grow`
**PostgreSQL (12)** — `pg_wal_fsync_wall`, `pg_autovacuum_pressure`, `pg_lock_monitor_spike`, `pg_checkpointer_backpressure`, `pg_bgwriter_lag`, `pg_replication_lag`, `pg_logical_slot_abandonment`, `pg_hot_toast`, `pg_large_object_leak`, `pg_prepared_tx_hang`, `pg_vacuum_full_wall`, `pg_tempfile_climb`
**SQLite (3)** — `sqlite_wal_wall`, `sqlite_vacuum_into_wall`, `sqlite_shm_contention`
**MongoDB (5)** — `mongo_write_lock_queue`, `mongo_replica_election`, `mongo_oplog_pressure`, `mongo_journal_fsync_wall`, `mongo_wiredtiger_evict_pressure`
**CockroachDB / TiDB (3)** — `cockroach_raft_stall`, `cockroach_range_split_storm`, `tidb_intent_cleanup_wall`
**InfluxDB / TimescaleDB (3)** — `influx_tsm_compaction_wall`, `influx_wal_wall`, `timescale_chunk_compression_wall`
**Cassandra / ScyllaDB (2)** — `cassandra_memtable_flush_wall`, `scylla_shard_imbalance`

### C. Caches / in-memory stores (25)

**Redis (8)** — `redis_fork_bgsave_wall`, `redis_rdb_rewrite_stall`, `redis_aof_fsync_wall`, `redis_cluster_slot_migration_stuck`, `redis_pubsub_flood`, `redis_expired_keys_storm`, `redis_cluster_bus_thrash`, `redis_lazyfree_backlog`
**Memcached (4)** — `memcached_lru_churn`, `memcached_slab_imbalance`, `memcached_flush_all_stall`, `memcached_large_evict`
**OPcache / PHP-FPM (4)** — `opcache_lock_contention`, `phpfpm_max_children_exhausted`, `phpfpm_slow_log_flood`, `opcache_revalidate_storm`
**Varnish (4)** — `varnish_nuke_rate_climb`, `varnish_backend_sick`, `varnish_vcl_recompile_wall`, `varnish_mempool_pressure`
**APC / APCu / Groupcache (3)** — `apcu_shm_contention`, `apcu_gc_storm`, `groupcache_hot_key`
**Nginx-cache / Squid (2)** — `nginx_disk_cache_rebuild`, `squid_aging_pass_wall`

### D. Logging / observability (15)

**rsyslog (3)** — `rsyslog_queue_overflow`, `rsyslog_output_blocked`, `rsyslog_impstats_drops`
**systemd-journald (3)** — `journald_rate_limit_kicked`, `journald_forward_fail`, `journald_storage_sync_wall`
**fluent-bit / fluentd (3)** — `fluentbit_backlog`, `fluentbit_retry_storm`, `fluentd_outforward_handshake_wall`
**vector (2)** — `vector_sink_unavailable`, `vector_batch_drop`
**promtail / filebeat (2)** — `promtail_tail_stall`, `filebeat_inode_confusion`
**opentelemetry-collector (2)** — `otelcol_exporter_failing`, `otelcol_sampler_mismatch`

### E. Containers / runtime (30)

**Docker / containerd / runc (8)** — `docker_image_pull_storm`, `containerd_layer_unpack_wall`, `cri_socket_pressure`, `containerd_snapshotter_backpressure`, `overlay_mount_wall`, `runc_exec_latency`, `cgroup_throttle_on_container`, `docker_daemon_stuck`
**Podman (4)** — `podman_slirp4netns_stall`, `podman_pause_container_churn`, `podman_journald_link_slow`, `podman_rootless_uidmap_wall`
**Kubernetes kubelet / kube-proxy (6)** — `kubelet_pod_sandbox_gc`, `kubelet_cadvisor_pressure`, `kubeproxy_iptables_rebuild_storm`, `kubelet_liveness_hammer`, `kubelet_imagegc_pressure`, `kubelet_exec_session_leak`
**CRI-O (2)** — `crio_image_gc_wall`, `crio_pod_sandbox_wall`
**containerd-shim (2)** — `containerd_shim_startup_wall`, `containerd_shim_reaper_quiesce`
**LXC / LXD (2)** — `lxc_uidmap_wall`, `lxc_veth_setup_wall`
**Firecracker / Kata (3)** — `firecracker_vmm_boot_wall`, `kata_vsock_stall`, `kata_device_setup_wall`
**crun / youki (3)** — `crun_cgroup_setup_wall`, `youki_namespace_setup_wall`, `oci_hook_wall`

### F. Runtime / language stacks (30)

**Node.js (8)** — `node_v8_gc_pause`, `node_event_loop_block`, `node_uv_threadpool_starved`, `node_async_hook_storm`, `node_inspector_attached`, `node_worker_thread_churn`, `node_child_process_spawn_storm`, `node_signalfd_pressure`
**JVM (8)** — `jvm_gc_stw`, `jvm_full_gc`, `jvm_safepoint_delay`, `jvm_deopt_storm`, `jvm_class_loading_wall`, `jvm_finalizer_backlog`, `jvm_compile_queue_climb`, `jvm_metaspace_pressure`
**Python (5)** — `py_gil_contention`, `py_gc_pause`, `py_asyncio_loop_lag`, `py_interpreter_shutdown_wall`, `py_atexit_stall`
**Go (5)** — `go_gc_assist_wall`, `go_scheduler_stall`, `go_netpoll_latency`, `go_lock_os_thread_leak`, `go_gomaxprocs_mismatch`
**.NET (4)** — `dotnet_gc_gen2_pause`, `dotnet_threadpool_starved`, `dotnet_valuetask_leak`, `dotnet_finalizer_thread_pressure`

### G. Messaging / queues (15)

**Kafka (4)** — `kafka_producer_backpressure`, `kafka_controller_election`, `kafka_segment_roll_wall`, `kafka_isr_shrink`
**RabbitMQ (3)** — `rabbit_queue_mem_alarm`, `rabbit_flow_control`, `rabbit_mnesia_stall`
**NATS (2)** — `nats_slow_consumer`, `nats_pubsub_drop`
**Redis Streams (2)** — `redis_stream_consumer_lag`, `redis_stream_xadd_burst`
**Pulsar (2)** — `pulsar_bookie_fsync_wall`, `pulsar_broker_ownership_change`
**NSQ (2)** — `nsq_channel_backlog`, `nsqlookupd_lag`

### H. File systems / storage (10)

**ext4 / XFS / BTRFS (5)** — `fs_journal_commit_wall`, `fs_barrier_wall`, `btrfs_balance_wall`, `btrfs_nocow_fallback`, `fs_write_barrier_storm`
**CephFS / NFS (3)** — `nfs_mount_hung`, `cephfs_mds_slow`, `nfs_oplock_wait`
**S3-compatible mounts (2)** — `s3fs_rate_limit`, `s3fs_multipart_stall`

### I. Networking stack (15)

**systemd-resolved / nscd (3)** — `resolver_storm`, `resolver_cache_miss_wall`, `resolver_timeout_cascade`
**ebpf programs loaded elsewhere (2)** — `ebpf_other_tracer_interference`, `ebpf_map_pressure`
**WireGuard / OpenVPN (2)** — `wg_peer_handshake_retry`, `openvpn_rekey_wall`
**Ingress / Envoy sidecar (3)** — `envoy_config_distribution_wall`, `envoy_hot_restart_drain`, `envoy_listener_drain_wall`
**QUIC / HTTP3 (2)** — `quic_initial_handshake_wall`, `quic_migration_storm`
**gRPC (3)** — `grpc_keepalive_ping_storm`, `grpc_connection_half_closed`, `grpc_flow_control_window_squeeze`

**Total: 30 + 40 + 25 + 15 + 30 + 30 + 15 + 10 + 15 = 210**

## Config example

```toml
[identity]
version_probe = true
version_probe_timeout_ms = 500

# Disable an entire family in one line
[app.cassandra]
enabled = false

# Tune a single rule
[rule.nginx_ssl_handshake_storm]
enabled = true
confidence_floor = "medium"
rate_per_sec_min = 50

[rule.redis_fork_bgsave_wall]
enabled = true
confidence_floor = "high"
fork_duration_ms_min = 200
```

## Expected size

| | lines |
|---|---|
| 210 scenario files | ~9500 (≈45 each) |
| ~70 identity matchers (one per detectable app) | ~1050 |
| Identity cache + plumbing in `AppState` | ~250 |
| Version-probe runner | ~180 |
| Tests | ~900 (≈3 per rule, plus matcher tests) |
| **Total** | **~11900 LoC** |

No new deps, no engine changes.

## Rollout plan

- Lands as one PR.
- Rules organised under `ghost/src/analyze/apps/<family>/`; each family has a `mod.rs` that registers its matchers so reviewers can read one family at a time.
- All 210 rules default to **enabled** at Info severity with `confidence_floor = "medium"` (= Quiet mode suppresses Low), so turning this PR on doesn't flood an existing user.
- Each heuristic rule's rustdoc names its known false-positive shape (so disabling with one config line is obvious).

## Testing

- Per-rule unit tests: positive-fire, negative-no-fire, boundary — ~3 per rule → ~630 new tests.
- Identity-matcher tests: synthetic `ProcSnapshot` with each match source wired independently, so matcher order and precedence are locked down.
- Version-probe tests: timeout path, non-zero exit path, parse-success path (mocked `Command`).
- End-to-end replay fixture: craft a `.ghost` fingerprint-shaped as nginx worker under DDoS and assert the expected 4-rule stacking (`nginx_worker_starved` + `connect_timeout_wall` + `connection_reset_storm` + `rss_climb_steady`) all fire together.
- Total: ~290 (post-RFC-0002) → ~**920 tests**.

## Risk / rollout

- Pure additive. Every family can be disabled wholesale.
- Identity matching is read-only; version probe is explicit opt-in.
- Rule evaluation is gated by identity match, so unidentified processes pay only the identity-matcher cost once per pid (then cache).

## Open calls for review (final sanity-check before implementation)

1. **Default identity confidence**: an exe-basename match surfaces as Medium today. Promote to High if the basename is unambiguous (e.g. `postgres`), or always Medium?
2. **Version-probe parse failures**: silently cache "unknown" and continue, or disable version-conditioned rules for that pid?
3. **Rule-id prefix**: current scheme uses the app name as prefix (`nginx_worker_starved`). Keep flat, or namespace via `apps::nginx::worker_starved` style for the config file too?
4. **"Suggestion" wording**: for app rules, write them with product-specific vocabulary ("tune `innodb_buffer_pool_size`", "lower `pm.max_children`") — ok, or stick to generic phrasing?
