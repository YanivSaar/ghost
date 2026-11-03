//! RFC 0003 — 210 application-specific analyzer rules (generated).
//!
//! Each rule gates on a prior `identity::identify()` match for its app
//! family. Rules reserve their id and emit `None` by default; a
//! representative subset below carries a real heuristic over the
//! existing samplers (syscall deltas, lock max_queue, oom_score, rss).

#![allow(non_upper_case_globals)]

use crate::analyze::{
    config::RuleThresholds, engine::TickSnapshot, identity::identify, rules::Rule, Confidence,
    Diagnosis, Severity,
};
use crate::state::AppState;
use std::collections::VecDeque;

use crate::analyze::scenarios::nr;

fn ident_hit(st: &AppState, app: &str) -> bool {
    identify(st.snap.as_ref(), &st.comm)
        .map(|i| i.app == app)
        .unwrap_or(false)
}

fn delta(hist: &VecDeque<TickSnapshot>, nr: u32) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.per_syscall_counts
        .get(&nr)
        .copied()
        .unwrap_or(0)
        .saturating_sub(prev.per_syscall_counts.get(&nr).copied().unwrap_or(0)) as f64
}

fn blank_diag(
    id: &'static str,
    headline: &str,
    detail: String,
    sev: Severity,
    conf: Confidence,
) -> Diagnosis {
    Diagnosis {
        id,
        headline: headline.into(),
        detail,
        signals: vec![],
        severity: sev,
        confidence: conf,
        suggestion: None,
        first_seen_tick: 0,
        last_seen_tick: 0,
        consecutive_ticks: 0,
    }
}

macro_rules! app_rule {
    ($name:ident, $ty:ident, $id:literal, $app:literal, $imp:expr) => {
        pub struct $ty;
        pub static $name: $ty = $ty;
        impl Rule for $ty {
            fn id(&self) -> &'static str {
                $id
            }
            fn evaluate(
                &self,
                state: &AppState,
                th: &RuleThresholds,
                hist: &VecDeque<TickSnapshot>,
                tick: u64,
            ) -> Option<Diagnosis> {
                if !ident_hit(state, $app) {
                    return None;
                }
                let f: fn(
                    &AppState,
                    &RuleThresholds,
                    &VecDeque<TickSnapshot>,
                    u64,
                ) -> Option<Diagnosis> = $imp;
                f(state, th, hist, tick)
            }
        }
    };
}

fn stub(
    _s: &AppState,
    _t: &RuleThresholds,
    _h: &VecDeque<TickSnapshot>,
    _tk: u64,
) -> Option<Diagnosis> {
    None
}
app_rule!(
    nginx_worker_starved,
    NginxWorkerStarvedRule,
    "nginx_worker_starved",
    "nginx",
    |_st, _th, hist, _tk| {
        let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
        let clones = delta(hist, nr::CLONE) + delta(hist, nr::CLONE3);
        if cpu > 85.0 && clones > 5.0 {
            return Some(blank_diag(
                "nginx_worker_starved",
                "nginx: workers starved under fork pressure",
                format!("{:.0}% CPU, {:.0} clone/s", cpu, clones),
                Severity::Warning,
                Confidence::Medium,
            ));
        }
        None
    }
);
app_rule!(
    nginx_upstream_stuck,
    NginxUpstreamStuckRule,
    "nginx_upstream_stuck",
    "nginx",
    stub
);
app_rule!(
    nginx_ssl_handshake_storm,
    NginxSslHandshakeStormRule,
    "nginx_ssl_handshake_storm",
    "nginx",
    |_st, th, hist, _tk| {
        const READ: u32 = 0;
        const WRITE: u32 = 1;
        let rate = delta(hist, READ) + delta(hist, WRITE);
        let min = th.get_f("rate_per_sec_min", 2000.0);
        if rate >= min {
            Some(blank_diag(
                "nginx_ssl_handshake_storm",
                "nginx: possible SSL handshake storm",
                format!("~{:.0} read+write syscalls/s", rate),
                Severity::Notice,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    nginx_rate_limit_tripping,
    NginxRateLimitTrippingRule,
    "nginx_rate_limit_tripping",
    "nginx",
    stub
);
app_rule!(
    nginx_log_flush_stall,
    NginxLogFlushStallRule,
    "nginx_log_flush_stall",
    "nginx",
    stub
);
app_rule!(
    nginx_reload_quiescence,
    NginxReloadQuiescenceRule,
    "nginx_reload_quiescence",
    "nginx",
    stub
);
app_rule!(
    nginx_cache_miss_storm,
    NginxCacheMissStormRule,
    "nginx_cache_miss_storm",
    "nginx",
    stub
);
app_rule!(
    nginx_shm_zone_full,
    NginxShmZoneFullRule,
    "nginx_shm_zone_full",
    "nginx",
    stub
);
app_rule!(
    httpd_prefork_saturation,
    HttpdPreforkSaturationRule,
    "httpd_prefork_saturation",
    "apache",
    stub
);
app_rule!(
    httpd_worker_mpm_thrash,
    HttpdWorkerMpmThrashRule,
    "httpd_worker_mpm_thrash",
    "apache",
    stub
);
app_rule!(
    httpd_mod_php_bottleneck,
    HttpdModPhpBottleneckRule,
    "httpd_mod_php_bottleneck",
    "apache",
    stub
);
app_rule!(
    httpd_modsec_block_storm,
    HttpdModsecBlockStormRule,
    "httpd_modsec_block_storm",
    "apache",
    stub
);
app_rule!(
    httpd_slow_client_wall,
    HttpdSlowClientWallRule,
    "httpd_slow_client_wall",
    "apache",
    stub
);
app_rule!(
    httpd_keepalive_exhaustion,
    HttpdKeepaliveExhaustionRule,
    "httpd_keepalive_exhaustion",
    "apache",
    stub
);
app_rule!(
    httpd_graceful_restart_drag,
    HttpdGracefulRestartDragRule,
    "httpd_graceful_restart_drag",
    "apache",
    stub
);
app_rule!(
    httpd_fcgi_stuck,
    HttpdFcgiStuckRule,
    "httpd_fcgi_stuck",
    "apache",
    stub
);
app_rule!(
    lsws_lsapi_pool_pressure,
    LswsLsapiPoolPressureRule,
    "lsws_lsapi_pool_pressure",
    "lsws",
    stub
);
app_rule!(
    lsws_connect_backlog,
    LswsConnectBacklogRule,
    "lsws_connect_backlog",
    "lsws",
    stub
);
app_rule!(
    lsws_cache_rebuild,
    LswsCacheRebuildRule,
    "lsws_cache_rebuild",
    "lsws",
    stub
);
app_rule!(
    lsws_qos_tripping,
    LswsQosTrippingRule,
    "lsws_qos_tripping",
    "lsws",
    stub
);
app_rule!(
    caddy_autocert_wall,
    CaddyAutocertWallRule,
    "caddy_autocert_wall",
    "caddy",
    stub
);
app_rule!(
    caddy_admin_api_flood,
    CaddyAdminApiFloodRule,
    "caddy_admin_api_flood",
    "caddy",
    stub
);
app_rule!(
    caddy_reverse_proxy_stuck,
    CaddyReverseProxyStuckRule,
    "caddy_reverse_proxy_stuck",
    "caddy",
    stub
);
app_rule!(
    caddy_config_reload_quiescence,
    CaddyConfigReloadQuiescenceRule,
    "caddy_config_reload_quiescence",
    "caddy",
    stub
);
app_rule!(
    traefik_routing_rebuild_pressure,
    TraefikRoutingRebuildPressureRule,
    "traefik_routing_rebuild_pressure",
    "traefik",
    stub
);
app_rule!(
    traefik_dynamic_config_churn,
    TraefikDynamicConfigChurnRule,
    "traefik_dynamic_config_churn",
    "traefik",
    stub
);
app_rule!(
    traefik_backend_marker_flapping,
    TraefikBackendMarkerFlappingRule,
    "traefik_backend_marker_flapping",
    "traefik",
    stub
);
app_rule!(
    haproxy_backend_down,
    HaproxyBackendDownRule,
    "haproxy_backend_down",
    "haproxy",
    |_st, _th, hist, _tk| {
        const CONNECT: u32 = 42;
        let r = delta(hist, CONNECT);
        if r > 20.0 {
            Some(blank_diag(
                "haproxy_backend_down",
                "haproxy: connect burst (backend may be down)",
                format!("{:.0} connect/s", r),
                Severity::Warning,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    haproxy_queue_climb,
    HaproxyQueueClimbRule,
    "haproxy_queue_climb",
    "haproxy",
    stub
);
app_rule!(
    haproxy_check_timeout_storm,
    HaproxyCheckTimeoutStormRule,
    "haproxy_check_timeout_storm",
    "haproxy",
    stub
);
app_rule!(
    mysql_innodb_row_lock_wait,
    MysqlInnodbRowLockWaitRule,
    "mysql_innodb_row_lock_wait",
    "mysql",
    |st, th, _hist, _tk| {
        let min_q = th.get_f("max_queue_min", 4.0) as u32;
        let longest = st
            .lock
            .top_locks
            .iter()
            .map(|(_, s)| s.max_queue)
            .max()
            .unwrap_or(0);
        if longest >= min_q {
            Some(blank_diag(
                "mysql_innodb_row_lock_wait",
                "mysql: InnoDB row-lock queue",
                format!("queue depth {}", longest),
                Severity::Warning,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    mysql_buffer_pool_pressure,
    MysqlBufferPoolPressureRule,
    "mysql_buffer_pool_pressure",
    "mysql",
    stub
);
app_rule!(
    mysql_slow_query_log_flood,
    MysqlSlowQueryLogFloodRule,
    "mysql_slow_query_log_flood",
    "mysql",
    |_st, _th, hist, _tk| {
        const WRITE: u32 = 1;
        let r = delta(hist, WRITE);
        if r > 500.0 {
            Some(blank_diag(
                "mysql_slow_query_log_flood",
                "mysql: write-heavy (slow query log?)",
                format!("{:.0} write/s", r),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    mysql_replication_lag,
    MysqlReplicationLagRule,
    "mysql_replication_lag",
    "mysql",
    stub
);
app_rule!(
    mysql_deadlock_loop,
    MysqlDeadlockLoopRule,
    "mysql_deadlock_loop",
    "mysql",
    stub
);
app_rule!(
    mysql_open_table_cache_miss,
    MysqlOpenTableCacheMissRule,
    "mysql_open_table_cache_miss",
    "mysql",
    stub
);
app_rule!(
    mysql_temp_disk_spill,
    MysqlTempDiskSpillRule,
    "mysql_temp_disk_spill",
    "mysql",
    stub
);
app_rule!(
    mysql_binlog_fsync_wall,
    MysqlBinlogFsyncWallRule,
    "mysql_binlog_fsync_wall",
    "mysql",
    |_st, th, hist, _tk| {
        const FDATASYNC: u32 = 75;
        let min_ms = th.get_f("p99_ms_min", 20.0);
        let m = hist
            .back()
            .and_then(|s| s.per_syscall_max_ns.get(&FDATASYNC).copied())
            .unwrap_or(0) as f64
            / 1_000_000.0;
        if m >= min_ms {
            Some(blank_diag(
                "mysql_binlog_fsync_wall",
                "mysql: binlog fdatasync wall",
                format!("max {:.1} ms", m),
                Severity::Warning,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    mysql_aria_pwrite_stall,
    MysqlAriaPwriteStallRule,
    "mysql_aria_pwrite_stall",
    "mysql",
    stub
);
app_rule!(
    mysql_galera_flow_control,
    MysqlGaleraFlowControlRule,
    "mysql_galera_flow_control",
    "mysql",
    stub
);
app_rule!(
    mysql_thread_pool_full,
    MysqlThreadPoolFullRule,
    "mysql_thread_pool_full",
    "mysql",
    stub
);
app_rule!(
    mysql_ibtmp_grow,
    MysqlIbtmpGrowRule,
    "mysql_ibtmp_grow",
    "mysql",
    stub
);
app_rule!(
    pg_wal_fsync_wall,
    PgWalFsyncWallRule,
    "pg_wal_fsync_wall",
    "postgres",
    |_st, th, hist, _tk| {
        const FDATASYNC: u32 = 75;
        let min_ms = th.get_f("p99_ms_min", 20.0);
        let m = hist
            .back()
            .and_then(|s| s.per_syscall_max_ns.get(&FDATASYNC).copied())
            .unwrap_or(0) as f64
            / 1_000_000.0;
        if m >= min_ms {
            Some(blank_diag(
                "pg_wal_fsync_wall",
                "postgres: WAL fsync wall",
                format!("max {:.1} ms", m),
                Severity::Warning,
                Confidence::High,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    pg_autovacuum_pressure,
    PgAutovacuumPressureRule,
    "pg_autovacuum_pressure",
    "postgres",
    |_st, _th, hist, _tk| {
        let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
        let reads = delta(hist, 0) + delta(hist, 17);
        if cpu > 50.0 && reads > 1000.0 {
            Some(blank_diag(
                "pg_autovacuum_pressure",
                "postgres: autovacuum pressure",
                format!("{:.0}% CPU, {:.0} reads/s", cpu, reads),
                Severity::Notice,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    pg_lock_monitor_spike,
    PgLockMonitorSpikeRule,
    "pg_lock_monitor_spike",
    "postgres",
    stub
);
app_rule!(
    pg_checkpointer_backpressure,
    PgCheckpointerBackpressureRule,
    "pg_checkpointer_backpressure",
    "postgres",
    stub
);
app_rule!(
    pg_bgwriter_lag,
    PgBgwriterLagRule,
    "pg_bgwriter_lag",
    "postgres",
    stub
);
app_rule!(
    pg_replication_lag,
    PgReplicationLagRule,
    "pg_replication_lag",
    "postgres",
    stub
);
app_rule!(
    pg_logical_slot_abandonment,
    PgLogicalSlotAbandonmentRule,
    "pg_logical_slot_abandonment",
    "postgres",
    stub
);
app_rule!(
    pg_hot_toast,
    PgHotToastRule,
    "pg_hot_toast",
    "postgres",
    stub
);
app_rule!(
    pg_large_object_leak,
    PgLargeObjectLeakRule,
    "pg_large_object_leak",
    "postgres",
    stub
);
app_rule!(
    pg_prepared_tx_hang,
    PgPreparedTxHangRule,
    "pg_prepared_tx_hang",
    "postgres",
    stub
);
app_rule!(
    pg_vacuum_full_wall,
    PgVacuumFullWallRule,
    "pg_vacuum_full_wall",
    "postgres",
    stub
);
app_rule!(
    pg_tempfile_climb,
    PgTempfileClimbRule,
    "pg_tempfile_climb",
    "postgres",
    stub
);
app_rule!(
    sqlite_wal_wall,
    SqliteWalWallRule,
    "sqlite_wal_wall",
    "sqlite",
    stub
);
app_rule!(
    sqlite_vacuum_into_wall,
    SqliteVacuumIntoWallRule,
    "sqlite_vacuum_into_wall",
    "sqlite",
    stub
);
app_rule!(
    sqlite_shm_contention,
    SqliteShmContentionRule,
    "sqlite_shm_contention",
    "sqlite",
    stub
);
app_rule!(
    mongo_write_lock_queue,
    MongoWriteLockQueueRule,
    "mongo_write_lock_queue",
    "mongo",
    stub
);
app_rule!(
    mongo_replica_election,
    MongoReplicaElectionRule,
    "mongo_replica_election",
    "mongo",
    stub
);
app_rule!(
    mongo_oplog_pressure,
    MongoOplogPressureRule,
    "mongo_oplog_pressure",
    "mongo",
    stub
);
app_rule!(
    mongo_journal_fsync_wall,
    MongoJournalFsyncWallRule,
    "mongo_journal_fsync_wall",
    "mongo",
    stub
);
app_rule!(
    mongo_wiredtiger_evict_pressure,
    MongoWiredtigerEvictPressureRule,
    "mongo_wiredtiger_evict_pressure",
    "mongo",
    stub
);
app_rule!(
    cockroach_raft_stall,
    CockroachRaftStallRule,
    "cockroach_raft_stall",
    "cockroach",
    stub
);
app_rule!(
    cockroach_range_split_storm,
    CockroachRangeSplitStormRule,
    "cockroach_range_split_storm",
    "cockroach",
    stub
);
app_rule!(
    tidb_intent_cleanup_wall,
    TidbIntentCleanupWallRule,
    "tidb_intent_cleanup_wall",
    "cockroach",
    stub
);
app_rule!(
    influx_tsm_compaction_wall,
    InfluxTsmCompactionWallRule,
    "influx_tsm_compaction_wall",
    "influx",
    stub
);
app_rule!(
    influx_wal_wall,
    InfluxWalWallRule,
    "influx_wal_wall",
    "influx",
    stub
);
app_rule!(
    timescale_chunk_compression_wall,
    TimescaleChunkCompressionWallRule,
    "timescale_chunk_compression_wall",
    "influx",
    stub
);
app_rule!(
    cassandra_memtable_flush_wall,
    CassandraMemtableFlushWallRule,
    "cassandra_memtable_flush_wall",
    "cassandra",
    |_st, th, hist, _tk| {
        const FDATASYNC: u32 = 75;
        let min_ms = th.get_f("p99_ms_min", 100.0);
        let m = hist
            .back()
            .and_then(|s| s.per_syscall_max_ns.get(&FDATASYNC).copied())
            .unwrap_or(0) as f64
            / 1_000_000.0;
        if m >= min_ms {
            Some(blank_diag(
                "cassandra_memtable_flush_wall",
                "cassandra: memtable flush fdatasync wall",
                format!("max {:.1} ms", m),
                Severity::Warning,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    scylla_shard_imbalance,
    ScyllaShardImbalanceRule,
    "scylla_shard_imbalance",
    "cassandra",
    stub
);
app_rule!(
    redis_fork_bgsave_wall,
    RedisForkBgsaveWallRule,
    "redis_fork_bgsave_wall",
    "redis",
    |_st, th, hist, _tk| {
        let min_ms = th.get_f("fork_duration_ms_min", 200.0);
        let clones = delta(hist, nr::CLONE) + delta(hist, nr::CLONE3);
        if clones > 0.0 {
            let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
            if cpu < 10.0 {
                return Some(blank_diag(
                    "redis_fork_bgsave_wall",
                    "redis: fork for BGSAVE blocking",
                    format!("fork + quiet CPU (threshold {:.0} ms)", min_ms),
                    Severity::Warning,
                    Confidence::Medium,
                ));
            }
        }
        None
    }
);
app_rule!(
    redis_rdb_rewrite_stall,
    RedisRdbRewriteStallRule,
    "redis_rdb_rewrite_stall",
    "redis",
    stub
);
app_rule!(
    redis_aof_fsync_wall,
    RedisAofFsyncWallRule,
    "redis_aof_fsync_wall",
    "redis",
    |_st, th, hist, _tk| {
        const FSYNC: u32 = 74;
        const FDATASYNC: u32 = 75;
        let min_ms = th.get_f("p99_ms_min", 50.0);
        let max_ns = hist
            .back()
            .and_then(|s| {
                s.per_syscall_max_ns
                    .get(&FSYNC)
                    .or(s.per_syscall_max_ns.get(&FDATASYNC))
                    .copied()
            })
            .unwrap_or(0);
        let ms = max_ns as f64 / 1_000_000.0;
        if ms >= min_ms {
            Some(blank_diag(
                "redis_aof_fsync_wall",
                "redis: AOF fsync wall",
                format!("max fsync {:.1} ms", ms),
                Severity::Warning,
                Confidence::High,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    redis_cluster_slot_migration_stuck,
    RedisClusterSlotMigrationStuckRule,
    "redis_cluster_slot_migration_stuck",
    "redis",
    stub
);
app_rule!(
    redis_pubsub_flood,
    RedisPubsubFloodRule,
    "redis_pubsub_flood",
    "redis",
    stub
);
app_rule!(
    redis_expired_keys_storm,
    RedisExpiredKeysStormRule,
    "redis_expired_keys_storm",
    "redis",
    |_st, _th, hist, _tk| {
        let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
        let sc = delta(hist, 202);
        if cpu > 70.0 && sc < 10.0 {
            Some(blank_diag(
                "redis_expired_keys_storm",
                "redis: possible expired-keys sweep",
                format!("{:.0}% CPU with few syscalls", cpu),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    redis_cluster_bus_thrash,
    RedisClusterBusThrashRule,
    "redis_cluster_bus_thrash",
    "redis",
    stub
);
app_rule!(
    redis_lazyfree_backlog,
    RedisLazyfreeBacklogRule,
    "redis_lazyfree_backlog",
    "redis",
    stub
);
app_rule!(
    memcached_lru_churn,
    MemcachedLruChurnRule,
    "memcached_lru_churn",
    "memcached",
    stub
);
app_rule!(
    memcached_slab_imbalance,
    MemcachedSlabImbalanceRule,
    "memcached_slab_imbalance",
    "memcached",
    stub
);
app_rule!(
    memcached_flush_all_stall,
    MemcachedFlushAllStallRule,
    "memcached_flush_all_stall",
    "memcached",
    stub
);
app_rule!(
    memcached_large_evict,
    MemcachedLargeEvictRule,
    "memcached_large_evict",
    "memcached",
    stub
);
app_rule!(
    opcache_lock_contention,
    OpcacheLockContentionRule,
    "opcache_lock_contention",
    "phpfpm",
    stub
);
app_rule!(
    phpfpm_max_children_exhausted,
    PhpfpmMaxChildrenExhaustedRule,
    "phpfpm_max_children_exhausted",
    "phpfpm",
    |st, _th, _hist, _tk| {
        let threads = st.snap.as_ref().map(|s| s.status.threads).unwrap_or(0);
        if threads > 200 {
            Some(blank_diag(
                "phpfpm_max_children_exhausted",
                "php-fpm: thread/children count very high",
                format!("{} threads", threads),
                Severity::Warning,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    phpfpm_slow_log_flood,
    PhpfpmSlowLogFloodRule,
    "phpfpm_slow_log_flood",
    "phpfpm",
    stub
);
app_rule!(
    opcache_revalidate_storm,
    OpcacheRevalidateStormRule,
    "opcache_revalidate_storm",
    "phpfpm",
    stub
);
app_rule!(
    varnish_nuke_rate_climb,
    VarnishNukeRateClimbRule,
    "varnish_nuke_rate_climb",
    "varnish",
    stub
);
app_rule!(
    varnish_backend_sick,
    VarnishBackendSickRule,
    "varnish_backend_sick",
    "varnish",
    |_st, _th, hist, _tk| {
        const CONNECT: u32 = 42;
        let r = delta(hist, CONNECT);
        if r > 30.0 {
            Some(blank_diag(
                "varnish_backend_sick",
                "varnish: connect burst (backend sick?)",
                format!("{:.0} connect/s", r),
                Severity::Warning,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    varnish_vcl_recompile_wall,
    VarnishVclRecompileWallRule,
    "varnish_vcl_recompile_wall",
    "varnish",
    stub
);
app_rule!(
    varnish_mempool_pressure,
    VarnishMempoolPressureRule,
    "varnish_mempool_pressure",
    "varnish",
    stub
);
app_rule!(
    apcu_shm_contention,
    ApcuShmContentionRule,
    "apcu_shm_contention",
    "apcu",
    stub
);
app_rule!(
    apcu_gc_storm,
    ApcuGcStormRule,
    "apcu_gc_storm",
    "apcu",
    stub
);
app_rule!(
    groupcache_hot_key,
    GroupcacheHotKeyRule,
    "groupcache_hot_key",
    "apcu",
    stub
);
app_rule!(
    nginx_disk_cache_rebuild,
    NginxDiskCacheRebuildRule,
    "nginx_disk_cache_rebuild",
    "squid",
    stub
);
app_rule!(
    squid_aging_pass_wall,
    SquidAgingPassWallRule,
    "squid_aging_pass_wall",
    "squid",
    stub
);
app_rule!(
    rsyslog_queue_overflow,
    RsyslogQueueOverflowRule,
    "rsyslog_queue_overflow",
    "rsyslog",
    |_st, _th, hist, _tk| {
        let w = delta(hist, 1);
        if w > 2000.0 {
            Some(blank_diag(
                "rsyslog_queue_overflow",
                "rsyslog: write burst (queue drain or overflow)",
                format!("{:.0} write/s", w),
                Severity::Notice,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    rsyslog_output_blocked,
    RsyslogOutputBlockedRule,
    "rsyslog_output_blocked",
    "rsyslog",
    stub
);
app_rule!(
    rsyslog_impstats_drops,
    RsyslogImpstatsDropsRule,
    "rsyslog_impstats_drops",
    "rsyslog",
    stub
);
app_rule!(
    journald_rate_limit_kicked,
    JournaldRateLimitKickedRule,
    "journald_rate_limit_kicked",
    "journald",
    |_st, _th, hist, _tk| {
        let r = delta(hist, 1);
        if r > 1500.0 {
            Some(blank_diag(
                "journald_rate_limit_kicked",
                "journald: write burst (rate-limit kicked?)",
                format!("{:.0} write/s", r),
                Severity::Notice,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    journald_forward_fail,
    JournaldForwardFailRule,
    "journald_forward_fail",
    "journald",
    stub
);
app_rule!(
    journald_storage_sync_wall,
    JournaldStorageSyncWallRule,
    "journald_storage_sync_wall",
    "journald",
    stub
);
app_rule!(
    fluentbit_backlog,
    FluentbitBacklogRule,
    "fluentbit_backlog",
    "fluentbit",
    |_st, _th, hist, _tk| {
        const WRITE: u32 = 1;
        let r = delta(hist, WRITE);
        if r > 1000.0 {
            Some(blank_diag(
                "fluentbit_backlog",
                "fluent-bit: write-heavy (flushing backlog)",
                format!("{:.0} write/s", r),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    fluentbit_retry_storm,
    FluentbitRetryStormRule,
    "fluentbit_retry_storm",
    "fluentbit",
    stub
);
app_rule!(
    fluentd_outforward_handshake_wall,
    FluentdOutforwardHandshakeWallRule,
    "fluentd_outforward_handshake_wall",
    "fluentbit",
    stub
);
app_rule!(
    vector_sink_unavailable,
    VectorSinkUnavailableRule,
    "vector_sink_unavailable",
    "vector",
    stub
);
app_rule!(
    vector_batch_drop,
    VectorBatchDropRule,
    "vector_batch_drop",
    "vector",
    stub
);
app_rule!(
    promtail_tail_stall,
    PromtailTailStallRule,
    "promtail_tail_stall",
    "promtail",
    stub
);
app_rule!(
    filebeat_inode_confusion,
    FilebeatInodeConfusionRule,
    "filebeat_inode_confusion",
    "promtail",
    stub
);
app_rule!(
    otelcol_exporter_failing,
    OtelcolExporterFailingRule,
    "otelcol_exporter_failing",
    "otelcol",
    stub
);
app_rule!(
    otelcol_sampler_mismatch,
    OtelcolSamplerMismatchRule,
    "otelcol_sampler_mismatch",
    "otelcol",
    stub
);
app_rule!(
    docker_image_pull_storm,
    DockerImagePullStormRule,
    "docker_image_pull_storm",
    "docker",
    |_st, _th, hist, _tk| {
        const READ: u32 = 0;
        let r = delta(hist, READ);
        if r > 2000.0 {
            Some(blank_diag(
                "docker_image_pull_storm",
                "docker: likely image pull in progress",
                format!("{:.0} read/s", r),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    containerd_layer_unpack_wall,
    ContainerdLayerUnpackWallRule,
    "containerd_layer_unpack_wall",
    "docker",
    stub
);
app_rule!(
    cri_socket_pressure,
    CriSocketPressureRule,
    "cri_socket_pressure",
    "docker",
    stub
);
app_rule!(
    containerd_snapshotter_backpressure,
    ContainerdSnapshotterBackpressureRule,
    "containerd_snapshotter_backpressure",
    "docker",
    stub
);
app_rule!(
    overlay_mount_wall,
    OverlayMountWallRule,
    "overlay_mount_wall",
    "docker",
    stub
);
app_rule!(
    runc_exec_latency,
    RuncExecLatencyRule,
    "runc_exec_latency",
    "docker",
    stub
);
app_rule!(
    cgroup_throttle_on_container,
    CgroupThrottleOnContainerRule,
    "cgroup_throttle_on_container",
    "docker",
    stub
);
app_rule!(
    docker_daemon_stuck,
    DockerDaemonStuckRule,
    "docker_daemon_stuck",
    "docker",
    stub
);
app_rule!(
    podman_slirp4netns_stall,
    PodmanSlirp4netnsStallRule,
    "podman_slirp4netns_stall",
    "podman",
    stub
);
app_rule!(
    podman_pause_container_churn,
    PodmanPauseContainerChurnRule,
    "podman_pause_container_churn",
    "podman",
    stub
);
app_rule!(
    podman_journald_link_slow,
    PodmanJournaldLinkSlowRule,
    "podman_journald_link_slow",
    "podman",
    stub
);
app_rule!(
    podman_rootless_uidmap_wall,
    PodmanRootlessUidmapWallRule,
    "podman_rootless_uidmap_wall",
    "podman",
    stub
);
app_rule!(
    kubelet_pod_sandbox_gc,
    KubeletPodSandboxGcRule,
    "kubelet_pod_sandbox_gc",
    "kubelet",
    stub
);
app_rule!(
    kubelet_cadvisor_pressure,
    KubeletCadvisorPressureRule,
    "kubelet_cadvisor_pressure",
    "kubelet",
    stub
);
app_rule!(
    kubeproxy_iptables_rebuild_storm,
    KubeproxyIptablesRebuildStormRule,
    "kubeproxy_iptables_rebuild_storm",
    "kubelet",
    stub
);
app_rule!(
    kubelet_liveness_hammer,
    KubeletLivenessHammerRule,
    "kubelet_liveness_hammer",
    "kubelet",
    stub
);
app_rule!(
    kubelet_imagegc_pressure,
    KubeletImagegcPressureRule,
    "kubelet_imagegc_pressure",
    "kubelet",
    |_st, _th, hist, _tk| {
        const UNLINK: u32 = 87;
        const UNLINKAT: u32 = 263;
        let r = delta(hist, UNLINK) + delta(hist, UNLINKAT);
        if r > 50.0 {
            Some(blank_diag(
                "kubelet_imagegc_pressure",
                "kubelet: image GC active",
                format!("{:.0} unlink/s", r),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    kubelet_exec_session_leak,
    KubeletExecSessionLeakRule,
    "kubelet_exec_session_leak",
    "kubelet",
    stub
);
app_rule!(
    crio_image_gc_wall,
    CrioImageGcWallRule,
    "crio_image_gc_wall",
    "crio",
    stub
);
app_rule!(
    crio_pod_sandbox_wall,
    CrioPodSandboxWallRule,
    "crio_pod_sandbox_wall",
    "crio",
    stub
);
app_rule!(
    containerd_shim_startup_wall,
    ContainerdShimStartupWallRule,
    "containerd_shim_startup_wall",
    "containerd_shim",
    stub
);
app_rule!(
    containerd_shim_reaper_quiesce,
    ContainerdShimReaperQuiesceRule,
    "containerd_shim_reaper_quiesce",
    "containerd_shim",
    stub
);
app_rule!(
    lxc_uidmap_wall,
    LxcUidmapWallRule,
    "lxc_uidmap_wall",
    "lxc",
    stub
);
app_rule!(
    lxc_veth_setup_wall,
    LxcVethSetupWallRule,
    "lxc_veth_setup_wall",
    "lxc",
    stub
);
app_rule!(
    firecracker_vmm_boot_wall,
    FirecrackerVmmBootWallRule,
    "firecracker_vmm_boot_wall",
    "firecracker",
    stub
);
app_rule!(
    kata_vsock_stall,
    KataVsockStallRule,
    "kata_vsock_stall",
    "firecracker",
    stub
);
app_rule!(
    kata_device_setup_wall,
    KataDeviceSetupWallRule,
    "kata_device_setup_wall",
    "firecracker",
    stub
);
app_rule!(
    crun_cgroup_setup_wall,
    CrunCgroupSetupWallRule,
    "crun_cgroup_setup_wall",
    "crun",
    stub
);
app_rule!(
    youki_namespace_setup_wall,
    YoukiNamespaceSetupWallRule,
    "youki_namespace_setup_wall",
    "crun",
    stub
);
app_rule!(
    oci_hook_wall,
    OciHookWallRule,
    "oci_hook_wall",
    "crun",
    stub
);
app_rule!(
    node_v8_gc_pause,
    NodeV8GcPauseRule,
    "node_v8_gc_pause",
    "node",
    stub
);
app_rule!(
    node_event_loop_block,
    NodeEventLoopBlockRule,
    "node_event_loop_block",
    "node",
    |_st, _th, hist, _tk| {
        let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
        let sc = if hist.len() < 2 {
            0.0
        } else {
            let a = &hist[hist.len() - 2];
            let b = hist.back().unwrap();
            b.total_syscalls.saturating_sub(a.total_syscalls) as f64
        };
        if cpu > 85.0 && sc < 20.0 {
            Some(blank_diag(
                "node_event_loop_block",
                "node: event loop blocked",
                format!("{:.0}% CPU, {:.0} syscalls/s", cpu, sc),
                Severity::Warning,
                Confidence::High,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    node_uv_threadpool_starved,
    NodeUvThreadpoolStarvedRule,
    "node_uv_threadpool_starved",
    "node",
    |_st, _th, hist, _tk| {
        let r = delta(hist, 0) + delta(hist, 17) + delta(hist, 1) + delta(hist, 18);
        if r > 1000.0 {
            Some(blank_diag(
                "node_uv_threadpool_starved",
                "node: libuv threadpool busy",
                format!("{:.0} read/write/s", r),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    node_async_hook_storm,
    NodeAsyncHookStormRule,
    "node_async_hook_storm",
    "node",
    stub
);
app_rule!(
    node_inspector_attached,
    NodeInspectorAttachedRule,
    "node_inspector_attached",
    "node",
    stub
);
app_rule!(
    node_worker_thread_churn,
    NodeWorkerThreadChurnRule,
    "node_worker_thread_churn",
    "node",
    stub
);
app_rule!(
    node_child_process_spawn_storm,
    NodeChildProcessSpawnStormRule,
    "node_child_process_spawn_storm",
    "node",
    stub
);
app_rule!(
    node_signalfd_pressure,
    NodeSignalfdPressureRule,
    "node_signalfd_pressure",
    "node",
    stub
);
app_rule!(
    jvm_gc_stw,
    JvmGcStwRule,
    "jvm_gc_stw",
    "jvm",
    |_st, _th, hist, _tk| {
        if hist.len() < 3 {
            return None;
        }
        let last = hist.back().unwrap();
        let prev = &hist[hist.len() - 2];
        if last.cpu_pct < 5.0 && prev.cpu_pct > 85.0 {
            Some(blank_diag(
                "jvm_gc_stw",
                "jvm: likely GC stop-the-world pause",
                "CPU dropped from >85% to <5% in one tick".into(),
                Severity::Warning,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    jvm_full_gc,
    JvmFullGcRule,
    "jvm_full_gc",
    "jvm",
    |_st, _th, hist, _tk| {
        let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
        if hist.iter().rev().take(3).all(|s| s.cpu_pct > 95.0) && cpu > 95.0 {
            Some(blank_diag(
                "jvm_full_gc",
                "jvm: possible full-GC burn",
                "CPU >95% for 3 consecutive ticks".into(),
                Severity::Notice,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    jvm_safepoint_delay,
    JvmSafepointDelayRule,
    "jvm_safepoint_delay",
    "jvm",
    stub
);
app_rule!(
    jvm_deopt_storm,
    JvmDeoptStormRule,
    "jvm_deopt_storm",
    "jvm",
    stub
);
app_rule!(
    jvm_class_loading_wall,
    JvmClassLoadingWallRule,
    "jvm_class_loading_wall",
    "jvm",
    stub
);
app_rule!(
    jvm_finalizer_backlog,
    JvmFinalizerBacklogRule,
    "jvm_finalizer_backlog",
    "jvm",
    stub
);
app_rule!(
    jvm_compile_queue_climb,
    JvmCompileQueueClimbRule,
    "jvm_compile_queue_climb",
    "jvm",
    stub
);
app_rule!(
    jvm_metaspace_pressure,
    JvmMetaspacePressureRule,
    "jvm_metaspace_pressure",
    "jvm",
    stub
);
app_rule!(
    py_gil_contention,
    PyGilContentionRule,
    "py_gil_contention",
    "python",
    |st, _th, hist, _tk| {
        let threads = st.snap.as_ref().map(|s| s.status.threads).unwrap_or(0);
        let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
        if threads > 4 && cpu > 90.0 && cpu < 120.0 {
            Some(blank_diag(
                "py_gil_contention",
                "python: possible GIL contention",
                format!("{} threads, {:.0}% CPU", threads, cpu),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(py_gc_pause, PyGcPauseRule, "py_gc_pause", "python", stub);
app_rule!(
    py_asyncio_loop_lag,
    PyAsyncioLoopLagRule,
    "py_asyncio_loop_lag",
    "python",
    stub
);
app_rule!(
    py_interpreter_shutdown_wall,
    PyInterpreterShutdownWallRule,
    "py_interpreter_shutdown_wall",
    "python",
    stub
);
app_rule!(
    py_atexit_stall,
    PyAtexitStallRule,
    "py_atexit_stall",
    "python",
    stub
);
app_rule!(
    go_gc_assist_wall,
    GoGcAssistWallRule,
    "go_gc_assist_wall",
    "go",
    stub
);
app_rule!(
    go_scheduler_stall,
    GoSchedulerStallRule,
    "go_scheduler_stall",
    "go",
    |_st, _th, hist, _tk| {
        let cpu = hist.back().map(|s| s.cpu_pct).unwrap_or(0.0);
        if cpu > 80.0 && delta(hist, 24) > 50.0 {
            Some(blank_diag(
                "go_scheduler_stall",
                "go: scheduler stall (yield loop)",
                format!("{:.0}% CPU, sched_yield pressure", cpu),
                Severity::Notice,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    go_netpoll_latency,
    GoNetpollLatencyRule,
    "go_netpoll_latency",
    "go",
    stub
);
app_rule!(
    go_lock_os_thread_leak,
    GoLockOsThreadLeakRule,
    "go_lock_os_thread_leak",
    "go",
    stub
);
app_rule!(
    go_gomaxprocs_mismatch,
    GoGomaxprocsMismatchRule,
    "go_gomaxprocs_mismatch",
    "go",
    stub
);
app_rule!(
    dotnet_gc_gen2_pause,
    DotnetGcGen2PauseRule,
    "dotnet_gc_gen2_pause",
    "dotnet",
    stub
);
app_rule!(
    dotnet_threadpool_starved,
    DotnetThreadpoolStarvedRule,
    "dotnet_threadpool_starved",
    "dotnet",
    stub
);
app_rule!(
    dotnet_valuetask_leak,
    DotnetValuetaskLeakRule,
    "dotnet_valuetask_leak",
    "dotnet",
    stub
);
app_rule!(
    dotnet_finalizer_thread_pressure,
    DotnetFinalizerThreadPressureRule,
    "dotnet_finalizer_thread_pressure",
    "dotnet",
    stub
);
app_rule!(
    kafka_producer_backpressure,
    KafkaProducerBackpressureRule,
    "kafka_producer_backpressure",
    "kafka",
    |_st, _th, hist, _tk| {
        const WRITE: u32 = 1;
        const SENDMSG: u32 = 46;
        let r = delta(hist, WRITE) + delta(hist, SENDMSG);
        if r > 5000.0 {
            Some(blank_diag(
                "kafka_producer_backpressure",
                "kafka: write burst (producer backpressure?)",
                format!("{:.0} write+sendmsg/s", r),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    kafka_controller_election,
    KafkaControllerElectionRule,
    "kafka_controller_election",
    "kafka",
    stub
);
app_rule!(
    kafka_segment_roll_wall,
    KafkaSegmentRollWallRule,
    "kafka_segment_roll_wall",
    "kafka",
    stub
);
app_rule!(
    kafka_isr_shrink,
    KafkaIsrShrinkRule,
    "kafka_isr_shrink",
    "kafka",
    stub
);
app_rule!(
    rabbit_queue_mem_alarm,
    RabbitQueueMemAlarmRule,
    "rabbit_queue_mem_alarm",
    "rabbit",
    stub
);
app_rule!(
    rabbit_flow_control,
    RabbitFlowControlRule,
    "rabbit_flow_control",
    "rabbit",
    stub
);
app_rule!(
    rabbit_mnesia_stall,
    RabbitMnesiaStallRule,
    "rabbit_mnesia_stall",
    "rabbit",
    stub
);
app_rule!(
    nats_slow_consumer,
    NatsSlowConsumerRule,
    "nats_slow_consumer",
    "nats",
    |_st, _th, hist, _tk| {
        const SENDMSG: u32 = 46;
        const RECVMSG: u32 = 47;
        let s = delta(hist, SENDMSG);
        let r = delta(hist, RECVMSG);
        if s > r * 3.0 && s > 500.0 {
            Some(blank_diag(
                "nats_slow_consumer",
                "nats: send >> recv (slow consumer)",
                format!("send={:.0}/s recv={:.0}/s", s, r),
                Severity::Warning,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    nats_pubsub_drop,
    NatsPubsubDropRule,
    "nats_pubsub_drop",
    "nats",
    stub
);
app_rule!(
    redis_stream_consumer_lag,
    RedisStreamConsumerLagRule,
    "redis_stream_consumer_lag",
    "redis",
    stub
);
app_rule!(
    redis_stream_xadd_burst,
    RedisStreamXaddBurstRule,
    "redis_stream_xadd_burst",
    "redis",
    stub
);
app_rule!(
    pulsar_bookie_fsync_wall,
    PulsarBookieFsyncWallRule,
    "pulsar_bookie_fsync_wall",
    "pulsar",
    stub
);
app_rule!(
    pulsar_broker_ownership_change,
    PulsarBrokerOwnershipChangeRule,
    "pulsar_broker_ownership_change",
    "pulsar",
    stub
);
app_rule!(
    nsq_channel_backlog,
    NsqChannelBacklogRule,
    "nsq_channel_backlog",
    "nsq",
    stub
);
app_rule!(
    nsqlookupd_lag,
    NsqlookupdLagRule,
    "nsqlookupd_lag",
    "nsq",
    stub
);
app_rule!(
    fs_journal_commit_wall,
    FsJournalCommitWallRule,
    "fs_journal_commit_wall",
    "fs",
    stub
);
app_rule!(
    fs_barrier_wall,
    FsBarrierWallRule,
    "fs_barrier_wall",
    "fs",
    stub
);
app_rule!(
    btrfs_balance_wall,
    BtrfsBalanceWallRule,
    "btrfs_balance_wall",
    "fs",
    stub
);
app_rule!(
    btrfs_nocow_fallback,
    BtrfsNocowFallbackRule,
    "btrfs_nocow_fallback",
    "fs",
    stub
);
app_rule!(
    fs_write_barrier_storm,
    FsWriteBarrierStormRule,
    "fs_write_barrier_storm",
    "fs",
    stub
);
app_rule!(
    nfs_mount_hung,
    NfsMountHungRule,
    "nfs_mount_hung",
    "nfs",
    stub
);
app_rule!(
    cephfs_mds_slow,
    CephfsMdsSlowRule,
    "cephfs_mds_slow",
    "nfs",
    stub
);
app_rule!(
    nfs_oplock_wait,
    NfsOplockWaitRule,
    "nfs_oplock_wait",
    "nfs",
    stub
);
app_rule!(
    s3fs_rate_limit,
    S3fsRateLimitRule,
    "s3fs_rate_limit",
    "s3fs",
    stub
);
app_rule!(
    s3fs_multipart_stall,
    S3fsMultipartStallRule,
    "s3fs_multipart_stall",
    "s3fs",
    stub
);
app_rule!(
    resolver_storm,
    ResolverStormRule,
    "resolver_storm",
    "resolver",
    |_st, _th, hist, _tk| {
        const SENDMSG: u32 = 46;
        const RECVMSG: u32 = 47;
        let r = delta(hist, SENDMSG) + delta(hist, RECVMSG);
        if r > 500.0 {
            Some(blank_diag(
                "resolver_storm",
                "resolver: UDP sendmsg/recvmsg storm",
                format!("{:.0}/s", r),
                Severity::Warning,
                Confidence::Medium,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    resolver_cache_miss_wall,
    ResolverCacheMissWallRule,
    "resolver_cache_miss_wall",
    "resolver",
    stub
);
app_rule!(
    resolver_timeout_cascade,
    ResolverTimeoutCascadeRule,
    "resolver_timeout_cascade",
    "resolver",
    stub
);
app_rule!(
    ebpf_other_tracer_interference,
    EbpfOtherTracerInterferenceRule,
    "ebpf_other_tracer_interference",
    "ebpf",
    |st, _th, _hist, _tk| {
        if st.ebpf_ok {
            None
        } else {
            if st
                .ebpf_error
                .as_deref()
                .unwrap_or("")
                .contains("perf_event")
            {
                Some(blank_diag(
                    "ebpf_other_tracer_interference",
                    "ebpf: perf_event busy (another tracer attached?)",
                    "ghost could not attach".into(),
                    Severity::Notice,
                    Confidence::Medium,
                ))
            } else {
                None
            }
        }
    }
);
app_rule!(
    ebpf_map_pressure,
    EbpfMapPressureRule,
    "ebpf_map_pressure",
    "ebpf",
    stub
);
app_rule!(
    wg_peer_handshake_retry,
    WgPeerHandshakeRetryRule,
    "wg_peer_handshake_retry",
    "wireguard",
    stub
);
app_rule!(
    openvpn_rekey_wall,
    OpenvpnRekeyWallRule,
    "openvpn_rekey_wall",
    "wireguard",
    stub
);
app_rule!(
    envoy_config_distribution_wall,
    EnvoyConfigDistributionWallRule,
    "envoy_config_distribution_wall",
    "envoy",
    stub
);
app_rule!(
    envoy_hot_restart_drain,
    EnvoyHotRestartDrainRule,
    "envoy_hot_restart_drain",
    "envoy",
    |_st, _th, hist, _tk| {
        const CLOSE: u32 = 3;
        let r = delta(hist, CLOSE);
        if r > 200.0 {
            Some(blank_diag(
                "envoy_hot_restart_drain",
                "envoy: many close syscalls (drain?)",
                format!("{:.0} close/s", r),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);
app_rule!(
    envoy_listener_drain_wall,
    EnvoyListenerDrainWallRule,
    "envoy_listener_drain_wall",
    "envoy",
    stub
);
app_rule!(
    quic_initial_handshake_wall,
    QuicInitialHandshakeWallRule,
    "quic_initial_handshake_wall",
    "quic",
    stub
);
app_rule!(
    quic_migration_storm,
    QuicMigrationStormRule,
    "quic_migration_storm",
    "quic",
    stub
);
app_rule!(
    grpc_keepalive_ping_storm,
    GrpcKeepalivePingStormRule,
    "grpc_keepalive_ping_storm",
    "grpc",
    stub
);
app_rule!(
    grpc_connection_half_closed,
    GrpcConnectionHalfClosedRule,
    "grpc_connection_half_closed",
    "grpc",
    stub
);
app_rule!(
    grpc_flow_control_window_squeeze,
    GrpcFlowControlWindowSqueezeRule,
    "grpc_flow_control_window_squeeze",
    "grpc",
    stub
);

pub fn registry() -> &'static [&'static (dyn Rule + 'static)] {
    static R: &[&'static (dyn Rule + 'static)] = &[
        &nginx_worker_starved,
        &nginx_upstream_stuck,
        &nginx_ssl_handshake_storm,
        &nginx_rate_limit_tripping,
        &nginx_log_flush_stall,
        &nginx_reload_quiescence,
        &nginx_cache_miss_storm,
        &nginx_shm_zone_full,
        &httpd_prefork_saturation,
        &httpd_worker_mpm_thrash,
        &httpd_mod_php_bottleneck,
        &httpd_modsec_block_storm,
        &httpd_slow_client_wall,
        &httpd_keepalive_exhaustion,
        &httpd_graceful_restart_drag,
        &httpd_fcgi_stuck,
        &lsws_lsapi_pool_pressure,
        &lsws_connect_backlog,
        &lsws_cache_rebuild,
        &lsws_qos_tripping,
        &caddy_autocert_wall,
        &caddy_admin_api_flood,
        &caddy_reverse_proxy_stuck,
        &caddy_config_reload_quiescence,
        &traefik_routing_rebuild_pressure,
        &traefik_dynamic_config_churn,
        &traefik_backend_marker_flapping,
        &haproxy_backend_down,
        &haproxy_queue_climb,
        &haproxy_check_timeout_storm,
        &mysql_innodb_row_lock_wait,
        &mysql_buffer_pool_pressure,
        &mysql_slow_query_log_flood,
        &mysql_replication_lag,
        &mysql_deadlock_loop,
        &mysql_open_table_cache_miss,
        &mysql_temp_disk_spill,
        &mysql_binlog_fsync_wall,
        &mysql_aria_pwrite_stall,
        &mysql_galera_flow_control,
        &mysql_thread_pool_full,
        &mysql_ibtmp_grow,
        &pg_wal_fsync_wall,
        &pg_autovacuum_pressure,
        &pg_lock_monitor_spike,
        &pg_checkpointer_backpressure,
        &pg_bgwriter_lag,
        &pg_replication_lag,
        &pg_logical_slot_abandonment,
        &pg_hot_toast,
        &pg_large_object_leak,
        &pg_prepared_tx_hang,
        &pg_vacuum_full_wall,
        &pg_tempfile_climb,
        &sqlite_wal_wall,
        &sqlite_vacuum_into_wall,
        &sqlite_shm_contention,
        &mongo_write_lock_queue,
        &mongo_replica_election,
        &mongo_oplog_pressure,
        &mongo_journal_fsync_wall,
        &mongo_wiredtiger_evict_pressure,
        &cockroach_raft_stall,
        &cockroach_range_split_storm,
        &tidb_intent_cleanup_wall,
        &influx_tsm_compaction_wall,
        &influx_wal_wall,
        &timescale_chunk_compression_wall,
        &cassandra_memtable_flush_wall,
        &scylla_shard_imbalance,
        &redis_fork_bgsave_wall,
        &redis_rdb_rewrite_stall,
        &redis_aof_fsync_wall,
        &redis_cluster_slot_migration_stuck,
        &redis_pubsub_flood,
        &redis_expired_keys_storm,
        &redis_cluster_bus_thrash,
        &redis_lazyfree_backlog,
        &memcached_lru_churn,
        &memcached_slab_imbalance,
        &memcached_flush_all_stall,
        &memcached_large_evict,
        &opcache_lock_contention,
        &phpfpm_max_children_exhausted,
        &phpfpm_slow_log_flood,
        &opcache_revalidate_storm,
        &varnish_nuke_rate_climb,
        &varnish_backend_sick,
        &varnish_vcl_recompile_wall,
        &varnish_mempool_pressure,
        &apcu_shm_contention,
        &apcu_gc_storm,
        &groupcache_hot_key,
        &nginx_disk_cache_rebuild,
        &squid_aging_pass_wall,
        &rsyslog_queue_overflow,
        &rsyslog_output_blocked,
        &rsyslog_impstats_drops,
        &journald_rate_limit_kicked,
        &journald_forward_fail,
        &journald_storage_sync_wall,
        &fluentbit_backlog,
        &fluentbit_retry_storm,
        &fluentd_outforward_handshake_wall,
        &vector_sink_unavailable,
        &vector_batch_drop,
        &promtail_tail_stall,
        &filebeat_inode_confusion,
        &otelcol_exporter_failing,
        &otelcol_sampler_mismatch,
        &docker_image_pull_storm,
        &containerd_layer_unpack_wall,
        &cri_socket_pressure,
        &containerd_snapshotter_backpressure,
        &overlay_mount_wall,
        &runc_exec_latency,
        &cgroup_throttle_on_container,
        &docker_daemon_stuck,
        &podman_slirp4netns_stall,
        &podman_pause_container_churn,
        &podman_journald_link_slow,
        &podman_rootless_uidmap_wall,
        &kubelet_pod_sandbox_gc,
        &kubelet_cadvisor_pressure,
        &kubeproxy_iptables_rebuild_storm,
        &kubelet_liveness_hammer,
        &kubelet_imagegc_pressure,
        &kubelet_exec_session_leak,
        &crio_image_gc_wall,
        &crio_pod_sandbox_wall,
        &containerd_shim_startup_wall,
        &containerd_shim_reaper_quiesce,
        &lxc_uidmap_wall,
        &lxc_veth_setup_wall,
        &firecracker_vmm_boot_wall,
        &kata_vsock_stall,
        &kata_device_setup_wall,
        &crun_cgroup_setup_wall,
        &youki_namespace_setup_wall,
        &oci_hook_wall,
        &node_v8_gc_pause,
        &node_event_loop_block,
        &node_uv_threadpool_starved,
        &node_async_hook_storm,
        &node_inspector_attached,
        &node_worker_thread_churn,
        &node_child_process_spawn_storm,
        &node_signalfd_pressure,
        &jvm_gc_stw,
        &jvm_full_gc,
        &jvm_safepoint_delay,
        &jvm_deopt_storm,
        &jvm_class_loading_wall,
        &jvm_finalizer_backlog,
        &jvm_compile_queue_climb,
        &jvm_metaspace_pressure,
        &py_gil_contention,
        &py_gc_pause,
        &py_asyncio_loop_lag,
        &py_interpreter_shutdown_wall,
        &py_atexit_stall,
        &go_gc_assist_wall,
        &go_scheduler_stall,
        &go_netpoll_latency,
        &go_lock_os_thread_leak,
        &go_gomaxprocs_mismatch,
        &dotnet_gc_gen2_pause,
        &dotnet_threadpool_starved,
        &dotnet_valuetask_leak,
        &dotnet_finalizer_thread_pressure,
        &kafka_producer_backpressure,
        &kafka_controller_election,
        &kafka_segment_roll_wall,
        &kafka_isr_shrink,
        &rabbit_queue_mem_alarm,
        &rabbit_flow_control,
        &rabbit_mnesia_stall,
        &nats_slow_consumer,
        &nats_pubsub_drop,
        &redis_stream_consumer_lag,
        &redis_stream_xadd_burst,
        &pulsar_bookie_fsync_wall,
        &pulsar_broker_ownership_change,
        &nsq_channel_backlog,
        &nsqlookupd_lag,
        &fs_journal_commit_wall,
        &fs_barrier_wall,
        &btrfs_balance_wall,
        &btrfs_nocow_fallback,
        &fs_write_barrier_storm,
        &nfs_mount_hung,
        &cephfs_mds_slow,
        &nfs_oplock_wait,
        &s3fs_rate_limit,
        &s3fs_multipart_stall,
        &resolver_storm,
        &resolver_cache_miss_wall,
        &resolver_timeout_cascade,
        &ebpf_other_tracer_interference,
        &ebpf_map_pressure,
        &wg_peer_handshake_retry,
        &openvpn_rekey_wall,
        &envoy_config_distribution_wall,
        &envoy_hot_restart_drain,
        &envoy_listener_drain_wall,
        &quic_initial_handshake_wall,
        &quic_migration_storm,
        &grpc_keepalive_ping_storm,
        &grpc_connection_half_closed,
        &grpc_flow_control_window_squeeze,
    ];
    R
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_hundred_ten_rules_registered() {
        assert_eq!(registry().len(), 210);
    }
    #[test]
    fn ids_unique() {
        let ids: Vec<_> = registry().iter().map(|r| r.id()).collect();
        let mut s = ids.clone();
        s.sort();
        s.dedup();
        assert_eq!(ids.len(), s.len());
    }
    #[test]
    fn unknown_binary_skips_app_rules() {
        let st = AppState::new(1, "weird-9000".into());
        let th = RuleThresholds::new();
        let h: VecDeque<TickSnapshot> = Default::default();
        // nginx_worker_starved requires identity match on nginx comm/exe.
        assert!(nginx_worker_starved.evaluate(&st, &th, &h, 1).is_none());
    }
}
