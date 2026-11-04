# ghost daemon — persistent headless watcher

Since **v0.11.0**, ghost ships a daemon mode: a long-running headless
process that attaches to a target (pid / tree / cgroup / systemd unit)
and writes rotated `.ghost` segments to disk continuously. The TUI is
not involved. The user `scp`s the segment back and runs
`ghost replay <segment>.ghost` locally.

The "daemon-ness" is not a fork — ghost itself stays a single foreground
process. Persistence is systemd (`Type=simple`) + in-process segment
rotation + a `--headless` run loop.

> There is **no network listener**. "Remote standalone" here means the
> daemon runs on whatever host you install it on — it is not a wire
> protocol.

## Install

```
sudo ghost --install --pid 1234
```

Also accepted: `--tree <root-pid>`, `--cgroup <path>`, `--unit <systemd.unit>`.

That one command:

1. Writes `/etc/ghost/<slug>.toml` — the daemon config (target + rotation).
2. Writes `/etc/systemd/system/ghost@<slug>.service` — unit file calling
   `ghost daemon --config /etc/ghost/<slug>.toml`.
3. Creates `/var/log/ghost/<slug>/` for rotated segments.
4. Runs `systemctl daemon-reload && systemctl enable --now ghost@<slug>.service`.

Pass `--dry-run` to see exactly what would be written without touching
the system. Pass `--no-systemctl` to skip the enable step (useful on
WSL2 / containers where systemd is not the active init — ghost will
still lay down the unit file for you to copy somewhere that uses it).

Rotation defaults — override at install time:

| Flag | Default | Meaning |
|---|---|---|
| `--max-segment-bytes` | `104857600` (100 MiB) | rotate when the live segment exceeds this |
| `--keep-segments`     | `10` | prune oldest segments beyond this count |
| `--max-age-secs`      | `86400` (24 h) | rotate even if under size cap |

With the defaults a single watcher's disk footprint is capped at ~1 GiB.

## Uninstall

```
sudo ghost --uninstall             # all installed ghost@* services
sudo ghost --uninstall --pid 1234  # just one
sudo ghost --uninstall --purge     # also delete /var/log/ghost/<slug>/
```

Uninstall is all-or-nothing: every file install wrote is removed, and
`systemctl daemon-reload` runs so the removed unit disappears from
systemd's view. Logs under `/var/log/ghost/` are the user's data and
stay by default; `--purge` removes them.

Dry-run (`--dry-run`) and `--no-systemctl` work on uninstall too.

## Session layout on disk

```
/var/log/ghost/<slug>/
├── index.json                 # segment manifest (seq, bytes, open/close)
├── segment-000000.ghost       # oldest kept segment
├── segment-000001.ghost
└── segment-000002.ghost       # current live segment
```

Each `segment-N.ghost` is a complete, independent session file (same
format as `--record`'s output), so **any one segment can be replayed
on its own**:

```
scp box:/var/log/ghost/pid-1234/segment-000005.ghost .
ghost replay segment-000005.ghost
```

`index.json` is advisory; losing it does not invalidate the segments
themselves.

## Capabilities

The daemon needs `cap_bpf` + `cap_perfmon`, same as the interactive
lenses. The installer's companion `scripts/install.sh` applies them to
the binary via `setcap`; the systemd unit also carries
`AmbientCapabilities=` so a service launched by systemd inherits them.

## Config file reference (`/etc/ghost/<slug>.toml`)

```toml
[target]
kind = "pid"            # pid | tree | cgroup | unit
value = 1234            # integer for pid/tree, "path" string for cgroup/unit

[log]
dir = "/var/log/ghost/pid-1234"

[rotation]
max_segment_bytes = 104857600
keep_segments = 10
max_age_secs = 86400
```

Edit, then `systemctl restart ghost@<slug>.service`.

## Ad-hoc runs (no install)

The daemon command can also run directly, without any installed unit:

```
ghost daemon --pid 1234 --log-dir /tmp/g
```

Same rotation flags apply. Press `Ctrl+C` or send SIGTERM to shut down
cleanly (segments are flushed and the index.json is finalized before exit).
