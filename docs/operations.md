# Operations

This guide covers running Getter after the quick start: service supervision,
logs, health checks, backups, upgrades, worker revocation, and troubleshooting.
Commands assume a Unix-like host and one home per role. Adjust paths and service
users for your deployment.

> Getter `0.1.0` is alpha and has no signed release. Use a build from this
> repository, protect local state, and read [Limitations](limitations.md) before
> production-style use.

## Files and permissions

A home contains everything for one identity:

```text
<home>/
├── config.toml                 # 0600, parsed with deny_unknown_fields
├── secrets/
│   ├── admin-token             # coordinator only, 0600, never printed
│   └── control-token           # worker only, 0600
├── tls/                        # coordinator with TLS
│   ├── ca.pem
│   ├── server.pem
│   └── server-key.pem          # 0600
├── trust/
│   └── coordinator-ca.pem      # worker copy of the pinned CA
├── worker/
│   └── identity.json           # worker Ed25519 key + id, 0600
└── data/
    └── getter.db               # coordinator SQLite (WAL sidecars possible)
```

The coordinator creates the home, `secrets`, `data`, and `tls` directories as
`0700` on Unix; secret files are written `0600`. On startup the worker refuses an
identity/token it can read too broadly and requires regular files, not symlinks.
The database is opened `0600` on Unix. On Windows these Unix mode checks do not
apply; use filesystem ACLs and full-disk encryption.

Do not copy a home to another machine as a shortcut for enrollment. A worker
identity is bound to the coordinator's database; moving it is a key-management
operation, not a backup strategy.

## Foreground operation

```sh
getter --home /srv/getter coordinator start
getter --home /srv/getter-w1 worker start
```

Both commands run in the foreground and log to stderr. The coordinator serves
HTTP(S) until interrupted. At this revision, `coordinator start` handles
SIGINT/Ctrl-C; send SIGINT for a graceful HTTP shutdown. The worker handles
SIGINT and SIGTERM, stops taking work, cancels/drains in-flight tasks for a short
bounded period, and attempts a signed `leave`.

Pause and resume a worker without stopping the process:

```sh
getter --home /srv/getter-w1 worker pause
getter --home /srv/getter-w1 worker resume
getter --home /srv/getter-w1 worker status
getter --home /srv/getter-w1 worker stop
```

Pause stops polling and cancels running local tasks immediately. The worker
submits infrastructure requeues; the coordinator returns those tasks to the queue
without consuming a workload attempt, up to 32 abandoned leases per task, after
which the task fails. A pause is not a workload failure. `resume` only makes the
worker eligible when no battery policy holds it paused. `stop` asks the control
API to shut down; the service process then exits.

## Logging

Getter uses `tracing` and writes to stderr. There is no built-in file, rotation,
metrics endpoint, or OpenTelemetry exporter.

```sh
RUST_LOG=info getter --home /srv/getter coordinator start
RUST_LOG=getter_coordinator=debug,getter_worker=debug getter --home /srv/getter-w1 worker start
```

Do not enable `trace` in production: request tracing can include paths and
worker identifiers. The coordinator never intentionally logs admin tokens,
worker private keys, or lease tokens. Pairing tokens are printed once by
`getter pair` by design; do not paste its output into logs.

With systemd, use `journalctl --user -u getter-coordinator -f` or the system
unit equivalent.

## systemd examples

These units are examples, not installed by Getter. Put the binary somewhere
stable (for example `~/.local/bin/getter` or `/usr/local/bin/getter`), create the
home with `getter init`, and protect the unit files like any other service
configuration.

### User coordinator unit

`~/.config/systemd/user/getter-coordinator.service`:

```ini
[Unit]
Description=Getter coordinator
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/getter --home %h/.getter coordinator start
Environment=RUST_LOG=info
Restart=on-failure
RestartSec=5
# The coordinator handles SIGINT for graceful HTTP shutdown.
KillSignal=SIGINT
TimeoutStopSec=20

[Install]
WantedBy=default.target
```

### User worker unit

`~/.config/systemd/user/getter-worker.service`:

```ini
[Unit]
Description=Getter worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/getter --home %h/.getter-w1 worker start
Environment=RUST_LOG=info
Restart=on-failure
RestartSec=5
TimeoutStopSec=15

[Install]
WantedBy=default.target
```

Enable and start:

```sh
systemctl --user daemon-reload
systemctl --user enable --now getter-coordinator.service
systemctl --user enable --now getter-worker.service
loginctl enable-linger "$USER"   # keep user services after logout/boot
```

For a system-wide service, create a dedicated unprivileged user, run
`getter init` as that user, and use `User=`, `Group=`, `WorkingDirectory=`, and
absolute paths. Do not run the coordinator or worker as root. If you add
hardening such as `ProtectSystem=strict`, explicitly allow the home and database
directory as writable. `PrivateTmp=true` is safe; `ProtectHome=true` is not
unless you relocate the home.

Running multiple workers on one host means multiple homes, names, and
**different loopback control ports** (for example `47811` and `47821`), with one
service per worker.

## Health and readiness

Public endpoints require no token:

```sh
CA="$HOME/.getter/tls/ca.pem"
curl --fail --cacert "$CA" https://127.0.0.1:47810/healthz
curl --fail --cacert "$CA" https://127.0.0.1:47810/readyz
curl --fail --cacert "$CA" https://127.0.0.1:47810/v1/ca.pem
```

- `/healthz` returns process/protocol version information.
- `/readyz` returns HTTP 200 only when the database is healthy; otherwise 503.
- `/v1/ca.pem` is absent when TLS is disabled.

Use the CLI for authenticated checks:

```sh
getter --home /srv/getter status
getter --home /srv/getter workers
getter --home /srv/getter doctor
getter --home /srv/getter contribute
```

`doctor` is read-only and reports failures versus warnings. It checks config
parsing, TLS material and fingerprint, token/identity permissions, database
parent, coordinator reachability, admin authentication, and local worker control
reachability as applicable. It exits non-zero when it finds blocking problems.

## Backups

SQLite is a single-writer database in WAL mode. The safest simple backup is a
**stopped coordinator** plus a copy of the whole home:

```sh
systemctl --user stop getter-coordinator.service
cp -a /srv/getter /srv/getter-backup-$(date +%Y%m%d)
systemctl --user start getter-coordinator.service
```

Copying only `getter.db` while the service is running can miss WAL contents.
If you need an online backup, use SQLite's backup mechanism (for example the
`sqlite3` `.backup` command) and test the restored copy. Back up the database,
config, TLS material, and admin token together; a database without its admin
token is not operational. Protect backups at least as strictly as the live home:
they contain job inputs/outputs, worker public keys, and the coordinator server
private key in `tls/server-key.pem`; the CA private key itself is discarded after
generation.

There is no built-in restore command. Stop the service, replace the home, keep
ownership and modes (`0700`/`0600`), then start and run `doctor`.

## Upgrades and migrations

1. Read [CHANGELOG](../CHANGELOG.md) and back up the home.
2. Stop the coordinator (and workers if you are upgrading them).
3. Replace the binary, keeping the same toolchain/lock expectations.
4. Start the coordinator. Schema migrations run automatically and are
   forward-only; a failure rolls back that migration version.
5. Start workers and verify with `getter doctor`, `status`, and a small job.

There is no downgrade path. An older binary may refuse a newer schema or config.
There is no online CA rotation: replacing TLS material requires reinitializing
the coordinator home and re-enrolling workers. Plan that as an outage and
preserve any data you need; `getter init --force` overwrites config/credentials,
and you should treat old worker identities as invalid.

Rolling upgrades across a heterogeneous worker fleet are not specifically
supported or tested in `0.1.0`; keep protocol identifiers compatible.

## Worker revocation

The CLI does not expose a revoke subcommand, but the coordinator API does. Get
the worker ID from `getter workers`, then call the admin endpoint with the
coordinator admin token over TLS:

```sh
TOKEN=$(cat /srv/getter/secrets/admin-token)
WORKER_ID=00000000-0000-0000-0000-000000000000
curl --fail --cacert /srv/getter/tls/ca.pem \
  -H "Authorization: Bearer $TOKEN" \
  -X DELETE "https://127.0.0.1:47810/v1/admin/workers/$WORKER_ID"
unset TOKEN
```

Revocation marks the worker revoked/offline and expires its active leases so the
scheduler can recover their tasks. The worker's signed requests are then
rejected. There is no un-revoke operation; enroll a new identity with a new
pairing token. Revoking does not erase the worker's historical task/lease rows.

## Pairing-token handling

`getter pair` prints the token once. To avoid shell history and terminal
scrollback, write JSON to a protected file and move only that file to the worker
host through a trusted channel:

```sh
umask 077
getter --json --home /srv/getter pair --name worker-2 --ttl-secs 600 > /tmp/worker-2-pair.json
# transfer /tmp/worker-2-pair.json, then on the worker:
getter --home /srv/getter-w2 worker join \
  --coordinator "$(jq -r .coordinator_url /tmp/worker-2-pair.json)" \
  --token-file <(jq -r .token /tmp/worker-2-pair.json) \
  --ca-fingerprint "$(jq -r .ca_fingerprint /tmp/worker-2-pair.json)"
rm -f /tmp/worker-2-pair.json
```

`--token-file <(...)` uses a process-substitution file descriptor, which may not
work on all shells. A regular file created with `umask 077` is simpler:

```sh
umask 077
jq -r .token /tmp/worker-2-pair.json > /tmp/worker-2-token
getter --home /srv/getter-w2 worker join \
  --coordinator "$(jq -r .coordinator_url /tmp/worker-2-pair.json)" \
  --token-file /tmp/worker-2-token \
  --ca-fingerprint "$(jq -r .ca_fingerprint /tmp/worker-2-pair.json)"
rm -f /tmp/worker-2-token /tmp/worker-2-pair.json
```

The examples above use `jq` to parse the pairing JSON. Tokens are name-scoped,
one-time, and expire after the TTL (60–86400 seconds; default 900). An unused token remains valid until expiry; there is no CLI to
revoke a single unused token early. Keep TTLs short.

## Time synchronization

Worker request signatures are accepted only within ±90 seconds of coordinator
time, and worker heartbeats/leases use UTC timestamps. Run NTP or another trusted
clock source on the coordinator and every worker. Large clock skew produces
`401` authentication failures that can look like bad keys.

## Capacity planning

There is no benchmark guarantee. Start conservatively:

- Worker concurrency defaults to available CPUs minus one, clamped to 1–4.
  Raise it only after accounting for Wasm compilation and host load.
- Per-task memory defaults to 256 MiB, timeout 300 s, fuel 5,000,000,000, and
  output 1 MiB. Jobs can request less, never more than the worker maximum.
- The coordinator stores all artifacts and outputs in SQLite. Disk grows with
  job history; there is no automatic retention/GC.
- The coordinator serializes all database writes through one mutex. Many
  simultaneous submitters/results will queue; SQLite's busy timeout and body
  limits are not a throughput plan.
- The scheduler does not reserve memory across concurrent tasks. A worker with
  concurrency 4 and 256 MiB tasks can commit 1 GiB of guest linear memory plus
  host overhead.

## Troubleshooting

| Symptom | Likely cause / action |
| --- | --- |
| `configuration not found` | Wrong `--home`/`GETTER_HOME`; run `getter config path --home ...`. |
| `required file ... 600` / permission failure | A secret is group/other-readable or a symlink. `chmod 600` the file and `chmod 700` its directory; replace symlinks with regular files. |
| `Address already in use` on coordinator | Another coordinator, test, or process owns the port. Change `coordinator.bind` and `public_url`, restart, update workers. |
| Worker start fails binding control API | Two workers share `47811`. Set a unique loopback `control_bind` per worker. |
| `worker has not joined a coordinator` | Run `getter worker join` with a fresh token before `worker start`. |
| Pairing says coordinator unreachable | `pair` uses `coordinator.public_url`, not the bind address. Ensure the URL is correct, the service is running, and the CLI trusts the CA. |
| TLS `invalid peer certificate` / fingerprint mismatch | The worker pinned a different CA or the coordinator was reinitialized. Verify the fingerprint from `getter pair`; re-enroll if the CA changed. Do not disable verification as a fix. |
| Worker enrolled but never claims work | Check `getter workers` status; worker may be paused, battery-paused, offline, revoked, or unable to meet job limits. Check `getter worker status` and logs. |
| Enrollment succeeded on the coordinator but the worker still has no ID | A lost join response consumes the one-time token. Issue a new pairing token and re-enroll; do not reuse the old token. |
| Task assigned but never received by the worker | A lost claim response leaves the lease active until expiry; the task is requeued after expiry. Check coordinator/worker logs and lease timing. |
| Job stays queued | No active worker supports the ABI or fits all requirements, concurrency is saturated, or the job was submitted to a coordinator with no workers. Check `workers`, worker maxima, and `jobs inspect`. Repeated infrastructure requeues are shown in task errors. |
| `too many infrastructure interruptions` | A task accumulated more than 32 abandoned leases (pause, shutdown, cancellation, missing slots, download failure, or lease-time safety). Investigate worker churn; the task is now failed. |
| Job slow after worker death | Heartbeat timeout and lease expiry govern recovery. A dead worker is shown offline after the heartbeat timeout; its tasks are requeued on lease expiry. |
| `workload artifact SHA-256 mismatch` | The job manifest and artifact file disagree. Rebuild with `scripts/build-example.sh` and regenerate with `generate_job.py`; do not edit the hash by hand. |
| `result rejected by verification policy` | The workload output does not match `expected_output_sha256`, or the job uses `trusted` mode without coordinator opt-in. Inspect the task error; fix the reference or workload. |
| `aggregate result did not match expected_aggregate` | All tasks completed but the sum/shape differs. Check for overlapping/missing partitions and reference arithmetic. |
| `401` from worker requests | Clock skew beyond 90 s, revoked worker, wrong worker ID/key, replayed nonce, or coordinator state mismatch. Check time sync and `doctor`. |
| `429 rate_limited` | A worker exceeded the per-worker signed-request rate window. Reduce polling/parallelism or investigate a loop; retry shortly. |
| `503 replay_guard_capacity` | The coordinator's process-local replay guard is at capacity (100,000 tracked workers or a worker's nonce ceiling). Restart clears it; investigate worker count/nonce behavior rather than treating it as a normal state. |
| `403` for a result | Lease token mismatch, lease belongs to another worker, or attempt to use another worker's lease. Never copy lease material between workers. |
| `409` lease no longer active | The lease expired or was revoked while the worker was executing/uploading. The task will be requeued if attempts remain; stale results are rejected. |
| Database locked / coordinator slow | Single-writer SQLite with many concurrent writes. Reduce submission concurrency, inspect disk latency, and avoid running another process against the same DB. |
| `doctor` reports worker control API unreachable | The worker process is not running, the control bind changed, or the control token is unreadable. Start/restart the worker and re-run. |
| LAN worker cannot connect | Check address/route, firewall TCP port, `public_url` reachability, TLS SAN/name mismatch, and CA fingerprint. Discovery is optional; use explicit `--coordinator`. |
| `getter discover` finds nothing | Broadcast is blocked or devices are on different subnets. This is normal; use the coordinator URL from `getter pair` or configure a unicast discovery `target`. |

For diagnostics, prefer `getter doctor` and sanitized logs. If the problem is a
suspected vulnerability, follow [SECURITY.md](../SECURITY.md), not a public
issue.
