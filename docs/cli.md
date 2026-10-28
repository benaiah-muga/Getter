# CLI reference

The binary is `getter`, version `0.1.0`. This page reflects the actual
`getter --help` and subcommand help in this repository. Global options:

| Option | Meaning |
| --- | --- |
| `--home <DIR>` | Local state directory; defaults to `$GETTER_HOME` or `~/.getter` |
| `--json` | Emit machine-readable JSON where supported instead of a human table |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

`--home` and `--json` are global (Clap `global = true`), so they may appear
before or after the subcommand. Examples put them before the command.

Exit status is `0` on success and `1` on an error or a doctor failure. The CLI
prints errors to stderr and logs to stderr; normal tables/JSON go to stdout.

## `getter init`

Initialize a coordinator or worker identity and configuration. Required:
`--role coordinator|worker`. Refuses to overwrite an existing config/identity
unless `--force`.

```text
getter init --role coordinator [OPTIONS]
getter init --role worker [OPTIONS]
```

| Option | Applies to | Meaning |
| --- | --- | --- |
| `--role <ROLE>` | both | `coordinator` or `worker` (required) |
| `--name <NAME>` | both | Display name; defaults `getter-coordinator`/`getter-worker` |
| `--bind <BIND>` | coordinator | Listen address; default `127.0.0.1:47810`, or `0.0.0.0:47810` with `--lan` |
| `--lan` | coordinator | Bind all interfaces, enable TLS, derive public URL, enable discovery |
| `--no-tls` | coordinator | Disable TLS; only permitted for loopback unless config is edited |
| `--public-url <URL>` | coordinator | Explicit coordinator URL; must match TLS scheme and certificate SAN |
| `--discovery` | coordinator | Enable UDP discovery (automatic with `--lan`) |
| `--hostname <HOST>` | coordinator | Additional DNS SAN; repeatable |
| `--coordinator-url <URL>` | worker | Coordinator URL; default `http://127.0.0.1:47810` |
| `--ca-cert <PATH>` | worker | Copy a coordinator CA into worker trust state |
| `--control-bind <ADDR>` | worker | Loopback control API; default `127.0.0.1:47811` |
| `--force` | both | Overwrite existing config/credentials; dangerous |

`init` creates secure state and prints next steps. It does not start a service or
enroll a worker. `--force` on a coordinator replaces TLS material and the admin
token; on a worker it replaces the identity and control token. Existing data may
remain but old credentials/trust will not work. Back up and plan re-enrollment.

Examples:

```sh
getter --home ./.getter-coord init --role coordinator --name home-coordinator
getter --home ./.getter-w1 init --role worker --name local-worker \
  --control-bind 127.0.0.1:47811
getter --home ~/.getter init --role coordinator --name lab --lan \
  --hostname getter.lan
```

## `getter coordinator start`

Run the coordinator HTTP(S) service in the foreground. No flags beyond the
globals. It loads `config.toml`, opens/migrates SQLite, reads the admin token,
starts background lease/stale-worker sweeps, optional discovery, and the
HTTP(S) listener. At this revision it handles SIGINT/Ctrl-C for graceful HTTP
shutdown.

```sh
getter --home ./.getter-coord coordinator start
```

The service logs to stderr. Use `getter status` from another terminal, or a
systemd unit for supervision.

## `getter worker join`

Enroll a worker using a one-time pairing token. Required: `--coordinator` and
exactly one of `--token`/`--token-file`.

```sh
getter worker join --coordinator <URL> (--token <TOKEN> | --token-file <PATH>) \
  [--ca-cert <PATH>] [--ca-fingerprint <SHA256>]
```

| Option | Meaning |
| --- | --- |
| `--coordinator <URL>` | Coordinator base URL (required) |
| `--token <TOKEN>` | Pairing token value; visible in history/process list |
| `--token-file <PATH>` | Read token from a file (recommended; mode `0600`) |
| `--ca-cert <PATH>` | Coordinator CA PEM to validate/copy |
| `--ca-fingerprint <SHA256>` | `sha256:<64 hex>`; fetch CA over bootstrap and require this DER fingerprint |

For HTTPS, either a CA cert, a fingerprint, or an existing saved CA is required.
The fingerprint bootstrap fetches the public CA over an unverified connection but
does not send the token there; it refuses a mismatch. Use the fingerprint printed
by `getter pair` or another trusted channel.

On success the worker ID is saved in `<home>/worker/identity.json` (mode `0600`)
and the config is updated. Re-running join with a different coordinator URL
clears the old CA association and requires trust material again.

## `getter worker start`

Run the worker in the foreground. Loads identity/config, binds the loopback
control API, applies niceness, then starts heartbeat, assignment polling, and
battery-policy loops. It handles SIGINT/SIGTERM and attempts a signed `leave`
on shutdown.

```sh
getter --home ./.getter-w1 worker start
```

The worker must already be joined. It polls only when not paused, not
battery-paused, and not shutting down. It never listens for coordinator traffic.

## `getter worker pause|resume|stop|status`

These use the **local loopback control API** and its bearer token; the worker
must be running and the control address must be reachable from the CLI host.

```sh
getter --home ./.getter-w1 worker pause
getter --home ./.getter-w1 worker resume
getter --home ./.getter-w1 worker stop
getter --home ./.getter-w1 worker status
```

| Command | Behavior |
| --- | --- |
| `pause` | Stop polling and immediately cancel running local tasks; coordinator infrastructure-requeues them without consuming a workload attempt (bounded to 32 abandoned leases per task) |
| `resume` | Resume when no battery policy holds a pause; reports `battery-paused` if applicable |
| `stop` | Ask the worker to shut down; running tasks are cancelled/drained under a short bound |
| `status` | Print worker ID/name, state, coordinator, slots, uptime, stats, active tasks, last error |

`worker status` and top-level `status` on a worker home call the same control
API. The control API is never network-accessible; `control_bind` must be
loopback and each worker on a host needs a distinct port.

## `getter pair`

Create a one-time worker pairing token. Requires a running coordinator and its
admin token (read from the coordinator home). Not available on a worker home.

```sh
getter --home ./.getter-coord pair --name <WORKER_NAME> [--ttl-secs <SECS>] \
  [--write-ca <PATH>]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--name <NAME>` | required | Worker name; the token is scoped to it |
| `--ttl-secs <SECS>` | `900` | Lifetime; coordinator accepts 60–86400 |
| `--write-ca <PATH>` | none | Write a copy of the coordinator CA PEM for transfer |

The human output prints the token once, coordinator URL, CA fingerprint, and
expiry. `--json` prints the `PairingTokenResponse` for scripting. The token
itself is a secret; write JSON to a protected file (`umask 077`) and remove it
after enrollment.

## `getter status`

Show the local role and service state. On a coordinator home, uses the admin API
to print coordinator status. On a worker home, queries the local control API.

```sh
getter --home ./.getter-coord status
getter --home ./.getter-w1 status
getter --json --home ./.getter-coord status
```

Coordinator output includes readiness, public URL, uptime, online/authorized
workers, active tasks, job counts, and version/protocol. Worker output includes
slots, uptime, completed tasks/compute, active tasks, pause state, and last
error. This command does not start anything.

## `getter workers`

List authorized workers from the coordinator admin API: ID, name, derived
status, active tasks, successful tasks, compute milliseconds, and last seen.

```sh
getter --home ./.getter-coord workers
getter --home ./.getter-coord workers --json
```

Status is derived from heartbeats and participation: `online`, `paused`,
`offline`, `revoked`. There is no CLI revoke command; use the admin API
documented in [Operations](operations.md).

## `getter jobs`

Job management. All forms require a coordinator home.

### `getter jobs submit`

```sh
getter --home ./.getter-coord jobs submit --file <JOB_JSON> [--watch]
```

Reads the `getter.job/v1` file, removes `workload.artifact`, resolves it relative
to the job file, verifies its SHA-256, base64-encodes it, and posts a
`JobSubmission`. `--watch` polls until the job is terminal (approximately every
750 ms) and prints progress plus the final detail. `--json` prints the created
job detail; with `--watch --json` each poll is printed as JSON.

### `getter jobs list`

```sh
getter --home ./.getter-coord jobs list [--limit <N>]
```

`--limit` defaults to 50. Prints ID, state, progress, verified flag, workload,
and name, or the JSON response.

### `getter jobs inspect`

```sh
getter --home ./.getter-coord jobs inspect <JOB_ID> [--watch]
```

Prints job metadata, progress, per-task state/attempt/worker/compute/validation,
and the result if present. `--watch` polls until terminal. `--json` prints the
raw `JobDetailResponse`; with `--watch`, each poll is printed.

### `getter jobs cancel`

```sh
getter --home ./.getter-coord jobs cancel <JOB_ID>
```

Requests cancellation. Queued/assigned/running tasks are marked cancelled and
active leases revoked; workers are told to abort on their next heartbeat.
Cancelling an already cancelled job is idempotent; cancelling a completed or
failed job is a conflict. A race can leave already-accepted task rows completed;
the job itself becomes cancelled.

## `getter contribute`

Show coordinator-recorded contribution statistics: authorized/online workers,
successful tasks, verified tasks, failed attempts, completed jobs, compute time,
and per-worker rows.

```sh
getter --home ./.getter-coord contribute
getter --json --home ./.getter-coord contribute
```

These are accepted-work figures recorded by this coordinator, not theoretical
CPU capacity. They are not a cryptocurrency or payout ledger.

## `getter doctor`

Read-only diagnostics for the home:

- config presence, parse, and validation;
- TLS files, CA fingerprint, and HTTPS/public URL consistency (coordinator);
- admin/control token and worker identity existence/permissions;
- database parent and status;
- coordinator health/admin API reachability;
- worker control API reachability (if running);
- pinned CA and coordinator health (worker).

It prints `[ok]`, `[warn]`, and `[fail]` lines and a summary. It exits 1 on
blocking failures; warnings alone do not fail. `--json` is a global option but
`doctor` currently prints its human diagnostic format.

```sh
getter --home ./.getter-coord doctor
```

## `getter config`

### `getter config show`

Print the parsed config file with its path, including secret **paths** but never
secret contents. `--json` prints `{"config": {...}}`.

### `getter config set`

```sh
getter --home ./.getter-coord config set <KEY> <VALUE>
```

Set a supported dotted key (list in [Configuration](configuration.md)), validate
the resulting config, write it atomically, and tell you to restart. Unknown keys
and invalid values are refused without writing.

### `getter config path`

Print `<home>/config.toml` for the active home. Useful when unsure which home
`--home`/`GETTER_HOME` selected.

## `getter discover`

Send an unauthenticated UDP discovery query and print compatible coordinator
announcements for a bounded duration.

```sh
getter discover [--port <PORT>] [--seconds <SECONDS>]
getter discover --json
```

Defaults: port `47812`, duration `3` seconds (clamped by the command to at most
30). It binds the discovery UDP port, so another process using that port causes
an error. Results are informational only and grant no trust; enrollment still
requires a pairing token and CA verification. If nothing answers, use the URL
from `getter pair`.

## `getter uninstall`

Remove local configuration, identities, keys, tokens, and database for the
active home. Requires `--yes`.

```sh
getter --home ./.getter-w1 uninstall --yes
```

For a worker, it first asks the local control API to shut down, then removes the
home directory. It refuses a path without a Getter config or filesystem root, and
canonicalizes the path before deletion. It does **not** remove systemd/launchd
units or stop a coordinator service; clean those up manually. This is
irreversible; back up first.

## Examples

```sh
# Loopback development
getter --home ./.getter-coord init --role coordinator --name dev-coord
getter --home ./.getter-coord coordinator start
getter --home ./.getter-coord pair --name dev-worker --ttl-secs 600
getter --home ./.getter-w1 init --role worker --name dev-worker --control-bind 127.0.0.1:47811
getter --home ./.getter-w1 worker join --coordinator https://127.0.0.1:47810 \
  --token-file ./.pair-token --ca-fingerprint sha256:...
getter --home ./.getter-w1 worker start
getter --home ./.getter-coord jobs submit --file examples/sum-squares/job.json --watch
getter --home ./.getter-coord contribute

# Inspection
getter --home ./.getter-coord status
getter --home ./.getter-coord workers
getter --home ./.getter-coord jobs list --limit 10
getter --home ./.getter-coord jobs inspect <job-id>
getter --home ./.getter-coord doctor
```

For LAN, multiple workers on one host, systemd, and firewall details, see
[Local network](local-network.md) and [Operations](operations.md).
