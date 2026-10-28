# Local network deployment

This guide describes a coordinator and workers on the same trusted LAN, with
explicit addresses, TLS, CA-fingerprint pinning, optional discovery, and no
internet dependency.

> **Verification status:** this procedure is designed and documented but **has
> not been tested on separate physical LAN machines in this environment.** Treat
> it as a procedure to validate in your own isolated lab, and do not skip
> fingerprint verification. See [Limitations](limitations.md).

## Topology

```text
                   TCP 47810 (TLS)
  ┌──────────────┐  ◄──────────────  ┌────────────────────┐
  │ Coordinator  │                   │ Worker A           │
  │ 192.168.1.10 │  ──────────────►  │ 192.168.1.21       │
  │ getter home  │   assignments     │ control 127.0.0.1  │
  └──────┬───────┘                   └────────────────────┘
         │
         │           TCP 47810 (TLS)
         │  ◄────────────────────────  ┌────────────────────┐
         │  ────────────────────────►  │ Worker B           │
         │                             │ 192.168.1.22       │
         │                             │ control 127.0.0.1  │
         │                             └────────────────────┘
         │
         └── optional UDP 47812 discovery announcements
```

Workers only initiate outbound connections. The coordinator never connects to a
worker. Each worker's control API stays on its own loopback interface.

## Prerequisites

- The same Getter build on every machine (built from this repository or a
  future verified release).
- A trusted LAN with stable addressing. Prefer static leases or documented DHCP
  reservations over changing IPs.
- A trusted clock source on every machine (worker signatures allow ±90 s skew).
- Firewall rules described below.
- A way to transfer a pairing token and CA fingerprint through a trusted channel
  (for example SSH or a password manager), not just the untrusted discovery
  output.

## 1. Initialize the coordinator

Choose the address workers will use. On the coordinator host:

```sh
getter --home ~/.getter init \
  --role coordinator \
  --name lab-coordinator \
  --lan \
  --hostname getter.lan
```

`--lan` does four things:

- binds `0.0.0.0:47810`;
- enables TLS with a newly generated local CA;
- derives `public_url` from a non-loopback interface address;
- enables UDP discovery advertisements.

The generated certificate includes `localhost`, `127.0.0.1`, `::1`, all local
interface addresses (because the bind is unspecified), and any `--hostname`
values. The CA private key is discarded after signing the server certificate;
the CA certificate and server key remain under `~/.getter/tls/`. The printed CA
fingerprint is the SHA-256 of the CA certificate DER, formatted as
`sha256:<64 hex>`.

If the derived URL is not the address workers should use, set it explicitly and
make sure the certificate covers that name:

```sh
getter --home ~/.getter init --force \
  --role coordinator \
  --name lab-coordinator \
  --lan \
  --public-url https://getter.lan:47810 \
  --hostname getter.lan
```

`--force` replaces local configuration and credentials. Do not use it on a home
that already has jobs or enrolled workers unless you intend to re-enroll
everyone and have backed up the state.

To avoid discovery, omit `--lan` and be explicit:

```sh
getter --home ~/.getter init \
  --role coordinator \
  --name lab-coordinator \
  --bind 0.0.0.0:47810 \
  --public-url https://192.168.1.10:47810
```

`public_url` must use `https` when TLS is configured. A non-loopback bind
without TLS is refused unless `allow_insecure_remote = true` is edited into
`config.toml`; do not do that outside an isolated lab.

Start it in the foreground (or as a service, below):

```sh
getter --home ~/.getter coordinator start
```

Admin CLI commands read the coordinator home's admin token, so run them on the
coordinator host. To administer from another machine, use the authenticated HTTP
API with the token over TLS; do not copy the coordinator home to a worker.

Verify on the coordinator host:

```sh
getter --home ~/.getter status
getter --home ~/.getter doctor
curl --fail --cacert ~/.getter/tls/ca.pem https://127.0.0.1:47810/healthz
```

## 2. Firewall and routing

For the default configuration:

| Where | Rule | Why |
| --- | --- | --- |
| Coordinator host | Allow inbound TCP `47810` from worker/admin hosts | HTTP(S) API, including worker assignments/results and admin CLI |
| Coordinator host | Allow outbound UDP to worker LAN broadcast address on `47812` (if discovery) | Discovery announcements |
| Worker/discovery hosts | Allow inbound UDP `47812` from the LAN (if discovery) | Receive announcements and run `getter discover` |
| Everywhere | No inbound worker control port | Control binds loopback only; it must not be reachable over the LAN |

If you change `coordinator.bind` or `public_url`, change the TCP rule to match.
If discovery is disabled, UDP `47812` is not needed. Discovery uses
`255.255.255.255` by default, which many managed networks and Wi-Fi APs block;
explicit coordinator addressing is the supported fallback.

Check reachability from a worker host **before** installing credentials:

```sh
curl --fail --cacert /path/to/copied-ca.pem https://192.168.1.10:47810/healthz
```

If this fails, fix routing/DNS/firewall/TLS before pairing. Do not work around it
with `curl -k` and do not disable TLS.

## 3. Optional: verify discovery

On a host on the same LAN:

```sh
getter discover --seconds 5
getter discover --seconds 5 --json
```

This binds UDP `47812`, sends a query, and prints compatible announcements. A
result is **not** a trust decision: the datagram is unauthenticated, and anyone
can send one. The printed URL and CA fingerprint must still match the values
obtained from `getter pair` through a trusted channel. Discovery does not enroll
a worker and does not replace the pairing token.

If discovery returns nothing, use explicit addresses. That is expected on many
networks. You can also set a unicast `target` in `config.toml`:

```toml
[coordinator.discovery]
enabled = true
port = 47812
interval_secs = 5
target = "192.168.1.255:47812"
```

`target` is optional and cannot be set through `getter config set` in `0.1.0`;
edit the TOML and restart. The coordinator's announcer sends from an ephemeral
UDP port, not from a listener on `47812`.

## 4. Pair and enroll a worker

On the coordinator host, create a short-lived token for the exact worker name:

```sh
umask 077
getter --json --home ~/.getter pair \
  --name lab-worker-a \
  --ttl-secs 600 > /tmp/lab-worker-a-pair.json
```

Transfer that file (or the token and fingerprint separately) to the worker host
over a trusted channel. The token is a one-time secret and is scoped to the name.
The default TTL is 900 seconds; allowed values are 60–86400 seconds.

On the worker host:

```sh
# Option A: copy the coordinator CA during init, then join.
scp coordinator:/path/to/ca.pem /tmp/getter-ca.pem   # trusted channel
getter --home ~/.getter init \
  --role worker \
  --name lab-worker-a \
  --coordinator-url https://192.168.1.10:47810 \
  --ca-cert /tmp/getter-ca.pem

getter --home ~/.getter worker join \
  --coordinator https://192.168.1.10:47810 \
  --token-file /tmp/lab-worker-a-token

# Option B: fetch and pin the CA by the fingerprint printed by `pair`.
getter --home ~/.getter init \
  --role worker \
  --name lab-worker-a \
  --coordinator-url https://192.168.1.10:47810
getter --home ~/.getter worker join \
  --coordinator https://192.168.1.10:47810 \
  --token-file /tmp/lab-worker-a-token \
  --ca-fingerprint 'sha256:...'
```

For option B, `join` fetches the CA over an unverified bootstrap connection but
refuses to save or use it unless its SHA-256 matches the out-of-band fingerprint.
The pairing token is not sent on that unverified connection. This is why the
fingerprint must come from `getter pair` (or another trusted channel), not from
discovery alone. In both options the CA file must contain **exactly one**
certificate; a concatenated multi-certificate bundle is rejected rather than
silently trusted by its first certificate.

After joining:

```sh
getter --home ~/.getter worker start
getter --home ~/.getter worker status
```

On the coordinator:

```sh
getter --home ~/.getter workers
```

The worker should become `online` within a heartbeat interval. If it does not,
check the worker log, address, firewall, TLS fingerprint, and clock.

## 5. Multiple workers on one host

Each worker needs a distinct home, name, control port, and pairing token:

```sh
getter --home ~/.getter-w1 init --role worker --name lab-w1 \
  --control-bind 127.0.0.1:47811
getter --home ~/.getter-w2 init --role worker --name lab-w2 \
  --control-bind 127.0.0.1:47821
```

Then join each with its own token and start each as a separate process/service.
The control port is only for the local CLI; it must remain loopback-only. A
second worker on the default `47811` will fail to bind, which is intentional.

## 6. Submit and verify a job

From the coordinator host:

```sh
getter --home ~/.getter jobs submit \
  --file examples/sum-squares/job.json --watch
getter --home ~/.getter jobs list
getter --home ~/.getter contribute
```

For the checked-in example, a successful run reports 12/12 verified tasks and:

```json
{"total":"575999928000002000000"}
```

The job's artifact path is relative to `job.json`; copy both if you submit from
another directory. The CLI checks the artifact SHA-256 before upload, and the
coordinator verifies the trusted per-task hashes.

## 7. Offline operation

Runtime operation does not require the internet:

- Getter has no telemetry, cloud account, package fetch, or remote update check.
- The coordinator and workers communicate only on the configured address/port.
- TLS uses the locally generated CA.
- Discovery is optional and local.
- Jobs and artifacts are stored locally.

Build-time dependencies are a separate matter: `cargo build --locked` needs the
crates in the local Cargo cache (or a vendor/offline mirror), and the first build
in a fresh environment normally needs network access. Once built, the binary does
not phone home. An offline build gate is not claimed here.

For an isolated LAN without DNS, use IP addresses in `public_url` and worker
`--coordinator` URLs. If you use a hostname, ensure it resolves on every worker
through `/etc/hosts` or local DNS and that the certificate SAN includes it.
Use a local NTP source or otherwise keep clocks within 90 seconds.

## 8. systemd examples

Install the binary at a stable path and use one unit per role. These are
examples; Getter does not install or manage units.

Coordinator (`~/.config/systemd/user/getter-coordinator.service`):

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
KillSignal=SIGINT
TimeoutStopSec=20

[Install]
WantedBy=default.target
```

Worker (`~/.config/systemd/user/getter-worker.service`):

```ini
[Unit]
Description=Getter worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/getter --home %h/.getter worker start
Environment=RUST_LOG=info
Restart=on-failure
RestartSec=5
TimeoutStopSec=15

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now getter-coordinator.service
systemctl --user enable --now getter-worker.service
loginctl enable-linger "$USER"
```

For a system unit, run as a dedicated unprivileged user with explicit absolute
paths and writable state. Do not run as root. See [Operations](operations.md) for
backups, revocation, upgrades, and troubleshooting.

## 9. LAN security checklist

- [ ] TLS is enabled and `public_url` uses `https`.
- [ ] The CA fingerprint was transferred and verified out of band.
- [ ] Each worker joined with its own one-time, name-scoped token.
- [ ] Pairing token files were mode `0600` and deleted after use.
- [ ] Worker control ports are loopback-only and not firewalled open.
- [ ] The coordinator admin token is not on worker hosts.
- [ ] TCP `47810` is restricted to intended hosts; UDP `47812` is allowed only
      if discovery is used.
- [ ] Clocks are synchronized.
- [ ] Backups of the coordinator home are protected and tested.
- [ ] The LAN is trusted enough for the coordinator's HTTP(S) exposure; there is
      per-worker request throttling but no admin/public rate limiting or per-job
      ACL.
- [ ] You have read [Security](security.md) and [Limitations](limitations.md).

If any check cannot be met, use loopback/SSH tunnels or an isolated lab rather
than weakening TLS or exposing the coordinator broadly.
