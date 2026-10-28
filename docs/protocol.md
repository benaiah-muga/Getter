# Protocol

Getter speaks JSON over HTTP/1.1 or HTTP/2, optionally wrapped in TLS. The
wire protocol identifier is `getter.protocol/v1`. The user-facing job file
format is `getter.job/v1`; the workload ABI is `getter.abi.v1`.

All protocol types are defined in `crates/getter-protocol` and reject unknown
JSON fields. Breaking changes require a new protocol identifier. Timestamps in
JSON are RFC 3339; the worker signature timestamp is Unix seconds. Hashes are
lowercase SHA-256 hex unless stated otherwise.

## Transport and TLS

- The coordinator listens on `coordinator.bind` (default
  `127.0.0.1:47810`).
- TLS is enabled by default at `init`. The server certificate is signed by a
  locally generated CA; workers trust a copy of that CA or pin its SHA-256
  fingerprint. There are **no TLS client certificates**.
- A non-loopback coordinator bind without TLS is refused unless
  `allow_insecure_remote = true` is explicitly set in the config. The same
  override is needed for a non-loopback plaintext worker `coordinator_url`.
- Public URL scheme must match TLS configuration; see
  [Configuration](configuration.md).
- The coordinator's certificate includes `localhost`, `127.0.0.1`, `::1`, the
  bind IP (or all interface IPs for an unspecified bind), and any
  `--hostname` values.
- A CA trust file must contain exactly one certificate. Multi-certificate PEM
  bundles are rejected; Getter does not silently use the first certificate.

## Namespaces and authentication

| Namespace | Authentication | Examples |
| --- | --- | --- |
| Public | None | `/healthz`, `/readyz`, `/v1/ca.pem`, `/v1/enroll` |
| Admin | `Authorization: Bearer <admin-token>` | `/v1/admin/*` |
| Worker | Ed25519 request signature headers; lease endpoints also require `x-getter-lease-token` | `/v1/worker/*`, `/v1/worker/leases/{id}/artifact` |

The admin token is a random `getter_admin_`-prefixed value stored at
`<home>/secrets/admin-token` with mode `0600`. It is compared in constant time
and never printed by the CLI. The public enrollment endpoint is authenticated by
a one-time pairing token in the request body, not by the admin token.

### Worker request signature

Every worker request (including GET requests and artifact downloads) carries:

| Header | Meaning |
| --- | --- |
| `x-getter-worker-id` | Enrolled worker UUID |
| `x-getter-timestamp` | Unix seconds, within ±90 s of coordinator time |
| `x-getter-nonce` | Fresh random string, 8–128 characters |
| `x-getter-signature` | Standard base64 Ed25519 signature over the canonical message |
| `x-getter-lease-token` | Only on artifact download; the raw lease secret |

The canonical signature message is UTF-8 with newline separators:

```text
getter-worker-request-v1
<worker_id>
<UPPERCASE_METHOD>
<path-and-query>
<unix_timestamp>
<nonce>
<sha256_hex_of_exact_body_bytes>
```

Notes:

- `path-and-query` starts with `/` and includes the exact query string on the
  wire. The worker sends `/v1/worker/assignments?max=N`.
- The body hash is over the exact bytes sent; semantically equivalent JSON with
  different serialization has a different signature.
- The method is uppercased.
- The timestamp is checked against coordinator clock time with a ±90 s window.
- Nonces are cached per worker for 180 s; reuse is rejected with 401. The
  in-memory guard is **process-local**, so it resets on coordinator restart. In
  the current build it enforces 76,800 signed requests per 60 s per worker, up to
  262,144 nonces per worker, and up to 100,000 tracked workers. Exceeding the rate
  window returns 429 `rate_limited`; exhausting guard capacity returns 503
  `replay_guard_capacity`. These limits are not configurable in `0.1.0`.
- The verifying key is the base64 Ed25519 public key stored at enrollment.
- A revoked worker is rejected with 403 regardless of a valid signature.
- `401`/`403` are authentication/authorization failures. `429` (rate limited) and
  `503` (replay-guard capacity) are transient and must not de-authorize a worker;
  retry later.

The worker implementation signs the request after serializing the body, then
sends exactly those bytes. Artifact `GET` requests sign an empty body.

### Pairing and lease tokens

- Pairing tokens have the form `getter_pair_<random>` and are shown once by
  `getter pair`. Only a SHA-256 hash is stored. A token is one-time, scoped to the
  requested worker name, and expires after 60–86,400 seconds (default 900).
- Lease tokens have the form `getter_lease_<random>`. The coordinator stores only
  their SHA-256 hash. A lease token is bound to one worker, lease, task, and
  expiry. It authorizes `start`, `results`, and artifact download for that lease.
- Neither kind is logged by Getter. Treat both as secrets.

## Endpoints

### Public

#### `GET /healthz`

Returns process health information. No auth.

```json
{
  "status": "ok",
  "version": "0.1.0",
  "protocol": "getter.protocol/v1"
}
```

#### `GET /readyz`

HTTP 200 with an empty body when the database is healthy; HTTP 503 with a JSON
body whose `status` is `not_ready` otherwise.

#### `GET /v1/ca.pem`

Returns the coordinator CA certificate as `application/x-pem-file` with
`Cache-Control: no-store` and `x-getter-ca-fingerprint: sha256:<hex>`.
Returns 404 if TLS is disabled. This endpoint is intentionally public so a
worker can bootstrap trust; it grants no authority and contains no private key.

#### `POST /v1/enroll`

Public endpoint authenticated by a pairing token. Request:

```json
{
  "protocol": "getter.protocol/v1",
  "pairing_token": "getter_pair_...",
  "worker_name": "lab-worker-a",
  "public_key": "<base64 Ed25519 verifying key>",
  "capabilities": {
    "abi": ["getter.abi.v1"],
    "os": "linux",
    "arch": "x86_64",
    "cpu_threads": 8,
    "max_concurrency": 4,
    "max_task_memory_bytes": 268435456,
    "max_task_timeout_secs": 300,
    "max_output_bytes": 1048576,
    "max_fuel": 5000000000,
    "version": "0.1.0"
  }
}
```

Success returns 200:

```json
{
  "protocol": "getter.protocol/v1",
  "worker_id": "<uuid>",
  "coordinator_name": "lab-coordinator",
  "coordinator_url": "https://192.168.1.10:47810",
  "ca_fingerprint": "sha256:...",
  "server_time": "2026-10-28T00:00:00Z"
}
```

The request body is independently capped at 64 KiB; exceeding it is rejected
before enrollment processing. The token is consumed atomically with worker
creation. Invalid, expired, reused, or wrong-name tokens return 401. A duplicate
worker name/public key returns 401 with an enrollment rejection. Malformed
capabilities or protocol mismatch return 400/422. A lost success response leaves
the token consumed; enrollment is not transport-idempotent.

### Admin

All admin endpoints require `Authorization: Bearer <admin-token>`; a missing or
wrong token returns 401 with an `ApiErrorBody`.

| Method and path | Purpose | Success |
| --- | --- | --- |
| `POST /v1/admin/pairing-tokens` | Create pairing token | 200 `PairingTokenResponse` |
| `GET /v1/admin/workers` | List authorized workers and derived status | 200 `WorkerListResponse` |
| `DELETE /v1/admin/workers/{worker_id}` | Revoke worker, mark offline, expire active leases | 204 |
| `GET /v1/admin/jobs?limit=N` | List recent jobs (CLI default 50) | 200 `JobListResponse` |
| `POST /v1/admin/jobs` | Submit job + base64 artifact | 201 `JobDetailResponse` |
| `GET /v1/admin/jobs/{job_id}` | Inspect job, tasks, progress, result | 200 `JobDetailResponse` |
| `POST /v1/admin/jobs/{job_id}/cancel` | Request cancellation | 200 `CancelResponse` |
| `GET /v1/admin/status` | Coordinator status | 200 `CoordinatorStatusResponse` |
| `GET /v1/admin/contribution` | Aggregated worker contribution stats | 200 `ContributionResponse` |

`POST /v1/admin/pairing-tokens` body:

```json
{ "name": "lab-worker-a", "ttl_secs": 900 }
```

`ttl_secs` defaults to 900 and must be 60–86400. The response contains the raw
token once, limits, name, expiry, coordinator URL, and CA fingerprint.

`POST /v1/admin/jobs` body is a `JobSubmission`, **not** the job file directly:

```json
{
  "manifest": {
    "protocol": "getter.job/v1",
    "name": "sum-of-squares",
    "description": "optional",
    "workload": {
      "name": "sum-of-squares",
      "abi": "getter.abi.v1",
      "sha256": "<64 lowercase hex>"
    },
    "tasks": [
      {
        "id": "task-000",
        "input": "0:1000000",
        "expected_output_sha256": "<64 lowercase hex>"
      }
    ],
    "requirements": {
      "cpu_slots": 1,
      "memory_bytes": 67108864,
      "timeout_secs": 10,
      "output_bytes": 1048576,
      "fuel": 5000000000
    },
    "verification": { "mode": "exact_sha256" },
    "aggregation": { "mode": "json_sum", "field": "value" },
    "expected_aggregate": { "total": "575999928000002000000" },
    "max_attempts": 3,
    "lease_seconds": 20
  },
  "artifact_base64": "<standard base64 of the Wasm bytes>"
}
```

The CLI removes `workload.artifact` from the job file, resolves it relative to
the job file, verifies the SHA-256, and builds this envelope. The coordinator
stores the artifact BLOB by digest. Unknown fields, bad protocol/ABI, missing
trusted hashes, oversized inputs/output limits, invalid artifact magic/digest,
and bad aggregation shape are rejected before acceptance.

`GET /v1/admin/jobs/{id}` returns:

```json
{
  "job": {
    "id": "<uuid>",
    "name": "sum-of-squares",
    "description": "...",
    "state": "completed",
    "workload_name": "sum-of-squares",
    "artifact_sha256": "73bd...",
    "verification_mode": { "mode": "exact_sha256" },
    "aggregation": { "mode": "json_sum", "field": "value" },
    "created_at": "...",
    "updated_at": "...",
    "started_at": "...",
    "completed_at": "...",
    "cancel_requested": false,
    "error": null
  },
  "tasks": [
    {
      "id": "<uuid>",
      "key": "task-000",
      "state": "completed",
      "attempts": 1,
      "max_attempts": 3,
      "assigned_worker_id": "<uuid>",
      "assigned_worker_name": "lab-worker-a",
      "output_sha256": "...",
      "output_preview": "{\"value\":\"...\"}",
      "error": null,
      "validation_status": "verified",
      "compute_ms": 123,
      "created_at": "...",
      "started_at": "...",
      "finished_at": "..."
    }
  ],
  "progress": {
    "total": 12,
    "queued": 0,
    "assigned": 0,
    "running": 0,
    "completed": 12,
    "failed": 0,
    "cancelled": 0,
    "percent_complete": 100.0
  },
  "result": {
    "aggregate": { "total": "575999928000002000000" },
    "expected_aggregate": { "total": "575999928000002000000" },
    "aggregate_matches_expected": true,
    "verified_tasks": 12,
    "completed_tasks": 12,
    "compute_ms": 1500
  }
}
```

`result` is absent until the job completes (or is failed after aggregation). A
completed job can still have `validation_status: "unverified"` only in the
explicitly opted-in `trusted` mode.

### Worker

| Method and path | Purpose |
| --- | --- |
| `GET /v1/worker/assignments?max=N` | Claim up to N eligible tasks (N clamped to 1..32; default 1) |
| `POST /v1/worker/heartbeat` | Report participation, capabilities, stats; receive cancel leases |
| `POST /v1/worker/leases/{lease_id}/start` | Mark an assigned task running; body `{"lease_token":"..."}` |
| `GET /v1/worker/leases/{lease_id}/artifact` | Download Wasm; requires `x-getter-lease-token` |
| `POST /v1/worker/results` | Submit success, failure, or infrastructure requeue for a lease |
| `POST /v1/worker/leave` | Graceful disconnect; body `{"protocol":"getter.protocol/v1"}` |

`assignments` response:

```json
{
  "protocol": "getter.protocol/v1",
  "assignments": [
    {
      "protocol": "getter.protocol/v1",
      "lease_id": "<uuid>",
      "lease_token": "getter_lease_...",
      "job_id": "<uuid>",
      "job_name": "sum-of-squares",
      "task_id": "<uuid>",
      "task_key": "task-000",
      "attempt": 1,
      "max_attempts": 3,
      "lease_expires_at": "2026-10-28T00:00:20Z",
      "workload_name": "sum-of-squares",
      "abi": "getter.abi.v1",
      "artifact_sha256": "73bd...",
      "artifact_url": "/v1/worker/leases/<uuid>/artifact",
      "input": "0:1000000",
      "input_sha256": "<sha256 of input bytes>",
      "requirements": {
        "cpu_slots": 1,
        "memory_bytes": 67108864,
        "timeout_secs": 10,
        "output_bytes": 1048576,
        "fuel": 5000000000
      }
    }
  ],
  "coordinator_time": "..."
}
```

The worker checks the artifact digest after download, but it does not recompute
`input_sha256`; the coordinator is trusted for task input, and the digest is
informational on the wire. Workers reject assignments whose ABI is unsupported
or whose requirements exceed local maxima (the scheduler normally prevents
these).

`heartbeat` request:

```json
{
  "protocol": "getter.protocol/v1",
  "participation": "active",
  "capabilities": { "...": "same shape as enrollment" },
  "running_tasks": 2,
  "uptime_secs": 3600,
  "tasks_completed": 42,
  "task_failures": 1,
  "compute_ms": 123456,
  "acknowledged_cancellations": []
}
```

`participation` is `active`, `paused`, `draining`, or `offline`. A heartbeat with
`offline` marks the worker offline. `acknowledged_cancellations` is optional
(defaults to empty): it clears matching pending cancellation notifications for
that worker. The response contains `coordinator_time` and `cancel_leases`, the
pending cancellation notifications (up to 64) for that worker; the worker aborts
those local tasks. Cancellation notifications are persisted so they can be
delivered after a lost heartbeat or coordinator restart, rather than existing
only in memory.

`results` request:

```json
{
  "protocol": "getter.protocol/v1",
  "lease_id": "<uuid>",
  "task_id": "<uuid>",
  "lease_token": "getter_lease_...",
  "outcome": {
    "kind": "success",
    "output_base64": "eyJ2YWx1ZSI6IjIyMSJ9",
    "output_sha256": "<sha256 of decoded output>"
  },
  "compute_ms": 123,
  "fuel_used": 100000
}
```

Failure outcome:

```json
{
  "kind": "failure",
  "message": "workload trapped: ...",
  "retryable": false
}
```

Infrastructure requeue outcome:

```json
{
  "kind": "requeue",
  "reason": "worker paused or stopping before execution"
}
```

A requeue is for a local pause, shutdown, cancelled sandbox, unavailable CPU
slot, artifact download failure, or insufficient lease time.
The coordinator marks the lease `abandoned`, returns the task to `queued`, and
decrements the attempt counter so the interruption does not consume a workload
retry. This is bounded: if a requeue would make a task's abandoned-lease count
exceed 32, the task is failed with `too many infrastructure interruptions`
instead.
Requeue is not a way to bypass `max_attempts` for workload failures.

The coordinator verifies that the declared output digest matches the received
bytes, then recomputes SHA-256 itself. A result that arrives for an expired or
revoked lease, a cancelled job, or a terminal task is normally returned as HTTP
200 with `accepted: false` and an explanatory `message`; an identical duplicate
of an accepted completed output returns `accepted: true, duplicate: true`. A
lease/task mismatch or invalid token is an HTTP 403/409 error. An accepted
infrastructure requeue returns `accepted: true` with a message about the release.

## Job and task state machines

Task states: `queued`, `assigned`, `running`, `completed`, `failed`,
`cancelled`.

Allowed transitions:

```text
queued   -> assigned, cancelled
assigned -> running, queued, failed, cancelled
running  -> completed, queued, failed, cancelled
completed/failed/cancelled -> same state (idempotent)
```

Job states: `queued`, `running`, `completed`, `failed`, `cancelled`.

```text
queued  -> running, failed, cancelled
running -> completed, failed, cancelled
terminal states do not reopen
```

A job is `completed` only when all tasks are completed, verification passes for
the policy, aggregation succeeds, and any `expected_aggregate` matches exactly.
A mismatch or aggregation error makes the job `failed` even if all tasks
completed.

Worker-visible status is derived from heartbeats, not just a stored row:
`online`, `paused`, `offline`, or `revoked`. A worker becomes offline when its
last heartbeat is older than `heartbeat_timeout_secs` (default 20 s) or it sent an
`offline` heartbeat/left.

## Lease semantics and idempotency

- Claims happen in one immediate SQLite transaction; a task is leased to at most
  one worker at a time. If the assignment response is lost after commit, the
  lease remains active until expiry and the task is requeued then.
- Enrollment is also non-idempotent: a lost join response consumes the pairing
  token, so recovery requires a new token.
- Each claim increments `attempts`. A retryable workload failure or lease expiry
  requeues the task if `attempts < max_attempts`; otherwise it becomes failed.
- An **infrastructure requeue** (pause, shutdown, local cancellation, missing CPU
  slot, artifact download failure, or insufficient lease time)
  marks the lease `abandoned`, decrements `attempts`, and returns the task to the
  queue without consuming a workload retry. After 32 abandoned leases for one
  task, the next requeue fails it. This bound is not configurable.
- The worker is expected to stop `lease_safety_secs` before expiry. If it cannot
  finish in the remaining lease, it submits an infrastructure requeue.
- There is no lease extension in `getter.protocol/v1`; jobs must declare
  `lease_seconds >= timeout_secs + 5`.
- Exactly-once is not provided. A task can be computed more than once; external
  side effects are the workload author's responsibility.
- Duplicate completed output with the same lease and bytes is acknowledged
  idempotently. Conflicting bytes are not accepted as success.
- Job cancellation is idempotent: cancelling an already cancelled job returns
  cancelled; cancelling a terminal completed/failed job is a conflict.
- Cancellation notifications are persisted for active leases and delivered on
  heartbeat; a worker's optional `acknowledged_cancellations` clears them. A
  worker that never acknowledges receives the same notification again. This is
  separate from a result accepted before cancellation.
- Pairing is not idempotent: the second use is rejected.
- Job submission is not idempotent: each request creates a new job ID.
- `leave` is best-effort; a worker that disappears is handled by heartbeat and
  lease expiry.

## Limits

Defaults and protocol ceilings:

| Item | Limit |
| --- | --- |
| Tasks per job | 1,000 |
| Task input | 1 MiB per task; 16 MiB total (hard cap) |
| Sum of declared task output limits | 64 MiB per job (hard cap) |
| Per-task output | 1 MiB (hard cap) |
| Result acceptance | 1 MiB (hard cap) |
| Artifact/module | 16 MiB (hard cap) |
| HTTP request body | 48 MiB default; endpoint-specific result/artifact limits still apply |
| Public enrollment body | 64 KiB (independent cap) |
| Task timeout | 1–3,600 s; must fit inside lease with 5 s grace |
| Lease | 10–3,600 s |
| Max attempts | 1–10 (CLI/example default 3); infrastructure requeues do not consume attempts |
| Infrastructure requeues per task | 32 abandoned leases; a further requeue fails the task |
| Fuel | 1–100,000,000,000 |
| Coordinator HTTP body config | Must be at least encoded maximum artifact + maximum total inputs + 1 MiB, at most 64 MiB |

The coordinator can be configured below these ceilings. A remote job cannot
raise a worker's local maxima. See [Configuration](configuration.md).

## Status codes and errors

Errors use:

```json
{ "code": "invalid_submission", "message": "human-readable explanation" }
```

Common mappings:

| Status | Meaning / examples |
| --- | --- |
| 200 | Successful read/action, including `accepted: false` result outcomes |
| 201 | Job created |
| 204 | Worker revoked or worker left |
| 400 | Malformed request, protocol mismatch, bad encoding, missing required ids |
| 401 | Missing/invalid admin token, invalid/expired pairing token, bad/expired/replayed worker signature |
| 403 | Revoked worker, lease/token belongs to another worker, invalid lease token |
| 404 | Unknown job, worker, lease, artifact, or CA disabled |
| 409 | Lease no longer active, job already terminal, conflicting state |
| 413 | Request body exceeds the configured limit |
| 422 | Valid JSON but failed validation (manifest, artifact, capabilities, result size/hash) |
| 429 | Per-worker signed-request rate limit exceeded; retry shortly |
| 500 | Internal database/storage/processing error; details are logged, not exposed |
| 503 | Database not ready, storage lock unavailable, or replay-guard capacity exhausted |

Representative error codes: `protocol_mismatch`, `invalid_worker_name`,
`invalid_public_key`, `invalid_pairing_name`, `invalid_submission`,
`artifact_too_large`, `invalid_artifact_encoding`, `result_too_large`,
`invalid_result_encoding`, `invalid_output_hash`, `invalid_result`,
`unauthorized`, `forbidden`, `not_found`, `conflict`, `body_too_large`,
`rate_limited`, `replay_guard_capacity`, `database_error`,
`invalid_stored_data`, `storage_unavailable`, `internal_error`.

HTTP framework-level malformed JSON/content-type failures may produce the
framework's normal 400/415/422 body rather than `ApiErrorBody`.

## Discovery datagrams

Discovery is optional, unauthenticated, and UDP-only. Query (worker/host):

```json
{ "magic": "GETTER_DISCOVER_V1", "protocol": "getter.protocol/v1" }
```

Announcement (coordinator):

```json
{
  "magic": "GETTER_DISCOVER_V1",
  "protocol": "getter.protocol/v1",
  "coordinator_name": "lab-coordinator",
  "coordinator_url": "https://192.168.1.10:47810",
  "ca_fingerprint": "sha256:...",
  "version": "0.1.0",
  "announced_at": "2026-10-28T00:00:00Z"
}
```

Default UDP port is `47812`; announcements go to `255.255.255.255:47812` unless a
unicast `target` is configured. Messages are rejected if `magic`/`protocol` do
not match, have unknown fields, or exceed 8 KiB. Discovery grants no trust and
never enrolls a worker; pairing and CA-fingerprint verification are still
required. See [Local network](local-network.md).
