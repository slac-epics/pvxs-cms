## Context

The pvxs repository provides a PVAccess implementation with TLS, and the pvxs-cms repository provides certificate management. A historical baseline benchmark comparing CA vs PVA throughput exists as a chart (`baseline.png`), but the tooling that produced it is lost. Two new protocol modes — SPVA without cert monitoring and SPVA with cert monitoring — need benchmarking alongside the original CA and PVA modes.

EPICS Base provides Channel Access client/server APIs (`libca`, `libdbCore`, `libdbRecStd`), and PVXS provides PVAccess client/server APIs (`pvxs::client::Context`, `pvxs::server::SharedPV`). TLS and cert monitoring are controlled via `pvxs::impl::ConfigCommon` methods (`tls_disabled`, `disableStatusCheck()`, `disableStapling()`).

## Features

- A single, self-contained host executable (`pvxperf`) that benchmarks update throughput across CA, PVA, SPVA (no cert monitoring), and SPVA (with cert monitoring).
- Support both sequential (one update consumed at a time) and parallel (pipelined monitor subscription with configurable window) execution modes.
- Sweep across configurable payload sizes (bytes).
- Output machine-readable CSV that can reproduce charts matching the baseline layout.
- Ensure repeatability on the same hardware by running server and client in-process, eliminating network stack variability.
- Follow existing tool patterns (Makefile fragment, EPICS coding conventions, CLI11 for argument parsing).

**Out of Scope:**
- Network-level benchmarking (we measure application-layer data throughput only).
- Latency distribution analysis (focus is on throughput / updates-per-second).
- Automated chart generation (CSV output feeds external plotting tools).
- Cross-host benchmarking or distributed test harness.

## Decisions

### D1: Single executable with embedded servers

**Decision:** Run CA IOC and PVXS server in-process alongside the client benchmark loops, all within `pvxperf`.

**Rationale:** Eliminates process coordination, network jitter, and port conflict issues. The test infra in `testtlswithcms.cpp` already demonstrates in-process server+client patterns with `server::SharedPV`, `Server::start()`, and `clientConfig().build()`. For CA, EPICS Base supports programmatic IOC initialisation via `dbLoadDatabase`, `dbLoadRecords`, and `iocInit`.

**Alternative considered:** Separate server/client executables orchestrated by a shell script. Rejected because it introduces timing dependencies, port management, and reduces repeatability.

### D2: Payload structure with counter-based integrity checking

**Decision:** The payload SHALL be a UInt8 byte array of the target size, with a 16-byte header: the first 8 bytes contain a 64-bit monotonic counter (network byte order), and bytes 8-15 contain a send timestamp as epoch microseconds (network byte order, via `epicsTime`). The remaining bytes are filled with a deterministic pattern derived from the counter (e.g., repeating low byte of counter). Use `nt::NTScalar{TypeCode::UInt8A}` for PVA/SPVA and a `waveform` record of `FTVL=UCHAR` for CA.

The server increments the counter on every `post()` and stamps the current time. The client receives updates via a **monitor subscription with pipelining enabled** (`record("pipeline", true)`), consuming them via `Subscription::pop()`. After warm-up, the client records the counter value from the first measurement update, and then on every subsequent `pop()` verifies that the received counter is exactly previous+1. Any gap (counter skip) is a **drop**; any error is also recorded.

The send timestamp enables finer-grained analysis: "how many updates sent during second S were eventually delivered to the client?" This decouples server-side send rate from client-side receive rate, providing a true measure of delivered throughput grouped by send time.

**Rationale:** Using a known data pattern (monotonic counter) rather than random bytes enables the client to **detect drops** — missing or reordered values — which is the real stopping condition for the benchmark. This matches the historical methodology: the goal is maximum throughput *before drops occur*, not just raw speed. `UInt8A` directly represents N bytes of application payload. The counter + timestamp in the first 16 bytes is cheap to encode/decode and unambiguous. The minimum payload size of 1 byte is too small for the 16-byte header, so payloads smaller than 16 bytes use only the counter (8 bytes) or are padded to 16 bytes — the implementation should enforce a minimum payload size of 16 bytes or gracefully degrade to counter-only for tiny payloads.

**Alternative considered:** Random bytes with separate sequence-number field. Rejected because embedding the counter in the payload itself keeps the data structure simple and avoids adding extra NTScalar fields that would change the wire format.

### D3: Four protocol modes as an enum-driven loop

**Decision:** Define a `ProtocolMode` enum `{CA, PVA, SPVA, SPVA_CERTMON}`. Each mode configures a server+client pair differently:

| Mode         | Server                                                 | Client                                         | TLS | StatusCheck                 | CMS             |
|--------------|--------------------------------------------------------|------------------------------------------------|-----|-----------------------------|-----------------|
| CA           | Embedded IOC (dbCore+dbRecStd)                         | `libca` `ca_create_subscription`               | N/A | N/A                         | N/A             |
| PVA          | `SharedPV` + `Server(config)` with `tls_disabled=true` | `client::Context` monitor with `pipeline=true` | Off | Off                         | N/A             |
| SPVA         | `SharedPV` + `Server(config)` with TLS keychain        | `client::Context` monitor with `pipeline=true` | On  | `disableStatusCheck(true)`  | N/A             |
| SPVA_CERTMON | Same as SPVA                                           | Same as SPVA                                   | On  | `disableStatusCheck(false)` | **Real PVACMS** |

**Rationale:** Follows the exact configuration patterns used in `testtlswithcms.cpp` and `testtlswithcmsandstapling.cpp`. The Expert API (`PVXS_ENABLE_EXPERT_API` is already set in `src/Makefile`) exposes `disableStatusCheck()`.

### D3a: Real PVACMS for SPVA_CERTMON (not a mock)

**Decision:** The SPVA_CERTMON mode SHALL use a **real PVACMS instance** rather than the mock CMS used in unit tests. PVACMS will be launched as a child process (`fork/exec` or `popen`) by `pvxperf`, not embedded in-process.

**Rationale:** The mock CMS (`ConfigCms::mockCms()` + `WildcardPV::buildMailbox()` with hardcoded GOOD status) bypasses all real CMS code paths:
- No SQLite database operations (`initCertsDatabase`, certificate lookup)
- No real OCSP response signing (`CertStatusFactory`, `onGetStatus`)
- No real `statusMonitor` periodic refresh loop
- No ACF-based access control evaluation
- No real certificate chain validation

Using the mock would produce benchmark numbers that do not reflect production cert-monitoring overhead — defeating the purpose of the SPVA_CERTMON permutation. The whole point is to measure the impact of real certificate status verification on throughput.

Real PVACMS (`src/pvacms/pvacms.cpp`) is a ~3400-line standalone executable requiring:
- SQLite database file (`EPICS_PVACMS_DB`)
- Certificate Authority keychain (`EPICS_CERT_AUTH_TLS_KEYCHAIN`)
- PVACMS server keychain (`EPICS_PVACMS_TLS_KEYCHAIN`)
- ACF file (`EPICS_PVACMS_ACF`)
- Authenticator configuration

Embedding it in-process is impractical — it has its own `main()`, global state, and heavy dependencies. Instead:
1. `pvxperf` launches `pvacms` as a child process with the required env vars.
2. `pvxperf` waits for PVACMS to become ready (probe the `CERT:STATUS:*` PV namespace).
3. Benchmarks run against the server with cert monitoring contacting the real PVACMS.
4. `pvxperf` sends SIGTERM to the child process on completion.

**Alternative considered:** Refactoring PVACMS into a library callable from other executables. Rejected as out of scope — it would be a major refactor of pvacms.cpp's architecture and is not needed for benchmarking.

**Alternative considered:** Requiring the user to start PVACMS manually before running pvxperf. Rejected for repeatability — automated child-process management ensures identical setup every time.

### D3b: PVACMS infrastructure setup — zero-config bootstrap

**Decision:** `pvxperf` SHALL provide a `--setup-cms` option that bootstraps the entire PVACMS + certificate infrastructure from scratch with no pre-existing configuration. The bootstrap leverages PVACMS's self-initialisation capability and `authnstd` for cert provisioning.

**Rationale:** PVACMS auto-creates its CA certificate, SQLite database, server keychain, and ACF on first startup when started with no prior state. Combined with `--certs-dont-require-approval`, cert requests from `authnstd` are auto-approved without admin intervention. This eliminates any dependency on `gen_test_certs` or pre-existing cert hierarchies.

**CRITICAL: Isolation from existing installations.** PVACMS defaults to storing state under `${XDG_CONFIG_HOME}/pva/1.5/` and `${XDG_DATA_HOME}/pva/1.5/`. Running it without redirecting these paths would **clobber any existing PVACMS setup** on the machine. The `--setup-cms` bootstrap MUST use PVACMS's CLI flags to redirect all paths into the temp directory:

The `--setup-cms` bootstrap sequence:
1. Create a temp directory (e.g. `mkdtemp("pvxperf-cms-XXXXXX")`) for all CMS state.
2. Launch `pvacms` as a child process with CLI flags isolating all state to the temp dir:
   ```
   pvacms \
     --certs-dont-require-approval \
     -c <tmpdir>/cert_auth.p12 \
     -d <tmpdir>/certs.db \
     -p <tmpdir>/pvacms.p12 \
     --acf <tmpdir>/pvacms.acf \
     -a <tmpdir>/admin.p12
   ```
   PVACMS auto-creates all of these on first start:
   - Root CA certificate and key (`cert_auth.p12`)
   - PVACMS server certificate (`pvacms.p12`)
   - SQLite certificate database (`certs.db`)
   - Default ACF file (`pvacms.acf`)
3. Wait for PVACMS readiness (probe `CERT:ROOT:*` PV).
4. Run `authnstd -n pvxperf-server -u server` with `EPICS_PVAS_TLS_KEYCHAIN=<tmpdir>/server.p12` → PVACMS auto-approves and provisions a server keychain.
5. Run `authnstd -n pvxperf-client -u client` with `EPICS_PVA_TLS_KEYCHAIN=<tmpdir>/client.p12` → PVACMS auto-approves and provisions a client keychain.
6. Use `server.p12` and `client.p12` as the keychains for SPVA/SPVA_CERTMON benchmarks.
7. On cleanup: SIGTERM the PVACMS child process, remove the temp directory.

Alternatively, the tool accepts `--cms-db`, `--cms-keychain`, and `--cms-acf` paths pointing at an existing PVACMS configuration, or `--external-cms` to skip launching entirely.

This keeps benchmarks fully self-contained, repeatable, and **safe** — no risk of clobbering existing installations.

### D4: Monitor-based measurement with per-subscriber pipelining

**Decision:** For PVA/SPVA modes, the benchmark uses **monitor subscriptions** (not repeated GETs) to receive server updates. Pipelining (`record("pipeline", true)`) provides protocol-level flow control per subscriber — each subscriber has an independent queue with a pipeline window controlling how many updates the server may send before the client must acknowledge consumption.

Both modes use a **single `client::Context`** (one client connection to the server):
- **Sequential:** A **single** monitor subscription with default `queueSize=4` (PVXS default). One subscriber receives every update. Measures single-subscriber throughput.
- **Parallel:** **N independent monitor subscriptions** (configurable via `--subscriptions`, **default 1000**) to the **same PV**, all on the same `client::Context`. Each subscription has its own pipeline window (`queueSize=4` default). The server fans out each `SharedPV::post()` to all N subscribers independently. Each subscriber receives every update and independently verifies its counter sequence. This tests the server's ability to fan out updates to many concurrent subscribers — matching the baseline's "1000 parallel" methodology.

The server uses `SharedPV::post()` for updates. Internally, `SharedPV::post()` iterates over all subscribers and calls each subscriber's `MonitorControlOp::post()` — which **squashes** onto the last queue entry if that subscriber's queue is full. This is the natural PVA behavior: a slow subscriber gets squashed updates while fast subscribers keep up. The counter-based integrity check detects squashed updates as counter gaps (drops).

Key insight from PVXS source code (`sharedpv.cpp` line 438, `servermon.cpp` line 267-312):
- `SharedPV` stores a `std::set<std::shared_ptr<MonitorControlOp>> subscribers`
- `SharedPV::post()` iterates all subscribers and calls `sub->post(copy)` on each
- Each `MonitorControlOp::post()` squashes if `queue.size() >= limit` (but doesn't block)
- Each subscriber has its own `window`, `queue`, and `limit` — completely independent
- The server is **never blocked** by any subscriber — it always advances the counter

For CA mode: CA uses multiple `ca_create_subscription` calls to the same channel (1 for sequential, N for parallel). CA monitors have their own queue semantics — if the queue overflows, CA squashes updates. The counter pattern detects this.

**Rationale:** The "1000 parallel" in the baseline measures fan-out throughput: can the server deliver updates to 1000 concurrent subscribers without any of them seeing drops? This is fundamentally different from a single subscription with a large pipeline window (which would only measure single-stream throughput with deep buffering). With 1000 subscriptions, the server must serialize and send each update 1000 times, and any subscriber that falls behind gets squashed — exactly the load pattern that matters for production PV servers.

### D5: Measurement methodology — max clean throughput via monitor fan-out with counter verification

**Decision:** The benchmark finds the **maximum update rate achievable without any drops or errors** for each (mode × payload_size × execution_style) triple. The algorithm:

1. **Server-side:** For each payload size, a server-side pump thread calls `SharedPV::post()` as fast as possible with the counter+timestamp-bearing payload. `SharedPV::post()` fans out to all active subscribers — each gets its own copy. If any subscriber's queue is full, its entry is squashed (not blocked). The server always advances the counter. The send timestamp (epoch microseconds via `epicsTime`) is written alongside the counter.

2. **Client-side:** One subscription (sequential) or N subscriptions (parallel, default 1000), all with `pipeline=true` and `queueSize=4` (PVXS default). Each subscription's `event` callback calls `Subscription::pop()` in a loop to drain available updates. Each subscription independently tracks its expected counter.

3. **Warm-up phase** (configurable, default 100 updates): All subscriptions consume updates to establish connections, TLS handshakes, and cert monitoring subscriptions. Counter values during warm-up are discarded.

4. **Measurement phase:** After warm-up, each subscription records the counter value from its first measurement `pop()`. On every subsequent `pop()`, it verifies the received counter equals `expected_counter` (previous + 1). The measurement runs for a configurable duration (default 5 seconds).
   - If the counter matches: success, increment expected.
   - If the counter is ahead (gap): **drop detected** — one or more values were squashed by `SharedPV::post()` because that subscriber's queue was full.
   - If the subscription delivers an error: **error detected**.

5. **Stopping condition:** The measurement runs for the full duration. Drops and errors are counted but do not stop the run early.

6. **Recording:** For each measurement point, record: total successful updates (summed across all subscriptions), drops (summed across all subscriptions), errors, elapsed wall-clock time.

7. **Computation:** `updates_per_second = total_successful_updates / elapsed_seconds`. The CSV includes the drop count so graphing tools can filter to only drop-free data points.

Use `epicsTime` for high-resolution timing (already used throughout the codebase).

**Rationale:** `SharedPV::post()` with squash-on-full is the natural PVA server behavior. In production, a PV server doesn't use `tryPost()` — it posts updates and slow subscribers get squashed. The benchmark should measure this real-world scenario: what is the maximum rate the server can post updates such that all N subscribers receive every update without any squashes? The counter-based integrity check directly detects squashes as counter gaps, making the metric "clean throughput" (updates/sec with zero drops) meaningful.

**Alternative considered:** Using `MonitorControlOp::tryPost()` on each subscriber individually (server slows down to slowest subscriber). Rejected because (a) `SharedPV::post()` doesn't expose per-subscriber `tryPost()` — it calls `sub->post()` which squashes, and (b) real PV servers use `SharedPV::post()`, so the benchmark should match production behavior.

**Alternative considered:** Using repeated GETs instead of monitors. Rejected because GETs don't test fan-out to multiple subscribers and have no flow control mechanism.

### D6: CSV output schema

**Decision:** Output columns:
```
protocol,mode,payload_bytes,updates_per_second,total_updates,drops,errors,duration_seconds
```
Where `protocol` is `CA|PVA|SPVA|SPVA_CERTMON`, `mode` is `sequential|parallel`, `drops` is the count of counter-sequence gaps (missing values), and `errors` is the count of subscription failures.

**Rationale:** Flat CSV with one row per measurement point. The `drops` column is critical — it lets graphing tools plot "max updates/sec before drops" by filtering to rows where `drops == 0`. External tools (Python/matplotlib, R, Excel) can pivot on protocol×mode to produce the subplot grid matching the baseline chart. The `total_updates` column provides the raw count for cross-checking.

### D7: CLI interface using CLI11

**Decision:** Use CLI11 (already bundled at `bundle/CLI11`) for argument parsing, consistent with `pvxcert`.

Options:
- `--duration <secs>` — measurement duration per data point (default 5)
- `--warmup <count>` — warm-up updates to consume before measurement (default 100)
- `--subscriptions <n>` — number of parallel monitor subscriptions (default 1000); sequential mode always uses 1
- `--sizes <list>` — comma-separated payload sizes in bytes (default: 1,10,100,1000,10000,100000)
- `--modes <list>` — comma-separated protocol modes to run (default: all)
- `--keychain <path>` — TLS keychain file for SPVA benchmark server/client
- `--setup-cms` — auto-bootstrap: generate test certs, launch real PVACMS as child process, use generated keychains
- `--external-cms` — assume an already-running PVACMS is reachable (skip child-process launch)
- `--cms-db <path>` — path to existing PVACMS SQLite database
- `--cms-keychain <path>` — path to existing PVACMS server keychain
- `--cms-acf <path>` — path to existing PVACMS ACF file
- `--output <file>` — CSV output file (default: stdout)
- `-d,--debug` — enable PVXS debug logging
- `-V,--version` — print version

### D8: Build integration

**Decision:** Follow the `pvxcert` Makefile fragment pattern:
- `src/tools/pvxperf/Makefile` — defines `PROD += pvxperf`, `pvxperf_SRCS`, `pvxperf_LIBS`.
- `src/tools/Makefile` — add `include $(TOOLS_DIR)/pvxperf/Makefile`.
- Link libraries: `pvxs Com ca dbCore dbRecStd`.

## Risks / Trade-offs

- **[CA IOC in-process complexity]** → Embedding a full IOC requires `dbLoadDatabase`, `dbLoadRecords`, `iocInit` which pull in the EPICS database layer. Mitigation: Keep IOC setup minimal (single waveform record), teardown via `iocShutdown`. If linking proves problematic, CA mode can be made optional via a build flag.
- **[PVACMS child-process management]** → Launching and managing a real PVACMS as a child process adds complexity (startup wait, health-check, shutdown). Mitigation: Use a simple readiness probe (attempt `client.get("CERT:ROOT:*")` with retry) and SIGTERM for cleanup. Wrap in RAII so PVACMS is always cleaned up even on exceptions. Provide `--external-cms` escape hatch for users who prefer manual CMS management.
- **[PVACMS adds separate-process overhead to SPVA_CERTMON]** → Unlike PVA/SPVA where everything is in-process, SPVA_CERTMON has the CMS in a separate process, adding real IPC overhead. This is actually desirable — it matches the production deployment topology where CMS is a separate service. The benchmark captures real-world cert monitoring cost.
- **[Certificate infrastructure bootstrapping]** → SPVA/SPVA_CERTMON modes need keychains, and PVACMS needs a CA keychain + DB + ACF. Mitigation: PVACMS self-initialises everything on first start. `--setup-cms` creates a temp dir, starts PVACMS with `--certs-dont-require-approval`, then provisions server/client keychains via `authnstd`. No external dependencies needed.
- **[Existing PVACMS on the network]** → If another PVACMS is already running on the same broadcast domain, PVA clients could discover it instead of the benchmark's own PVACMS, causing false results. Mitigation: (1) Bind the benchmark PVACMS, benchmark server, and benchmark client all to loopback (`127.0.0.1`) on ephemeral/non-standard ports. Since cert status monitoring respects the client/server config's interface and port settings, this isolates all benchmark traffic from the production network. (2) Document prominently (help text + source header) that pvxperf should be run on a network with no other active PVACMS as an additional safety measure.
- **[Measurement noise]** → In-process server/client share CPU; PVACMS adds a third process for SPVA_CERTMON. Mitigation: The goal is comparative (same hardware, same conditions). The PVACMS process overhead is real production overhead and should be included in the measurement.
- **[Large payloads may cause memory pressure]** → 1MB+ arrays at high concurrency. Mitigation: Cap max payload at 10MB, pre-allocate buffers.
