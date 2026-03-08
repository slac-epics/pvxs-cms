## Context

The pvxs repository provides a PVAccess implementation with TLS, and the pvxs-cms repository provides certificate management. A historical baseline benchmark comparing CA vs PVA throughput exists as a chart (`baseline.png`), but the tooling that produced it is lost. Two new protocol modes - SPVA without cert monitoring and SPVA with cert monitoring - need benchmarking alongside the original CA and PVA modes.

EPICS Base provides Channel Access client/server APIs (`libca`, `libdbCore`, `libdbRecStd`), and PVXS provides PVAccess client/server APIs (`pvxs::client::Context`, `pvxs::server::SharedPV`). TLS and cert monitoring are controlled via `pvxs::impl::ConfigCommon` methods (`tls_disabled`, `disableStatusCheck()`, `disableStapling()`).

## Features

- A single, self-contained host executable (`pvxperf`) that benchmarks update throughput across CA, PVA, SPVA (no cert monitoring), and SPVA (with cert monitoring).
- Use adaptive rate discovery (exponential ramp + binary search) to find maximum sustainable throughput with zero drops.
- Sweep across configurable payload sizes (bytes).
- Output machine-readable CSV that can reproduce charts matching the baseline layout.
- Ensure repeatability on the same hardware by running server and client in-process, eliminating network stack variability.
- Follow existing tool patterns (Makefile fragment, EPICS coding conventions, CLI11 for argument parsing).
- Measure connection phase timing (search, tcp_connect, validation, create_channel) for PVA, SPVA, and SPVA_CERTMON, with percentage overhead comparison vs PVA baseline.
- Distributed testing with separate server/client processes (`--role server` / `--role client`).
- Gateway-in-the-middle topology support with config generation (`--print-gateway-config`).
- Multiple independent measurement iterations with mean/stddev/min/max variance analysis.

**Out of Scope:**
- Network-level benchmarking (we measure application-layer data throughput only).
- Latency distribution analysis (focus is on throughput / updates-per-second).
- Automated chart generation (CSV output feeds external plotting tools).
- pvxperf does not start or manage the gateway process - operators configure and start it manually.

## Decisions

### D1: Single executable with embedded servers

**Decision:** Run CA IOC and PVXS server in-process alongside the client benchmark loops, all within `pvxperf`.

**Rationale:** Eliminates process coordination, network jitter, and port conflict issues. The test infra in `testtlswithcms.cpp` already demonstrates in-process server+client patterns with `server::SharedPV`, `Server::start()`, and `clientConfig().build()`. For CA, EPICS Base supports programmatic IOC initialisation via `dbLoadDatabase`, `dbLoadRecords`, and `iocInit`.

PVA/SPVA/SPVA_CERTMON servers use a custom `loopbackServerConfig()` helper that binds to `127.0.0.1` on ephemeral ports with `auto_beacon=false`. This is intentionally **not** `Config::isolated()` - the pvxs `isolated()` method calls `disableStatusCheck(true)` and `disableStapling(true)`, which would prevent SPVA_CERTMON from performing real certificate status monitoring. The loopback helper provides the same network isolation (no broadcast, no collision with production services) without disabling the TLS status machinery. The user is responsible for ensuring no other PVACMS is running on the same machine during benchmarks.

`loopbackServerConfig()` accepts an optional `pvacms_udp_port` parameter. When non-zero (used for SPVA_CERTMON), it appends `127.0.0.1:<port>` to `beaconDestinations`. This entry propagates into the server's inner cert-status client (which derives its config from `clientConfig(effective)`, mapping `beaconDestinations` to `addressList`) so that inner client can discover PVACMS on its fixed port. The benchmark client also receives this entry via `server.clientConfig()`, but it's harmless - PVACMS never claims `PVXPERF:*` PVs and simply ignores searches for them. See D17 for the full discovery flow.

**Alternative considered:** Separate server/client executables orchestrated by a shell script. Rejected because it introduces timing dependencies, port management, and reduces repeatability.

**Alternative considered:** Using `Config::isolated()` for network isolation. Rejected because it explicitly disables certificate status checking and OCSP stapling, which defeats the purpose of the SPVA_CERTMON benchmark mode.

### D2: Payload structure with counter-based integrity checking

**Decision:** The payload SHALL be a UInt8 byte array of the target size, with a 16-byte header: the first 8 bytes contain a 64-bit monotonic counter (network byte order), and bytes 8-15 contain a send timestamp as epoch microseconds (network byte order, via `epicsTime`). The remaining bytes are filled with a deterministic pattern derived from the counter (e.g., repeating low byte of counter). Use `nt::NTScalar{TypeCode::UInt8A}` for PVA/SPVA and a `waveform` record of `FTVL=UCHAR` for CA.

The server increments the counter on every `post()` and stamps the current time. The client receives updates via a **monitor subscription with pipelining enabled** (`record("pipeline", true)`), consuming them via `Subscription::pop()`. After warm-up, the client records the counter value from the first measurement update, and then on every subsequent `pop()` verifies that the received counter is exactly previous+1. Any gap (counter skip) is a **drop**; any error is also recorded.

The send timestamp enables finer-grained analysis: "how many updates sent during second S were eventually delivered to the client?" This decouples server-side send rate from client-side receive rate, providing a true measure of delivered throughput grouped by send time.

**Rationale:** Using a known data pattern (monotonic counter) rather than random bytes enables the client to **detect drops** - missing or reordered values - which is the real stopping condition for the benchmark. This matches the historical methodology: the goal is maximum throughput *before drops occur*, not just raw speed. `UInt8A` directly represents N bytes of application payload. The counter + timestamp in the first 16 bytes is cheap to encode/decode and unambiguous. The minimum payload size of 1 byte is too small for the 16-byte header, so payloads smaller than 16 bytes use only the counter (8 bytes) or are padded to 16 bytes - the implementation should enforce a minimum payload size of 16 bytes or gracefully degrade to counter-only for tiny payloads.

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

Using the mock would produce benchmark numbers that do not reflect production cert-monitoring overhead - defeating the purpose of the SPVA_CERTMON permutation. The whole point is to measure the impact of real certificate status verification on throughput.

Real PVACMS (`src/pvacms/pvacms.cpp`) is a ~3400-line standalone executable requiring:
- SQLite database file (`EPICS_PVACMS_DB`)
- Certificate Authority keychain (`EPICS_CERT_AUTH_TLS_KEYCHAIN`)
- PVACMS server keychain (`EPICS_PVACMS_TLS_KEYCHAIN`)
- ACF file (`EPICS_PVACMS_ACF`)
- Authenticator configuration

Embedding it in-process is impractical - it has its own `main()`, global state, and heavy dependencies. Instead:
1. `pvxperf` launches `pvacms` as a child process with the required env vars.
2. `pvxperf` waits for PVACMS to become ready (probe the `CERT:STATUS:*` PV namespace).
3. Benchmarks run against the server with cert monitoring contacting the real PVACMS.
4. `pvxperf` sends SIGTERM to the child process on completion.

**Port assignments for the PVACMS child process:** The child is launched with `EPICS_PVAS_BROADCAST_PORT=15076`, `EPICS_PVAS_SERVER_PORT=15075`, and `EPICS_PVAS_TLS_PORT=15076` set in its environment. These non-default ports (vs production 5075/5076) avoid collisions with any production PVACMS on the same machine. The benchmark server and client use ephemeral ports. See D17 for how the inner cert-status clients discover PVACMS on these fixed ports.

**Alternative considered:** Refactoring PVACMS into a library callable from other executables. Rejected as out of scope - it would be a major refactor of pvacms.cpp's architecture and is not needed for benchmarking.

**Alternative considered:** Requiring the user to start PVACMS manually before running pvxperf. Rejected for repeatability - automated child-process management ensures identical setup every time.

### D3b: PVACMS infrastructure setup - zero-config bootstrap

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

This keeps benchmarks fully self-contained, repeatable, and **safe** - no risk of clobbering existing installations.

### D4: Monitor-based measurement with per-subscriber pipelining

**Decision:** For PVA/SPVA modes, the benchmark uses **monitor subscriptions** (not repeated GETs) to receive server updates. Pipelining (`record("pipeline", true)`) provides protocol-level flow control per subscriber - each subscriber has an independent queue with a pipeline window controlling how many updates the server may send before the client must acknowledge consumption. All subscriptions use the PVXS default `queueSize` of 4.

Both modes use a **single `client::Context`** (one client connection to the server):
- **Single subscriber:** A **single** monitor subscription. One subscriber receives every update. Measures single-subscriber throughput.
- **Multi-subscriber:** **N independent monitor subscriptions** (configurable via `--subscriptions`, **default 1000**) to the **same PV**, all on the same `client::Context`. Each subscription has its own pipeline window with the default `queueSize` of 4. The server fans out each `SharedPV::post()` to all N subscribers independently. Each subscriber receives every update and independently verifies its counter sequence. This tests the server's ability to fan out updates to many concurrent subscribers - matching the baseline's "1000 parallel" methodology.

The server uses `SharedPV::post()` for updates. Internally, `SharedPV::post()` iterates over all subscribers and calls each subscriber's `MonitorControlOp::post()` - which **squashes** onto the last queue entry if that subscriber's queue is full. This is the natural PVA behavior: a slow subscriber gets squashed updates while fast subscribers keep up. The counter-based integrity check detects squashed updates as counter gaps (drops).

Key insight from PVXS source code (`sharedpv.cpp` line 438, `servermon.cpp` line 267-312):
- `SharedPV` stores a `std::set<std::shared_ptr<MonitorControlOp>> subscribers`
- `SharedPV::post()` iterates all subscribers and calls `sub->post(copy)` on each
- Each `MonitorControlOp::post()` squashes if `queue.size() >= limit` (but doesn't block)
- Each subscriber has its own `window`, `queue`, and `limit` - completely independent
- The server is **never blocked** by any subscriber - it always advances the counter

For CA mode: CA uses multiple `ca_create_subscription` calls to the same channel (1 for single, N for multi). CA monitors have their own queue semantics - if the queue overflows, CA squashes updates. The counter pattern detects this.

**Rationale:** The "1000 parallel" in the baseline measures fan-out throughput: can the server deliver updates to 1000 concurrent subscribers without any of them seeing drops? This is fundamentally different from a single subscription with a large pipeline window (which would only measure single-stream throughput with deep buffering). With 1000 subscriptions, the server must serialize and send each update 1000 times, and any subscriber that falls behind gets squashed - exactly the load pattern that matters for production PV servers.

### D5: Measurement methodology - adaptive rate discovery with counter verification

**Decision:** The benchmark finds the **maximum sustainable update rate with zero drops or errors** for each (mode × payload_size × subscriber_count) triple using adaptive rate discovery. The algorithm:

1. **Adaptive rate discovery:** Instead of flooding updates as fast as possible (which causes queue overflow and obscures the true sustainable rate), the benchmark uses a three-phase approach:
   - **Phase 1 (Exponential ramp):** Start at 1,000 updates/sec, double each probe (1-second duration) until drops appear. This brackets the max rate in `[last_clean_rate, first_drop_rate]`.
   - **Phase 2 (Binary search):** Narrow the bracket to within 2% precision with additional 1-second probes.
   - **Phase 3 (Confirmation):** Run at the discovered rate for 3 seconds to verify stability. If drops appear, back off 10% and retry.

2. **Server-side:** A pump thread calls `SharedPV::post()` with a configurable inter-post delay (`post_delay_ns`) calculated from the target rate. `SharedPV::post()` fans out to all active subscribers - each gets its own copy. If any subscriber's queue is full, its entry is squashed (not blocked). The server always advances the counter.

3. **Client-side:** One or N subscriptions (configurable via `--subscriptions`, default 1000), all with `pipeline=true` and the default `queueSize` of 4 (PVXS default). Each subscription's `event` callback calls `Subscription::pop()` in a loop to drain available updates. Each subscription independently tracks its expected counter.

4. **Warm-up phase** (50 updates per probe): All subscriptions consume updates to establish connections, TLS handshakes, and cert monitoring subscriptions. Counter values during warm-up are discarded.

5. **Counter verification:** After warm-up, each subscription records the counter value from its first measurement `pop()`. On every subsequent `pop()`, it verifies the received counter equals `expected_counter` (previous + 1).
   - If the counter matches: success, increment expected.
   - If the counter is ahead (gap): **drop detected** - one or more values were squashed by `SharedPV::post()` because that subscriber's queue was full.
   - If the subscription delivers an error: **error detected**.

6. **Recording:** For each data point, record: total successful updates (summed across all subscriptions), drops, errors, elapsed wall-clock time.

7. **Computation:** `updates_per_second = total_successful_updates / elapsed_seconds`.

**Rationale:** The adaptive approach eliminates flooding artifacts and queue backpressure effects. When the server floods as fast as possible, the measured rate depends heavily on queue depth, CPU scheduling, and buffer management - not on the true maximum sustainable throughput. The adaptive method discovers the actual clean rate where all subscribers receive every update without squashes. This produces stable, reproducible numbers that directly reflect the protocol's throughput capacity.

Earlier experiments with fixed flood-mode benchmarks showed that varying queue depth (4, 144, 288) and queue scaling formulas had no effect on the TLS/PVA ratio - confirming that the adaptive approach correctly isolates the protocol overhead.

**Alternative considered:** Flooding updates as fast as possible with configurable queue depth (`SharedPV::post()` + squash-on-full). Rejected because it makes measurements dependent on queue configuration rather than protocol throughput.

**Alternative considered:** Using repeated GETs instead of monitors. Rejected because GETs don't test fan-out to multiple subscribers and have no flow control mechanism.

### D6: CSV output schema

**Decision:** Throughput CSV columns:
```
protocol,payload_mode,subscribers,payload_bytes,topology,iteration,updates_per_second,per_sub_updates_per_second,total_updates,drops,errors,duration_seconds
```
Where `protocol` is `CA|PVA|SPVA|SPVA_CERTMON`, `payload_mode` is `raw|nt`, `topology` is `loopback|direct|gateway`, `iteration` is 1..N, `drops` is the count of counter-sequence gaps, and `errors` is the count of subscription failures.

Phase timing uses a separate CSV (see D13):
```
test_type,protocol,iteration,phase,duration_us
```

**Rationale:** Flat CSV with one row per measurement point. The `drops` column lets graphing tools filter to drop-free data points. The `topology` column enables cross-topology comparisons. The `iteration` column is always present (value `1` when `--throughput-iterations` is not specified) for schema consistency. External tools (Python/matplotlib, R, Excel) can pivot on protocol×topology to produce the subplot grid matching the baseline chart.

### D7: CLI interface using CLI11

**Decision:** Use CLI11 (already bundled at `bundle/CLI11`) for argument parsing, consistent with `pvxcert`.

Options:
- `--duration <secs>` - measurement duration per data point (default 5)
- `--warmup <count>` - warm-up updates to consume before measurement (default 100)
- `--subscriptions <n>` - number of parallel monitor subscriptions (default 1000); sequential mode always uses 1
- `--sizes <list>` - comma-separated payload sizes in bytes (default: 1,10,100,1000,10000,100000)
- `--modes <list>` - comma-separated protocol modes to run (default: all)
- `--keychain <path>` - TLS keychain file for SPVA benchmark server/client
- `--setup-cms` - auto-bootstrap: generate test certs, launch real PVACMS as child process, use generated keychains
- `--external-cms` - assume an already-running PVACMS is reachable (skip child-process launch)
- `--cms-db <path>` - path to existing PVACMS SQLite database
- `--cms-keychain <path>` - path to existing PVACMS server keychain
- `--cms-acf <path>` - path to existing PVACMS ACF file
- `--output <file>` - CSV output file (default: stdout)
- `--throughput-iterations <N>` - number of independent measurement iterations per data point (default 5)
- `--benchmark-phases` - run connection phase timing benchmark
- `--phase-iterations <N>` - number of connect/disconnect cycles for phase timing (default 50)
- `--phase-output <file>` - separate CSV file for phase timing output
- `--role <mode>` - operating mode: `loopback` (default), `server`, `client`
- `--bind-addr <host:port>` - server bind address (default `0.0.0.0:0`)
- `--server-addr <host:port>` - remote server address (required for `--role client`)
- `--gateway` - mark benchmark topology as gateway (client mode)
- `--print-gateway-config` - print example PVAGW gateway config and exit
- `-d,--debug` - enable PVXS debug logging
- `-V,--version` - print version

### D8: Build integration

**Decision:** Follow the `pvxcert` Makefile fragment pattern:
- `src/tools/pvxperf/Makefile` - defines `PROD += pvxperf`, `pvxperf_SRCS`, `pvxperf_LIBS`.
- `src/tools/Makefile` - add `include $(TOOLS_DIR)/pvxperf/Makefile`.
- Link libraries: `pvxs Com ca dbCore dbRecStd`.

### D9: Per-phase connection timing via debug log parsing

**Decision:** Measure per-phase connection timing by parsing pvxs debug log messages captured via `errlogAddListener()`. No modifications to pvxs library internals are required. Only PVA, SPVA, and SPVA_CERTMON are measured - CA is excluded because its protocol stages are not comparable to the PVA message sequence.

Phases measured: `search` (UDP broadcast + response), `tcp_connect` (TCP connection + TLS handshake for SPVA), `validation` (PVA auth negotiation, includes cert status check for SPVA_CERTMON), `create_channel` (channel creation round-trip), and `total` (end-to-end). Only two loggers are set to DEBUG: `pvxs.st.cli` (state transitions) and `pvxs.cli.io` (protocol message arrivals). All other pvxs loggers remain at default level.

**Rationale:** Debug log parsing avoids modifying pvxs library internals. The `status_cli` logger already emits structured state transition messages at every phase boundary with nanosecond timestamps. Since we measure *relative* differences between protocols, debug logging overhead applies equally to all modes and does not affect comparison validity.

**Alternative considered:** Modifying pvxs to expose a `ConnectionTimings` struct via the `Connected` event. Rejected because it requires public API changes and is unnecessary when debug logs already provide the needed phase boundaries.

### D10: Relative comparison table output

**Decision:** After all phase timing benchmarks complete, pvxperf emits a summary table to stderr showing each phase with absolute mean times and percentage overhead relative to PVA baseline. Only PVA, SPVA, and SPVA_CERTMON are compared. PVA is always the baseline.

Example output (real measured numbers, mean of 5 iterations on loopback):
```
=== Connection Phase Timing (mean of 5 iterations) ===
Phase             PVA (baseline)      SPVA                SPVA_CERTMON        
search            1.0 ms              1.0 ms (+7%)        2.7 ms (+185%)      
tcp_connect       0.1 ms              3.3 ms (+2165%)     13.2 ms (+8886%)    
validation        0.1 ms              0.5 ms (+333%)      1.0 ms (+744%)      
create_channel    0.2 ms              0.3 ms (+33%)       14.0 ms (+5559%)    
total             1.5 ms              5.2 ms (+253%)      30.9 ms (+2007%)    
```

What each SPVA_CERTMON phase measures:

- **search** - slightly higher variance than SPVA because the benchmark client's inner cert-status client is also searching in parallel, adding occasional extra UDP traffic on the same loopback interface.
- **tcp_connect** - TLS handshake including OCSP stapling. The server must fetch the client certificate's status from PVACMS and staple it to the TLS response before completing the handshake. This cross-process round-trip to PVACMS explains the 4x increase over SPVA's pure TLS handshake (~3.3ms).
- **validation** - PVA protocol authentication negotiation. Similar to SPVA; the cert status check that matters for timing happens in `create_channel`, not here.
- **create_channel** - the dominant SPVA_CERTMON overhead (~14ms). After `CONNECTION_VALIDATION`, the client's `Connection::ready` is gated on `context->isTlsReady()` (`clientconn.cpp:563`). Channel creation is deferred until the client's inner cert-status client subscribes to `CERT:STATUS:*`, receives a GOOD response from PVACMS, and `peerStatusCallback(GOOD)` fires, triggering `proceedWithCreatingChannels()`. This entire pipeline runs over a separate plain-PVA connection to PVACMS.
- **total** - ~31ms end-to-end connection time vs ~5ms for SPVA and ~1.5ms for plain PVA.

**Rationale:** Operators care about where TLS/cert overhead comes from - is it the handshake or cert validation? The numbers show that OCSP stapling during the TLS handshake and the post-validation cert-status subscription pipeline each contribute roughly equally (~13ms and ~14ms). Printing to stderr keeps CSV output clean for scripting.

### D11: Distributed mode via `--role` flag

**Decision:** Add `--role` with values `loopback` (default, current behavior), `server`, or `client`. Server mode creates a `SharedPV` for `PVXPERF:BENCH` and a `PVXPERF:READY` PV, binds to `--bind-addr`, and runs until SIGTERM or `--duration` timeout. Client mode connects to `--server-addr`, probes `PVXPERF:READY` before starting (30s timeout), and runs the standard benchmark loop. CA is not supported in distributed mode.

**Rationale:** The `--role` flag cleanly extends the existing CLI while preserving backward compatibility. Server mode prints its listening address so the operator knows where to point the client. CA is excluded because it doesn't use TLS and gateway testing is primarily about measuring security overhead across network hops.

**Alternative considered:** Two separate executables. Rejected because it doubles build complexity and the shared code (payload encoding, counter verification, CSV output) would need to be factored into a library.

### D12: Gateway topology support

**Decision:** pvxperf does NOT manage the gateway. `--print-gateway-config` generates a starter PVAGW v2 JSON config (plus minimal `gateway.acf` and `gateway.pvlist`) based on the in-repo gateway examples at `example/kubernetes/docker/gateway/`. The operator starts PVAGW manually. The client uses `--gateway` to mark the topology column as `gateway` in CSV output.

**Rationale:** PVAGW is an external tool with its own lifecycle. Providing a config template based on the repo's own examples reduces setup friction and ensures the generated config uses current best practices (v2 format, `statusprefix`, `downstream_status` pattern) without creating a fragile coupling between pvxperf and the gateway process.

### D13: Connection phase timing CSV output

**Decision:** Phase timing results use a separate CSV (or separate file if `--phase-output` is specified) with columns:
```
test_type,protocol,iteration,phase,duration_us
```
Where `test_type` is `connection_phase`, `protocol` is `PVA|SPVA|SPVA_CERTMON`, `iteration` is 1..N, `phase` is `search|tcp_connect|validation|create_channel|total`, and `duration_us` is microseconds.

**Rationale:** Per-iteration data enables statistical analysis (stddev, percentiles) while the stderr summary shows the mean. A separate CSV section avoids breaking existing throughput CSV consumers.

### D14: Throughput CSV extended with topology column

**Decision:** Add a `topology` column to the throughput CSV with values `loopback` (default, in-process), `direct` (client/server, no gateway), or `gateway` (client/gateway/server). The column is always present.

**Rationale:** Allows comparing the same protocol's throughput across different deployment topologies in a single CSV file.

### D15: Throughput benchmark variance via multiple iterations

**Decision:** `--throughput-iterations <N>` (default 5) runs N independent measurement cycles per data point. Each iteration is a full connect → warm-up → measure → disconnect cycle. The CSV emits one row per iteration (with an `iteration` column). After all iterations complete, a stderr summary shows mean, stddev, min, and max across iterations. When `--throughput-iterations` is 1, the `iteration` column is still present (value `1`) for schema consistency.

**Rationale:** Distributed topologies introduce real network jitter, making single-run numbers unreliable. Multiple independent iterations provide mean and variance so operators can assess measurement confidence. Sub-window statistics within a single connection were rejected because TCP congestion state and TLS session state carry over between windows, making them non-independent.

### D16: PVA queue depth (removed - using PVXS default)

**Decision:** All PVA/SPVA/SPVA_CERTMON monitor subscriptions use the PVXS default `queueSize` of 4. No dynamic queue scaling.

**Rationale:** Experiments with queue depths of 4, 144, and 288 - including a subscriber-aware scaling formula - showed that queue depth has **no effect on the TLS/PVA throughput ratio**. The TLS overhead comes from the write path (per-message TLS record framing), not the application-layer buffer. The adaptive rate-finding methodology eliminates flooding artifacts that previously made queue depth seem relevant. With adaptive discovery, the server pumps at exactly the sustainable rate, so queue overflow is naturally avoided regardless of queue size.

### D17: SPVA_CERTMON port architecture and inner client discovery

**Decision:** Two modes of PVACMS discovery are supported, controlled by a `cms_udp_port` parameter threaded through `waitForPvacms()`, `runPvaBenchmark()`, and `runPvaPhaseTiming()`:

- **`--setup-cms`** (`cms_udp_port = kPvacmsUdpPort = 15076`): PVACMS runs on fixed non-default ports (UDP 15076, TCP 15075, TLS 15076). The benchmark server uses `loopbackServerConfig(kPvacmsUdpPort)` which injects `127.0.0.1:15076` into `beaconDestinations`. `waitForPvacms()` overrides `udp_port` and `addressList` to search on `127.0.0.1:15076`.

- **`--external-cms`** (`cms_udp_port = 0`): PVACMS is already running and reachable via standard EPICS environment variables (`EPICS_PVA_ADDR_LIST`, `EPICS_PVA_BROADCAST_PORT`, etc.). The benchmark server uses `server::Config::fromEnv()` instead of `loopbackServerConfig()`, so the inner cert-status client inherits the user's environment and discovers PVACMS normally. `waitForPvacms()` uses `client::Config::fromEnv()` without overriding ports or addresses.

**Port layout:**

| Component | UDP port | TCP port | TLS port |
|-----------|----------|----------|----------|
| PVACMS child process | 15076 (fixed) | 15075 (fixed) | 15076 (fixed) |
| Benchmark server | ephemeral | ephemeral | 5076 (default) |
| Benchmark client | derived from `server.clientConfig()` | | |

PVACMS ports are set via env vars in the fork/exec: `EPICS_PVAS_BROADCAST_PORT=15076`, `EPICS_PVAS_SERVER_PORT=15075`, `EPICS_PVAS_TLS_PORT=15076`.

**Inner cert-status client architecture:**

When pvxs builds a TLS server or client with `disableStatusCheck(false)`, it internally creates a plain-PVA "inner client" for cert status monitoring. The inner client config is derived from the outer config - you cannot give it a separate address list:

- **Server-side inner client** (`server.cpp:559`): `auto inner_conf = clientConfig(effective);` - maps `beaconDestinations` to `addressList`, inherits `udp_port`. Has `tls_disabled = true` (talks plain PVA to PVACMS).
- **Client-side inner client** (`client.cpp:583`): `auto innerConf = effective;` - direct copy of the benchmark client's effective config. Also has `tls_disabled = true`.

Both inner clients need to find PVACMS. Because their configs are derived from the outer configs, the only way to give them PVACMS's address is to include it in the outer config's address list.

**Discovery flow:**

1. `loopbackServerConfig(kPvacmsUdpPort=15076)` sets `beaconDestinations = ["127.0.0.1", "127.0.0.1:15076"]`.
2. After `server.build()`, the effective config has resolved an ephemeral `udp_port` (e.g. 42000). Beacon destinations remain `"127.0.0.1"` (no port, uses ephemeral) and `"127.0.0.1:15076"` (explicit).
3. The server's inner cert-status client gets `addressList = beaconDestinations`. It searches on both the ephemeral port (finds nothing useful) and 15076 (finds PVACMS). PVACMS responds and the inner client subscribes to `CERT:STATUS:*`.
4. `server.clientConfig()` produces the benchmark client config with the same `addressList`. `"127.0.0.1"` uses `udp_port` (ephemeral) as default, so it finds the benchmark server. `"127.0.0.1:15076"` sends searches to PVACMS, which ignores them (PVACMS doesn't serve `PVXPERF:*` PVs).
5. The benchmark client's inner cert-status client copies the benchmark client's effective config, so it also searches on 15076 and finds PVACMS.

The extra search traffic from the benchmark client to PVACMS is harmless. PVACMS simply doesn't respond to `PVXPERF:*` searches. You can't strip the PVACMS address from the benchmark client config without also breaking the client's inner cert-status client, which inherits the same config and needs that address to find PVACMS.

**TLS keychain loading:**

All keychain configuration uses direct struct assignment (`config.tls_keychain_file = keychain`), not environment variables. Using `setenv("EPICS_PVAS_TLS_KEYCHAIN", ...)` doesn't work because the config struct is already constructed before the env var would be read. The `authnstd` child process uses env vars correctly because it reads them fresh via `Config::fromEnv()` - that's a different code path.

**Rationale:** Fixed non-default ports for PVACMS avoid collisions with production services (5075/5076) while keeping all benchmark traffic on loopback. The `beaconDestinations` injection is the only mechanism available to route inner client discovery to a specific port without modifying pvxs internals.

**Alternative considered:** Patching pvxs to accept a separate address list for the inner cert-status client. Rejected as out of scope - the inner client config derivation is an implementation detail of pvxs, and the injection approach works without any pvxs changes.

### D18: Phase timing log filtering for SPVA_CERTMON

**Decision:** `phaseTimingListener()` filters pvxs debug log messages to exclude transitions from inner cert-status clients, using two complementary mechanisms: PV name filtering and port-based filtering.

**The problem:** In SPVA_CERTMON, three entities produce `pvxs.st.cli` log transitions:
1. The benchmark server's inner cert-status client (subscribes to `CERT:STATUS:*` on PVACMS)
2. The benchmark client's inner cert-status client (same)
3. The benchmark client itself (subscribes to `PVXPERF:PHASE`)

Without filtering, transitions from the inner clients contaminate phase timing measurements.

**Filtering strategy:**

1. **PV name filtering** - `Channel::state` messages include the PV name (e.g. `PVXPERF:PHASE`). The filter requires `PVXPERF:` in the message for `Connecting` and `Active` transitions. Inner clients subscribe to `CERT:STATUS:*` PVs, which don't match, so their channel transitions are excluded.

2. **Port-based whitelist filtering** - `ConnBase::state` messages (`Connected`, `Validated`) include the peer address (e.g. `127.0.0.1:42000`). After `server.start()`, the filter records the benchmark server's actual TCP and TLS ports from `server.config().tcp_port` / `server.config().tls_port`. Only messages whose `peerName` contains one of these known server port strings are accepted. Inner cert-status clients connect to PVACMS on different ports, so their connection transitions are rejected. This whitelist approach works for both `--setup-cms` (where PVACMS ports are known constants) and `--external-cms` (where PVACMS ports are unknown and a blacklist would be impossible).

**pvxs debug log modification:**

The `ConnBase::state = Connected` message in `clientconn.cpp:354` originally logged an opaque pointer (`%p`, `context.get()`) which contained no port information. This was changed to log `peerName.c_str()` (`%s`) so the port-based filter can distinguish benchmark connections (ephemeral port) from PVACMS connections (port 15075). The `Disconnected` message at line 188 received the same treatment. Only debug-level messages were modified - no behavior change, no API change.

**Server inner client settling:**

A 500ms sleep followed by `errlogFlush()` is inserted after `server.start()` for SPVA_CERTMON. This lets the server's inner cert-status client finish its initial connection to PVACMS before phase timing capture begins. Without this pause, the server's inner client transitions appear in the log during the first iteration and can skew the `tcp_connect` timestamp. The benchmark client's inner cert-status client starts later (at `cconfig.build()`) but its transitions are filtered by port, so no settling delay is needed for it.

**Search tick messages:**

`Search tick` messages don't include PV names or ports. They're used only for the initial `searching` timestamp - the first occurrence wins and subsequent ticks are ignored. Extra search ticks from inner clients don't affect timing because `searching` is recorded only once per iteration.

**Rationale:** Two filtering mechanisms are needed because different log message types carry different identifying information. PV name filtering handles channel-level transitions; port filtering handles connection-level transitions. Together they cleanly separate benchmark client activity from inner client activity without requiring any changes to pvxs logging infrastructure beyond the one-line `peerName` substitution.

**Alternative considered:** Disabling the inner cert-status clients entirely during phase timing. Rejected because the whole point of SPVA_CERTMON is to measure the overhead of real cert status monitoring, including the inner client's connection to PVACMS.

**Alternative considered:** Using a separate logger name for inner clients. Rejected because pvxs doesn't distinguish inner clients from outer clients in its logger hierarchy - both use `pvxs.st.cli`.

## Risks / Trade-offs

- **[CA IOC in-process complexity]** → Embedding a full IOC requires `dbLoadDatabase`, `dbLoadRecords`, `iocInit` which pull in the EPICS database layer. Mitigation: Keep IOC setup minimal (single waveform record), teardown via `iocShutdown`. If linking proves problematic, CA mode can be made optional via a build flag.
- **[PVACMS child-process management]** → Launching and managing a real PVACMS as a child process adds complexity (startup wait, health-check, shutdown). Mitigation: Use a simple readiness probe (attempt `client.get("CERT:ROOT:*")` with retry) and SIGTERM for cleanup. Wrap in RAII so PVACMS is always cleaned up even on exceptions. Provide `--external-cms` escape hatch for users who prefer manual CMS management.
- **[PVACMS adds separate-process overhead to SPVA_CERTMON]** → Unlike PVA/SPVA where everything is in-process, SPVA_CERTMON has the CMS in a separate process, adding real IPC overhead. This is actually desirable - it matches the production deployment topology where CMS is a separate service. The benchmark captures real-world cert monitoring cost.
- **[Certificate infrastructure bootstrapping]** → SPVA/SPVA_CERTMON modes need keychains, and PVACMS needs a CA keychain + DB + ACF. Mitigation: PVACMS self-initialises everything on first start. `--setup-cms` creates a temp dir, starts PVACMS with `--certs-dont-require-approval`, then provisions server/client keychains via `authnstd`. No external dependencies needed.
- **[Existing PVACMS on the network]** → If another PVACMS is already running on the same broadcast domain, PVA clients could discover it instead of the benchmark's own PVACMS, causing false results. Mitigation: (1) Bind the benchmark PVACMS, benchmark server, and benchmark client all to loopback (`127.0.0.1`) on ephemeral/non-standard ports. Since cert status monitoring respects the client/server config's interface and port settings, this isolates all benchmark traffic from the production network. (2) Document prominently (help text + source header) that pvxperf should be run on a network with no other active PVACMS as an additional safety measure.
- **[Measurement noise]** → In-process server/client share CPU; PVACMS adds a third process for SPVA_CERTMON. Mitigation: The goal is comparative (same hardware, same conditions). The PVACMS process overhead is real production overhead and should be included in the measurement.
- **[Large payloads may cause memory pressure]** → 1MB+ arrays at high concurrency. Mitigation: Cap max payload at 10MB, pre-allocate buffers.
- **[Debug log parsing fragility]** → Phase timing relies on parsing pvxs debug log message format strings, which could change between pvxs versions. Mitigation: Use the structured `status_cli` logger format which is stable across pvxs versions. Add regression tests that verify expected log markers are present.
- **[Debug overhead on timing]** → Debug logging adds overhead to all protocol modes during phase timing. Mitigation: Only two loggers are set to DEBUG; all others remain at default level. Since we measure relative differences, any remaining overhead applies equally and does not affect comparisons.
- **[Connection timing variance]** → UDP search has inherent variance from multicast timing. Mitigation: Run 50+ iterations (configurable via `--phase-iterations`) and report mean and stddev.
- **[Distributed mode coordination]** → Server and client must be started manually in the right order. Mitigation: Server prints its listening address and serves `PVXPERF:READY`; client probes with a 30s timeout. Help text documents the startup sequence.
- **[Gateway not managed]** → Operator must configure and start PVAGW manually. Mitigation: `--print-gateway-config` generates a working config template based on in-repo examples, reducing setup friction.
- **[CSV schema change]** → Adding `topology` and `iteration` columns to throughput CSV. Mitigation: Both columns are always present for schema consistency. `iteration` defaults to `1` when `--throughput-iterations` is not specified.
- **[PVACMS port collision]** → The PVACMS child process uses fixed ports 15075/15076, which could collide with other services already bound to those ports. Mitigation: Non-default ports were chosen specifically to avoid collision with production PVA (5075/5076). All benchmark traffic runs on loopback only, so the exposure is limited to the local machine.
- **[Inner client config coupling]** → The inner cert-status client's config is derived from the outer config and cannot be configured independently. This means the benchmark client's search destinations include the PVACMS port (15076), sending search traffic to PVACMS for `PVXPERF:*` PVs. Mitigation: The extra search traffic is harmless - PVACMS doesn't serve benchmark PVs and simply ignores those searches. Stripping the PVACMS address from the benchmark client config is not possible without also breaking the client's inner cert-status client, which needs that address to find PVACMS.
