## pvxperf — EPICS PVAccess GET Benchmark Tool

A single, self-contained host executable that benchmarks GET round-trip latency and throughput across five protocol modes. Measures the performance cost of TLS and certificate monitoring relative to plain PVA.

## Protocol Modes

| Mode | Client | Server | PV Name | TLS | Cert Monitoring |
|------|--------|--------|---------|-----|-----------------|
| **CA** | `ca_array_get()` / `ca_array_get_callback()` | `softIoc` child process | `PVXPERF:CA:BENCH` | N/A | N/A |
| **EPICS_PVA** | pvAccessCPP `ChannelGet::get()` | `softIocPVA` child process | `PVXPERF:CA:BENCH` | No | No |
| **PVXS_PVA** | pvxs `reExecGet()` expert API | In-process `BenchmarkSource` (default) or `softIocPVX` child (`--pvxs-server external`) | `PVXPERF:PVXS_PVA:BENCH` (in-process) / `PVXPERF:PVXS:BENCH` (external) | No | No |
| **SPVA** | pvxs `reExecGet()` over TLS | In-process `BenchmarkSource` (default) or `softIocPVX` child (`--pvxs-server external`) | `PVXPERF:SPVA:BENCH` (in-process) / `PVXPERF:PVXS:BENCH` (external) | Yes | `disableStatusCheck(true)` |
| **SPVA_CERTMON** | pvxs `reExecGet()` over TLS | In-process `BenchmarkSource` (default) or `softIocPVX` child (`--pvxs-server external`) | `PVXPERF:SPVA_CERTMON:BENCH` (in-process) / `PVXPERF:PVXS:BENCH` (external) | Yes | Real PVACMS |

### Server Implementations

- **CA and EPICS_PVA** use external `softIoc` / `softIocPVA` child processes (fork/exec) serving a waveform record. This ensures real TCP loopback communication — not in-process shortcuts.

- **PVXS_PVA, SPVA, SPVA_CERTMON** default to an in-process `BenchmarkSource`. Use `--pvxs-server external` to switch to a `softIocPVX` child process (pvxs-based IOC, supports TLS) for an apples-to-apples comparison with CA/EPICS_PVA. `BenchmarkSource` is — a custom `server::Source` subclass that stamps each GET response with a `benchCounter` (monotonically incrementing `UInt64`) and `benchTimestampNs` (`Int64`, steady_clock nanoseconds). Unlike `SharedPV::buildReadonly()` which clones a cached value, `BenchmarkSource` creates a fresh response for every GET.

### Build-Time IOC Paths

The external IOC executables are located via paths compiled into the binary at build time. These are set in the `Makefile` from EPICS build system variables, which must be defined in `configure/RELEASE.local`:

| Makefile variable | IOC binary | Used by |
|-------------------|-----------|---------|
| `$(EPICS_BASE)/bin/$(EPICS_HOST_ARCH)/softIoc` | `softIoc` | CA |
| `$(EPICS_BASE)/bin/$(EPICS_HOST_ARCH)/softIocPVA` | `softIocPVA` | EPICS_PVA |
| `$(PVXS)/bin/$(EPICS_HOST_ARCH)/softIocPVX` | `softIocPVX` | PVXS_PVA, SPVA, SPVA_CERTMON (external mode) |

Run `pvxperf --help` to see the actual compiled-in paths.

### Payload Structure

The response type extends `NTScalar{Float64A}` with two additional fields:

```
value         : Float64A  (array of doubles, size = --sizes parameter)
benchCounter  : UInt64    (increments per GET, server-side)
benchTimestampNs : Int64  (steady_clock nanoseconds at server reply time)
```

## Measurement Approach

pvxperf measures wall-clock time of individual GET operations (or batches of parallel GETs).

### GET Benchmark

Each data point (mode × array_size × parallelism) consists of:

1. **Connection setup** — client connects to server, performs PVA INIT handshake once per Operation
2. **Warmup phase** — N GETs discarded to stabilise connections, caches, and JIT paths
3. **Measurement phase** — N timed GET samples
4. **Statistics** — median, mean, P25/P75/P99, min/max, coefficient of variation (CV%), and throughput (gets/sec derived from median latency)

The pvxs `reExecGet()` API (enabled via `PVXS_ENABLE_EXPERT_API`) performs the PVA INIT handshake once per Operation, then each subsequent `reExecGet()` call sends only the EXEC message — achieving true single-round-trip GETs comparable to CA's `ca_array_get()`.

For parallel GETs (parallelism > 1), all N Operations are created with `autoExec(false)`, initialised in parallel, then for each sample all N `reExecGet()` calls are issued simultaneously. The batch completion time is measured and per-GET latency is `batch_time / N`.

### Connection Phase Timing

Measures per-phase connection setup overhead by parsing pvxs debug log messages captured via `errlogAddListener()`. Only PVXS_PVA, SPVA, and SPVA_CERTMON are measured — CA and EPICS_PVA are excluded.

Two pvxs loggers are set to DEBUG during phase timing:
- `pvxs.st.cli` — state transition messages (Connecting, Connected, Validated, Active)
- `pvxs.cli.io` — protocol message arrivals (search responses)

Phases measured:

| Phase | Start Event | End Event |
|-------|------------|-----------|
| **search** | First `Search tick` message | `Connecting` state transition |
| **tcp_connect** | `Connecting` | `Connected` (includes TLS handshake for SPVA modes) |
| **validation** | `Connected` | `Validated` (PVA auth negotiation) |
| **create_channel** | `Validated` | `Active` (for SPVA_CERTMON, gated on cert status) |
| **total** | End-to-end from first search to channel active |

Each iteration is a full connect → GET → disconnect cycle with a fresh client and server.

**SPVA_CERTMON filtering:** Inner cert-status clients also produce log messages. These are filtered using: (1) PV name filtering — only `PVXPERF:` messages for channel transitions; (2) port-based whitelist — only the benchmark server's known TCP/TLS ports for connection transitions.

## CLI Options

```
pvxperf [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--modes <list>` | Comma-separated protocol modes: `ca,epics_pva,pvxs_pva,spva,spva_certmon` | all five |
| `--sizes <list>` | Comma-separated array sizes in doubles | `1,10,100,1000,10000,100000` |
| `--parallelism <list>` | Comma-separated parallelism values | `1,10,100,1000` |
| `--samples <N>` | Number of measured GETs per data point | `1000` |
| `--warmup <N>` | Number of warmup GETs to discard | `100` |
| `--output <file>` | CSV output file | stdout |
| `--keychain <path>` | TLS keychain file for SPVA modes | — |
| `--pvxs-server <mode>` | PVXS server: `in-process` (BenchmarkSource) or `external` (softIocPVX child) | `in-process` |
| `--setup-cms` | Auto-bootstrap PVACMS with temp certs | — |
| `--external-cms` | Use already-running PVACMS | — |
| `--cms-db <path>` | Path to existing PVACMS SQLite database | — |
| `--cms-keychain <path>` | Path to existing PVACMS server keychain | — |
| `--cms-acf <path>` | Path to existing PVACMS ACF file | — |
| `--benchmark-phases` | Run connection phase timing after GET benchmark | — |
| `--phase-iterations <N>` | Connect/disconnect cycles for phase timing | `50` |
| `--phase-output <file>` | Separate CSV file for phase timing results | — |
| `-d, --debug` | Enable PVXS debug logging | — |
| `-V, --version` | Print version and exit | — |
| `-v, --verbose` | Verbose mode | — |

### Example: Full benchmark with phase timing

```bash
pvxperf --setup-cms \
    --benchmark-phases \
    --parallelism 1,10,100,1000 \
    --output /tmp/pvxperf_results.csv \
    --phase-output /tmp/pvxperf_phases.csv
```

## CSV Output Schemas

### GET Throughput CSV

One row per sample (iteration) per data point:

```
protocol,array_size,parallelism,iteration,gets_per_second,per_getter_gets_per_second,total_gets,duration_seconds
```

| Column | Description |
|--------|-------------|
| `protocol` | `CA`, `EPICS_PVA`, `PVXS_PVA`, `SPVA`, or `SPVA_CERTMON` |
| `array_size` | Number of doubles in the response array |
| `parallelism` | Number of parallel GET operations |
| `iteration` | Sample number (1..N where N = `--samples`) |
| `gets_per_second` | Aggregate throughput: `parallelism × 1e6 / per_get_us` |
| `per_getter_gets_per_second` | Per-getter throughput: `1e6 / per_get_us` |
| `total_gets` | Number of GETs in this batch (= parallelism) |
| `duration_seconds` | Wall-clock time for this batch |

### Phase Timing CSV

One row per phase per iteration:

```
test_type,protocol,iteration,phase,duration_us
```

| Column | Description |
|--------|-------------|
| `test_type` | Always `connection_phase` |
| `protocol` | `PVXS_PVA`, `SPVA`, or `SPVA_CERTMON` |
| `iteration` | Cycle number (1..N where N = `--phase-iterations`) |
| `phase` | `search`, `tcp_connect`, `validation`, `create_channel`, or `total` |
| `duration_us` | Duration in microseconds |

## Build

pvxperf is built as part of pvxs-cms via the EPICS build system:

```bash
make -C src -j4
```

The resulting binary is installed to `bin/<arch>/pvxperf`.

### Dependencies

- EPICS Base (for `libca`, `softIoc`, `softIocPVA`)
- pvxs (for PVAccess client/server APIs)
- pvxs-cms (for TLS certificate management, `pvacms`, `authnstd`)
- CLI11 (bundled at `bundle/CLI11`)

Link libraries: `pvxs pvAccess pvData ca Com`.

Build flag: `PVXS_ENABLE_EXPERT_API` (set in `src/Makefile`) enables the `reExecGet()` API.

## CMS Bootstrap (`--setup-cms`)

When `--setup-cms` is specified, pvxperf bootstraps the entire PVACMS + certificate infrastructure from scratch:

1. Creates a temp directory (`mkdtemp("pvxperf-cms-XXXXXX")`) for all CMS state
2. Launches `pvacms` as a child process with CLI flags isolating all state:
   ```
   pvacms --certs-dont-require-approval \
     -c <tmpdir>/cert_auth.p12 -d <tmpdir>/certs.db \
     -p <tmpdir>/pvacms.p12 --acf <tmpdir>/pvacms.acf \
     -a <tmpdir>/admin.p12
   ```
3. Waits for PVACMS readiness (probes `CERT:ROOT:*` PV)
4. Provisions server keychain via `authnstd -n pvxperf-server -u server`
5. Provisions client keychain via `authnstd -n pvxperf-client -u client`
6. Runs benchmarks using the provisioned keychains
7. On cleanup: SIGTERM to PVACMS, removes temp directory

**Isolation:** PVACMS runs on fixed non-default ports (UDP 15076, TCP 15075, TLS 15076) to avoid collision with production services. All benchmark traffic is on loopback.

## Network Architecture

### Loopback Server Configuration

PVXS_PVA, SPVA, and SPVA_CERTMON servers use `loopbackServerConfig()` which binds to `127.0.0.1` on ephemeral ports with `auto_beacon=false`. This is intentionally **not** `Config::isolated()` — the pvxs `isolated()` method disables certificate status checking, which would defeat the SPVA_CERTMON benchmark.

### SPVA_CERTMON Inner Client Discovery

When pvxs creates a TLS server/client with `disableStatusCheck(false)`, it internally creates a plain-PVA "inner client" for cert status monitoring. The inner client config is derived from the outer config.

`loopbackServerConfig(kPvacmsUdpPort=15076)` injects `127.0.0.1:15076` into `beaconDestinations`, which propagates to the inner client's `addressList`, allowing it to discover PVACMS.

| Component | UDP | TCP | TLS |
|-----------|-----|-----|-----|
| PVACMS child | 15076 | 15075 | 15076 |
| Benchmark server | ephemeral | ephemeral | ephemeral |

## Out of Scope

- Network-level benchmarking (application-layer only)
- Automated chart generation (CSV feeds external tools like Excel)
- Distributed/multi-host testing
- Gateway topology benchmarking
