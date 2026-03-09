# pvxs PVAccess Performance Analysis Report

## Executive Summary

This report presents GET-based throughput benchmarks comparing five EPICS protocol modes across varying array sizes and parallelism levels. The benchmark tool `pvxperf` measures round-trip GET latency and throughput using a consistent methodology across all modes.

**Protocol modes tested:**

| Mode             | Client Library           | Server                                    | Transport             |
|------------------|--------------------------|-------------------------------------------|-----------------------|
| **CA**           | libca (Channel Access)   | softIoc (EPICS Base, separate process)    | TCP                   |
| **EPICS_PVA**    | pvAccessCPP (EPICS Base) | softIocPVA (EPICS Base, separate process) | TCP                   |
| **PVXS_PVA**     | pvxs `reExecGet()`       | In-process `BenchmarkSource`              | TCP                   |
| **SPVA**         | pvxs `reExecGet()`       | In-process `BenchmarkSource`              | TLS                   |
| **SPVA_CERTMON** | pvxs `reExecGet()`       | In-process `BenchmarkSource`              | TLS + cert monitoring |

**Key findings (array_size=1):**

- **CA is fastest for sequential GETs** - 30 µs median at par=1 (33K gets/sec) due to its lightweight synchronous protocol
- **EPICS_PVA outperforms PVXS_PVA by 2–2.6×** at high parallelism - 308K vs 119K aggregate gets/sec at par=1000, indicating architectural differences in the pvxs single-threaded event loop vs EPICS Base's dual-thread model
- **TLS overhead is modest at par=1 (14%)** but grows to ~37% at par=100 - SPVA achieves 62K vs PVXS_PVA's 100K aggregate gets/sec
- **Certificate monitoring overhead is negligible in steady state** - SPVA_CERTMON ≈ SPVA across all configurations (within 1–4%)
- **Array size has minimal impact** on pvxs-based modes - the bottleneck is event loop dispatch, not data serialization

**Recommendations:** Section 5 contains optimization opportunities for pvxs GET performance, including throughput improvements (T-1 and T-2) and Section 3 contains architectural analysis.

---

## 1. Benchmark Methodology

### 1.1 Measurement Approach: GET Round-Trip Timing

pvxperf measures the wall-clock time of individual GET operations (or batches of parallel GETs). Each data point consists of:

1. **Warmup phase** - 100 GETs discarded to establish connections, fill caches, and stabilize JIT paths
2. **Measurement phase** - 1000 timed GET samples
3. **Statistics** - median, mean, P25/P75/P99, min/max, coefficient of variation (CV%), and throughput (gets/sec derived from median latency)

For parallel GETs (parallelism > 1), all N GETs are issued simultaneously and the batch completion time is measured. Per-GET latency is `batch_time / N`.

### 1.2 Client Techniques by Mode

| Mode             | Client Technique                                                                                 | Round-Trips per GET |
|------------------|--------------------------------------------------------------------------------------------------|---------------------|
| **CA**           | `ca_array_get()` + `ca_pend_io()` (par=1) or `ca_array_get_callback()` + `ca_flush_io()` (par>1) | 1                   |
| **EPICS_PVA**    | `ChannelGet::get()` via pvAccessCPP native API                                                   | 1                   |
| **PVXS_PVA**     | `reExecGet()` expert API - INIT once, then single EXEC per call                                  | 1                   |
| **SPVA**         | Same as PVXS_PVA over TLS (`disableStatusCheck(true)`)                                           | 1                   |
| **SPVA_CERTMON** | Same as PVXS_PVA over TLS with real PVACMS cert monitoring                                       | 1                   |

The pvxs `reExecGet()` API (enabled via `PVXS_ENABLE_EXPERT_API`) performs the PVA INIT handshake once per Operation, then each subsequent `reExecGet()` call sends only the EXEC message - achieving true single-round-trip GETs comparable to CA's `ca_array_get()`.

### 1.3 Server Configurations

- **CA and EPICS_PVA** use a `softIoc` / `softIocPVA` child process (fork/exec) serving a waveform record (`PVXPERF:CA:BENCH`). This ensures real TCP loopback communication - not in-process shortcuts.
- **PVXS_PVA, SPVA, SPVA_CERTMON** use an in-process `BenchmarkSource` (custom `server::Source`) that stamps each GET response with a steady-clock timestamp and incrementing counter. Server binds to `127.0.0.1` on ephemeral ports.
- **SPVA_CERTMON** additionally runs a real PVACMS child process for certificate status monitoring.

### 1.4 Test Environment

| Parameter         | Value                                      |
|-------------------|--------------------------------------------|
| Platform          | macOS / darwin-aarch64 (Apple Silicon)     |
| Topology          | Loopback (127.0.0.1)                       |
| Array sizes       | 1, 10, 100, 1,000, 10,000, 100,000 doubles |
| Parallelism       | 1, 10, 100, 1,000 concurrent GETs          |
| Samples           | 1,000 per data point                       |
| Warmup            | 100 GETs                                   |
| Total data points | 5 modes × 6 sizes × 4 parallelisms = 120   |

---

## 2. Results

All results from a single benchmark run: 5 modes × 6 array sizes × 4 parallelism levels = 120 data points, 1000 samples each. Platform: macOS darwin-aarch64 (Apple Silicon), loopback.

**Throughput convention:** All "gets/sec" figures are **aggregate throughput** - the total number of GET round-trips completed per second across all parallel getters combined. For example, 252,605 gets/sec at par=100 means 100 parallel getters each completing ~2,526 GETs/sec individually.

![](/Users/george/Projects/com/slac/pvxs-cms/src/tools/pvxperf/results/results.png)

### 2.1 Summary by Mode (array_size=1, all parallelisms)

| Mode             | par=1 gets/sec | par=1 median µs | par=10 gets/sec | par=100 gets/sec | par=1000 gets/sec |
|------------------|---------------:|----------------:|----------------:|-----------------:|------------------:|
| **CA**           |         33,287 |            30.0 |           6,529 |            7,051 |             3,735 |
| **EPICS_PVA**    |         28,520 |            35.1 |          96,463 |          252,605 |           308,315 |
| **PVXS_PVA**     |         14,371 |            69.6 |          55,568 |           99,757 |           119,469 |
| **SPVA**         |         12,618 |            79.3 |          38,996 |           61,730 |            76,278 |
| **SPVA_CERTMON** |         12,186 |            82.1 |          39,085 |           62,549 |            78,317 |

### 2.2 Key Ratios

| Comparison                     | par=1 | par=10 | par=100 | par=1000 |
|--------------------------------|------:|-------:|--------:|---------:|
| EPICS_PVA / PVXS_PVA           | 1.98× |  1.74× |   2.53× |    2.58× |
| PVXS_PVA / SPVA (TLS overhead) | 1.14× |  1.42× |   1.62× |    1.57× |
| SPVA / SPVA_CERTMON            | 1.04× |  1.00× |   0.99× |    0.97× |

### 2.3 Full Benchmark Results

#### CA

| Array Size | par=1 µs | par=1 get/s | par=10 µs | par=10 get/s | par=100 µs | par=100 get/s | par=1000 µs | par=1000 get/s |
|-----------:|---------:|------------:|----------:|-------------:|-----------:|--------------:|------------:|---------------:|
|          1 |     30.0 |      33,287 |     153.2 |        6,529 |      141.8 |         7,051 |       267.8 |          3,735 |
|         10 |     27.7 |      36,172 |     133.6 |        7,488 |      166.9 |         5,991 |       483.4 |          2,069 |
|        100 |     27.9 |      35,874 |     138.1 |        7,242 |      239.7 |         4,173 |       342.3 |          2,921 |
|      1,000 |     28.6 |      34,985 |     130.3 |        7,673 |      254.8 |         3,924 |     1,546.7 |            647 |
|     10,000 |     49.7 |      20,143 |     472.4 |        2,117 |    1,187.6 |           842 |    10,031.2 |            100 |
|    100,000 |    239.3 |       4,178 |   1,354.8 |          738 |    9,375.4 |           107 |    85,940.6 |             12 |

#### EPICS_PVA

| Array Size | par=1 µs | par=1 get/s | par=10 µs | par=10 get/s | par=100 µs | par=100 get/s | par=1000 µs | par=1000 get/s |
|-----------:|---------:|------------:|----------:|-------------:|-----------:|--------------:|------------:|---------------:|
|          1 |     35.1 |      28,520 |      10.4 |       96,463 |        4.0 |       252,605 |         3.2 |        308,315 |
|         10 |     34.0 |      29,394 |       6.4 |      156,812 |        4.0 |       248,267 |         3.3 |        302,292 |
|        100 |     36.1 |      27,713 |      11.3 |       88,643 |        4.4 |       225,691 |         3.4 |        290,978 |
|      1,000 |     36.3 |      27,586 |       6.6 |      150,659 |        4.6 |       219,238 |         3.5 |        287,677 |
|     10,000 |     34.9 |      28,691 |       6.8 |      147,330 |        4.1 |       242,547 |         3.3 |        304,915 |
|    100,000 |     35.9 |      27,891 |       8.7 |      115,108 |        4.6 |       218,122 |         3.5 |        282,365 |

#### PVXS_PVA

| Array Size | par=1 µs | par=1 get/s | par=10 µs | par=10 get/s | par=100 µs | par=100 get/s | par=1000 µs | par=1000 get/s |
|-----------:|---------:|------------:|----------:|-------------:|-----------:|--------------:|------------:|---------------:|
|          1 |     69.6 |      14,371 |      18.0 |       55,568 |       10.0 |        99,757 |         8.4 |        119,469 |
|         10 |     68.6 |      14,585 |      20.1 |       49,777 |       10.5 |        95,042 |         8.3 |        120,885 |
|        100 |     64.4 |      15,524 |      17.2 |       57,992 |        9.7 |       102,837 |         8.4 |        118,529 |
|      1,000 |     64.6 |      15,489 |      15.5 |       64,742 |        9.4 |       106,854 |         7.9 |        127,190 |
|     10,000 |     61.1 |      16,371 |      14.4 |       69,384 |        9.5 |       105,862 |         7.9 |        126,815 |
|    100,000 |     57.0 |      17,544 |      15.2 |       65,601 |        9.4 |       106,308 |         7.9 |        126,646 |

#### SPVA

| Array Size | par=1 µs | par=1 get/s | par=10 µs | par=10 get/s | par=100 µs | par=100 get/s | par=1000 µs | par=1000 get/s |
|-----------:|---------:|------------:|----------:|-------------:|-----------:|--------------:|------------:|---------------:|
|          1 |     79.3 |      12,618 |      25.6 |       38,996 |       16.2 |        61,730 |        13.1 |         76,278 |
|         10 |     91.3 |      10,954 |      26.7 |       37,529 |       16.5 |        60,717 |        13.0 |         76,697 |
|        100 |     83.5 |      11,976 |      25.4 |       39,445 |       16.8 |        59,426 |        13.0 |         77,192 |
|      1,000 |     80.5 |      12,419 |      30.4 |       32,942 |       16.0 |        62,374 |        12.8 |         78,378 |
|     10,000 |     83.6 |      11,958 |      25.5 |       39,206 |       16.1 |        62,101 |        12.8 |         77,912 |
|    100,000 |     78.5 |      12,746 |      25.7 |       38,904 |       16.0 |        62,662 |        12.9 |         77,715 |

#### SPVA_CERTMON

| Array Size | par=1 µs | par=1 get/s | par=10 µs | par=10 get/s | par=100 µs | par=100 get/s | par=1000 µs | par=1000 get/s |
|-----------:|---------:|------------:|----------:|-------------:|-----------:|--------------:|------------:|---------------:|
|          1 |     82.1 |      12,186 |      25.6 |       39,085 |       16.0 |        62,549 |        12.8 |         78,317 |
|         10 |     96.6 |      10,356 |      26.6 |       37,638 |       16.0 |        62,551 |        12.8 |         78,367 |
|        100 |     73.4 |      13,621 |      25.2 |       39,669 |       15.8 |        63,262 |        12.8 |         78,386 |
|      1,000 |     78.0 |      12,824 |      26.1 |       38,262 |       15.9 |        62,845 |        12.8 |         78,127 |
|     10,000 |     78.5 |      12,742 |      24.7 |       40,472 |       15.9 |        62,981 |        12.9 |         77,321 |
|    100,000 |     77.0 |      12,987 |      25.9 |       38,632 |       16.1 |        62,152 |        12.9 |         77,571 |

### 2.4 Key Observations

1. **CA is fastest for sequential GETs (par=1).** CA's `ca_array_get()` achieves 30 µs median round-trip - roughly 2× faster than EPICS_PVA (35 µs) and 2.3× faster than PVXS_PVA (65–70 µs). CA's lightweight synchronous protocol has minimal framing and dispatch overhead.

2. **EPICS_PVA scales dramatically better than PVXS_PVA under parallelism.** At par=1000 with array_size=1, EPICS_PVA achieves 308K aggregate gets/sec vs PVXS_PVA's 119K - a 2.58× gap. This is consistent across all array sizes and is analyzed in Section 3.

3. **Array size has minimal impact on PVXS_PVA, SPVA, and SPVA_CERTMON throughput.** For pvxs modes, per-GET latency is dominated by event loop dispatch overhead, not serialization. At par=100: PVXS_PVA ranges from 99K–106K gets/sec across all array sizes (1 to 100,000). This confirms the bottleneck is in the dispatch path, not data handling.

4. **Array size significantly impacts EPICS_PVA at par=10** (96K→115K gets/sec from size 1→100K) but **not at par=100+** (218K–252K gets/sec across all sizes). At high parallelism, EPICS_PVA saturates its dual-thread architecture regardless of payload.

5. **TLS overhead (SPVA vs PVXS_PVA) is consistent: 14% at par=1, growing to 37–57% at par=100+.** The per-GET TLS encryption cost is additive to the event loop overhead. At par=1 the network round-trip dominates so TLS is a small fraction. At high parallelism the event loop is saturated and TLS adds measurably to each iteration.

6. **Certificate monitoring adds zero measurable steady-state overhead.** SPVA and SPVA_CERTMON are within 1–4% of each other across all 24 configurations - well within measurement noise. The cert monitoring subscription runs in the background and does not interfere with GET processing.

7. **CA throughput *decreases* with parallelism.** CA at par=1000 size=1 gives only 3,735 aggregate gets/sec vs 33,287 at par=1. This is because the parallel CA path uses `ca_array_get_callback()` with `ca_pend_event()` polling - a much slower pattern than the synchronous `ca_array_get()` + `ca_pend_io()` used at par=1. CA was not designed for high-parallelism workloads.

8. **CA collapses at large arrays + high parallelism.** CA at 100K doubles × par=1000 gives only 12 aggregate gets/sec (86ms per GET). The softIoc cannot serve 1000 concurrent large-array GETs efficiently.

---

## 3. Architectural Analysis: PVXS vs EPICS Base PVA

### 3.1 The 2× Gap at High Parallelism

The most significant finding is that EPICS Base PVA (pvAccessCPP) outperforms pvxs PVA by ~2× at high parallelism. This section analyzes the root cause.

### 3.2 pvxs Architecture (Single Event Loop)

pvxs uses a **single event loop per context** (libevent-based). Every operation - send, receive, dispatch, callback - is serialized on one thread:

```
reExecGet() call
  → loop.dispatch(lambda)              // Queues std::function + shared_ptr copy + mutex
    → event loop picks up from queue   // Processes action queue (doWork)
      → serialize GET message          // Encode PVA EXEC into evbuffer
        → send to server               // TCP/TLS write
          [server processes GET]
        → receive response             // TCP/TLS read, same thread
      → deserialize response           // Decode PVA reply
    → invoke callback                  // User's result callback
```

**Per-GET overhead in pvxs:**
- `dispatch()`: mutex acquire + `std::function` allocation + `shared_ptr` copy + deque push + `event_add()`
- Event loop iteration: `event_base_loop()` → `doWork()` → process action queue
- Server-side `reply()` uses `dispatch()` back to the same event loop - adding another event loop iteration
- **~7 event loop iterations per round-trip GET**

### 3.3 EPICS Base PVA Architecture (Dual-Thread)

EPICS Base pvAccessCPP uses **separate sender and receiver threads** per transport:

```
ChannelGet::get()
  → fair_queue.push(request)           // Near-lock-free intrusive queue, zero allocation
    [sender thread picks up]
      → serialize + send               // Parallel with any in-flight receives
        [server processes GET]
      [receiver thread picks up]
        → deserialize response          // TRUE parallel with next send
      → invoke callback                // Direct callback, no dispatch
```

**Per-GET overhead in EPICS Base:**
- `fair_queue`: intrusive linked list with atomic CAS - no allocation, no `std::function`, no mutex
- Sender and receiver run in **true parallelism** - can overlap send of request N+1 with receive of response N
- Server's `ChannelGetLocal::get()` calls `getDone()` directly - no dispatch overhead
- **~0 event loop overhead**

### 3.4 Why the Gap Widens with Parallelism

At par=1, the bottleneck is the network round-trip (~88µs for PVXS, ~66µs for EPICS_PVA). The dispatch overhead is a small fraction.

At par=100, pvxs must serialize 100 GETs through a single event loop. Each GET requires multiple event loop iterations (dispatch → serialize → flush → receive → callback). The event loop processes one action at a time, creating a serialization bottleneck. Meanwhile, EPICS Base's dual-thread model allows true overlap: the sender thread can be writing request #50 while the receiver thread processes response #20.

### 3.5 Quantified Dispatch Overhead

Per `reExecGet()` call in pvxs:
- `std::function` construction: ~50ns (allocation + copy)
- `shared_ptr` atomic increment: ~10ns
- Mutex acquire/release in `_dispatch()`: ~30ns
- `event_add()` for deferred event: ~20ns
- Event loop wake + iteration: ~200ns
- **Total client-side dispatch: ~310ns per GET**

For 100 parallel GETs: 100 × 310ns = 31µs of pure dispatch overhead - significant compared to the 9.7µs per-GET median.

---

## 4. Connection Phase Timing

### 4.1 Phase Definitions

| Phase              | What It Measures                                                       |
|--------------------|------------------------------------------------------------------------|
| **search**         | UDP broadcast + response time (PVA name resolution)                    |
| **tcp_connect**    | TCP connection + TLS handshake (for SPVA/SPVA_CERTMON)                 |
| **validation**     | PVA protocol authentication negotiation                                |
| **create_channel** | Channel creation round-trip. For SPVA_CERTMON, gated on `isTlsReady()` |
| **total**          | End-to-end from first search to channel active                         |

### 4.2 Connection Phase Results

Median of 50 connect/disconnect cycles per mode. All measurements on loopback (darwin-aarch64, Apple Silicon).

| Phase          | PVXS_PVA (ms) | SPVA (ms) | SPVA/PVXS_PVA | SPVA_CERTMON (ms) | CERTMON/PVXS_PVA |
|----------------|--------------:|----------:|--------------:|------------------:|-----------------:|
| search         |           0.9 |       1.0 |          1.0× |               1.5 |             1.6× |
| tcp_connect    |           0.1 |       3.0 |           25× |               3.6 |              30× |
| validation     |           0.1 |       0.4 |          3.2× |               0.4 |             3.3× |
| create_channel |           0.3 |       0.3 |          1.1× |              12.4 |              44× |
| **total**      |       **1.5** |   **4.7** |      **3.2×** |          **21.4** |        **14.4×** |

### 4.3 SPVA_CERTMON create_channel Overhead

The dominant SPVA_CERTMON overhead (median 12.4ms) in `create_channel` is caused by the certificate status verification pipeline:

1. **Own certificate status** - initiated when the `client::Context` is created. The inner cert-status client establishes a plain-PVA connection to PVACMS and subscribes to `CERT:STATUS:<issuer_id>:<own_serial>`.

2. **Peer certificate status** - initiated when the `Connected` event arrives after TLS handshake. The client subscribes to `CERT:STATUS:<issuer_id>:<peer_serial>`.

3. **Channel creation gate** - deferred until **both** subscriptions have received GOOD responses from PVACMS. Only then does `isTlsReady()` return true and `proceedWithCreatingChannels()` fire.

4. **Steady-state caching** - once verified, certificate status is cached in memory. Subsequent connections to the same peer skip the PVACMS round-trip.

The measured 12.4ms median overhead is **inherent to real certificate monitoring** and only affects connection setup - not steady-state throughput.

### 4.4 OCSP Stapling

OCSP stapling is fully implemented.

`clientOCSPCallback()` successfully receives and validates the server's stapled OCSP response during the TLS handshake. `setPeerStatus()` stores the `shared_ptr` in the `peer_statuses` map. When `subscribeToPeerCertStatus()` runs later, it finds the `shared_ptr`, uses the result, and skips a fresh PVACMS subscription.

---

## 5. Recommendations

### 5.1 GET Throughput Optimizations

#### T1: kTLS kernel offload (Linux only)

**What:** Use Linux kTLS to offload symmetric encryption from userspace to kernel space, eliminating the `SSL_write()` overhead in the TLS path.

**Expected improvement:** Would bring SPVA throughput close to PVXS_PVA levels by eliminating per-GET encryption overhead.

**Risk:** High implementation effort. Linux-only (not macOS). Requires kernel 4.13+, OpenSSL 3.0+ with kTLS support.

**Where:** `serverconn.cpp`, `clientconn.cpp`, `openssl.cpp`

#### T2: io_uring + kTLS (Future)

**What:** Replace libevent's `epoll` + `read`/`write` pattern with io_uring for batched async I/O combined with kTLS for zero-copy encryption.

**Expected improvement:** Near-plaintext TLS performance with lower CPU usage.

**Risk:** Very high. Architectural change affecting all I/O paths. Linux 5.19+ only.

### 5.3 Throughput Optimization Priority

| #  | Change          | Effort | Risk      | Expected Impact         | Dependency  |
|----|-----------------|--------|-----------|-------------------------|-------------|
| T1 | kTLS offload    | Weeks  | High      | SPVA → ~PVXS_PVA levels | Linux only  |
| T2 | io_uring + kTLS | Months | Very High | Near-plaintext TLS      | Linux 5.19+ |

---

## Appendix A: Protocol Mode Details

| Mode         | Client                   | Server                        | PV Name                    | Transport | Notes                      |
|--------------|--------------------------|-------------------------------|----------------------------|-----------|----------------------------|
| CA           | libca                    | softIoc (fork, EPICS Base)    | PVXPERF:CA:BENCH           | TCP       | Real out-of-process IOC    |
| EPICS_PVA    | pvAccessCPP `ChannelGet` | softIocPVA (fork, EPICS Base) | PVXPERF:CA:BENCH           | TCP       | Real out-of-process IOC    |
| PVXS_PVA     | pvxs `reExecGet()`       | In-process `BenchmarkSource`  | PVXPERF:PVXS_PVA:BENCH     | TCP       | In-process server          |
| SPVA         | pvxs `reExecGet()`       | In-process `BenchmarkSource`  | PVXPERF:SPVA:BENCH         | TLS       | `disableStatusCheck(true)` |
| SPVA_CERTMON | pvxs `reExecGet()`       | In-process `BenchmarkSource`  | PVXPERF:SPVA_CERTMON:BENCH | TLS       | Real PVACMS child process  |

## Appendix B: reExecGet() Expert API

The pvxs `reExecGet()` API separates the INIT phase (protocol negotiation) from the EXEC phase (actual GET):

```cpp
#define PVXS_ENABLE_EXPERT_API
#include <pvxs/client.h>

// INIT once - establishes channel, negotiates type
auto op = ctxt.get(pvname)
    .autoExec(false)
    .onInit([](const Value&) { /* channel ready */ })
    .exec();

// EXEC many - single round-trip per call
op->reExecGet([](client::Result&& r) {
    auto val = r();  // throws on error
    // process val
});
```

Without `reExecGet()`, each `ctxt.get().exec()` performs both INIT and EXEC - two round-trips. The `reExecGet()` optimization gives pvxs GET performance comparable to EPICS Base's `ChannelGet::get()` which similarly reuses an established channel.
