# Rate Limiting and Overload Protection

## Executive Summary

We propose adding two complementary overload-protection mechanisms to the
`CERT:CREATE` RPC handler: a token-bucket rate limiter that bounds the sustained
throughput of new certificate creation requests, and a concurrent-request cap
that bounds the number of certificate creation requests in flight simultaneously.

Without these controls, a burst of simultaneous CCR submissions — whether
from a legitimate large-scale deployment event, a misconfigured automation
script, or a deliberate denial-of-service attempt — can saturate the PVACMS
thread pool, exhaust the SQLite connection's write capacity, and make the
service unresponsive for all clients.  Both mechanisms are configurable and
can be disabled independently.

---

## Background and Motivation

### The certificate creation bottleneck

Each Certificate Creation Request (CCR) involves: parsing and validating the
request, an authentication plugin verification step (which may involve a
Kerberos or LDAP round-trip), an RSA or EC key signature operation, one or more
SQLite writes, and a PV status publication.  Under normal operation this takes
tens to hundreds of milliseconds.  A burst of N concurrent requests therefore
takes O(N × single-request latency) to service, during which status monitoring
and cluster SYNC are blocked behind the same SQLite write lock.

### Token bucket rationale

A token bucket is the standard algorithm for smoothing bursty traffic while
permitting short bursts above the sustained rate.  The `burst` parameter allows
legitimate deployment scenarios — such as a rack of IOCs all requesting
certificates simultaneously on restart — while the `rate` parameter prevents
that burst from being sustained indefinitely.

### Concurrent-request cap rationale

The token bucket governs the rate at which requests are admitted.  The
concurrent-request cap governs how many are processed at the same time.  Both
are needed: a fast-arriving burst can pass the token bucket but still pile up
if processing is slow.  The cap ensures that at most N cryptographic operations
and N SQLite writes are in flight simultaneously.

---

## Scope of Changes

### What changes

1. **`src/pvacms/tokenbucket.h`** (new file) — Thread-safe token-bucket class
   with `configure()`, `tryConsume()`, and `secsUntilReady()` methods
2. **`src/pvacms/pvacms.cpp`** — `TokenBucket` instance and atomic in-flight
   counter added to the PVACMS server state; both checked in
   `onCreateCertificate()` after the trust-anchor fast path; rejection response
   includes a `retry_after_secs` hint
3. **`src/pvacms/configcms.h` / `configcms.cpp`** — Three new configuration
   fields
4. **`test/testratelimiting.cpp`** — Self-contained test executable with 21
   test cases

### What does not change

- The CCR PVAccess message format (the rejection is a standard RPC error
  response)
- The trust-anchor fast path (requests from trusted anchors bypass the rate
  limiter, as they did before)
- All other RPC handlers (`CERT:STATUS` approve/revoke/deny)
- Behaviour when `--rate-limit 0` is set (rate limiting disabled entirely)

---

## Detailed Design

### TokenBucket

`TokenBucket` in `src/pvacms/tokenbucket.h` is a self-contained, thread-safe
implementation of the leaky-bucket-as-meter algorithm:

- `rate_` tokens are added per second, up to a maximum of `burst_` tokens
- `tryConsume()` atomically checks and decrements the token count under a mutex
- `secsUntilReady()` returns the fractional seconds until the next token is
  available, used to compute the `retry_after_secs` hint in rejection responses
- Setting `rate_ == 0.0` makes `tryConsume()` always return `true` (disabled)
- Tokens are refilled lazily on each call using `std::chrono::steady_clock`

### Concurrent-request cap

A `std::atomic<uint32_t> ccr_in_flight_` counter is incremented with a
compare-and-swap at the start of `onCreateCertificate()` and decremented via
an RAII guard on all exit paths (normal completion, exception, early rejection).
If the counter is already at `max_concurrent_ccr_`, the request is rejected
immediately without decrementing.

The RAII guard pattern ensures the counter is always decremented, even if an
exception is thrown partway through certificate creation.

### Request admission in `onCreateCertificate()`

```
1. Trust-anchor fast path check (unchanged — returns immediately if trusted)
2. Check ccr_in_flight_ < max_concurrent_ccr_; reject with BUSY if not
3. Increment ccr_in_flight_ (RAII guard)
4. Check rate_limiter_.tryConsume(); reject with THROTTLED if not
5. Proceed with authentication, signing, database write
```

The rate-limiter check is placed after the concurrent-request check so that a
burst that fills the concurrent cap does not consume tokens for requests that
will be rejected anyway.

### Rejection response

Rejected requests receive a structured RPC error with:
- A human-readable message (`"Rate limit exceeded"` or `"Too many concurrent requests"`)
- A `retry_after_secs` field computed from `secsUntilReady()` (for rate-limit
  rejections) or set to a fixed backoff (for concurrent-cap rejections)

This gives well-behaved clients enough information to implement exponential
back-off without polling.

### Configuration

| CLI Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--rate-limit` | `EPICS_PVACMS_RATE_LIMIT` | `10` | Sustained CCR rate (requests/second); `0` disables |
| `--rate-limit-burst` | `EPICS_PVACMS_RATE_LIMIT_BURST` | `50` | Maximum burst above sustained rate |
| `--max-concurrent-ccr` | `EPICS_PVACMS_MAX_CONCURRENT_CCR` | `100` | Maximum simultaneous CCR in-flight |

**Default reasoning:**  10 req/s sustained is sufficient for all normal
deployment scenarios (a 100-IOC facility restarting over several minutes).
A burst of 50 accommodates rack-level restart events.  100 concurrent requests
bounds the worst-case database write pressure.

---

## Security Considerations

Rate limiting is a defence-in-depth measure against denial of service.  It does
not replace authentication: unauthenticated or invalid CCRs are rejected by the
authentication plugin before reaching the rate limiter.

The token bucket is per-process, not per-client.  A single misbehaving client
can therefore consume the entire token budget and starve legitimate clients.  A
per-client rate limiter (keyed on peer identity or IP address) is a possible
future enhancement if this proves necessary in practice.

Setting `--rate-limit 0` disables rate limiting entirely.  This is appropriate
for development environments but should be considered carefully in production.

---

## Migration and Rollback

The rate limiter and concurrent cap are active as soon as the new binary is
deployed.  Existing deployments will see no change in behaviour unless the
request rate exceeds the defaults.

**Rollback** requires reverting `pvacms.cpp` to remove the `TokenBucket` and
in-flight counter.  The `tokenbucket.h` header can be left in place
harmlessly.  No persistent state is involved.

---

## Testing

`test/testratelimiting.cpp` exercises (21 tests):

- `tryConsume()` returns true while tokens are available
- `tryConsume()` returns false when the bucket is empty
- Tokens refill at the correct rate after a measured delay
- `secsUntilReady()` returns a positive value when the bucket is empty
- Setting `rate_ == 0.0` makes all `tryConsume()` calls succeed
- `configure()` resets the bucket state
- Concurrent `tryConsume()` calls from multiple threads do not over-consume
  (thread-safety test)
- CCR rejection returns the expected `retry_after_secs` hint

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `0b380c3` — "Add rate limiting and overload protection for certificate creation" |
| TokenBucket class | `src/pvacms/tokenbucket.h` |
| CCR admission | `src/pvacms/pvacms.cpp` — `onCreateCertificate()` |
| Configuration | `src/pvacms/configcms.h` — `rate_limit`, `rate_limit_burst`, `max_concurrent_ccr` |
| Tests | `test/testratelimiting.cpp` |
