# Startup Self-Tests

## Executive Summary

We propose adding a suite of prerequisite validation checks that run immediately
at PVACMS startup, before the server begins accepting any PVAccess connections.
In the original implementation, failures in critical subsystems — an expired CA
certificate, a mismatched private key, an incompatible database schema — were
either silently ignored or only discovered when a client request triggered the
affected code path, potentially hours or days after deployment.

The self-tests gate service availability on the verification of four invariants:
CA certificate chain validity, CA private key consistency, database schema
version compatibility, and a live OpenSSL sign/verify round-trip.  If any check
fails, PVACMS exits immediately with a descriptive error message and a non-zero
exit code, making the failure visible to process supervisors and deployment
pipelines before any certificate operations are attempted.

This is a strictly additive change with no impact on deployments where all
invariants hold.

---

## Background and Motivation

### Silent misconfiguration risk

PVACMS is typically operated as a long-running service managed by a supervisor
(e.g. `supervisord`).  Misconfigurations that prevent correct operation —
such as a CA keychain whose certificate has expired, or a private key that does
not correspond to the CA certificate after a keychain rotation — are not
detected until the first certificate operation fails.  By that point the
failure may manifest as a cryptic OpenSSL error returned to a client, with no
indication that the root cause is a misconfigured CA.

### Schema version mismatch after rollback

When a newer PVACMS binary is deployed against a database that was last written
by an older version, the schema migration framework (see `SQLITE_HARDENING.md`)
handles the upgrade automatically.  However, the reverse — an older binary
against a database that was migrated to a newer schema — is not safe, because
older code may not know about new tables or columns.  Detecting and rejecting
this case at startup prevents silent data corruption or incorrect behaviour.

### OpenSSL runtime integrity

OpenSSL is a complex library with platform-specific build variations.  A
sign/verify round-trip using the actual CA key confirms that the OpenSSL
algorithms PVACMS relies on are functional in the runtime environment, providing
a smoke-test against unusual build or configuration problems that would
otherwise only surface during certificate issuance.

---

## Scope of Changes

### What changes

1. **`src/pvacms/pvacms.cpp`** — New `runStartupSelfTests()` function called
   from `main()` before the PVAccess server is constructed; each check is a
   separate named function with its own diagnostic output
2. **`src/pvacms/pvacms.h`** — Declaration of `runStartupSelfTests()`

### What does not change

- The command-line interface and environment variables
- The PVAccess wire protocol
- Database initialisation (self-tests run after `initCertsDatabase()` but
  before the server starts accepting connections)
- Behaviour when all checks pass (identical to current startup)

---

## Detailed Design

### Check 1: CA certificate chain validity

Loads the CA certificate from the configured keychain file, builds the
verification chain, and calls `X509_verify_cert()`.  The check fails if:

- The keychain file cannot be opened (wrong path, wrong password)
- The CA certificate is expired (`X509_V_ERR_CERT_HAS_EXPIRED`)
- The chain cannot be verified against the trusted store embedded in the
  keychain

On failure, PVACMS logs the OpenSSL verification error string and exits with
code 1.  The error message names the keychain file and the specific
`X509_V_ERR_*` code so that operators can identify the problem without
inspecting the database or running `pvxcert`.

### Check 2: CA private key consistency

Calls `EVP_PKEY_eq()` (OpenSSL ≥ 3) or `EVP_PKEY_cmp()` (OpenSSL 1.x) to
verify that the private key in the CA keychain corresponds to the public key
in the CA certificate.  This detects keychain rotation errors where the
certificate and key were replaced independently, leaving the keychain in an
inconsistent state.

### Check 3: Database schema version

Queries `SELECT MAX(version) FROM schema_version` and compares the result
against the maximum schema version the current binary knows about.  If the
database version is higher, the binary is too old and exits immediately.  If
the table is absent or the query fails, the database is treated as
pre-versioning (version 0) and the migration framework handles the upgrade in
`initCertsDatabase()` — which runs before `runStartupSelfTests()`.

### Check 4: OpenSSL sign/verify round-trip

Generates a small random buffer (32 bytes), signs it with the CA private key
using SHA-256 and RSA/EC (matching the CA key type), then immediately verifies
the signature using the CA public key.  Failure at either step indicates a
broken OpenSSL build or a key type mismatch that would cause all subsequent
certificate signing operations to fail.

### Failure behaviour

Each failed check calls `log_err_printf` with a message that names the failed
check and the specific error, then calls `exit(1)`.  The exit code is
intentionally non-zero so that process supervisors can detect and report the
failure.  No PVAccess server is created; no PVs are advertised.

When all checks pass, a single `log_info_printf` message is emitted:
`"Startup self-tests passed"`.

---

## Security Considerations

The self-tests load the CA keychain (which contains the CA private key) earlier
in the startup sequence than would otherwise be necessary.  This is not a new
exposure: the CA private key is loaded unconditionally during normal startup for
certificate signing.  The self-tests do not leave the key material in any
additional locations.

---

## Migration and Rollback

The self-tests are transparent to deployments where all invariants hold.  A
deployment that was previously operating with a misconfigured CA will begin
failing at startup after this change is applied — this is the intended
behaviour: the misconfiguration was always fatal, but was previously silent.

**Rollback** requires removing the `runStartupSelfTests()` call from `main()`.
This is a one-line change and does not affect any persistent state.

---

## Testing

`runStartupSelfTests()` is exercised indirectly by the existing integration
test suite: any test that starts PVACMS with a valid configuration exercises
the pass path.  The individual check functions are unit-tested by constructing
deliberately broken inputs (expired certificate, mismatched key, wrong schema
version) and asserting that the appropriate exception or error is produced.

---

## References

| Resource | Location |
|---|---|
| Implementation commit | `592321a` — "Add startup self-tests: CA chain, key match, schema version, sign/verify" |
| Primary source | `src/pvacms/pvacms.cpp` — `runStartupSelfTests()` |
| Companion feature | `docs/SQLITE_HARDENING.md` — schema version table |
| OpenSSL `X509_verify_cert` | Certificate chain verification API |
| OpenSSL `EVP_PKEY_eq` | Key consistency check API |
