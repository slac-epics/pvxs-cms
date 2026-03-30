# PVACMS Clustering

## Overview

PVACMS runs as an always-on, auto-scaling cluster using PVAccess (PVA) as the
communication protocol.  Clustering is not optional - every PVACMS instance
participates in a cluster, even if it is the sole node.  All nodes in a cluster
share the same Certificate Authority (CA) identity (`issuer_id`) and
independently serve certificate operations (create, revoke, approve, renew).

### Network Requirements

PVACMS requires **full mesh connectivity** between all cluster nodes.  Every
node must be able to reach every other node's SYNC PV.  Each node subscribes
directly to all peers — data is not relayed through intermediaries.

If node B cannot reach node C, B's subscription to C keeps searching
indefinitely (no crash, no disconnect loop), but B silently misses C's
certificate changes.  There is no transitive data flow: A receiving B's updates
does not cause A to republish them on A's own SYNC PV.

This is the same requirement as Redis Cluster (all nodes must reach all other
nodes on the Cluster Bus) and Cassandra (all nodes must participate in gossip).

The cluster uses two PV channels per cluster:

- **CTRL PV** - One shared PV for the cluster.  Carries the authoritative
  membership list and handles join requests via RPC.
- **SYNC PV** - One per node.  Each node publishes its local certificate
  database state on its own SYNC PV.

## Architecture

### Components

| Component              | File                       | Role                                                                                 |
|------------------------|----------------------------|--------------------------------------------------------------------------------------|
| `ClusterController`    | `clusterctrl.{h,cpp}`      | Manages CTRL PV, processes join RPCs, maintains membership list                      |
| `ClusterSyncPublisher` | `clustersync.{h,cpp}`      | Publishes this node's cert database as signed snapshots on its SYNC PV               |
| `ClusterDiscovery`     | `clusterdiscovery.{h,cpp}` | Discovers existing clusters, subscribes to peer SYNC PVs, handles connect/disconnect |
| `clustertypes`         | `clustertypes.{h,cpp}`     | PVA type definitions, xcode encoding, signing, verification, transition validation   |

### PV Naming

```
CERT:CLUSTER:CTRL:<issuer_id>                    - Cluster control (monitoring)
CERT:CLUSTER:CTRL:<issuer_id>:<joiner_node_id>   - Cluster join discovery
CERT:CLUSTER:SYNC:<issuer_id>:<node_id>          - Per-node sync
```

The prefix `CERT:CLUSTER` is configurable via `--cluster-pv-prefix`.

### Node Identity

Each node derives its `node_id` from the Subject Key Identifier (SKID) of its
PVACMS server certificate - a deterministic, certificate-bound identifier.

## Protocol

### Startup

1. Node initialises its CA, database, and server certificate.
2. It creates a `ClusterSyncPublisher` (its own SYNC PV) and a
   `ClusterController` (the shared CTRL PV).
3. It starts the PVAccess server, initialises itself as a sole-node cluster
   (`initAsSoleNode()`), and publishes an initial SYNC snapshot.
4. **If the CA was freshly created** (no existing CA keychain was found), the
   node skips discovery and remains as the sole-node cluster.  A new CA cannot
   have peers — all cluster members must share the same CA certificate, so
   there is nothing to discover.
5. **If an existing CA was loaded**, the node sends a **join request** via RPC
   to the discovery CTRL PV variant
   (`CERT:CLUSTER:CTRL:<issuer_id>:<own_node_id>`), with a configurable
   timeout (default 10 seconds, `--cluster-discovery-timeout`).  The CTRL PV
   is located using standard PVAccess name resolution — UDP broadcast,
   unicast address lists (`EPICS_PVA_ADDR_LIST`), or TCP name servers
   (`EPICS_PVA_NAME_SERVERS`) — so clusters work across routed networks
   without cluster-specific configuration.  This single RPC both discovers
   whether a cluster exists and joins it in one step.

   **If the join RPC times out** (no existing cluster is serving the CTRL PV):
   - The node remains the sole cluster member it already bootstrapped as.

   **If the join RPC succeeds** (an existing node responds):
   - The joiner validates the signed response (see [Join Protocol](#join-protocol))
     and subscribes to all peer SYNC PVs.

### Join Protocol

The join handshake is a single RPC round-trip on the CTRL PV:

1. **Joiner** constructs a `JoinRequest`:
   - `version_major`, `version_minor`, `version_patch` - the joiner's protocol
     version (semver)
   - `node_id` - its SKID-derived identifier
   - `sync_pv` - the PV name it will publish sync data on
   - `nonce` - 16 bytes of cryptographic randomness (replay protection)
   - `signature` - ECDSA signature over the canonicalized request, using the
     CA private key

2. **Existing node** (whichever serves the CTRL PV) validates the request:
   - Checks `version_major` is compatible (currently must equal 1; requests
     with a different major version are rejected with "Unsupported protocol
     version")
   - Verifies the signature against the CA public key
   - Checks the nonce is present
   - Adds the joiner to the membership list
   - Constructs a `JoinResponse` containing:
      - `version_major`, `version_minor`, `version_patch`, `issuer_id`,
        `timeStamp` (NT `time_t` struct - see [Timestamps](#timestamps))
     - `members` - the full membership list (including the joiner)
     - `nonce` - echoed back from the request
     - `signature` - signed with the CA private key

3. **Joiner** validates the response:
   - Verifies the signature
   - Confirms the `issuer_id` matches
   - Confirms the nonce matches what it sent (anti-replay)
   - Checks the timestamp is within 30 seconds of its own clock
     (anti-relay/stale response)
   - Updates its local membership and subscribes to all peer SYNC PVs

### Sync Protocol

Each node publishes sync updates on its SYNC PV using a **per-subscriber
incremental model**.  The publisher maintains an in-memory update log (bounded
`std::deque<CertUpdate>`, default 10,000 entries) and tracks each subscriber's
position independently.

A sync update contains:

- `node_id` - publisher's identity
- `timeStamp` - wall-clock time of publication (NT `time_t` struct - see
  [Timestamps](#timestamps))
- `sequence` - monotonic `Int64` sequence number
- `update_type` - `Int32`: `0` = incremental, `1` = full snapshot
- `members[]` - the node's current view of cluster membership (each member
  carries `node_id`, `sync_pv`, `version_major`, `version_minor`,
  `version_patch`)
- `certs[]` - changed certificates (incremental) or the full database (snapshot)
- `signature` - ECDSA signature over the encoded payload

**Per-subscriber dispatch:**

- **New subscriber**: receives a full snapshot (`update_type=1`) containing the
  entire certificate database, then streams incremental updates.
- **Up-to-date subscriber**: receives only the certificates that changed since
  its last acknowledged sequence (`update_type=0`).
- **Fallen-behind subscriber**: if a subscriber's position has been evicted
  from the bounded log, it receives a full snapshot to resync.

The publisher uses a custom `server::Source` implementation (`SyncSource`)
instead of `SharedPV` to access per-subscriber `MonitorControlOp` handles.
This enables `tryPost()` for back-pressure and `onHighMark()` callbacks for
flow control (see [Back-Pressure](#back-pressure)).

**When updates are published:**
- After a new certificate is created (CCR processed)
- After a certificate is revoked (admin action)
- After a certificate is approved (admin action)
- After a new member joins the cluster (the existing node publishes its
  database so the joiner receives it)
- At cluster bootstrap (initial snapshot)

**When updates are NOT published:**
- On time-based status transitions (see [Design Decisions](#design-decisions))
- On membership removal (the CTRL PV is updated, but no sync update is sent
  because the departing node's data is already replicated)

### Ingestion

When a node receives a sync update from a peer:

1. **Peer SKID verification** - reject if the peer's identity has not been
   verified via the TLS connection, or if the snapshot `node_id` does not match
   the expected peer.
2. **Signature verification** - reject if the CA public key does not verify the
   signature.
3. **Anti-replay** - reject if the timestamp is older than the global
   high-water mark minus a 5-second clock-skew tolerance.  The high-water mark
   is updated atomically.
4. **Sequence and update type** - read `update_type` and `sequence` fields.
   Track the last received sequence from each peer; log a warning if a gap is
   detected (non-contiguous sequence).
5. **Loop guard** - a flag (`sync_ingestion_in_progress`) prevents a node from
   re-publishing its own snapshot in response to ingesting a peer's update.
6. **Cert-by-cert application** - for each certificate in `certs[]`:
   - If the cert exists locally: apply the update only if
     `isValidStatusTransition()` allows the remote status.  When allowed, all
     fields are overwritten (including `renew_by` and `status_date`).
   - If the cert does not exist locally: insert it.
   - This logic is the same for both incremental (`update_type=0`) and full
     snapshot (`update_type=1`) updates — the difference is only in how many
     certs appear in `certs[]`.
7. **Membership reconciliation** - the update includes the publisher's
   membership view.  The receiver subscribes to any peers it is not yet
   tracking.

### Disconnect and Removal

Each node independently detects peer disconnects via its own PVA subscription.
When a peer's SYNC PV disconnects:

1. The subscription is removed immediately.
2. `removeMember()` is called, which updates the CTRL PV membership list.
3. The `on_membership_changed` callback fires, but no new subscriptions are
   created (the departing node is gone).

There is no grace period or removal timeout.  Every node that was subscribed
to the departing peer independently detects the disconnect and removes it.

### Rejoin

If a previously-disconnected node comes back:

1. Other nodes discover it through membership reconciliation (the rejoining
   node sends a new join request to the CTRL PV).
2. The CTRL PV handler calls `addMember()`, which adds the node back to the
   membership list and publishes a sync snapshot.
3. The `on_membership_changed` callback fires on all nodes, and they subscribe
   to the rejoining node's SYNC PV.
4. The `on_membership_changed` callback fires even if the node is already in
   the membership list (covers the case where a rejoin arrives before the
   disconnect was processed).

## Design Decisions

### Always-on Clustering

Clustering is not opt-in.  A single-node deployment is simply a cluster of one.
This eliminates conditional code paths and ensures the CTRL/SYNC PVs are always
available.

### Protocol Versioning

All cluster messages (CTRL PV, JoinRequest, JoinResponse) carry a semver-style
version as three `uint32` fields: `version_major`, `version_minor`,
`version_patch`.  Currently version `1.0.0`.

**Compatibility rule**: The existing node rejects join requests where
`version_major` does not equal 1.  Minor and patch versions are informational
and do not affect acceptance - this allows rolling upgrades where nodes at
different minor/patch versions coexist freely, while a major version bump
signals a breaking protocol change that requires a coordinated upgrade.

### Timestamps

All cluster messages that carry a timestamp use the EPICS NT `time_t` struct
(`timeStamp`) instead of a flat `Int64`.  The struct has three fields:

| Field              | Type  | Description                                    |
|--------------------|-------|------------------------------------------------|
| `secondsPastEpoch` | Int64 | Seconds since the EPICS epoch (1990-01-01 UTC) |
| `nanoseconds`      | Int32 | Sub-second nanoseconds                         |
| `userTag`          | Int32 | Reserved (always 0)                            |

Helper functions in `clustertypes.{h,cpp}` work directly in the EPICS epoch:

- `setTimeStamp(val)` - writes the current wall-clock time as an EPICS-epoch
  NT `time_t` struct via `epicsTimeGetCurrent()`.
- `getTimeStamp(val)` - reads the `secondsPastEpoch` field and returns an
  EPICS-epoch `int64_t`.

Using NT types ensures interoperability with standard EPICS tooling (e.g.
`pvget`, `pvmonitor`, CSS) which recognise and display `time_t` structs
natively.

### No Sync for Time-Based Status Transitions

Certificate status transitions that are deterministic functions of time are
**not** synced between nodes.  Each node computes them independently from the
same certificate dates stored in its local database:

| Transition                       | Trigger                                  | Synced? |
|----------------------------------|------------------------------------------|---------|
| PENDING → VALID                  | `now >= not_before`                      | No      |
| VALID → PENDING_RENEWAL          | `now >= renew_by`                        | No      |
| VALID → EXPIRED                  | `now >= not_after`                       | No      |
| PENDING_RENEWAL → EXPIRED        | `now >= not_after`                       | No      |
| VALID (renewal_due flag)         | `now >= midpoint(status_date, renew_by)` | No      |
| New cert created                 | CCR processed                            | **Yes** |
| Any → REVOKED                    | Admin action                             | **Yes** |
| PENDING_APPROVAL → VALID/PENDING | Admin approval                           | **Yes** |
| PENDING_RENEWAL → VALID          | Renewal CCR processed                    | **Yes** |
| VALID → VALID                    | Renewal updates `renew_by`               | **Yes** |

This is safe because:
- All nodes have the same `not_before`, `not_after`, and `renew_by` values.
- Small timing differences between nodes are harmless - a client connecting to
  a node that hasn't yet flipped PENDING → VALID will simply retry.
- The `renewal_due` flag is a notification hint, not a status change.

### VALID → VALID Sync for Renewals

When a renewal is processed on one node, the cert status may remain VALID but
the `renew_by` date changes.  The sync snapshot includes all fields, so when a
peer receives a VALID → VALID update, it overwrites `renew_by` and
`status_date`.  This prevents the peer's status monitor from incorrectly
transitioning the cert to PENDING_RENEWAL based on stale dates.

### Immediate Disconnect Removal

When a peer disconnects, it is removed from the cluster immediately - there is
no grace period.  The rationale:

- Every node independently detects disconnects via its own PVA subscription.
  There is no single point of detection that could miss a disconnect.
- A grace period adds complexity (timers, purge logic) with no benefit, because
  a rejoining node goes through the full join protocol regardless.
- The departing node's certificate data is already replicated to all surviving
  nodes, so no data is lost.

### CMS Node Certificate Revocation

CMS server certificates intentionally omit the certificate status extension to
avoid a circular dependency (the CMS cannot verify its own certificate status
without itself running).  Instead, CMS node certificate revocation is handled
as a special case of the normal certificate status transition machinery.

**Detection**: The `ClusterController` maintains a set of node SKIDs derived
from the cluster membership list.  When any certificate transitions to REVOKED
status in the local database — whether from an admin action on this node or
from sync ingestion of a peer's snapshot — the revoked certificate's SKID is
checked against this set.  There is one check, not separate code paths per
origin.

**Peer revocation**: If the revoked certificate's SKID matches a peer CMS
node, that peer's SYNC PV subscription is cancelled, the peer is removed from
the cluster membership, and an error is logged.

**Self revocation**: If the revoked certificate's SKID matches this node's own
SKID, a critical message is logged and graceful shutdown is initiated via
`ServerEv::interrupt()`.

**Startup check**: On startup, after loading the server certificate and
initialising the database, the node queries its own certificate status.  If the
status is REVOKED, the node logs a critical error and refuses to start.

**Operational note**: Revoking a CMS node certificate is an irreversible action
that causes the affected node to shut down.  The node cannot rejoin the cluster
without a new, valid certificate.

## Security and Integrity

### Cryptographic Signing

All cluster messages (sync snapshots, CTRL values, join requests, join
responses) are signed with the Certificate Authority's private key and verified
with its public key.  This ensures:

- Only nodes possessing the CA private key can publish valid sync data or join
  the cluster.
- Tampered snapshots are rejected before any database writes occur.

### Encode/Decode Signing

Each message type is serialized for signing using `pvxs::xcode::encodeFull()`,
which produces a deterministic byte representation of all fields.  Before
encoding, the `signature` field is cleared so it is not included in the signed
data.  The signature covers this encoded form.

This relies on the pvxs xcode API ([PR #118](https://github.com/epics-base/pvxs/pull/118)) for
deterministic serialization.

### Anti-Replay

- **Sync snapshots**: A global high-water mark tracks the newest timestamp seen
  from any peer.  Snapshots with timestamps older than `hwm - 5s` are rejected.
- **Join requests**: The joiner includes a 16-byte cryptographic nonce.  The
  responder echoes it back in the signed response.  The joiner rejects any
  response with a mismatched nonce.
- **Join responses**: The joiner checks that the response timestamp is within
  30 seconds of its own clock.

### Peer Certificate Verification

When a node subscribes to a peer's SYNC PV, it verifies the peer's TLS
certificate identity on connection:

1. On the `Connected` event, the peer's x509 credentials (`issuer_id` and
   `serial`) are extracted from the TLS handshake and cached.
2. The peer's `issuer_id` is verified to match the cluster's own `issuer_id` —
   a mismatch causes immediate disconnection and membership removal.
3. On each received sync snapshot, the `node_id` field is verified to match the
   expected `node_id` (from the subscription).  A mismatch triggers
   `handleDisconnect()` which removes the peer from the membership list and
   cancels the subscription.
4. Snapshots received before the peer's identity has been verified (before the
   `Connected` event) are rejected.

This prevents a compromised node from replaying another node's signed snapshots
over its own connection.  Each node independently performs this verification, so
no explicit sync of membership removals is needed.

### Automatic Rejoin

Any peer disconnection triggers a full rejoin.  The disconnected peer is
evicted (subscription destroyed, removed from membership), all remaining
subscriptions are cleared, and the node re-runs the full join protocol on a
background thread.  This is the same join handshake used at startup — with
nonce, signature verification, ACF enforcement, and version negotiation.

If a cluster is found, fresh subscriptions are created to all members.  If no
cluster is found, the node remains as a sole-node cluster.

Self-eviction is also detected: if a SYNC snapshot from a peer that previously
acknowledged this node no longer includes it, the node triggers a rejoin.  The
detection is per-peer to avoid false eviction from stale snapshots during
initial join.

### Access Control (ACF)

The default ACF file restricts cluster PV access via `UAG(CMS_CLUSTER)`:

- **`UAG(CMS_CLUSTER)`** contains the PVACMS service identity (matching
  `config.pvacms_name`, default `"PVACMS Service"`).
- **`ASG(CLUSTER)`** requires `UAG(CMS_CLUSTER)`, `METHOD(x509)`,
  `AUTHORITY(CMS_AUTH)`, and `PROTOCOL(TLS)` for both READ and WRITE.

The CTRL PV RPC handler enforces CLUSTER ASG rules at runtime using
`SecurityClient.update(as_cluster_mem, ASL1, credentials)` and rejects join
requests from clients that do not satisfy `canWrite()`.

### Sync Loop Prevention

When a node is ingesting a peer's sync update, it sets
`sync_ingestion_in_progress` to true.  Any attempt to publish while this flag
is set is suppressed, preventing A → B → A feedback loops.

## Network Load

### Publish-Subscribe Model

Sync updates are only transmitted when there are active subscribers.  The
`SyncSource` does not send data if no client is monitoring the PV.  In a
cluster of N nodes, each node subscribes to (N-1) peer SYNC PVs.

### Back-Pressure

The sync publisher uses `MonitorControlOp::tryPost()` to send updates to each
subscriber individually.  If `tryPost()` returns false (the subscriber's output
window is full), the update is queued in the subscriber's pending queue.  When
the subscriber acknowledges earlier updates, the `onHighMark()` callback fires
and drains the pending queue.  Watermarks are configured per-subscriber using
`setWatermarks(0, limitQueue)` (matching the pvxs `spam.cpp` pattern).

This ensures no updates are dropped under load — slow subscribers accumulate a
backlog that is delivered in order when they catch up.

### Update Log

The publisher maintains a bounded in-memory `std::deque<CertUpdate>` (default
10,000 entries).  Each entry holds a monotonic sequence number and the
certificate data at the time of the change.  When the log exceeds its bound,
oldest entries are evicted.  Subscribers whose position falls behind the evicted
entries are automatically marked for full resync.

Memory overhead: 10,000 entries × ~200 bytes ≈ 2 MB.

### When Data is Transmitted

Sync snapshots are published only on operator/CCR-driven events:

- Certificate creation
- Certificate revocation
- Certificate approval
- Certificate renewal
- New member join

Membership changes (CTRL PV updates) are lightweight - they contain only the
membership list (node IDs and sync PV names), not the certificate database.

Time-based status transitions do **not** trigger any network traffic.

### Payload Size

Per-cert overhead in a sync update:

| Field       | Type   | Size                                      |
|-------------|--------|-------------------------------------------|
| serial      | int64  | 8 bytes                                   |
| skid        | string | ~12 bytes (8 hex chars + length prefix)   |
| cn          | string | ~20-60 bytes                              |
| o           | string | ~20-40 bytes                              |
| ou          | string | ~20-60 bytes                              |
| c           | string | ~6 bytes (2-char country + length prefix) |
| approved    | int32  | 4 bytes                                   |
| not_before  | int64  | 8 bytes                                   |
| not_after   | int64  | 8 bytes                                   |
| renew_by    | int64  | 8 bytes                                   |
| renewal_due | int32  | 4 bytes                                   |
| status      | int32  | 4 bytes                                   |
| status_date | int64  | 8 bytes                                   |

**Per-cert total: ~130-220 bytes** (varies with string field lengths).

Fixed overhead per update:

| Field         | Size                             |
|---------------|----------------------------------|
| node_id       | ~12 bytes                        |
| timeStamp     | 16 bytes (Int64 + Int32 + Int32) |
| sequence      | 8 bytes                          |
| update_type   | 4 bytes                          |
| members array | ~62 bytes per member             |
| signature     | ~72 bytes (ECDSA P-256)          |

**Incremental updates** (single cert change): ~200-300 bytes total.

**Full snapshot examples:**

| Certs   | Members | Approx payload |
|---------|---------|----------------|
| 100     | 3       | ~17 KB         |
| 1,000   | 3       | ~170 KB        |
| 10,000  | 3       | ~1.7 MB        |
| 100,000 | 3       | ~17 MB         |

With incremental sync, steady-state network traffic is dominated by single-cert
updates (~200 bytes each).  Full snapshots are only sent to new subscribers or
subscribers that fall behind the bounded update log.

## Configuration

| CLI Option                    | Env Var                                  | Default        | Description                                                |
|-------------------------------|------------------------------------------|----------------|------------------------------------------------------------|
| `--cluster-pv-prefix`         | `EPICS_PVACMS_CLUSTER_PV_PREFIX`         | `CERT:CLUSTER` | Prefix for cluster PV names                                |
| `--cluster-discovery-timeout` | `EPICS_PVACMS_CLUSTER_DISCOVERY_TIMEOUT` | `10`           | Seconds to wait for cluster discovery before bootstrapping |

## Source Files

```
src/pvacms/
├── clustertypes.h/.cpp      - PVA type definitions, signing, verification, transition rules
├── clustersync.h/.cpp       - Sync snapshot publishing (SYNC PV)
├── clusterctrl.h/.cpp       - Cluster control, join handling, membership (CTRL PV)
├── clusterdiscovery.h/.cpp  - Discovery, subscription management, snapshot ingestion
└── CLUSTER.md               - This document
test/
└── testcluster.cpp          - Unit and integration tests (119 assertions)
```
