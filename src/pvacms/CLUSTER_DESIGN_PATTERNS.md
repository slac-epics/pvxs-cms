# PVACMS Cluster Design: Industry Pattern Analysis

This document demonstrates that the PVACMS clustering implementation follows
well-established, industry-standard patterns used in production distributed
systems.  Each design choice maps directly to patterns found in systems such as [HashiCorp Consul](https://developer.hashicorp.com/consul/docs/architecture), [Apache Cassandra](https://cassandra.apache.org/doc/latest/cassandra/architecture/), [Redis Cluster](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/), [CockroachDB](https://www.cockroachlabs.com/docs/stable/architecture/overview), [etcd](https://etcd.io/docs/latest/learning/design-learner/), and Kubernetes.

---

## Executive Summary

PVACMS implements an auto-managing, peer-to-peer cluster using PVAccess as
the communication protocol.  The design draws on six foundational patterns
from distributed systems engineering:

| Pattern | Industry Precedent | PVACMS Mechanism |
|---------|--------------------| -----------------|
| Protocol-native discovery | Redis Cluster bus, Cassandra gossip | PVAccess beacon + RPC join |
| Peer-to-peer membership | SWIM protocol (Consul/Serf), Redis gossip | Signed CTRL PV with membership list |
| Subscription-based failure detection | ZooKeeper ephemeral nodes, etcd lease expiry | PVA monitor disconnect events |
| Per-subscriber incremental sync | Cassandra hinted handoff, Kafka consumer offsets | Bounded update log with sequence tracking |
| Deterministic conflict resolution | CRDTs (Riak), LWW-Register (Cassandra), Cassandra TTL expiration | Convergent state machine (sync rules + time-based transitions) |
| Cryptographic message authentication | Consul mTLS, Vault transit encryption, SPIFFE identity | CA-signed cluster messages with anti-replay |

None of these patterns are novel.  Each is a deliberate application of a
technique that has been validated in production at scale across the industry.

---

## 1. Membership and Discovery

### PVACMS Approach

Nodes discover the cluster through a single RPC to the shared CTRL PV.  If the
RPC succeeds, the joiner receives the full membership list.  If it times out
(no existing cluster), the node bootstraps as a sole-node cluster.  The join
protocol carries a cryptographic nonce and CA-signed messages for mutual
authentication.

### Industry Pattern: Gossip-Based Membership (SWIM Protocol)

The [SWIM protocol](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf) (Das et al., 2002) provides the foundation for membership management in Consul, Cassandra, and Redis Cluster.  SWIM uses probabilistic peer probing where each
node periodically selects a random peer to verify liveness, achieving O(1)
per-node message complexity regardless of cluster size.

HashiCorp's [Serf](https://www.serf.io/docs/internals/gossip.html) library extends SWIM with Lamport clocks, full-state synchronization over TCP, and the [Lifeguard](https://arxiv.org/abs/1707.00788) enhancement for adaptive suspicion timeouts.  Consul uses Serf for both LAN gossip (intra-datacenter) and WAN gossip (inter-datacenter).

**Redis Cluster** implements gossip-based membership using its own Cluster Bus
protocol.  Nodes exchange PING/PONG messages carrying node ID, address, hash
slot ownership, and master/replica relationships.  New nodes propagate through
the gossip layer within seconds.

### How PVACMS Aligns

| Aspect                    | SWIM/Gossip                                        | PVACMS                                                                                      |
| ------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Peer discovery            | Seed nodes or service registry (etcd, Consul, DNS) | PVAccess name resolution (broadcast, addr list, name server) + CTRL PV initial members list |
| Join mechanism            | Random peer probing                                | Single RPC to shared CTRL PV                                                                |
| Membership propagation    | Piggybacked on heartbeats                          | Embedded in SYNC snapshots (subscribed per-peer)                                            |
| Membership view           | ✓ Eventually consistent across all nodes           | ✓ Eventually consistent (reconciled via SYNC snapshots)                                     |
| No central coordinator    | ✓ (pure peer-to-peer)                              | ✓ (any node can serve the CTRL PV)                                                          |
| Protocol-native discovery | ✓ (Redis Cluster Bus, Cassandra gossip port)       | ✓ (PVAccess name resolution + beacons)                                                      |
| Self-bootstrapping        | Seed nodes                                         | Timeout-based bootstrap as sole node                                                        |

### Industry Precedent: Protocol-Native Discovery

Using the application protocol for cluster management rather than a separate
control plane is an established pattern:

- **Redis Cluster** uses the RESP protocol + Cluster Bus for application traffic
  AND cluster coordination on a single binary protocol.
- **Cassandra** uses its gossip port for both failure detection and topology
  management.
- **PVAccess** provides name resolution (UDP broadcast, unicast address lists,
  TCP name servers) and server beacons, which PVACMS leverages for cluster
  discovery without any additional infrastructure.

This approach eliminates external dependencies and simplifies deployment — a
property shared by Redis Cluster, Cassandra, and now PVACMS.

### Cluster Identity and Initial Connection

Most distributed systems require explicit configuration to connect a new node
to an existing cluster.  PVACMS does not.

**Redis Cluster** requires an operator to run `CLUSTER MEET <ip> <port>` on a
new node, pointing it at any existing member.  The new node then learns the
full topology through gossip.  Without this manual introduction, a Redis node
has no way to find its cluster.

**Cassandra** requires a `seed_provider` in `cassandra.yaml` listing one or
more known node addresses.  On startup, a new node contacts the seeds to
bootstrap and learn the ring topology.  Seeds must be configured identically
across all nodes.

**PVACMS** requires neither seed lists nor manual introductions.  Cluster
identity is cryptographic: all PVACMS instances sharing the same CA certificate
belong to the same cluster.  The CA's issuer ID (a hash of the CA public key)
is embedded in the CTRL PV name (`CERT:CLUSTER:CTRL:<issuer_id>`).  A node
with a different CA cannot join — the join handshake's signature verification
will reject it.

The CTRL PV is located using standard PVAccess protocol-native discovery (UDP
broadcast, `EPICS_PVA_ADDR_LIST`, or `EPICS_PVA_NAME_SERVERS`).  This means
PVACMS clusters work across routed networks and firewalled subnets with the
same PVAccess configuration that any other PVA client would use — no seed
lists, no manual introductions, no cluster-specific network setup.

| Aspect | Redis Cluster | Cassandra | PVACMS |
|--------|--------------|-----------|--------|
| Initial connection | `CLUSTER MEET` (manual) | Seed list (configured) | PVAccess name resolution (automatic) |
| Cluster identity | Cluster ID (generated) | Cluster name (configured) | CA issuer ID (derived from CA cert) |
| Address knowledge | Must know one peer's IP:port | Must know seed IPs | None required |
| Configuration needed | Yes (`CLUSTER MEET` command) | Yes (`seed_provider`) | None (shared CA keychain is sufficient) |

### Startup Ordering: Pre-Opened CTRL with Self-Join Filter

PVACMS starts the server and opens the CTRL PV **before** discovery, while
eliminating loopback self-join by construction.

The CTRL channel is served by a custom `server::Source` (`ClusterCtrlSource`).
It always claims the base monitoring PV name:

`CERT:CLUSTER:CTRL:<issuer_id>`

Join discovery searches a node-specific variant instead:

`CERT:CLUSTER:CTRL:<issuer_id>:<joiner_node_id>`

The source inspects the trailing `joiner_node_id` and refuses to claim names
whose suffix equals its own node ID.  In other words, each node declines its
own join-discovery search key while still serving every other node's key.

This enables safe pre-open ordering:

```
Instance A: start() → initAsSoleNode() → joinCluster(search ...:A)
Instance B: start() → initAsSoleNode() → joinCluster(search ...:B)
```

- A never claims `...:A`, so A cannot join itself.
- B never claims `...:B`, so B cannot join itself.
- A can claim `...:B`, and B can claim `...:A`, so both can discover each
  other even when they start simultaneously.

The base CTRL PV remains claimable by any node for backward-compatible
monitoring via tools such as `pvget`.

This is analogous to split-brain prevention patterns in distributed systems:
identity-scoped routing keys ensure a node cannot satisfy its own discovery
query, so peer discovery is constrained to remote responders only.

### Scaling Context: Why O(N) Is Appropriate

SWIM's O(1) per-node message complexity is designed for clusters of hundreds or
thousands of nodes (Redis Cluster supports up to 1,000; Cassandra routinely
runs 100+).  PVACMS clusters are expected to have 2–5 nodes — a single CA
does not need hundreds of certificate issuers.

At this scale, PVACMS's full-mesh O(N) subscription model has negligible
overhead:

- **Message count**: each node subscribes to N-1 peers, giving N×(N-1)
  subscription channels total.  For 3 nodes that is 6 channels; for 5 nodes,
  20.
- **Payload size**: incremental SYNC updates are ~200–300 bytes per certificate
  change.  Full snapshots for 1,000 certificates are ~200 KB (see the "Payload Size
  Calculation" section in CLUSTER.md).
- **Per-client queuing**: PVAccess monitors maintain a per-subscriber queue and
  coalesce updates — only data not already delivered is transmitted.  Rapid
  successive changes to the same certificate produce a single queued update,
  not one per change.

The O(1) gossip protocols add significant implementation complexity (protocol
state machines, protocol versioning, protocol-specific failure detectors) that
is justified at scale but unnecessary for a system where N ≤ 5 and the payload
per update fits in a single TCP segment.

---

## 2. Failure Detection

### PVACMS Approach

Each node subscribes to peer SYNC PVs via PVAccess `monitor()`.  Failure is
detected through two complementary mechanisms:

1. **Connection-level disconnect** — TCP connection loss fires a disconnect
   event on the subscription.  This catches clean shutdowns and network
   failures.
2. **Echo-based keepalive** — PVAccess connections include a built-in heartbeat:
   clients send `CMD_ECHO` every ~15 seconds and either peer times out after
   ~40 seconds of inactivity.  This detects hung or unresponsive nodes that
   have not cleanly disconnected (e.g. a process blocked on I/O or stuck in an
   infinite loop).

When either mechanism fires, the node immediately removes the peer from the
membership list — no grace period, no voting.  Every node independently detects
failures via its own subscriptions.

### Industry Patterns

**Heartbeat-Based Detection** is the simplest approach: nodes send periodic
heartbeats and are considered failed after a fixed timeout.  PostgreSQL and
MySQL replication use this model.  The fundamental tradeoff is between
detection speed (short timeout) and false positive rate (long timeout).

[**Phi Accrual Failure Detector**](https://doi.org/10.1109/RELDIS.2004.1353004)
(Hayashibara et al., 2004), used by Cassandra, provides an adaptive approach
that outputs a continuous suspicion level (φ) based on the statistical
distribution of heartbeat inter-arrival times.  Rather than a binary alive/dead
decision, phi accrual adjusts to network conditions automatically.

**SWIM Failure Detection**, used by Consul/Serf, employs direct probing with
indirect verification.  If a direct ping fails, k random peers are asked to
probe the target.  Only if all probes fail is the node marked suspected.  This
achieves constant-time detection regardless of cluster size.

[**ZooKeeper**](https://zookeeper.apache.org/doc/current/zookeeperProgrammers.html) **Ephemeral Nodes** disappear when the client session expires, providing
automatic failure notification to watchers.  This is functionally equivalent
to a subscription that fires on disconnect.

**etcd Lease Expiry** removes keys when their associated lease TTL expires
without renewal, functioning as a server-side heartbeat mechanism.

### How PVACMS Aligns

| Aspect | Industry Pattern | PVACMS |
|--------|-----------------|--------|
| Detection mechanism | Heartbeat + disconnect | PVA echo keepalive (~15s) + TCP disconnect |
| Closest analogue | ZooKeeper ephemeral node watch / etcd lease expiry | PVA subscription lifecycle + echo timeout |
| Detection latency | Bounded by protocol timeout | ~40s for hung nodes; immediate for TCP failures |
| Hung process detection | Heartbeat timeout | PVA echo timeout (no echo response → connection closed) |
| False positive handling | SWIM suspect state / phi threshold | Immediate removal + rejoin protocol |
| Independent detection | ✓ (each node monitors independently) | ✓ (each node has its own subscriptions) |
| No polling overhead | ✓ (event-driven) | ✓ (PVA monitor is push-based; echo is protocol-native) |

PVACMS failure detection combines **heartbeat-based detection** (PVA echo keepalive catches hung processes) with **session-based detection** analogous to **ZooKeeper ephemeral nodes** (subscription disconnect catches crashes and network failures).  The choice of immediate removal (no grace period) follows the [**crash-only design**](https://www.usenix.org/legacy/events/hotos03/tech/full_papers/candea/candea.pdf) principle (Candea & Fox, 2003) — recovery always goes through the full join protocol, eliminating the need for partial-state recovery paths.

### Automatic Rejoin After Eviction

A node that was temporarily unresponsive (e.g. blocked on I/O) may be evicted
by its peers via the echo timeout, but the node itself is still running.  Two
triggers cause the node to re-run the full join protocol on a background
thread:

1. **Any peer disconnect** — `handleDisconnect()` evicts the disconnected
   peer, clears all remaining subscriptions, and re-runs `joinCluster()`.
   No partial recovery, no tracking of individual peer state.

2. **Self-eviction detection** — `reconcileMembers()` receives a SYNC snapshot
   from a peer that previously acknowledged this node (included it in its
   membership list) but no longer does.  The detection is per-peer: a stale
   snapshot from a peer that has never acknowledged us is ignored (this
   prevents false eviction when a newly-joined node receives a snapshot from
   a peer that hasn't processed its join yet).

In both cases the node clears all subscriptions, resets to a sole-node cluster, and re-runs `joinCluster()`.  Fresh subscriptions are created to each member in the join response.  If no cluster is found, the node remains as a sole-node cluster.

This "any disconnect = full rejoin" approach follows the crash-only principle: there is exactly one recovery path (the join protocol), regardless of whether one peer or all peers disconnected.  It avoids partial-state recovery, stale subscription management, and security bypasses from subscription-level reconnection.

A `rejoin_in_progress_` atomic flag prevents concurrent rejoin attempts when
multiple disconnects arrive in quick succession.

### Industry Precedent: Crash-Only Design

The [crash-only](https://www.usenix.org/legacy/events/hotos03/tech/full_papers/candea/candea.pdf) principle (Candea & Fox, 2003) states that systems should only stop via crash and only recover via a defined restart path.  This simplifies the state space by eliminating graceful-shutdown code paths that are rarely tested.

PVACMS applies this principle:
- **Stop = disconnect** (subscription drops, peer removed immediately)
- **Start = full join** (complete join protocol with signature verification)
- **No partial recovery** (rejoining node gets full membership + full snapshot)

This is the same approach used by:
- **Kubernetes** pods (crash → restart → reconcile)
- **CockroachDB** (node gone for 5 minutes → automatic re-replication)
- **Redis Cluster** (master fails → replica election → full resync if needed)

---

## 3. State Synchronization

### PVACMS Approach

Each node publishes its certificate database state on a per-node SYNC PV.  The publisher maintains a bounded in-memory update log (default 10,000 entries) and tracks each subscriber's position independently:

- **New subscribers** receive a full snapshot, then stream incrementally.
- **Up-to-date subscribers** receive only changed certificates.
- **Fallen-behind subscribers** receive a full snapshot to resync.

Updates are dispatched per-subscriber via `MonitorControlOp::tryPost()` with
back-pressure handling through watermarks and `onHighMark()` callbacks.

### Industry Patterns

[**Raft**](https://raft.github.io/raft.pdf) **Log Replication** (Ongaro & Ousterhout, 2014; used by etcd, CockroachDB, Consul) maintains a total-ordered log of all state changes.  The leader replicates log entries to followers, and entries are committed after a majority acknowledge.  This provides strong consistency but requires a leader and quorum.

**Cassandra Hinted Handoff** stores writes destined for unavailable replicas as "hints" on the coordinator.  When the target recovers, hints are replayed. This ensures writes are not lost during transient failures.

[**Kafka**](https://kafka.apache.org/documentation/#design) **Consumer Offsets**
track each consumer's position in a topic partition independently.  New consumers can start from the beginning (full replay) or from the latest offset (incremental).  Fallen-behind consumers can be reset.

**Redis Partial Resynchronization** tracks replication via a monotonic offset. When a replica reconnects, it sends its offset; if the master's replication backlog contains that offset, only the delta is sent.  If the offset has been evicted, a full resync is triggered.

### How PVACMS Aligns

| Aspect | Kafka Offsets / Redis Backlog | PVACMS |
|--------|-------------------------------|--------|
| Per-subscriber position tracking | ✓ (consumer offset / replication offset) | ✓ (per-subscriber sequence number) |
| Bounded in-memory log | ✓ (Kafka retention / Redis replication backlog) | ✓ (bounded deque, default 10,000 entries) |
| Full resync on fallen-behind | ✓ (Kafka earliest offset / Redis full SYNC) | ✓ (full snapshot when evicted from log) |
| Incremental updates | ✓ (Kafka messages / Redis partial PSYNC) | ✓ (SYNC_INCREMENTAL with changed certs only) |
| Monotonic sequence numbers | ✓ (Kafka offset / Redis replication offset) | ✓ (Int64 sequence, strictly incrementing) |
| Back-pressure | ✓ (Kafka consumer lag / Redis output buffer limits) | ✓ (tryPost + pending queue + onHighMark) |

The PVACMS sync model is a direct implementation of the **bounded replication
log with per-subscriber cursor** pattern, identical in structure to Kafka
consumer offsets and Redis partial resynchronization.  The innovation is
delivering this pattern over PVAccess using the per-subscriber
`MonitorControlOp` API rather than a custom TCP protocol.

### Comparison: Why Not Raft?

PVACMS uses eventual consistency rather than Raft consensus.  This is a
deliberate design choice with clear tradeoffs:

| Property | Raft (etcd, CockroachDB) | PVACMS Eventual Consistency |
|----------|--------------------------|----------------------------|
| Write availability during network split | Requires quorum (unavailable in minority) | All nodes continue independently |
| Consistency model | Linearizable (strong) | Eventually consistent with deterministic merge |
| Leader requirement | Yes (single writer) | No (any node can issue certificates) |
| Complexity | High (log replication, snapshotting, membership changes) | Lower (pub-sub with conflict rules) |
| Certificate issuance during network split | Only on majority side | On any reachable node |
| Convergence guarantee | Immediate (after commit) | Eventual (after sync propagation) |

For a certificate authority, **availability** is more important than strong
consistency.  A client that cannot reach the majority of nodes during a network
split should still be able to obtain a certificate from a reachable node.  The
deterministic conflict resolution rules (Section 4) ensure that all nodes
converge to the same state once full mesh connectivity is restored.

**Important**: PVACMS prefers full mesh connectivity but supports partial mesh
via transitive data forwarding (see Section 7).  Each node subscribes directly
to all peers.  When a peer is unreachable, a connected intermediary relays that
peer's data through normal SYNC republish.  During a partial network split,
each node continues issuing certificates independently and cert data propagates
along connected paths — including forwarded paths.  Convergence is guaranteed
once connectivity (direct or forwarded) covers all peers.

This is the same tradeoff made by:
- **Cassandra** (AP system — availability over consistency)
- **Riak** (AP system — always writable, merge on read)
- **DynamoDB** (AP system — eventually consistent by default)

---

## 4. Conflict Resolution

### PVACMS Approach

PVACMS resolves conflicts through a **convergent status transition state
machine** backed by two complementary mechanisms:

1. **Sync transitions** — operator/CCR-driven actions propagated between nodes.
2. **Time-based transitions** — deterministic functions of certificate dates,
   computed independently by each node.

Together, these guarantee that all nodes converge to the same state.

**Sync transitions** are gated by `isValidStatusTransition(local, remote)`:

```
PENDING            → {REVOKED}
PENDING_APPROVAL   → {VALID, PENDING, REVOKED}
VALID              → {REVOKED}     (also VALID→VALID for renewal field updates)
PENDING_RENEWAL    → {VALID, REVOKED}
EXPIRED / REVOKED  → {}            (terminal — reject all remote transitions)
```

**Time-based transitions** are never propagated; every node computes them
from the same stored certificate dates (`not_before`, `not_after`, `renew_by`):

```
PENDING            → VALID              (now >= not_before)
VALID              → PENDING_RENEWAL    (now >= renew_by)
VALID              → EXPIRED            (now >= not_after)
PENDING_RENEWAL    → EXPIRED            (now >= not_after)
```

### Complete Certificate Lifecycle

Combining both mechanisms, the full state graph is:

```
PENDING_APPROVAL
  ├──→ VALID              (synced: approved, now >= not_before)
  ├──→ PENDING            (synced: approved, now <  not_before)
  └──→ REVOKED            (synced)

PENDING
  ├──→ VALID              (time-based: now >= not_before)
  └──→ REVOKED            (synced)

VALID
  ├──→ PENDING_RENEWAL    (time-based: now >= renew_by)
  ├──→ EXPIRED            (time-based: now >= not_after)
  └──→ REVOKED            (synced)

PENDING_RENEWAL
  ├──→ VALID              (synced: renewal processed, renew_by updated)
  ├──→ EXPIRED            (time-based: now >= not_after)
  └──→ REVOKED            (synced)

EXPIRED                   (terminal — no exits)
REVOKED                   (terminal — no exits)
```

Key paths:
- **PENDING_APPROVAL → VALID** (approved and `now >= not_before`, synced)
- **PENDING_APPROVAL → PENDING** (approved but `now < not_before`, synced)
  then **PENDING → VALID** (time-based when `now >= not_before`)
- **PENDING_APPROVAL → REVOKED** (rejected or revoked, synced)
- **PENDING → VALID** (time-based) — not synced, computed locally
- **PENDING → REVOKED** (synced)
- **VALID → PENDING_RENEWAL** (time-based) → **PENDING_RENEWAL → VALID**
  (renewal synced) — the only cycle
- **Any non-terminal → REVOKED** (synced) — always accepted, permanent

### Industry Patterns

[**CRDTs**](https://hal.inria.fr/inria-00555588/document) (Conflict-free Replicated Data Types; Shapiro et al., 2011) provide mathematically guaranteed conflict-free merging through commutative, associative, and idempotent operations over a join-semilattice.  [Riak](https://docs.riak.com/riak/kv/latest/developing/data-types/index.html) implements CRDTs as built-in data types (G-Counters, PN-Counters, OR-Sets, LWW-Registers).

**Last-Writer-Wins Register (LWW-Register)** resolves conflicts by keeping
the value with the highest timestamp.  Cassandra uses this as its default
conflict resolution strategy.

**Raft Log Ordering** avoids conflicts entirely by serializing all writes
through a single leader.  etcd, CockroachDB, and Consul use this approach.

**Vector Clocks** (Amazon Dynamo) track causal relationships between events,
detecting concurrent updates that require application-specific resolution.

### How PVACMS Aligns

PVACMS conflict resolution has **CRDT-like properties** but is not a pure
CRDT in the strict mathematical sense.  Instead, it achieves convergence
through two cooperating mechanisms — sync transitions for operator actions and
time-based transitions for deterministic state evolution — in the same way
that Cassandra achieves convergence through its merge rules *plus* TTL-based
expiration.

**Property 1: Revocation is a terminal absorber.**

REVOKED and EXPIRED accept no incoming transitions.  Once a certificate
reaches either state, it stays there permanently, regardless of what updates
arrive from peers.  This is the strongest convergence guarantee in the system
and the most important from a security perspective.

This is functionally identical to:
- **Cassandra tombstones** — deletes are permanent markers that win over
  concurrent writes.
- **Riak OR-Set removes** — a remove operation wins over a concurrent add.

**Property 2: Sync transitions are idempotent and commutative for revocation.**

If node A revokes a certificate while node B performs any other operation on
it, both nodes converge to REVOKED regardless of message ordering:

```
Node A: PENDING_RENEWAL → VALID     (renewal processed)
Node B: PENDING_RENEWAL → REVOKED   (admin revocation)

Sync A→B: VALID→REVOKED is valid       → B stays REVOKED ✓
Sync B→A: VALID→REVOKED is valid       → A becomes REVOKED ✓
Result: Both converge to REVOKED regardless of sync order
```

This holds for any starting state — REVOKED always wins.

**Property 3: Non-revocation divergence is temporary and safe.**

When two nodes approve the same certificate but reach different states due to
clock differences, they may temporarily diverge.  The divergence is always
resolved by time-based transitions and is harmless in the interim.

*Example: approval with clock skew near `not_before`*

```
Node A: PENDING_APPROVAL → VALID     (approved, A's clock past not_before)
Node B: PENDING_APPROVAL → PENDING   (approved, B's clock not yet at not_before)

Sync A→B: B has PENDING, receives VALID
          isValidStatusTransition(PENDING, VALID) = false (time-based only)
          → rejected, B stays PENDING

Sync B→A: A has VALID, receives PENDING
          isValidStatusTransition(VALID, PENDING) = false
          → rejected, A stays VALID

Temporary divergence: A=VALID, B=PENDING
```

This resolves naturally: node B will compute `PENDING → VALID` locally when
its own clock reaches `not_before`, converging to the same state as A.  In
the interim, a client reaching node B sees PENDING — a state the certificate
genuinely occupies (it has been approved but its validity period has not yet
begun on that node).  The client simply waits for `not_before` and is not
harmed.

This is the same **stale-but-safe** property exhibited by all eventually
consistent systems: observing a slightly stale state is acceptable when the
stale state only triggers safe actions (retry, wait).

**Property 4: The renewal cycle is bounded by field propagation.**

The `VALID ⇄ PENDING_RENEWAL` cycle is the only cycle in the graph.  It
occurs when a renewal is processed: the certificate's `renew_by` date is
updated and the status returns to VALID.

```
Node A: VALID → PENDING_RENEWAL      (local time-based, NOT synced)
Node B: PENDING_RENEWAL → VALID      (renewal processed, synced)

Sync B→A: PENDING_RENEWAL→VALID is valid
          → A becomes VALID with updated renew_by ✓
Result: A's stale PENDING_RENEWAL is corrected; both are VALID
         with the same renew_by date
```

The sync payload carries the updated `renew_by` and `status_date` fields
alongside the status.  Peers receiving the VALID update overwrite their stale
`renew_by`, preventing the local time-based logic from immediately
re-transitioning to PENDING_RENEWAL.

A client that observes PENDING_RENEWAL on node A before the sync arrives sees
a state that *was* true — the certificate genuinely needed renewal.  The
client will either initiate a renewal (idempotent — the already-renewed cert
stays VALID) or retry later.

When the `renew_by` timestamp is considered alongside the status, the
composite state `(status, renew_by)` advances monotonically: each renewal
produces a strictly higher `renew_by` value.  This is analogous to a
**LWW-Register** (Last-Writer-Wins Register) where the timestamp determines
which value prevails — a standard CRDT primitive used by Cassandra and Riak.

### Convergence Summary

| Scenario | Convergence mechanism | Temporary divergence harmful? |
|----------|----------------------|------------------------------|
| Any state + REVOKED | Sync (immediate) | No — revocation always wins |
| Approval with clock skew near `not_before` | Time-based (`now >= not_before`) | No — PENDING just means "wait" |
| Renewal + revocation | Sync (immediate) | No — revocation always wins |
| Renewal propagation to stale node | Sync (PENDING_RENEWAL→VALID) | No — PENDING_RENEWAL triggers idempotent renewal |
| Time-based transitions across nodes | Independent local computation | No — small timing differences harmless |

The system does not claim to be a pure CRDT.  It is a **convergent state
machine** where:
- **Safety** (revocation is permanent) is enforced by sync transitions alone.
- **Liveness** (all nodes eventually agree) is enforced by sync transitions
  *plus* time-based transitions.
- **Stale intermediate states** are always safe because they trigger only
  idempotent or advisory client actions.

This is the same design philosophy used by:
- **Cassandra** — merge rules + TTL expiration together guarantee convergence;
  stale reads are acceptable for non-critical paths.
- **DynamoDB** — LWW resolution + conditional writes for safety-critical
  operations.
- **Riak** — CRDT merge for data types + read-repair for anti-entropy.

The advantage of a domain-specific state machine over general-purpose CRDTs is
that the conflict resolution rules are meaningful to the application domain.  A
revoked certificate *should* stay revoked regardless of concurrent operations —
this is a security invariant, not just a data structure property.  And a
temporarily stale PENDING_RENEWAL or PENDING *should* be harmless — these are
liveness properties, not safety properties.

### Time-Based Transitions: Deterministic Local Computation

The decision not to sync time-based transitions follows the principle of
**derived state**: when a value can be computed from existing data (certificate
dates + current time), storing and replicating it is unnecessary.

This is the same principle applied by:
- **Cassandra TTLs**: expiration is computed locally from the write timestamp
  and TTL value, not replicated as a separate event.
- **Redis key expiry**: each node independently expires keys based on their TTL,
  without coordinating the expiration event across replicas.
- **Kubernetes controller reconciliation**: controllers recompute desired state
  from specs rather than replicating intermediate state.

---

## 5. Security and Authentication

### PVACMS Approach

All cluster messages are signed with the CA private key and verified with the CA
public key before processing.  The join protocol uses a cryptographic nonce for
replay protection.  Sync snapshots are protected by a global timestamp
high-water mark (±5s clock skew tolerance).  Peer identity is verified via TLS
certificate inspection on every subscription.

### Industry Patterns

**Consul mTLS**: All inter-node RPC uses mutual TLS with certificates managed
by Consul's built-in CA.  The `verify_incoming` and `verify_outgoing` settings
enforce TLS on gossip and RPC channels.

**Vault Transit Encryption**: Vault encrypts all data at rest and in transit.
Integrated Raft storage uses mutual TLS between nodes, with certificates issued
by Vault's own PKI engine.

[**SPIFFE/SPIRE**](https://spiffe.io/docs/latest/spiffe-about/overview/): The
Secure Production Identity Framework for Everyone provides cryptographic
identity to workloads via x509 SVIDs (SPIFFE Verifiable Identity Documents).
Cluster membership is gated on valid SPIFFE identity.

**Kubernetes RBAC + Service Accounts**: API server authenticates nodes via
client certificates and authorizes operations via role-based access control.

### How PVACMS Aligns

| Security Aspect | Industry Practice | PVACMS |
|----------------|-------------------|--------|
| Message authentication | mTLS (Consul), signed RPCs (gRPC) | mTLS on all PVAccess connections + CA-signed cluster messages (ECDSA) |
| Replay protection | Nonces (OAuth), sequence numbers (TLS) | Cryptographic nonce (join) + timestamp HWM (sync) |
| Identity verification | x509 certificates (SPIFFE), tokens (Kubernetes) | mTLS peer certificate inspection (issuer_id + SKID verification) |
| Access control | RBAC (Kubernetes), ACLs (Consul) | EPICS Access Security (ASG CLUSTER rules) |
| Key material boundary | CA private key (Vault), HSM (EJBCA) | CA private key required for cluster participation |

The requirement that all cluster members possess the CA private key creates
a clear, cryptographically enforced security boundary.  This is the same
pattern used by:
- **Vault**: only nodes with the unseal key can participate in the cluster.
- **Kubernetes**: only nodes with valid kubelet certificates can join.
- **EJBCA**: only nodes with HSM access can sign certificates.

### CMS Node Certificate Revocation

PVACMS handles revocation of cluster node certificates as a special case of
the normal status transition machinery.  When any certificate transitions to
REVOKED, its SKID is checked against the set of known cluster node SKIDs.
If the revoked certificate belongs to a peer, the peer is disconnected.  If
it belongs to this node, the node initiates graceful shutdown.

This is analogous to:
- **Consul's `force-leave`** command, which removes a failed or compromised
  agent from the cluster.
- **Kubernetes node eviction**, which removes pods from a node marked as
  NotReady or cordoned.
- **CockroachDB decommissioning**, which drains and removes a node from the
  cluster with automatic data rebalancing.

---

## 6. Back-Pressure and Flow Control

### PVACMS Approach

The sync publisher uses `MonitorControlOp::tryPost()` for non-blocking
per-subscriber dispatch.  If the subscriber's output window is full, the
update is queued in a per-subscriber pending queue.  When the subscriber
acknowledges earlier updates, the `onHighMark()` callback drains the queue.

### Industry Pattern: Producer-Consumer Flow Control

This is a standard reactive-streams / back-pressure pattern:

| System | Back-pressure Mechanism |
|--------|------------------------|
| **Kafka** | Consumer pull model; consumer controls fetch rate |
| **gRPC** | HTTP/2 flow control windows per stream |
| **Reactive Streams** | `Subscription.request(n)` demand signaling |
| **TCP** | Sliding window with acknowledgments |
| **PVACMS** | `tryPost()` + pending queue + `onHighMark()` watermarks |

The PVACMS approach follows the pvxs `spam.cpp` reference pattern, which
implements per-subscriber watermarks matching the TCP sliding window concept:
a producer can send up to the window limit without acknowledgment, and the
consumer signals readiness for more data as it processes earlier messages.

---

## 7. Comparison with CA Clustering Solutions

### [HashiCorp Vault](https://developer.hashicorp.com/vault/docs/internals/integrated-storage) PKI

Vault uses Raft consensus with an active-standby model.  Only the active
node processes writes; standbys forward requests.  This provides strong
consistency but limits write throughput to a single node and makes the cluster
unavailable for writes during leader election.

| Aspect | Vault PKI | PVACMS |
|--------|-----------|--------|
| Architecture | Active-standby (single writer) | Peer-to-peer (any node issues certs) |
| Consistency | Strong (Raft) | Eventual (deterministic merge) |
| Write availability | Majority required | Any reachable node |
| Clustering protocol | Raft over TCP | PVAccess pub-sub |
| External dependencies | None (integrated Raft) | None (integrated PVA) |

### EJBCA

EJBCA clusters through a shared database (typically Galera for MySQL/MariaDB).
Multiple EJBCA instances connect to the same HA database, with the database
providing consistency and availability guarantees.

| Aspect | EJBCA | PVACMS |
|--------|-------|--------|
| Architecture | Shared database | Replicated per-node database |
| Consistency | Strong (database transactions) | Eventual (sync snapshots) |
| External dependencies | Galera cluster / database HA | None |
| State ownership | Centralized (database) | Distributed (each node owns its state) |
| Deployment complexity | Database cluster + app servers | Single binary per node |

### CFSSL

CFSSL does not implement built-in clustering.  HA requires external load
balancers and shared storage.

| Aspect | CFSSL | PVACMS |
|--------|-------|--------|
| Built-in clustering | No | Yes |
| HA mechanism | External (load balancer + shared storage) | Integrated (PVA-based cluster) |
| Auto-discovery | No | Yes (PVA beacon-based) |

### Summary

PVACMS occupies a unique position: it provides **zero-dependency, auto-managing
clustering** with **protocol-native discovery**, combining the operational
simplicity of Vault's integrated storage with the availability characteristics
of Cassandra's peer-to-peer model.

---

## 8. Reconciliation and Convergence

### PVACMS Approach

Membership reconciliation occurs passively through sync snapshot metadata.
Each sync update includes the publisher's view of cluster membership.  When a
receiver sees a peer it is not tracking, it subscribes to that peer's SYNC PV.
This ensures the cluster converges to full connectivity even if a join response
is partially processed.

### Industry Pattern: Reconciliation Loops

Kubernetes popularized the **reconciliation loop** as a core design principle:
controllers continuously compare desired state with actual state and take
corrective action.

```
Observe desired state → Observe actual state → Compare → Act → Repeat
```

Key properties of reconciliation loops:
- **Level-triggered** (not edge-triggered): reacts to current state, not events
- **Idempotent**: running the loop multiple times with the same state has no
  additional effect
- **Self-healing**: automatically corrects drift without manual intervention

### How PVACMS Aligns

PVACMS membership reconciliation is a reconciliation loop:

1. **Desired state**: all nodes listed in peer's membership view should have
   active subscriptions.
2. **Actual state**: the set of currently active subscriptions.
3. **Action**: subscribe to any peer present in desired state but missing from
   actual state.
4. **Trigger**: every incoming sync snapshot.

This is functionally identical to:
- **Kubernetes ReplicaSet controller**: ensures N pods exist, creates missing
  ones, deletes excess.
- **Consul anti-entropy**: periodically compares agent state with catalog and
  reconciles differences.
- **Cassandra read repair**: on read, compares replica states and sends repair
  mutations for inconsistencies.

---

## 9. Opt-in Clustering

### PVACMS Approach

Cluster mode is activated with the `--cluster-mode` flag.  Without it, PVACMS
runs as a standalone node — no SYNC/CTRL PVs are published, no peer discovery
occurs, and all publish operations are no-ops.  When enabled, a single-node
deployment is a cluster of one: CTRL and SYNC PVs are present and the full
cluster protocol runs even with no peers.

### Industry Precedent

Most production distributed systems offer clustering as an opt-in mode:

- **Redis**: standard mode is standalone; `cluster-enabled yes` activates the
  Cluster Bus, gossip, and slot management.
- **CockroachDB**: can run as a single-node without `--join` peers, but
  multi-node requires explicit join addresses.
- **Consul**: a single-server deployment runs Raft with a quorum of one, using
  the same protocol as a multi-server cluster.

PVACMS follows the Redis model — clustering is an explicit operational choice
rather than a default.  This keeps standalone deployments simple while
preserving the uniform architecture (same code paths) when clustering is
enabled.

---

## 10. Protocol Versioning

### PVACMS Approach

All cluster messages carry a semver-style version (`major.minor.patch`).  The
existing node rejects join requests where `version_major ≠ 1`.  Minor and
patch versions are informational, allowing rolling upgrades where nodes at
different minor versions coexist.

### Industry Precedent

- **Cassandra**: gossip messages carry schema version UUIDs.  Nodes with
  different schemas can coexist; schema changes propagate via gossip.
- **Kubernetes**: API versioning (`v1`, `v1beta1`, `v2`) with strict
  compatibility rules per version level.
- **gRPC**: service versioning through protocol buffer package paths with
  backward compatibility requirements.
- **Redis Cluster**: `configEpoch` serves as an implicit version for cluster
  state.  Higher epoch wins during configuration conflicts.

---

## 11. Transitive Data Forwarding

### PVACMS Approach

When full mesh connectivity is unavailable, PVACMS uses transitive data
forwarding.  A node that cannot reach a peer asks a connected intermediary to
relay that peer's data.  The forwarding uses the existing SYNC republish path —
no separate forwarding protocol, no origin tagging, no dual signatures.

The intermediary merges the unreachable peer's cert data into its own database
via the existing `applySyncSnapshot`, then calls `publishSnapshot()`.  All
subscribers to the intermediary's SYNC PV — including the requester — receive
the data through the normal path.  The idempotent merge on receivers means
nodes that already have the data simply ignore it.

Feedback prevention is critical: the intermediary only republishes when
`applySyncSnapshot` produces actual DB changes (new rows or status
transitions).  If the merge is a no-op (all data already present), no publish
occurs.  This prevents: A publishes → C merges (change) → C publishes → A
merges (no change) → stops.

### Design Rationale

**Forwarding via SYNC republish (not a separate path)**: all peers already
subscribe to each other's SYNC PVs.  The intermediary's SYNC already contains
all certs in its DB — including those merged from the unreachable peer.  No new
protocol fields, no new verification logic, no new code path.

**Connectivity status is per-node**: each node's SYNC membership reports its
own connectivity to each peer.  A peer's `connected: false` does not mean the
local node can't reach that peer — different nodes have different network
paths.  Every node attempts direct subscription regardless.

**Bidirectional check at join time with step-aside retry**: PVAccess
connectivity is not necessarily symmetric.  A node behind a one-way gateway
could join a cluster that cannot subscribe to its data.  The test subscription
(configurable via `--cluster-bidi-timeout`, default 5 seconds) catches this at
join time.  In gateway-chained topologies (e.g. lab-gw ↔ ml-gw), increase this
timeout to accommodate the extra latency of multi-hop PV resolution.

**Gateway-mediated clusters and peer identity**: When nodes communicate through
PVA gateways, TLS is terminated at each gateway hop.  The receiving node sees
the gateway's TCP, or TLS, credentials, not the originating peer's x509 certificate.
This affects two mechanisms: (1) the sync snapshot identity pre-check, which
normally caches the peer's TLS cert before accepting data, and (2) the
forwarding RPC handler, which normally requires x509 authentication.  The
`--cluster-skip-peer-identity-check` flag relaxes both checks for nodes that
participate in gateway-mediated communication.  Security is maintained by the
CA-key signature on every sync snapshot — a node without the CA private key
cannot forge sync data regardless of the transport identity.  The cluster client
reads `EPICS_PVACMS_CLUSTER_NAME_SERVERS` to add TCP name servers for PV
discovery through gateways where UDP broadcast is not available.

In a partial-mesh cluster, any node may answer the join RPC — including one
that cannot reach the joiner.  To handle this, a node that fails the bidi check
records the joiner's node_id in a TTL cache (60 seconds) and stops claiming
that joiner's discovery PV in subsequent PVA searches.  The joiner retries (up
to 3 times, 1-second delay), and on the next search a different cluster node
responds — one that may have bidirectional connectivity.  This is analogous to
DNS round-robin with health-check exclusion: unhealthy backends stop answering
so the client naturally reaches a healthy one.

### Industry Precedent

Cassandra uses coordinator-based routing where any node can serve as
coordinator for data it doesn't own.  PVACMS forwarding is simpler — it
leverages the existing full-database publish rather than introducing a routing
layer.  The approach is closer to BGP route reflection where a designated
reflector redistributes routes between peers that cannot communicate directly.

---

## Summary: Pattern Mapping

| PVACMS Feature | Pattern Name | Used By |
|---------------|-------------|---------|
| CTRL PV join RPC | Protocol-native discovery | Redis Cluster, Cassandra |
| PVA beacon discovery | Zero-configuration networking | mDNS/Bonjour, Consul LAN gossip |
| Timeout-based bootstrap | Self-bootstrapping cluster | Consul bootstrap-expect, etcd discovery |
| SYNC PV subscriptions | Pub-sub state replication | Kafka, Redis replication |
| Per-subscriber sequence tracking | Consumer offset / replication cursor | Kafka offsets, Redis PSYNC offset |
| Bounded update log | Replication backlog | Redis repl_backlog, Kafka retention |
| Full snapshot on fallen-behind | Full resync | Redis full SYNC, Kafka earliest offset |
| `isValidStatusTransition` | Convergent state machine (CRDT-like merge rules) | Riak CRDTs, Cassandra tombstones + TTL |
| Time-based transitions computed locally | Derived state | Cassandra TTLs, Redis key expiry |
| Immediate disconnect removal | Crash-only design | Kubernetes pod lifecycle, CockroachDB node removal |
| CA-signed messages | Cryptographic message authentication | Consul mTLS, Vault transit, SPIFFE SVIDs |
| Nonce + timestamp anti-replay | Anti-replay protection | OAuth nonces, TLS sequence numbers |
| Peer SKID verification | Identity-based access control | SPIFFE, Kubernetes node certificates |
| `tryPost()` + pending queue | Back-pressure / flow control | Kafka consumer pull, gRPC flow control, TCP windows |
| `onHighMark()` watermarks | Reactive demand signaling | Reactive Streams `request(n)`, TCP window updates |
| Membership in sync snapshots | Passive reconciliation | Kubernetes controller reconciliation, Consul anti-entropy |
| Cluster of one | Uniform architecture | CockroachDB, etcd, Consul single-server |
| Semver protocol version | Versioned wire protocol | Kubernetes API versioning, Cassandra schema versioning |
| `sync_ingestion_in_progress` flag | Re-entrancy guard / loop prevention | Database trigger suppression, event loop de-duplication |
| Node cert revocation → disconnect | Cryptographic fencing | ZooKeeper session expiry, Raft term fencing |
| Transitive data forwarding via intermediary | Route reflection / coordinator routing | BGP route reflectors, Cassandra coordinator |
| Per-member `connected` field in SYNC | Health-annotated membership | Consul health checks, Kubernetes node conditions |
| Bidirectional connectivity check at join | Symmetric reachability verification | TCP simultaneous open, BGP session establishment |
| `--cluster-mode` opt-in | Explicit cluster activation | Redis `cluster-enabled`, CockroachDB `--join` |

---

## References

### Papers
- Das, A., Gupta, I., & Motivala, A. (2002). [*SWIM: Scalable Weakly-consistent
  Infection-style Process Group Membership Protocol.*](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf) IEEE DSN.
- Ongaro, D. & Ousterhout, J. (2014). [*In Search of an Understandable Consensus
  Algorithm (Extended Version).*](https://raft.github.io/raft.pdf) Stanford University.
- Hayashibara, N., Defago, X., Yared, R., & Katayama, T. (2004). [*The φ Accrual
  Failure Detector.*](https://doi.org/10.1109/RELDIS.2004.1353004) IEEE SRDS.
- Candea, G. & Fox, A. (2003). [*Crash-Only Software.*](https://www.usenix.org/legacy/events/hotos03/tech/full_papers/candea/candea.pdf) HotOS IX.
- Shapiro, M., Preguiça, N., Baquero, C., & Zawirski, M. (2011). [*A
  comprehensive study of Convergent and Commutative Replicated Data Types.*](https://hal.inria.fr/inria-00555588/document)
  INRIA Research Report.
- DeCandia, G. et al. (2007). [*Dynamo: Amazon's Highly Available Key-value
  Store.*](https://www.allthingsdistributed.com/files/amazon-dynamo-sosp2007.pdf) ACM SOSP.
- Brewer, E. (2000). [*Towards Robust Distributed Systems.*](https://people.eecs.berkeley.edu/~brewer/cs262b-2004/PODC-keynote.pdf) ACM PODC Keynote
  (CAP Theorem).

### System Documentation
- HashiCorp Consul Architecture: https://developer.hashicorp.com/consul/docs/architecture
- Apache Cassandra Architecture: https://cassandra.apache.org/doc/latest/cassandra/architecture/
- CockroachDB Architecture: https://www.cockroachlabs.com/docs/stable/architecture/overview
- etcd Design: https://etcd.io/docs/latest/learning/design-learner/
- Redis Cluster Specification: https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/
- Kubernetes Controllers: https://kubernetes.io/docs/concepts/architecture/controller/
- HashiCorp Vault Integrated Storage: https://developer.hashicorp.com/vault/docs/internals/integrated-storage
- EJBCA Architecture: https://doc.primekey.com/ejbca/ejbca-architecture
