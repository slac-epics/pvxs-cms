/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CMS_TESTHARNESS_H
#define PVXS_CMS_TESTHARNESS_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#if defined(__GNUC__) || defined(__clang__)
#  define PVXS_CMS_TEST_API __attribute__((visibility("default")))
#else
#  define PVXS_CMS_TEST_API
#endif

namespace pvxs {

// Forward declarations from <pvxs/server.h> and <pvxs/client.h> so this
// header can be included without dragging the entire PVA surface in.
namespace server {
class Server;
struct SharedPV;
struct Source;
struct Config;
}  // namespace server
namespace client {
struct Config;
}  // namespace client

namespace cms {
namespace test {

// ---------------------------------------------------------------------------
// Subject + per-call cert issuance options
// ---------------------------------------------------------------------------

struct SubjectSpec {
    std::string common_name;
    std::string country;
    std::string organization;
    std::string organizational_unit;
};

// ---------------------------------------------------------------------------
// PkiFixture - already implemented in pkiFixture.cpp (Section 3)
// ---------------------------------------------------------------------------

class PVXS_CMS_TEST_API PkiFixture {
public:
    PkiFixture();
    PkiFixture(const PkiFixture &) = delete;
    PkiFixture &operator=(const PkiFixture &) = delete;
    PkiFixture(PkiFixture &&) noexcept;
    PkiFixture &operator=(PkiFixture &&) noexcept;
    ~PkiFixture();

    const std::string &dir() const noexcept;

    const std::string &caP12Path() const noexcept;
    const std::string &caChainPemPath() const noexcept;
    const std::string &serverP12Path() const noexcept;
    const std::string &adminP12Path() const noexcept;

    std::string caFingerprintSha256() const;

    std::string issueServerEE(const SubjectSpec &subject);
    std::string issueClientEE(const SubjectSpec &subject);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Per-call options
// ---------------------------------------------------------------------------

struct TestServerOpts {
    /// Common-name override for the issued EE cert.  When empty the harness
    /// auto-generates a unique CN.
    std::string subject;
    /// Use IPv6 loopback (`::1`) instead of `127.0.0.1`.
    bool ipv6{false};
    /// Require that connecting clients present a valid TLS client cert.
    bool clientCertRequired{false};
};

struct TestClientOpts {
    /// CN override for the issued client EE cert.
    std::string subject;
    /// Use IPv6 loopback (`::1`) instead of `127.0.0.1`.
    bool ipv6{false};
};

// ---------------------------------------------------------------------------
// RegisteredServer - snapshot table entry for a started test server
// ---------------------------------------------------------------------------

struct PVXS_CMS_TEST_API RegisteredServer {
    std::string addr;          ///< IP literal (no port), e.g. "127.0.0.1"
    uint16_t tcp_port{0};
    uint16_t udp_port{0};
    uint16_t tls_port{0};
    std::string ee_subject;    ///< CN of the EE cert this server presents
    server::Server *server{nullptr};  ///< Non-owning pointer; owned by harness
};

// ---------------------------------------------------------------------------
// Process-wide one-time init (OpenSSL, libevent thread support)
// ---------------------------------------------------------------------------

PVXS_CMS_TEST_API void initOnce();

// ---------------------------------------------------------------------------
// Loopback sanity-check predicates (testable in isolation)
// ---------------------------------------------------------------------------

PVXS_CMS_TEST_API void sanityCheckLoopback(const client::Config &cfg);
PVXS_CMS_TEST_API void sanityCheckLoopback(const server::Config &cfg);

// ---------------------------------------------------------------------------
// PVACMSHarness - single-instance fixture
// ---------------------------------------------------------------------------

class TestServerBuilder;  // defined below; needed by PVACMSHarness::testServerBuilder()

class PVXS_CMS_TEST_API PVACMSHarness {
public:
    class Builder;

    PVACMSHarness(const PVACMSHarness &) = delete;
    PVACMSHarness &operator=(const PVACMSHarness &) = delete;
    PVACMSHarness(PVACMSHarness &&) noexcept;
    PVACMSHarness &operator=(PVACMSHarness &&) noexcept;
    ~PVACMSHarness();

    /// Resolved listener address of the harness's PVACMS PVA TCP listener
    /// in `ip:port` form (e.g. `127.0.0.1:54321`).  Set by `Builder::build()`.
    const std::string &pvacmsListenerAddr() const noexcept;

    uint16_t pvacmsTcpPort() const noexcept;
    uint16_t pvacmsTlsPort() const noexcept;

    /// Issuer SKID hex of the harness's CA, as embedded in CERT:STATUS:<issuer>:<serial>.
    const std::string &pvacmsIssuerId() const noexcept;

    /// Cumulative count of `cert-status: subscribe pv=<name> kind=...` events
    /// emitted by pvxs's TLS plumbing (logger `pvxs.certs.mon.event`) while
    /// this harness has been active.
    uint32_t subscribesFor(const std::string &pv_name) const;

    /// Cumulative count of `cert-status: delivery  pv=<name> ...` events.
    uint32_t deliveriesFor(const std::string &pv_name) const;

    /// Snapshot of every CERT:STATUS PV name that has had at least one
    /// observed event (subscribe or delivery).
    std::vector<std::string> observedStatusPvs() const;

    /// Sum of subscribesFor() across every observed PV.
    uint32_t totalSubscribes() const;

    /// Sum of deliveriesFor() across every observed PV.
    uint32_t totalDeliveries() const;

    /// Reset both counters to zero.
    void resetStatusEventCounters();

    /// Block until `subscribesFor(pv_name) >= n` or timeout (seconds) elapses.
    /// Returns true on success, false on timeout.
    bool waitSubscribesAtLeast(const std::string &pv_name, uint32_t n,
                               double timeout_secs = 5.0) const;

    /// Block until `deliveriesFor(pv_name) >= n` or timeout (seconds) elapses.
    bool waitDeliveriesAtLeast(const std::string &pv_name, uint32_t n,
                               double timeout_secs = 5.0) const;

    /// Bound CA + admin cert paths (delegated to the harness's PkiFixture).
    const std::string &caChainPemPath() const noexcept;
    const std::string &adminP12Path() const noexcept;
    const PkiFixture &pkiFixture() const noexcept;
    PkiFixture &pkiFixture() noexcept;

    /// Snapshot of every test server started under this harness so far.
    const std::vector<RegisteredServer> &startedTestServers() const noexcept;

    /// Stop and de-register a test server previously returned by
    /// `testServerBuilder().start()`.  No-op if `srv` is not owned here.
    void stopTestServer(server::Server &srv);

    /// Begin a fluent test-server builder bound to this harness.  Each call
    /// returns a fresh builder; the builder is consumed by `start() &&`.
    TestServerBuilder testServerBuilder();

    /// Client config for talking to the harness's PVACMS RPC surface as the
    /// admin user.
    client::Config cmsAdminClientConfig() const;

    /// Snapshot client config addressing every test server started up to the
    /// moment of this call (plus the harness's PVACMS).  See snapshot semantics.
    ///
    /// Snapshot semantics: the returned `Config` captures the current snapshot
    /// table by value.  A `client::Context` built from this `Config` will NOT
    /// see test servers started AFTER this call returns.  If the test starts
    /// additional servers and wants to talk to them, it MUST call
    /// `testClientConfig()` again and rebuild the client.
    client::Config testClientConfig(const TestClientOpts &opts = {}) const;

private:
    PVACMSHarness();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class Builder;
    friend class TestServerBuilder;
};

// ---------------------------------------------------------------------------
// PVACMSHarness::Builder
// ---------------------------------------------------------------------------

class PVXS_CMS_TEST_API PVACMSHarness::Builder {
public:
    Builder();
    Builder(const Builder &) = delete;
    Builder &operator=(const Builder &) = delete;
    Builder(Builder &&) noexcept;
    Builder &operator=(Builder &&) noexcept;
    ~Builder();

    /// Use IPv6 loopback (`::1`) instead of `127.0.0.1`.
    Builder &ipv6(bool yes) &;

    /// Borrow an externally-owned PkiFixture instead of constructing a fresh
    /// one.  The fixture must outlive the resulting harness.
    Builder &pki(PkiFixture &fixture) &;

    /// Read CMS env vars (`EPICS_PVACMS_*`) when constructing the ConfigCms.
    /// Default false; the harness explicitly ignores ENV to keep tests
    /// deterministic and prevent leakage from the developer's shell.
    Builder &applyEnv(bool yes) &;

    /// Bind on non-loopback interfaces.  Strongly discouraged: emits a
    /// `pvxs.cms.test` WARN log line and, if `_PVXS_CMS_TEST_REJECT_EXTERNAL`
    /// is set in the environment (CI), throws `std::runtime_error`.
    Builder &allowExternalBind() &;

    /// Install an observer invoked once per CERT:STATUS:* subscription that
    /// reaches the harness's PVACMS.  The callback receives the full PV name
    /// (e.g. `CERT:STATUS:<issuer>:<serial>`).  Tests use this to verify that
    /// peer-cert validation paths are actually subscribing to cert-status.
    Builder &observeStatusSubscriptions(
        std::function<void(const std::string &pv_name)> cb) &;

    /// Construct a ConfigCms with all isolation knobs applied, prepare the
    /// PVACMS server (binds listeners, runs self-tests), then start the
    /// cluster runtime on a background thread.  `build()` returns once the
    /// PVACMS run loop is active and resolved ports are readable.
    PVACMSHarness build();

private:
    struct Pvt;
    std::unique_ptr<Pvt> pvt_;
};

// ---------------------------------------------------------------------------
// TestServerBuilder - rvalue-only fluent server builder
// ---------------------------------------------------------------------------

class PVXS_CMS_TEST_API TestServerBuilder {
public:
    TestServerBuilder(const TestServerBuilder &) = delete;
    TestServerBuilder &operator=(const TestServerBuilder &) = delete;
    TestServerBuilder(TestServerBuilder &&) noexcept;
    TestServerBuilder &operator=(TestServerBuilder &&) noexcept;
    ~TestServerBuilder();

    TestServerBuilder &&opts(const TestServerOpts &o) &&;
    TestServerBuilder &&customize(std::function<void(server::Config &)> fn) &&;
    TestServerBuilder &&withPV(const std::string &name, server::SharedPV pv) &&;
    TestServerBuilder &&withSource(const std::string &name,
                                   std::shared_ptr<server::Source> source) &&;

    /// Build, register, and start a PVA server bound to this harness.
    /// Returns a non-owning reference to the harness-owned `Server`.
    server::Server &start() &&;

private:
    explicit TestServerBuilder(PVACMSHarness &harness);
    struct Pvt;
    std::unique_ptr<Pvt> pvt_;
    friend class PVACMSHarness;
};

// ---------------------------------------------------------------------------
// ClusterTopology - directed-edge graph describing a cluster's intra-cluster
// peer visibility.  Indexes are zero-based.  Edges are directed: A having B
// in nameServers lets A's join requests reach B but not vice-versa.  The
// symmetric factories (fullMesh / linearChain / star) construct pairs of
// directed edges as a convenience.
// ---------------------------------------------------------------------------

class PVXS_CMS_TEST_API ClusterTopology {
   public:
    static ClusterTopology fullMesh(size_t n);
    static ClusterTopology linearChain(size_t n);
    static ClusterTopology star(size_t n, size_t hub);
    static ClusterTopology empty(size_t n);
    static ClusterTopology custom(size_t n, std::vector<std::pair<size_t, size_t>> edges);

    ClusterTopology &addEdge(size_t from, size_t to);
    ClusterTopology &addBidirectional(size_t a, size_t b);
    ClusterTopology &removeEdge(size_t from, size_t to);
    ClusterTopology &removeBidirectional(size_t a, size_t b);

    bool sees(size_t from, size_t to) const;
    std::vector<size_t> peersSeenBy(size_t i) const;
    size_t size() const noexcept;

   private:
    explicit ClusterTopology(size_t n);
    size_t n_{0};
    std::vector<std::vector<bool>> adj_;
};

// ---------------------------------------------------------------------------
// PVACMSCluster - multi-instance fixture (Section 6)
// ---------------------------------------------------------------------------

class PVXS_CMS_TEST_API PVACMSCluster {
   public:
    class Builder;
    struct Impl;

    PVACMSCluster(const PVACMSCluster &) = delete;
    PVACMSCluster &operator=(const PVACMSCluster &) = delete;
    PVACMSCluster(PVACMSCluster &&) noexcept;
    PVACMSCluster &operator=(PVACMSCluster &&) noexcept;
    ~PVACMSCluster();

    size_t size() const noexcept;
    const ClusterTopology &topology() const noexcept;
    const std::vector<std::string> &memberAddrs() const noexcept;
    const PkiFixture &pkiFixture() const noexcept;
    PkiFixture &pkiFixture() noexcept;

    /// Restart member i.  Preserves EE cert + DB; recomputes nameServers
    /// from the current topology and any foreign-cluster bridge entries.
    void restartMember(size_t i);

    /// Bidirectional partition / restoration within this cluster.  Updates
    /// stored topology and restarts the affected pair (i, j).
    void setUnreachable(size_t i, size_t j);
    void setReachable(size_t i, size_t j);

    /// Aggregated client config: addressList lists every member's PVACMS
    /// PVA TCP listener; admin EE cert from the shared PKI fixture.
    client::Config cmsAdminClientConfig() const;

   private:
    PVACMSCluster();
    std::unique_ptr<Impl> impl_;
    friend class Builder;
    friend PVXS_CMS_TEST_API void bridge(PVACMSCluster &, size_t,
                                          PVACMSCluster &, size_t);
    friend PVXS_CMS_TEST_API void unbridge(PVACMSCluster &, size_t,
                                            PVACMSCluster &, size_t);
};

class PVXS_CMS_TEST_API PVACMSCluster::Builder {
   public:
    Builder();
    Builder(const Builder &) = delete;
    Builder &operator=(const Builder &) = delete;
    Builder(Builder &&) noexcept;
    Builder &operator=(Builder &&) noexcept;
    ~Builder();

    Builder &size(size_t n) &;
    Builder &topology(ClusterTopology t) &;
    Builder &ipv6(bool yes) &;
    Builder &pki(PkiFixture &fixture) &;
    Builder &clusterDiscoveryTimeoutSecs(uint32_t s) &;
    Builder &clusterBidiTimeoutSecs(uint32_t s) &;

    PVACMSCluster build();

   private:
    struct Pvt;
    std::unique_ptr<Pvt> pvt_;
};

/// Establish a bidirectional bridge between two existing clusters.  Both
/// clusters must already be built.  Throws std::logic_error otherwise.
PVXS_CMS_TEST_API void bridge(PVACMSCluster &a, size_t a_node,
                              PVACMSCluster &b, size_t b_node);

/// Remove a previously-established bridge.  Throws std::logic_error if no
/// bridge between (a_node, b_node) currently exists.
PVXS_CMS_TEST_API void unbridge(PVACMSCluster &a, size_t a_node,
                                PVACMSCluster &b, size_t b_node);

}  // namespace test
}  // namespace cms
}  // namespace pvxs

#endif  // PVXS_CMS_TESTHARNESS_H
