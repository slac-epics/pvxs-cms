/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef CMS_TEST_MOCKCLUSTERGATEWAY_H
#define CMS_TEST_MOCKCLUSTERGATEWAY_H

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <pvxs/client.h>
#include <pvxs/server.h>

namespace cms {
namespace test {

namespace client = ::pvxs::client;
namespace server = ::pvxs::server;

/**
 * Minimal pvxs forwarder for cluster sync traffic only.
 *
 * Mimics the production lab's `gateway-xgw` forwarder pod's role for
 * `EPICS_PVACMS_CLUSTER_NAME_SERVERS`: a TCP listener that, for any PV
 * matching `CERT:CLUSTER:CTRL:*` or `CERT:CLUSTER:SYNC:*`, opens an
 * upstream subscription/RPC to a configured backend address and pipes
 * results back.
 *
 * Test usage:
 *   - Build PVACMS A on loopback addr_a, PVACMS B on addr_b (both
 *     advertise CERT:CLUSTER:* via their own listeners).
 *   - Build a MockClusterGateway on addr_g listening for the cluster
 *     PVs, with upstream pointing at addr_b (and another instance the
 *     other way).
 *   - Configure each PVACMS's cluster_pva_name_servers to point at
 *     addr_g, NOT directly at the peer's addr.
 *   - Start the cluster, observe peer-via-gateway discovery.
 *   - Call gateway.stop() to simulate gateway pod restart.
 *   - Call gateway.start() to simulate recovery.
 *   - Assert that the cluster reconverges.
 *
 * What is NOT modelled (deliberately, to keep this tiny):
 *   - TLS termination + re-encryption (the real gateway-xgw bridges
 *     mTLS-on-one-side to TCP-on-the-other; our mock is plain TCP).
 *   - PUT operations, multi-search-batch optimisations, ACL filters,
 *     statistics, banning, fan-in / fan-out optimisations.
 *
 * The mock forwards exactly two operation kinds:
 *   - MONITOR (pvxs subscription) — used for SYNC PV ingestion
 *   - RPC      (pvxs request/response) — used for CTRL-PV joins
 *
 * Both are sufficient to reproduce the production cluster-sync
 * behaviour through a forwarder.
 */
class MockClusterGateway {
public:
    struct Options {
        /// Listener TCP port for this gateway (0 = pick one).
        uint16_t listen_port{0};
        /// Listener interface (defaults to 127.0.0.1).
        std::string listen_interface{"127.0.0.1"};
        /// Backend address the gateway forwards toward.  Format:
        /// "host:port".  Required.
        std::string upstream_address;
        /// PV-name substring patterns to forward.  A name is forwarded
        /// if it CONTAINS any of these substrings (not just starts-with).
        /// Default forwards CTRL and SYNC PVs regardless of the
        /// configurable `cluster_pv_prefix` (which may insert a
        /// per-cluster discriminator like ":GWRES:" between the
        /// `CERT:CLUSTER` root and the `CTRL`/`SYNC` segment).
        std::vector<std::string> forwarded_substrings{":CTRL:", ":SYNC:"};
    };

    explicit MockClusterGateway(Options opts);
    ~MockClusterGateway();

    /// Start the listener.  Idempotent: stop()+start() restarts.
    void start();

    /// Stop the listener.  In-flight forwarded operations are dropped
    /// (their downstream Subscription / ExecOp is destroyed), simulating
    /// the abrupt TCP loss a pod restart causes.
    void stop();

    /// Effective listener address ("host:port").  Available after start().
    std::string listenAddress() const;

    /// Current state.
    bool isRunning() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace test
}  // namespace cms

#endif  // CMS_TEST_MOCKCLUSTERGATEWAY_H
