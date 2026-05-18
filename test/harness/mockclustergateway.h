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
 * Minimal pvxs forwarder for cluster sync traffic only.  A TCP listener
 * that, for any PV matching the configured substrings (default: CERT:
 * CLUSTER:CTRL:* and CERT:CLUSTER:SYNC:*), opens an upstream subscription
 * or RPC to a backend address and pipes results back.
 *
 * Test usage:
 *   - Build PVACMS A on loopback addr_a, PVACMS B on addr_b.
 *   - Build a MockClusterGateway on addr_g forwarding to addr_b (and
 *     another forwarding the other way).
 *   - Configure each PVACMS's cluster nameservers to point at the
 *     gateway, not directly at the peer.
 *   - Call gateway.stop() / gateway.start() to simulate forwarder loss
 *     and recovery.
 *
 * Forwards exactly two pvxs operation kinds: MONITOR (for SYNC PV
 * ingestion) and RPC (for CTRL PV joins).  Does NOT model TLS
 * termination / re-encryption, PUT, ACL filtering, beacons, or
 * statistics.  Plain TCP only.
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
