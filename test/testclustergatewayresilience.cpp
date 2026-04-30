/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Cluster-resilience test with MockClusterGateway forwarders in the
// path, mimicking the production lab's `gateway-xgw` cross-zone
// forwarder pods.
//
// Asserts three invariants the production system must satisfy:
//   1. Cluster forms when peers are reachable only via a forwarder.
//   2. A forwarder restart causes a transient client::Disconnect on
//      the SYNC PV monitor but MUST NOT cause peer eviction.
//   3. After the forwarder comes back, pvxs auto-reconnect restores
//      sync without operator intervention.

#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <cms/cms.h>

#include <pvxs/log.h>
#include <pvxs/unittest.h>

#include "mockclustergateway.h"
#include "testharness.h"

namespace {

using cms::test::ClusterTopology;
using cms::test::MockClusterGateway;
using cms::test::PVACMSCluster;

// Wait up to `budget_secs` for ALL members of `cluster` to report a
// cluster_members count matching `expected`.  Returns elapsed seconds
// to convergence, or 0.0 on timeout.
double awaitMembershipReachesAcrossAll(PVACMSCluster &cluster,
                                       size_t expected,
                                       double budget_secs) {
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    const auto deadline = t0 + std::chrono::milliseconds(
        static_cast<int64_t>(budget_secs * 1000.0));
    while (clock::now() < deadline) {
        bool all_match = true;
        for (size_t i = 0; i < cluster.size(); ++i) {
            try {
                if (cluster.memberHandle(i).clusterMemberCount() != expected) {
                    all_match = false;
                    break;
                }
            } catch (...) {
                all_match = false;
                break;
            }
        }
        if (all_match) {
            return std::chrono::duration<double>(clock::now() - t0).count();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return 0.0;
}

// Build two single-node "clusters" — actually two independent PVACMS
// instances on isolated loopback addresses — and bridge them via two
// MockClusterGateway forwarders.  Returns the gateways via out-params
// for later stop()/start().
//
// The harness's `bridge()` helper would directly add B's listener to
// A's nameserver list, bypassing the forwarder — which defeats the
// point of this test.  Instead we build A and B with empty topology
// (sole node) and inject the gateway address as an extra peer on each
// side via PVACMSCluster::addExtraPeer() + restartMember().
//
// IMPORTANT: For the cluster to actually form, both A and B must use
// the SAME issuer (same CA).  We achieve this by constructing both
// from a single shared PkiFixture.
void buildGatewayedPair(cms::test::PkiFixture &pki,
                        std::unique_ptr<PVACMSCluster> &cluster_a_out,
                        std::unique_ptr<PVACMSCluster> &cluster_b_out,
                        std::unique_ptr<MockClusterGateway> &gw_a_to_b_out,
                        std::unique_ptr<MockClusterGateway> &gw_b_to_a_out) {
    // Build A and B as two sole-node clusters sharing one CA.
    {
        PVACMSCluster::Builder ba;
        cluster_a_out.reset(new PVACMSCluster(
            ba.size(1)
              .pki(pki)
              .topology(ClusterTopology::empty(1))
              .clusterName("CERT:CLUSTER:GWRES")
              .build()));
    }
    {
        PVACMSCluster::Builder bb;
        cluster_b_out.reset(new PVACMSCluster(
            bb.size(1)
              .pki(pki)
              .topology(ClusterTopology::empty(1))
              .clusterName("CERT:CLUSTER:GWRES")
              .build()));
    }

    const auto a_addr = cluster_a_out->memberAddrs()[0];
    const auto b_addr = cluster_b_out->memberAddrs()[0];

    // Spin up the two forwarders.  Each gateway proxies to the OTHER
    // cluster's PVACMS listener.
    {
        MockClusterGateway::Options opts;
        opts.upstream_address = b_addr;
        gw_a_to_b_out.reset(new MockClusterGateway(opts));
        gw_a_to_b_out->start();
    }
    {
        MockClusterGateway::Options opts;
        opts.upstream_address = a_addr;
        gw_b_to_a_out.reset(new MockClusterGateway(opts));
        gw_b_to_a_out->start();
    }

    // Tell A about the gateway it should use to reach B, and B about
    // the gateway it should use to reach A.  Then restart both members
    // so they pick up the new peer list.
    cluster_a_out->addExtraPeer(0, gw_a_to_b_out->listenAddress());
    cluster_b_out->addExtraPeer(0, gw_b_to_a_out->listenAddress());
    cluster_a_out->restartMember(0);
    cluster_b_out->restartMember(0);
}

void testGatewayedClusterFormsAndSurvivesGatewayRestart() {
    testDiag("Two PVACMS bridged through MockClusterGateway forwarders");

    cms::test::PkiFixture pki;
    std::unique_ptr<PVACMSCluster> cluster_a;
    std::unique_ptr<PVACMSCluster> cluster_b;
    std::unique_ptr<MockClusterGateway> gw_a_to_b;
    std::unique_ptr<MockClusterGateway> gw_b_to_a;
    buildGatewayedPair(pki, cluster_a, cluster_b, gw_a_to_b, gw_b_to_a);

    // Verify both PVACMS see the merged 2-member cluster (one each).
    // We do not assert this on PVACMSCluster level (each is sole-node
    // by topology); we ask each member directly through ServerHandle.
    const double t_initial = std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    (void)t_initial;

    // Joining via gateway is racier than direct join (extra hop, type
    // negotiation through the proxy).  Allow generous budget.
    double formed_at = 0.0;
    {
        using clock = std::chrono::steady_clock;
        const auto deadline = clock::now() + std::chrono::seconds(60);
        while (clock::now() < deadline) {
            const size_t a_view = cluster_a->memberHandle(0).clusterMemberCount();
            const size_t b_view = cluster_b->memberHandle(0).clusterMemberCount();
            if (a_view == 2 && b_view == 2) {
                formed_at = std::chrono::duration<double>(
                    clock::now() - (deadline - std::chrono::seconds(60))).count();
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    testOk(formed_at > 0.0,
           "cluster formed across MockClusterGateway forwarders (t=%.2fs)",
           formed_at);
    if (formed_at == 0.0) {
        testDiag("  cluster_a sees: %zu", cluster_a->memberHandle(0).clusterMemberCount());
        testDiag("  cluster_b sees: %zu", cluster_b->memberHandle(0).clusterMemberCount());
        testDiag("  skipping rest (cluster never formed)");
        testSkip(2, "cluster never formed via gateway");
        return;
    }

    // Restart the A->B gateway: simulates ml-gateway pod restarting in
    // production.  The TCP connection from cluster_a's pvxs client to
    // gw_a_to_b drops; cluster_a sees a client::Disconnect on the SYNC
    // PV monitor.  With the fix, cluster_a should NOT evict cluster_b.
    testDiag("Restarting gw_a_to_b — simulates gateway pod restart");
    gw_a_to_b->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    gw_a_to_b->start();

    // Recovery relies on pvxs's automatic TCP reconnect to the (same-port)
    // gateway; the rejoin watchdog backstops in case auto-reconnect is slow.
    const double recovered_at = awaitMembershipReachesAcrossAll(*cluster_a, 2, 60.0);
    testOk(recovered_at > 0.0,
           "cluster_a's view recovered to 2 within 60s after gw_a_to_b restart "
           "(observed at t=%.2fs)",
           recovered_at);
    if (recovered_at == 0.0) {
        testDiag("  cluster_a sees: %zu", cluster_a->memberHandle(0).clusterMemberCount());
        testDiag("  cluster_b sees: %zu", cluster_b->memberHandle(0).clusterMemberCount());
    }

    // Symmetric check: cluster_b's view should still report 2 (its own
    // path through gw_b_to_a is unaffected by the A->B restart).
    testOk(cluster_b->memberHandle(0).clusterMemberCount() == 2,
           "cluster_b's view of cluster unaffected by A->B gateway restart");

    // Tear down explicitly so destruction order is predictable.
    gw_a_to_b->stop();
    gw_b_to_a->stop();
    cluster_a.reset();
    cluster_b.reset();
}

}  // namespace

MAIN(testclustergatewayresilience) {
    // Always skip until MockClusterGateway's monitor-forwarding path
    // is finished: the gateway forwards CTRL-RPC successfully but the
    // upstream PVACMS's bidi-check (which itself opens a SYNC monitor
    // through the reverse gateway) is not yet plumbed through.  The
    // disconnect-resilience invariant this test was meant to assert
    // is also covered by testdisconnectresilience.cpp, which uses
    // restartMember() to inject the same client::Disconnect event
    // without requiring a forwarder in the middle.
    testPlan(1);
    pvxs::logger_config_env();
    testSkip(1, "testclustergatewayresilience: gateway monitor-forwarding "
                "incomplete; disconnect resilience covered by testdisconnectresilience");
    return testDone();
    (void)&testGatewayedClusterFormsAndSurvivesGatewayRestart;
}
