/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Reproduces the kubernetes split-brain bug:
//
//   When a peer's SYNC PV monitor receives a single client::Disconnect
//   exception (e.g. because a gateway pod restarted, briefly dropping
//   the forwarded TCP connection), the surviving PVACMS evicts the
//   peer from its membership IMMEDIATELY in handleDisconnect() — no
//   grace period for pvxs's automatic TCP reconnect.  The peer that
//   bounced is unaware of the eviction (it never sent a "leave"
//   message), so its own membership table still includes everyone.
//   The cluster is permanently split-brained.
//
// In the lab cluster, this fires on every gateway restart because
// PVACMS-to-PVACMS sync traffic is always gateway-mediated when
// crossing zones (idm <-> ml-gateway-xgw <-> ml).  go_tls Step 5
// restarts gateways twice → 2x Disconnect events → eviction → split.
//
// The test reproduces the bug entirely in-process, with no gateway
// involved, by using PVACMSCluster::restartMember() to drop and
// re-bring up one member's TLS listener.  pvxs's client context on
// the surviving member sees client::Disconnect when the listener
// goes away, just as it would for a gateway-flap-induced TCP loss.
//
// PASSING TEST INVARIANT (the system MUST satisfy):
//   After a peer has briefly disconnected and successfully rebound
//   its listener, the surviving members' membership view recovers
//   to the full cluster size.  Transient TCP loss MUST NOT cause
//   permanent eviction.

#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <cms/cms.h>

#include <pvxs/log.h>
#include <pvxs/unittest.h>

#include "testharness.h"

namespace {

using cms::test::ClusterTopology;
using cms::test::PVACMSCluster;

// Wait up to `budget_secs` for ALL surviving members to report a
// cluster_members count matching `expected`.  Returns the first
// time at which all members agree, or 0 on timeout.  Polls every
// 100ms.
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

// Reproduces the production failure mode.  This test is designed to
// FAIL on the buggy code (single-disconnect = permanent eviction)
// and PASS once handleDisconnect is fixed to defer eviction until
// the connectivity timeout fires.
void testSurvivorRecoversAfterPeerRestart() {
    testDiag("2-node cluster; restart member 1; surviving member must recover view to 2");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2)
                       .clusterName("CERT:CLUSTER:DISCONNRES")
                       .build();

    // Establish baseline: both members see 2.
    testOk(cluster.memberHandle(0).clusterMemberCount() == 2,
           "baseline: member 0 sees 2-member cluster");
    testOk(cluster.memberHandle(1).clusterMemberCount() == 2,
           "baseline: member 1 sees 2-member cluster");

    testDiag("Restarting member 1 (simulates gateway flap dropping ml-side TCP)");
    cluster.restartMember(1);

    // After restart, pvxs's client context on member 0 should reconnect
    // to member 1's relisted (same-port) SYNC PV, and the cluster should
    // converge back to 2.  The fix to handleDisconnect makes this work;
    // the buggy version evicts member 1 immediately and never recovers.
    //
    // Budget: 30s.  pvxs default reconnect backoff is sub-second on
    // loopback; the harness restartMember reuses the same TCP port so
    // there is no listener-discovery delay.
    const double convergence_secs =
        awaitMembershipReachesAcrossAll(cluster, 2, 30.0);

    testOk(convergence_secs > 0.0,
           "surviving member 0 recovered membership view to 2 within 30s "
           "(observed at t=%.2fs)",
           convergence_secs);

    if (convergence_secs == 0.0) {
        // Diagnostic: what does each member actually believe?
        for (size_t i = 0; i < cluster.size(); ++i) {
            try {
                size_t observed = cluster.memberHandle(i).clusterMemberCount();
                testDiag("  member %zu reports cluster_members = %zu (expected 2)",
                         i, observed);
            } catch (const std::exception &e) {
                testDiag("  member %zu memberHandle threw: %s", i, e.what());
            }
        }
    }
}

}  // namespace

MAIN(testdisconnectresilience) {
#ifdef __APPLE__
    // Skipped on the macOS GitHub-hosted runner (CI=true): multi-member
    // cluster convergence does not complete within a CI-reasonable bound
    // there.  Local macOS and every Linux runner exercise the suite.
    if (getenv("CI")) {
        testPlan(1);
        pvxs::logger_config_env();
        testSkip(1, "testdisconnectresilience skipped on macOS CI runner");
        return testDone();
    }
#endif
    testPlan(3);
    pvxs::logger_config_env();
    testSurvivorRecoversAfterPeerRestart();
    return testDone();
}
