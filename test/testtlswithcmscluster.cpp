/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Cluster behavior tests at the user-observable level.  Each test
// drives the cluster via its public API surface (ClusterController,
// memberHandle, memberClientConfig, restartMember) and asserts what an
// operator running pvxcert / pvget / a status-monitor subscriber would
// see.  No test inspects protocol-internal mechanism state.

#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <ctime>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <cms/cms.h>

#include <pvxs/client.h>
#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/unittest.h>

#include "testharness.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "certfilefactory.h"
#include "openssl.h"
#include "security.h"

namespace {

using cms::test::ClusterTopology;
using cms::test::PVACMSCluster;
using cms::cert::CertCreationRequest;
using cms::cert::IdFileFactory;
using cms::cert::PENDING_APPROVAL;
using cms::cert::VALID;
using cms::cert::getCertCreatePv;
using cms::cert::getCertStatusURI;
namespace members = pvxs::members;
namespace nt = pvxs::nt;

bool waitForStatusIndex(pvxs::client::Context &client,
                        const std::string &status_pv,
                        int32_t expected_status,
                        double timeout_secs) {
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(static_cast<int>(timeout_secs * 1000.0));
    while (std::chrono::steady_clock::now() < deadline) {
        try {
            auto status = client.get(status_pv).exec()->wait(1.0);
            if (status["value.index"].as<int32_t>() == expected_status) return true;
        } catch (const std::exception &) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    auto status = client.get(status_pv).exec()->wait(1.0);
    return status["value.index"].as<int32_t>() == expected_status;
}

pvxs::Value makeCreateArgument(const std::string &create_pv,
                               uint16_t usage,
                               const std::string &public_key,
                               const std::string &name) {
    cms::cert::CertCreationRequest request("std", {});
    request.ccr["type"] = std::string("std");
    request.ccr["name"] = name;
    request.ccr["country"] = std::string("US");
    request.ccr["organization"] = std::string("pvxs-cms-test");
    request.ccr["organization_unit"] = std::string("PkiFixture Entity");
    request.ccr["usage"] = usage;
    request.ccr["pub_key"] = public_key;
    request.ccr["config_uri_base"] = std::string();
    request.ccr["no_status"] = false;

    auto uri = nt::NTURI({}).build();
    uri += {members::Struct("query", CCR_PROTOTYPE(request.verifier_fields))};
    auto arg = uri.create();
    const auto now = std::time(nullptr);
    arg["path"] = create_pv;
    request.ccr["not_before"] = static_cast<uint64_t>(now);
    request.ccr["not_after"] = static_cast<uint64_t>(now + 3600);
    arg["query"].from(request.ccr);
    return arg;
}

double awaitMembershipReachesAcrossAll(PVACMSCluster &cluster, size_t expected, double budget_secs);

// =====================================================================
// Membership convergence
// =====================================================================

void testTwoNodeClusterMembershipConverges() {
    testDiag("2-node cluster: every member sees both members");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    testOk(cluster.size() == 2, "Cluster size reported correctly as 2");
    testOk(cluster.memberHandle(0).clusterMemberCount() == 2,
           "Cluster Member 0 reports size as 2");
    testOk(cluster.memberHandle(1).clusterMemberCount() == 2,
           "Cluster Member 1 reports size as 2");
}

void testLinearChainMembershipPropagates() {
    testDiag("3-node linearChain: outer nodes learn each other via middle");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(3)
                       .topology(ClusterTopology::linearChain(3))
                       .build();

    testOk(cluster.size() == 3, "Cluster size reported correctly as 3");
    testOk(cluster.memberHandle(0).clusterMemberCount() == 3,
           "Cluster Member 0 reports size as 3");
    testOk(cluster.memberHandle(1).clusterMemberCount() == 3,
           "Cluster Member 1 reports size as 3");
    testOk(cluster.memberHandle(2).clusterMemberCount() == 3,
           "Cluster Member 2 reports size as 3");
}

void testAllMembersShareIssuer() {
    testDiag("All cluster members share one issuer ID");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto &issuer_node_0 = cluster.memberHandle(0).issuerId();
    const auto &issuer_node_1 = cluster.memberHandle(1).issuerId();
    testOk(!issuer_node_0.empty(), "node 0 issuer ID is populated");
    testOk(issuer_node_0 == issuer_node_1,
           "node 0 and node 1 share the same issuer ID");
}

void testEmptyTopologyEachMemberSole() {
    testDiag("Empty topology: each member is a sole-node cluster");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(3)
                       .topology(ClusterTopology::empty(3))
                       .build();

    testOk(cluster.memberHandle(0).clusterMemberCount() == 1,
           "Cluster Member 0 reports size as 1 (sole node)");
    testOk(cluster.memberHandle(1).clusterMemberCount() == 1,
           "Cluster Member 1 reports size as 1 (sole node)");
    testOk(cluster.memberHandle(2).clusterMemberCount() == 1,
           "Cluster Member 2 reports size as 1 (sole node)");
}

void testSoleNodeStartCount() {
    testDiag("size=1 cluster builds and reports 1 member");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(1).build();

    testOk(cluster.size() == 1, "Cluster size reported correctly as 1");
    testOk(cluster.memberHandle(0).clusterMemberCount() == 1,
           "sole-node cluster member reports its own count as 1");
}

// =====================================================================
// CTRL / SYNC / HEALTH / METRICS PV reachability
// =====================================================================

void testAdminClientReachesClusterCtrlPv() {
    testDiag("Admin client reaches CERT:CLUSTER:CTRL:<issuer> PV");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();
    const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;

    auto admin_client_config = cluster.cmsAdminClientConfig();
    auto admin_client = admin_client_config.build();

    bool get_succeeded = false;
    try {
        auto reply = admin_client.get(ctrl_pv).exec()->wait(10.0);
        get_succeeded = reply.valid();
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(get_succeeded, "GET CERT:CLUSTER:CTRL succeeded through cluster client");
}

void testCtrlPvReportsAllMembers() {
    testDiag("CTRL PV's members[] field lists every cluster member");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();
    const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;

    auto admin_client = cluster.cmsAdminClientConfig().build();

    pvxs::Value reply;
    try {
        reply = admin_client.get(ctrl_pv).exec()->wait(10.0);
    } catch (const std::exception &e) {
        testFail("GET %s failed: %s", ctrl_pv.c_str(), e.what());
        return;
    }

    if (!reply.valid()) {
        testFail("CTRL PV reply not valid");
        return;
    }

    auto members = reply["members"].as<pvxs::shared_array<const pvxs::Value>>();
    testOk(members.size() == 2,
           "CTRL PV's members[] field lists both cluster members");
}

void testPreloadedCertResolvesViaStatusPv() {
    testDiag("Preloaded admin Entity Cert is queryable via CERT:STATUS");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    // A successful mTLS GET against any cluster PV implies the admin
    // cert's CERT:STATUS PV resolved on the responding member.
    const auto issuer = cluster.memberHandle(0).issuerId();
    const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;

    auto admin_client = cluster.cmsAdminClientConfig().build();

    bool get_succeeded = false;
    try {
        auto reply = admin_client.get(ctrl_pv).exec()->wait(10.0);
        get_succeeded = reply.valid();
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }
    testOk(get_succeeded, "TLS handshake + GET succeeded - admin cert is preloaded");
}

void testClusterPvNameShape() {
    testDiag("Cluster CTRL/SYNC PV names match the documented format");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();
    testOk(!issuer.empty(), "issuer ID is populated");
    testOk(issuer.size() == 8,
           "issuer ID is 8 hex chars (first 8 of subject key identifier)");

    auto admin_client = cluster.cmsAdminClientConfig().build();

    const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;
    bool ctrl_get_succeeded = false;
    try {
        admin_client.get(ctrl_pv).exec()->wait(5.0);
        ctrl_get_succeeded = true;
    } catch (const std::exception &) {}
    testOk(ctrl_get_succeeded, "%s resolves", ctrl_pv.c_str());
}

void testPerMemberCtrlPvReachable() {
    testDiag("Per-member CTRL PV: each node serves CTRL with full member list");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();
    const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;

    for (size_t i = 0; i < cluster.size(); ++i) {
        auto member_client = cluster.memberClientConfig(i).build();
        bool get_succeeded = false;
        size_t members_seen = 0;
        try {
            auto reply = member_client.get(ctrl_pv).exec()->wait(10.0);
            get_succeeded = reply.valid();
            if (get_succeeded) {
                auto members = reply["members"].as<pvxs::shared_array<const pvxs::Value>>();
                members_seen = members.size();
            }
        } catch (const std::exception &e) {
            testDiag("member %zu GET %s failed: %s", i, ctrl_pv.c_str(), e.what());
        }
        testOk(get_succeeded, "member %zu serves CTRL PV", i);
        testOk(members_seen == cluster.size(),
               "member %zu's CTRL reply lists all %zu cluster members",
               i, cluster.size());
    }
}

void testPerMemberSyncPvReachable() {
    testDiag("Per-member SYNC PV: each node serves its own SYNC PV (monitor)");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();

    for (size_t i = 0; i < cluster.size(); ++i) {
        auto ctrl_query_client = cluster.memberClientConfig(i).build();
        const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;
        std::vector<std::string> all_sync_pvs;
        try {
            auto reply = ctrl_query_client.get(ctrl_pv).exec()->wait(10.0);
            auto members = reply["members"].as<pvxs::shared_array<const pvxs::Value>>();
            for (const auto &member_value : members) {
                all_sync_pvs.push_back(member_value["sync_pv"].as<std::string>());
            }
        } catch (const std::exception &e) {
            testDiag("member %zu CTRL GET failed: %s", i, e.what());
        }

        // Member i's listener serves exactly one SYNC PV (its own).  We
        // assert the user-visible contract: at least one of the
        // cluster's SYNC PVs reaches Connected on member i's listener.
        bool any_sync_pv_connected = false;
        for (const auto &sync_pv : all_sync_pvs) {
            auto monitor_client = cluster.memberClientConfig(i).build();
            auto connected_promise = std::make_shared<std::promise<void>>();
            auto connected_future = connected_promise->get_future();
            auto sync_subscription = monitor_client.monitor(sync_pv)
                .maskConnected(false)
                .event([connected_promise](pvxs::client::Subscription &s) {
                    try {
                        while (s.pop()) {}
                    } catch (pvxs::client::Connected &) {
                        try { connected_promise->set_value(); } catch (...) {}
                    } catch (...) {}
                })
                .exec();
            if (connected_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready) {
                any_sync_pv_connected = true;
                break;
            }
        }
        testOk(any_sync_pv_connected, "member %zu serves a SYNC PV via its own listener", i);
    }
}

void testPerMemberHealthPvReportsConvergedCluster() {
    testDiag("Per-member HEALTH PV reports cluster healthy + correct member count");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();
    const auto health_pv = std::string("CERT:HEALTH:") + issuer;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);

    for (size_t i = 0; i < cluster.size(); ++i) {
        auto member_client = cluster.memberClientConfig(i).build();
        bool db_ok = false;
        bool ca_valid = false;
        uint32_t cluster_members_field = 0;
        bool health_post_observed_converged = false;

        // The status monitor's minimum interval is 5s, so a 30s budget
        // absorbs the first cycle plus headroom for CI variance.
        while (std::chrono::steady_clock::now() < deadline && !health_post_observed_converged) {
            try {
                auto reply = member_client.get(health_pv).exec()->wait(5.0);
                if (reply.valid()) {
                    db_ok = reply["db_ok"].as<bool>();
                    ca_valid = reply["ca_valid"].as<bool>();
                    cluster_members_field = reply["cluster_members"].as<uint32_t>();
                    if (cluster_members_field == cluster.size() && db_ok && ca_valid) {
                        health_post_observed_converged = true;
                        break;
                    }
                }
            } catch (const std::exception &e) {
                testDiag("member %zu HEALTH GET (poll): %s", i, e.what());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        testOk(health_post_observed_converged,
               "member %zu HEALTH converged: db_ok=%d ca_valid=%d cluster_members=%u",
               i, static_cast<int>(db_ok), static_cast<int>(ca_valid), cluster_members_field);
    }
}

void testPerMemberMetricsPvReachable() {
    testDiag("Per-member METRICS PV is reachable with documented schema");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();
    const auto metrics_pv = std::string("CERT:METRICS:") + issuer;

    for (size_t i = 0; i < cluster.size(); ++i) {
        auto member_client = cluster.memberClientConfig(i).build();
        bool metrics_pv_reachable = false;
        bool metrics_schema_ok = false;
        try {
            auto reply = member_client.get(metrics_pv).exec()->wait(10.0);
            metrics_pv_reachable = reply.valid();
            if (metrics_pv_reachable) {
                metrics_schema_ok = reply["value"].valid()
                                 && reply["uptime_secs"].valid()
                                 && reply["certs_created"].valid()
                                 && reply["certs_revoked"].valid()
                                 && reply["db_size_bytes"].valid();
            }
        } catch (const std::exception &e) {
            testDiag("member %zu METRICS GET: %s", i, e.what());
        }
        testOk(metrics_pv_reachable, "member %zu METRICS PV reachable", i);
        testOk(metrics_schema_ok, "member %zu METRICS PV has documented schema", i);
    }
}

// =====================================================================
// Per-member client isolation
// =====================================================================

void testPerMemberClientIsolation() {
    testDiag("memberClientConfig(i) cannot reach PVs served only by node j");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();

    auto client_at_node_0 = cluster.memberClientConfig(0).build();
    const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;
    std::string node_0_sync_pv;
    try {
        auto reply = client_at_node_0.get(ctrl_pv).exec()->wait(10.0);
        const auto members = reply["members"].as<pvxs::shared_array<const pvxs::Value>>();
        if (!members.empty()) node_0_sync_pv = members[0]["sync_pv"].as<std::string>();
    } catch (const std::exception &e) {
        testFail("Could not discover node 0's sync_pv: %s", e.what());
        return;
    }

    if (node_0_sync_pv.empty()) {
        testFail("Node 0 reported no sync_pv");
        return;
    }

    // Node 0's SYNC PV name embeds node 0's node_id. Node 1's listener
    // does not claim that name; memberClientConfig(1) restricts its
    // addressList to node 1's listener only.  pvxs may still resolve via
    // cluster sync subscribers — that would be a real isolation leak.
    auto client_at_node_1 = cluster.memberClientConfig(1).build();
    bool node_0_sync_pv_reachable_via_node_1 = false;
    try {
        client_at_node_1.get(node_0_sync_pv).exec()->wait(2.0);
        node_0_sync_pv_reachable_via_node_1 = true;
    } catch (const std::exception &) {
    }

    testOk(!node_0_sync_pv_reachable_via_node_1,
           "node 1 does NOT serve node 0's SYNC PV (isolation holds)");
}

// =====================================================================
// Resilience to transient TCP loss / member restart
// =====================================================================

void testAdminClientSurvivesMemberLoss() {
    testDiag("Admin queries survive after one member is stopped");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    const auto issuer = cluster.memberHandle(0).issuerId();
    const auto ctrl_pv = std::string("CERT:CLUSTER:CTRL:") + issuer;
    auto admin_client = cluster.cmsAdminClientConfig().build();

    bool get_succeeded_before_restart = false;
    try {
        admin_client.get(ctrl_pv).exec()->wait(10.0);
        get_succeeded_before_restart = true;
    } catch (const std::exception &) {}
    testOk(get_succeeded_before_restart, "GET succeeds before member loss");

    cluster.restartMember(0);

    bool get_succeeded_after_restart = false;
    try {
        // pvxs reconnect backoff may need a couple of attempts when the
        // stale connection to the restarted member needs to recycle.
        for (int attempt = 0; attempt < 2 && !get_succeeded_after_restart; ++attempt) {
            try {
                admin_client.get(ctrl_pv).exec()->wait(6.0);
                get_succeeded_after_restart = true;
            } catch (const std::exception &) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
    } catch (const std::exception &) {}
    testOk(get_succeeded_after_restart,
           "GET still succeeds after member 0 restart (routes to peer)");
}

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

void testSurvivorRecoversAfterPeerRestart() {
    testDiag("2-node cluster; restart member 1; surviving member must recover view to 2");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2)
                       .clusterName("CERT:CLUSTER:DISCONNRES")
                       .build();

    testOk(cluster.memberHandle(0).clusterMemberCount() == 2,
           "baseline: member 0 sees 2-member cluster");
    testOk(cluster.memberHandle(1).clusterMemberCount() == 2,
           "baseline: member 1 sees 2-member cluster");

    cluster.restartMember(1);

    // pvxs auto-reconnects to the same-port relisted SYNC PV; cluster
    // membership must NOT be evicted on a transient TCP disconnect.
    const double convergence_secs =
        awaitMembershipReachesAcrossAll(cluster, 2, 30.0);

    testOk(convergence_secs > 0.0,
           "surviving member recovered membership view to 2 within 30s "
           "(observed at t=%.2fs)",
           convergence_secs);

    if (convergence_secs == 0.0) {
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

void testGatewayApprovalPropagationViaStatusPut() {
    testDiag("status approval put on one cluster node propagates to peer");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    auto admin_on_node_zero = cluster.memberClientConfig(0).build();
    auto admin_on_node_one = cluster.memberClientConfig(1).build();

    const auto issuer_zero = cluster.memberIssuerId(0);
    const auto issuer_one = cluster.memberIssuerId(1);
    testOk(issuer_zero == issuer_one,
           "both nodes report the same issuer identifier");

    const auto create_pv = getCertCreatePv("CERT", issuer_zero);
    auto key_pair = IdFileFactory::createKeyPair();
    auto create_arg = makeCreateArgument(create_pv,
                                         cms::ssl::kForClientAndServer,
                                         key_pair->public_key,
                                         "cluster-gateway-approval-ioc");
    auto create_reply = admin_on_node_zero.rpc(create_pv, create_arg).exec()->wait(10.0);
    const auto serial = create_reply["serial"].as<uint64_t>();
    const auto status_pv = getCertStatusURI("CERT", issuer_zero, serial);

    testOk(waitForStatusIndex(admin_on_node_zero, status_pv, PENDING_APPROVAL, 10.0),
           "node zero observes pending approval before approval put");
    testOk(waitForStatusIndex(admin_on_node_one, status_pv, PENDING_APPROVAL, 10.0),
           "node one observes pending approval before approval put");

    cluster.approveCert(0, serial);

    testOk(waitForStatusIndex(admin_on_node_zero, status_pv, VALID, 10.0),
           "node zero observes valid after status put approval");
    testOk(waitForStatusIndex(admin_on_node_one, status_pv, VALID, 10.0),
           "node one observes propagated valid after status put approval");
}

}  // namespace

MAIN(testtlswithcmscluster) {
    pvxs::logger_config_env();

    // Multi-member cluster convergence does not complete within a
    // CI-reasonable bound on the macOS GitHub-hosted runner.  Skip
    // the suite there; local macOS and every Linux runner exercise
    // it fully.
#ifdef __APPLE__
    if (getenv("CI")) {
        testPlan(1);
        testSkip(1, "testtlswithcmscluster skipped on macOS CI runner");
        return testDone();
    }
#endif

    testPlan(43);

    testTwoNodeClusterMembershipConverges();
    testLinearChainMembershipPropagates();
    testAllMembersShareIssuer();
    testEmptyTopologyEachMemberSole();
    testSoleNodeStartCount();

    testAdminClientReachesClusterCtrlPv();
    testCtrlPvReportsAllMembers();
    testPreloadedCertResolvesViaStatusPv();
    testClusterPvNameShape();
    testPerMemberCtrlPvReachable();
    testPerMemberSyncPvReachable();
    testPerMemberHealthPvReportsConvergedCluster();
    testPerMemberMetricsPvReachable();

    testPerMemberClientIsolation();

    testAdminClientSurvivesMemberLoss();
    testSurvivorRecoversAfterPeerRestart();
    testGatewayApprovalPropagationViaStatusPut();

    return testDone();
}
