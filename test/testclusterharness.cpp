/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <chrono>
#include <set>
#include <stdexcept>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/cms/testHarness.h>
#include <pvxs/log.h>
#include <pvxs/unittest.h>

namespace {

using pvxs::cms::test::ClusterTopology;
using pvxs::cms::test::PVACMSCluster;
using pvxs::cms::test::PkiFixture;
using pvxs::cms::test::bridge;
using pvxs::cms::test::unbridge;

void testTopologyValueType() {
    testDiag("ClusterTopology factories produce expected adjacency");

    auto fm = ClusterTopology::fullMesh(3);
    testEq(fm.size(), size_t{3});
    testTrue(fm.sees(0, 1));
    testTrue(fm.sees(1, 2));
    testTrue(fm.sees(2, 0));
    testTrue(!fm.sees(0, 0));

    auto chain = ClusterTopology::linearChain(3);
    testTrue(chain.sees(0, 1));
    testTrue(chain.sees(1, 0));
    testTrue(chain.sees(1, 2));
    testTrue(chain.sees(2, 1));
    testTrue(!chain.sees(0, 2));
    testTrue(!chain.sees(2, 0));

    auto st = ClusterTopology::star(4, 0);
    testTrue(st.sees(0, 1));
    testTrue(st.sees(0, 2));
    testTrue(st.sees(0, 3));
    testTrue(st.sees(1, 0));
    testTrue(!st.sees(1, 2));

    auto e = ClusterTopology::empty(3);
    testTrue(!e.sees(0, 1));
    testTrue(!e.sees(0, 2));

    auto cu = ClusterTopology::custom(3, {{0, 1}, {1, 2}});
    testTrue(cu.sees(0, 1));
    testTrue(cu.sees(1, 2));
    testTrue(!cu.sees(1, 0));
    testTrue(!cu.sees(2, 1));
}

void testTopologyMutators() {
    testDiag("ClusterTopology mutators add/remove edges as expected");

    auto t = ClusterTopology::empty(3);
    t.addEdge(0, 1);
    testTrue(t.sees(0, 1));
    testTrue(!t.sees(1, 0));

    t.addBidirectional(1, 2);
    testTrue(t.sees(1, 2));
    testTrue(t.sees(2, 1));

    t.removeEdge(0, 1);
    testTrue(!t.sees(0, 1));

    t.removeBidirectional(1, 2);
    testTrue(!t.sees(1, 2));
    testTrue(!t.sees(2, 1));
}

void testPeersSeenBy() {
    testDiag("ClusterTopology::peersSeenBy returns all directed-out neighbours");

    auto fm = ClusterTopology::fullMesh(3);
    auto p0 = fm.peersSeenBy(0);
    std::set<size_t> p0_set(p0.begin(), p0.end());
    testEq(p0_set.size(), size_t{2});
    testTrue(p0_set.count(1) == 1);
    testTrue(p0_set.count(2) == 1);
    testTrue(p0_set.count(0) == 0);

    auto chain = ClusterTopology::linearChain(3);
    auto c0 = chain.peersSeenBy(0);
    auto c1 = chain.peersSeenBy(1);
    auto c2 = chain.peersSeenBy(2);
    testEq(c0.size(), size_t{1});
    testEq(c1.size(), size_t{2});
    testEq(c2.size(), size_t{1});
}

void testTopologyOutOfRange() {
    testDiag("ClusterTopology bounds-checks");
    auto t = ClusterTopology::empty(3);
    bool threw = false;
    try {
        t.addEdge(0, 5);
    } catch (const std::out_of_range &) {
        threw = true;
    }
    testTrue(threw);

    bool threw2 = false;
    try {
        ClusterTopology::star(3, 5);
    } catch (const std::out_of_range &) {
        threw2 = true;
    }
    testTrue(threw2);
}

void testClusterDefaultFullMeshBuild() {
    testDiag("PVACMSCluster::Builder{}.size(2).build() produces 2-node fullMesh cluster");

    PVACMSCluster::Builder b;
    auto cluster = b.size(2).build();

    testEq(cluster.size(), size_t{2});
    testEq(cluster.topology().size(), size_t{2});
    testTrue(cluster.topology().sees(0, 1));
    testTrue(cluster.topology().sees(1, 0));

    const auto &addrs = cluster.memberAddrs();
    testEq(addrs.size(), size_t{2});
    testTrue(!addrs[0].empty());
    testTrue(!addrs[1].empty());
    testTrue(addrs[0] != addrs[1]);
    testDiag("Member 0 listener: %s", addrs[0].c_str());
    testDiag("Member 1 listener: %s", addrs[1].c_str());

    auto cli_cfg = cluster.cmsAdminClientConfig();
    testEq(cli_cfg.addressList.size(), size_t{2});
    testTrue(!cli_cfg.tls_keychain_file.empty());
}

void testClusterLinearChainBuild() {
    testDiag("PVACMSCluster supports pre-partitioned linearChain(3)");

    PVACMSCluster::Builder b;
    auto cluster = b.size(3).topology(ClusterTopology::linearChain(3)).build();

    testEq(cluster.size(), size_t{3});
    testTrue(cluster.topology().sees(0, 1));
    testTrue(cluster.topology().sees(1, 2));
    testTrue(!cluster.topology().sees(0, 2));
    testTrue(!cluster.topology().sees(2, 0));
}

void testClusterEnvVarSuppression() {
    testDiag("PVACMSCluster::Builder::build() unsets EPICS_PVACMS_CLUSTER_NAME_SERVERS");

    setenv("EPICS_PVACMS_CLUSTER_NAME_SERVERS", "fake.host:5075", 1);
    setenv("EPICS_PVA_NAME_SERVERS", "bar.host:5075", 1);

    PVACMSCluster::Builder b;
    auto cluster = b.size(2).build();

    testTrue(getenv("EPICS_PVACMS_CLUSTER_NAME_SERVERS") == nullptr);
    testTrue(getenv("EPICS_PVA_NAME_SERVERS") == nullptr);

    const auto &addrs = cluster.memberAddrs();
    for (const auto &a : addrs) {
        testTrue(a.find("fake.host") == std::string::npos);
        testTrue(a.find("bar.host") == std::string::npos);
    }
}

__attribute__((unused)) void testRestartMemberPreservesSize() {
    testDiag("PVACMSCluster::restartMember keeps member count and CA stable");

    PVACMSCluster::Builder b;
    auto cluster = b.size(2).build();
    const auto fingerprint_before = cluster.pkiFixture().caFingerprintSha256();
    const auto sz_before = cluster.size();

    cluster.restartMember(0);

    testEq(cluster.size(), sz_before);
    testEq(cluster.pkiFixture().caFingerprintSha256(), fingerprint_before);
    const auto &addrs = cluster.memberAddrs();
    testTrue(!addrs[0].empty());
    testTrue(!addrs[1].empty());
    testDiag("After restart - member 0 listener: %s", addrs[0].c_str());
}

__attribute__((unused)) void testRestartMemberOutOfRange() {
    testDiag("PVACMSCluster::restartMember rejects out-of-range");
    PVACMSCluster::Builder b;
    auto cluster = b.size(2).build();
    bool threw = false;
    try {
        cluster.restartMember(5);
    } catch (const std::out_of_range &) {
        threw = true;
    }
    testTrue(threw);
}

__attribute__((unused)) void testBridgeOutOfRange() {
    testDiag("bridge() rejects out-of-range node indices");

    PVACMSCluster::Builder b1;
    PVACMSCluster::Builder b2;
    auto a = b1.size(2).build();
    auto b = b2.size(2).build();

    bool threw = false;
    try {
        bridge(a, 99, b, 0);
    } catch (const std::out_of_range &) {
        threw = true;
    }
    testTrue(threw);
}

__attribute__((unused)) void testBridgeAndUnbridgeBetweenClusters() {
    testDiag("bridge / unbridge between two 2-node clusters");

    PVACMSCluster::Builder b1;
    PVACMSCluster::Builder b2;
    auto a = b1.size(2).build();
    auto bcluster = b2.size(2).build();

    auto a0_addr_before = a.memberAddrs()[0];
    auto b0_addr_before = bcluster.memberAddrs()[0];

    bridge(a, 0, bcluster, 0);

    testTrue(!a.memberAddrs()[0].empty());
    testTrue(!bcluster.memberAddrs()[0].empty());

    unbridge(a, 0, bcluster, 0);

    bool threw = false;
    try {
        unbridge(a, 0, bcluster, 0);
    } catch (const std::logic_error &) {
        threw = true;
    }
    testTrue(threw);

    (void)a0_addr_before;
    (void)b0_addr_before;
}

}  // namespace

MAIN(testclusterharness) {
    testPlan(38);
    pvxs::logger_config_env();
    testTopologyValueType();
    testTopologyMutators();
    testPeersSeenBy();
    testTopologyOutOfRange();
    testClusterDefaultFullMeshBuild();
    testClusterLinearChainBuild();
    testClusterEnvVarSuppression();
    return testDone();
}
