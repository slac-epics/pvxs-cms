/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Harness self-tests.
//
// Verifies the test harness itself behaves as documented:
//   * PkiFixture lifecycle and cert issuance
//   * PVACMSHarness build/destruct, port isolation, env-var fencing
//   * TestServerBuilder + testClientConfig / cmsAdminClientConfig snapshots
//   * ClusterTopology adjacency factories and mutators
//   * PVACMSCluster build, restart, bridge, env-var suppression
//
// These tests target the harness API surface in test/harness/.  Failing
// tests here mean the harness is misbehaving, not the production PVACMS.

#include <chrono>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/unittest.h>

#include "clustertopology.h"
#include "mockclustergateway.h"
#include "testharness.h"

namespace {

using cms::test::ClusterTopology;
using cms::test::MockClusterGateway;
using cms::test::PkiFixture;
using cms::test::PVACMSCluster;
using cms::test::PVACMSHarness;
using cms::test::SubjectSpec;
using cms::test::TestClientOpts;
using cms::test::TestServerOpts;
using cms::test::bridge;
using cms::test::sanityCheckLoopback;
using cms::test::unbridge;

bool fileExists(const std::string &path) {
    struct stat path_stat;
    return ::stat(path.c_str(), &path_stat) == 0 && S_ISREG(path_stat.st_mode);
}

bool dirExists(const std::string &path) {
    struct stat path_stat;
    return ::stat(path.c_str(), &path_stat) == 0 && S_ISDIR(path_stat.st_mode);
}

// =====================================================================
// PkiFixture (22 assertions)
// =====================================================================

void testFreshPerConstruction() {
    testDiag("Two PkiFixtures produce different CA fingerprints + distinct temp dirs");
    PkiFixture first_fixture;
    PkiFixture second_fixture;

    testOk(!first_fixture.dir().empty() && dirExists(first_fixture.dir()),
           "first fixture temp dir exists: %s", first_fixture.dir().c_str());
    testOk(!second_fixture.dir().empty() && dirExists(second_fixture.dir()),
           "second fixture temp dir exists: %s", second_fixture.dir().c_str());
    testOk(first_fixture.dir() != second_fixture.dir(),
           "two fixtures use distinct temp directories");

    const auto first_fingerprint = first_fixture.caFingerprintSha256();
    const auto second_fingerprint = second_fixture.caFingerprintSha256();
    testOk(!first_fingerprint.empty() && first_fingerprint.size() == 64,
           "first fingerprint is a 64-char hex string");
    testOk(first_fingerprint != second_fingerprint,
           "two fixtures have distinct CA fingerprints");
}

void testCaArtifacts() {
    testDiag("CA, server, admin P12s and CA chain PEM exist after construction");
    PkiFixture pki;
    testOk(fileExists(pki.caP12Path()), "ca.p12 exists: %s", pki.caP12Path().c_str());
    testOk(fileExists(pki.caChainPemPath()), "ca-chain.pem exists: %s", pki.caChainPemPath().c_str());
    testOk(fileExists(pki.serverP12Path()), "pvacms-server.p12 exists: %s", pki.serverP12Path().c_str());
    testOk(fileExists(pki.adminP12Path()), "admin.p12 exists: %s", pki.adminP12Path().c_str());
}

void testIssueDistinctCerts() {
    testDiag("issueServerCert and issueClientCert produce distinct files per call");
    PkiFixture pki;

    SubjectSpec server_a_subject{"server-a", {}, {}, {}};
    SubjectSpec server_b_subject{"server-b", {}, {}, {}};
    SubjectSpec client_c_subject{"client-c", {}, {}, {}};

    auto server_a_cert_path = pki.issueServerCert(server_a_subject);
    auto server_b_cert_path = pki.issueServerCert(server_b_subject);
    auto client_c_cert_path = pki.issueClientCert(client_c_subject);

    std::set<std::string> distinct_cert_paths{
        server_a_cert_path, server_b_cert_path, client_c_cert_path};
    testOk(distinct_cert_paths.size() == 3, "three issued Entity Cert paths are distinct");
    testOk(fileExists(server_a_cert_path),
           "issued server Entity Cert (server-a) exists: %s", server_a_cert_path.c_str());
    testOk(fileExists(server_b_cert_path),
           "issued server Entity Cert (server-b) exists: %s", server_b_cert_path.c_str());
    testOk(fileExists(client_c_cert_path),
           "issued client Entity Cert (client-c) exists: %s", client_c_cert_path.c_str());
}

void testTempDirCleanup() {
    testDiag("Destructor removes temp directory and all files within");
    std::string captured_dir;
    std::string captured_ca;
    std::string captured_entity;
    {
        PkiFixture pki;
        captured_dir = pki.dir();
        captured_ca = pki.caP12Path();
        captured_entity = pki.issueServerCert({"throwaway", {}, {}, {}});

        testOk(dirExists(captured_dir), "temp dir present during fixture lifetime");
        testOk(fileExists(captured_ca), "CA file present during fixture lifetime");
        testOk(fileExists(captured_entity), "issued Entity Cert file present during fixture lifetime");
    }
    testOk(!dirExists(captured_dir), "temp dir removed after fixture destruction");
    testOk(!fileExists(captured_ca), "CA file removed after fixture destruction");
    testOk(!fileExists(captured_entity), "issued Entity Cert removed after fixture destruction");
}

void testBorrowedFixtureSharing() {
    testDiag("A single PkiFixture issues multiple Entity Certs; both share the same CA fingerprint");
    PkiFixture pki;
    const auto baseline_fingerprint = pki.caFingerprintSha256();

    auto first_entity_cert_path = pki.issueServerCert({"shared-srv-1", {}, {}, {}});
    auto second_entity_cert_path = pki.issueClientCert({"shared-cli-1", {}, {}, {}});

    testOk(fileExists(first_entity_cert_path),
           "first Entity Cert issued under shared fixture");
    testOk(fileExists(second_entity_cert_path),
           "second Entity Cert issued under shared fixture");
    testOk(pki.caFingerprintSha256() == baseline_fingerprint,
           "CA fingerprint stable across multiple issuances");
}

// =====================================================================
// PVACMSHarness (44 assertions)
// =====================================================================

void testInitOnce() {
    testDiag("initOnce() is idempotent");
    cms::test::initOnce();
    cms::test::initOnce();
    testPass("initOnce() called twice without error");
}

void testSanityCheckLoopback() {
    testDiag("sanityCheckLoopback accepts loopback configs and rejects non-loopback");

    pvxs::client::Config loopback_client_config;
    loopback_client_config.addressList = {"127.0.0.1:5075", "[::1]:5075"};
    loopback_client_config.nameServers = {"127.0.0.1:5075"};
    try {
        sanityCheckLoopback(loopback_client_config);
        testPass("sanityCheckLoopback accepts loopback client config");
    } catch (const std::exception &e) {
        testFail("sanityCheckLoopback should accept loopback client config: %s", e.what());
    }

    pvxs::client::Config non_loopback_client_config;
    non_loopback_client_config.addressList = {"192.168.1.1:5075"};
    try {
        sanityCheckLoopback(non_loopback_client_config);
        testFail("sanityCheckLoopback should reject non-loopback client config");
    } catch (const std::exception &) {
        testPass("sanityCheckLoopback rejects non-loopback client config");
    }

    pvxs::server::Config loopback_server_config;
    loopback_server_config.interfaces = {"127.0.0.1"};
    loopback_server_config.beaconDestinations = {"127.0.0.1"};
    try {
        sanityCheckLoopback(loopback_server_config);
        testPass("sanityCheckLoopback accepts loopback server config");
    } catch (const std::exception &e) {
        testFail("sanityCheckLoopback should accept loopback server config: %s", e.what());
    }

    pvxs::server::Config wildcard_server_config;
    wildcard_server_config.interfaces = {"0.0.0.0"};
    try {
        sanityCheckLoopback(wildcard_server_config);
        testFail("sanityCheckLoopback should reject 0.0.0.0 server config");
    } catch (const std::exception &) {
        testPass("sanityCheckLoopback rejects 0.0.0.0 server config");
    }
}

void testHarnessBuildAndDestruct() {
    testDiag("PVACMSHarness::Builder{}.build() returns a running harness; destructor cleans up");

    std::string captured_dir;
    {
        PVACMSHarness harness = PVACMSHarness::Builder{}.build();

        testOk(harness.pvacmsTcpPort() != 0,
               "PVACMS resolved tcp_port: %u", (unsigned)harness.pvacmsTcpPort());
        testOk(harness.pvacmsTlsPort() != 0,
               "PVACMS resolved tls_port: %u", (unsigned)harness.pvacmsTlsPort());
        testOk(!harness.pvacmsListenerAddr().empty(),
               "PVACMS listener addr: %s", harness.pvacmsListenerAddr().c_str());

        captured_dir = harness.pkiFixture().dir();
        testOk(!captured_dir.empty() && dirExists(captured_dir),
               "harness owns a PKI temp dir: %s", captured_dir.c_str());

        testOk(harness.startedTestServers().empty(), "no test servers started yet");
    }
    testOk(!dirExists(captured_dir), "harness destructor removed PKI temp dir");
}

void testTwoHarnessesDistinctPorts() {
    testDiag("Two harnesses use distinct ephemeral ports");
    PVACMSHarness first_harness = PVACMSHarness::Builder{}.build();
    PVACMSHarness second_harness = PVACMSHarness::Builder{}.build();

    testOk(first_harness.pvacmsTcpPort() != second_harness.pvacmsTcpPort(),
           "two harnesses get distinct tcp_port: %u vs %u",
           (unsigned)first_harness.pvacmsTcpPort(), (unsigned)second_harness.pvacmsTcpPort());
    testOk(first_harness.pvacmsTlsPort() != second_harness.pvacmsTlsPort(),
           "two harnesses get distinct tls_port: %u vs %u",
           (unsigned)first_harness.pvacmsTlsPort(), (unsigned)second_harness.pvacmsTlsPort());
    testOk(first_harness.pkiFixture().dir() != second_harness.pkiFixture().dir(),
           "two harnesses use distinct PKI dirs");
    testOk(first_harness.pkiFixture().caFingerprintSha256()
               != second_harness.pkiFixture().caFingerprintSha256(),
           "two harnesses have distinct CA fingerprints");
}

void testCmsAdminClientConfigIsLoopback() {
    testDiag("cmsAdminClientConfig() produces a loopback-only client config");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();
    auto admin_client_config = harness.cmsAdminClientConfig();

    testOk(!admin_client_config.addressList.empty(), "addressList is non-empty");
    testOk(!admin_client_config.tls_keychain_file.empty(), "tls_keychain_file is set");
    testOk(admin_client_config.tls_keychain_file == harness.adminP12Path(),
           "tls_keychain_file points at admin.p12");
    try {
        sanityCheckLoopback(admin_client_config);
        testPass("cmsAdminClientConfig() passes sanityCheckLoopback");
    } catch (const std::exception &e) {
        testFail("cmsAdminClientConfig() not loopback: %s", e.what());
    }
}

void testTestServerBuilderProducesIsolatedServer() {
    testDiag("testServerBuilder().start() returns a running, isolated PVA server");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto &test_server = harness.testServerBuilder().start();
    const auto &resolved_config = test_server.config();

    testOk(resolved_config.tcp_port != 0,
           "test server tcp_port resolved: %u", (unsigned)resolved_config.tcp_port);
    testOk(resolved_config.udp_port != 0,
           "test server udp_port resolved: %u", (unsigned)resolved_config.udp_port);
    testOk(!resolved_config.interfaces.empty() &&
           (resolved_config.interfaces.front() == "127.0.0.1"
            || resolved_config.interfaces.front() == "::1"),
           "test server interfaces loopback only");
    testOk(resolved_config.auto_beacon == false, "test server auto_beacon is false");

    const auto &server_snapshot = harness.startedTestServers();
    testOk(server_snapshot.size() == 1,
           "snapshot table has exactly 1 entry: %zu", server_snapshot.size());
    testOk(server_snapshot.front().tcp_port == resolved_config.tcp_port,
           "snapshot tcp_port (%u) matches resolved (%u)",
           (unsigned)server_snapshot.front().tcp_port, (unsigned)resolved_config.tcp_port);
}

void testTwoTestServersDistinctPorts() {
    testDiag("two testServerBuilder().start() calls produce distinct ports + snapshots");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto &first_server = harness.testServerBuilder().start();
    auto &second_server = harness.testServerBuilder().start();

    testOk(first_server.config().tcp_port != second_server.config().tcp_port,
           "two test servers get distinct tcp_port: %u vs %u",
           (unsigned)first_server.config().tcp_port, (unsigned)second_server.config().tcp_port);
    testOk(first_server.config().tls_port != second_server.config().tls_port,
           "two test servers get distinct tls_port: %u vs %u",
           (unsigned)first_server.config().tls_port, (unsigned)second_server.config().tls_port);

    const auto &server_snapshot = harness.startedTestServers();
    testOk(server_snapshot.size() == 2,
           "snapshot table has 2 entries: %zu", server_snapshot.size());
}

void testStopTestServerRemovesFromSnapshot() {
    testDiag("stopTestServer() removes server from snapshot table");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto &first_server = harness.testServerBuilder().start();
    auto &second_server = harness.testServerBuilder().start();
    (void)second_server;

    const auto first_server_port = first_server.config().tcp_port;
    const auto second_server_port = second_server.config().tcp_port;
    testOk(harness.startedTestServers().size() == 2, "started 2 servers");

    harness.stopTestServer(first_server);

    const auto &snapshot_after_stop = harness.startedTestServers();
    testOk(snapshot_after_stop.size() == 1,
           "after stop, snapshot has 1 entry: %zu", snapshot_after_stop.size());
    testOk(snapshot_after_stop.front().tcp_port == second_server_port,
           "remaining entry is the second server (port %u), not first (port %u)",
           (unsigned)snapshot_after_stop.front().tcp_port, (unsigned)first_server_port);
}

void testTestClientConfigSnapshotSemantics() {
    testDiag("testClientConfig() snapshot semantics: includes servers started before the call");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto config_before_servers = harness.testClientConfig();
    const size_t address_count_before = config_before_servers.addressList.size();
    testDiag("before any test server: addressList size = %zu (PVACMS only)",
             address_count_before);

    auto &first_server = harness.testServerBuilder().start();
    (void)first_server;

    auto config_after_first_server = harness.testClientConfig();
    testOk(config_after_first_server.addressList.size()
               > config_before_servers.addressList.size(),
           "after starting 1 server: addressList grew (%zu -> %zu)",
           config_before_servers.addressList.size(),
           config_after_first_server.addressList.size());

    auto &second_server = harness.testServerBuilder().start();
    (void)second_server;

    auto config_after_two_servers = harness.testClientConfig();
    testOk(config_after_two_servers.addressList.size()
               > config_after_first_server.addressList.size(),
           "after starting 2nd server: addressList grew further (%zu -> %zu)",
           config_after_first_server.addressList.size(),
           config_after_two_servers.addressList.size());

    testOk(config_before_servers.addressList.size() == address_count_before,
           "snapshot semantic: config_before_servers still has its original addressList size");

    testOk(!config_after_two_servers.tls_keychain_file.empty(),
           "client Entity Cert path is set");
    testOk(config_after_two_servers.tls_keychain_file
               != config_before_servers.tls_keychain_file,
           "two testClientConfig() calls produce distinct client Entity Cert paths");
}

void testTestClientConfigIsLoopback() {
    testDiag("testClientConfig() produces a loopback-only client config");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();
    harness.testServerBuilder().start();
    auto client_config = harness.testClientConfig();
    try {
        sanityCheckLoopback(client_config);
        testPass("testClientConfig() passes sanityCheckLoopback");
    } catch (const std::exception &e) {
        testFail("testClientConfig() not loopback: %s", e.what());
    }
}

void testCustomizeFnAppliedPreBuild() {
    testDiag("TestServerBuilder::customize() callback fires before build");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    bool customize_called = false;
    uint16_t observed_tcp_port = 0xffff;
    auto &test_server = harness.testServerBuilder()
                    .customize([&](pvxs::server::Config &server_config) {
                        customize_called = true;
                        observed_tcp_port = server_config.tcp_port;
                    })
                    .start();
    (void)test_server;

    testOk(customize_called, "customize() lambda was invoked");
    testOk(observed_tcp_port == 0,
           "customize() saw tcp_port=0 (kernel-managed) before build: %u",
           (unsigned)observed_tcp_port);
}

void testWithPVRegisters() {
    testDiag("withPV() registers a PV that can be reached via testClientConfig");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto mailbox_pv = pvxs::server::SharedPV::buildMailbox();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &test_server = harness.testServerBuilder()
        .withPV("HARNESS:TEST:PV", mailbox_pv).start();
    (void)test_server;

    const auto &server_snapshot = harness.startedTestServers();
    testOk(server_snapshot.size() == 1, "PV-registered server appears in snapshot");
}

void testBuilderApplyEnvDefaultsFalse() {
    testDiag("Builder default ignores EPICS env vars (applyEnv=false)");
    setenv("EPICS_PVACMS_TLS_PORT", "5076", 1);
    setenv("EPICS_PVA_AUTO_ADDR_LIST", "YES", 1);

    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    testOk(harness.pvacmsTlsPort() != 5076,
           "harness ignored EPICS_PVACMS_TLS_PORT=5076 (got %u)",
           (unsigned)harness.pvacmsTlsPort());

    unsetenv("EPICS_PVACMS_TLS_PORT");
    unsetenv("EPICS_PVA_AUTO_ADDR_LIST");
}

void testBorrowedPkiFixture() {
    testDiag("Builder::pki() borrows an external fixture without owning it");
    PkiFixture external;
    const auto external_dir = external.dir();
    const auto external_fp = external.caFingerprintSha256();

    {
        PVACMSHarness::Builder builder;
        builder.pki(external);
        PVACMSHarness harness = builder.build();
        testOk(harness.pkiFixture().caFingerprintSha256() == external_fp,
               "harness uses the borrowed fixture's CA");
    }

    testOk(dirExists(external_dir),
           "external PkiFixture's temp dir survives harness destruction");
}

void testAllowExternalBindThrowsInCI() {
    testDiag("allowExternalBind() throws when CI=non-empty");
    setenv("CI", "true", 1);
    bool threw_when_ci_set = false;
    try {
        PVACMSHarness::Builder builder;
        builder.allowExternalBind();
        threw_when_ci_set = false;
    } catch (const std::exception &) {
        threw_when_ci_set = true;
    }
    testOk(threw_when_ci_set, "allowExternalBind() threw with CI=true");
    unsetenv("CI");
}

// =====================================================================
// ClusterTopology (38 assertions)
// =====================================================================

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

// =====================================================================
// MockClusterGateway lifecycle (4 assertions)
// =====================================================================

void testMockGatewayUpstreamRequired() {
    testDiag("MockClusterGateway constructor requires upstream_address");
    bool threw_when_upstream_missing = false;
    try {
        MockClusterGateway::Options opts;
        opts.upstream_address.clear();
        MockClusterGateway gw(opts);
        (void)gw;
    } catch (const std::exception &) {
        threw_when_upstream_missing = true;
    }
    testOk(threw_when_upstream_missing,
           "constructing MockClusterGateway without upstream_address throws");
}

void testMockGatewayStartStop() {
    testDiag("MockClusterGateway start/stop yields a populated listener address");
    MockClusterGateway::Options opts;
    opts.upstream_address = "127.0.0.1:9999";
    MockClusterGateway gw(opts);

    testOk(!gw.isRunning(), "gateway is not running before start()");

    gw.start();
    testOk(gw.isRunning(), "gateway is running after start()");
    testOk(!gw.listenAddress().empty(),
           "listenAddress() is populated after start(): %s",
           gw.listenAddress().c_str());

    gw.stop();
}

// =====================================================================
// PVACMSCluster (41 assertions; 41 cluster build/teardown cycles)
// =====================================================================

void testClusterDefaultFullMeshBuild() {
    testDiag("PVACMSCluster::Builder{}.size(2).build() produces 2-node fullMesh cluster");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    testOk(cluster.size() == 2, "Cluster size reported correctly as 2");
    testOk(cluster.topology().size() == 2, "Cluster topology size reported correctly as 2");
    testOk(cluster.topology().sees(0, 1), "node 0 sees node 1 in default full-mesh topology");
    testOk(cluster.topology().sees(1, 0), "node 1 sees node 0 in default full-mesh topology");

    const auto &member_addrs = cluster.memberAddrs();
    testOk(member_addrs.size() == 2, "Cluster reports 2 member listener addresses");
    testOk(!member_addrs[0].empty(), "node 0 listener address is populated");
    testOk(!member_addrs[1].empty(), "node 1 listener address is populated");
    testOk(member_addrs[0] != member_addrs[1], "node 0 and node 1 bound to distinct addresses");
    testDiag("Member 0 listener: %s", member_addrs[0].c_str());
    testDiag("Member 1 listener: %s", member_addrs[1].c_str());

    auto admin_client_config = cluster.cmsAdminClientConfig();
    testOk(admin_client_config.addressList.size() == 2,
           "admin client config addressList contains both members");
    testOk(!admin_client_config.tls_keychain_file.empty(),
           "admin client config has a TLS keychain file populated");
}

void testClusterLinearChainBuild() {
    testDiag("PVACMSCluster supports pre-partitioned linearChain(3)");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(3).topology(ClusterTopology::linearChain(3)).build();

    testOk(cluster.size() == 3, "Cluster size reported correctly as 3");
    testOk(cluster.topology().sees(0, 1), "linear-chain: node 0 sees adjacent node 1");
    testOk(cluster.topology().sees(1, 2), "linear-chain: node 1 sees adjacent node 2");
    testOk(!cluster.topology().sees(0, 2), "linear-chain: node 0 does NOT see non-adjacent node 2");
    testOk(!cluster.topology().sees(2, 0), "linear-chain: node 2 does NOT see non-adjacent node 0");
}

void testClusterEnvVarSuppression() {
    testDiag("PVACMSCluster::Builder::build() unsets EPICS_PVACMS_CLUSTER_NAME_SERVERS");

    setenv("EPICS_PVACMS_CLUSTER_NAME_SERVERS", "fake.host:5075", 1);
    setenv("EPICS_PVA_NAME_SERVERS", "bar.host:5075", 1);

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).build();

    testOk(getenv("EPICS_PVACMS_CLUSTER_NAME_SERVERS") == nullptr,
           "EPICS_PVACMS_CLUSTER_NAME_SERVERS was unset by Builder");
    testOk(getenv("EPICS_PVA_NAME_SERVERS") == nullptr,
           "EPICS_PVA_NAME_SERVERS was unset by Builder");

    const auto &member_addrs = cluster.memberAddrs();
    for (size_t i = 0; i < member_addrs.size(); ++i) {
        const auto &member_addr = member_addrs[i];
        testOk(member_addr.find("fake.host") == std::string::npos,
               "member %zu address does not contain stale env-var hostname \"fake.host\"", i);
        testOk(member_addr.find("bar.host") == std::string::npos,
               "member %zu address does not contain stale env-var hostname \"bar.host\"", i);
    }
}

void testClusterSetUnreachableTopologyMutation() {
    testDiag("ClusterTopology pair-mutation matches setUnreachable spec");

    auto topology = ClusterTopology::fullMesh(3);
    testOk(topology.sees(0, 1), "initial full-mesh: 0 sees 1");
    testOk(topology.sees(1, 2), "initial full-mesh: 1 sees 2");
    testOk(topology.sees(0, 2), "initial full-mesh: 0 sees 2");
    testOk(topology.sees(2, 0), "initial full-mesh: 2 sees 0");

    topology.removeBidirectional(0, 2);
    testOk(!topology.sees(0, 2), "after removeBidirectional(0,2): 0 no longer sees 2");
    testOk(!topology.sees(2, 0), "after removeBidirectional(0,2): 2 no longer sees 0");
    testOk(topology.sees(0, 1), "after removeBidirectional(0,2): 0->1 edge unchanged");
    testOk(topology.sees(1, 2), "after removeBidirectional(0,2): 1->2 edge unchanged");

    topology.addBidirectional(0, 2);
    testOk(topology.sees(0, 2), "after addBidirectional(0,2): 0 sees 2 again");
    testOk(topology.sees(2, 0), "after addBidirectional(0,2): 2 sees 0 again");
}

void testRestartMemberPreservesEntityCert() {
    testDiag("restartMember reuses the same P12 path (=> same Entity Cert)");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).clusterName("CERT:CLUSTER:RESTART").build();

    const auto p12_path_before_restart = cluster.memberP12Path(0);
    const auto addr_before_restart = cluster.memberAddrs()[0];

    cluster.restartMember(0);

    testOk(cluster.memberP12Path(0) == p12_path_before_restart,
           "node 0 keychain file path is unchanged after restart");
    testOk(cluster.size() == 2, "Cluster size still 2 after restart");
    testOk(!cluster.memberAddrs()[0].empty(),
           "node 0 listener address remains populated after restart");
    (void)addr_before_restart;
}

void testAdminClientSurvivesRestart() {
    testDiag("cmsAdminClientConfig client remains usable across restartMember");

    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).clusterName("CERT:CLUSTER:CLISURV").build();

    auto admin_client_config_before = cluster.cmsAdminClientConfig();
    testOk(admin_client_config_before.addressList.size() == 2,
           "pre-restart admin client config addressList contains both members");

    cluster.restartMember(0);

    auto admin_client_config_after = cluster.cmsAdminClientConfig();
    testOk(admin_client_config_after.addressList.size() == 2,
           "post-restart admin client config addressList contains both members");
    testOk(!admin_client_config_after.tls_keychain_file.empty(),
           "admin client config still has TLS keychain file populated after restart");
}

void testRestartMemberOutOfRange() {
    testDiag("restartMember rejects out-of-range index");
    PVACMSCluster::Builder builder;
    auto cluster = builder.size(2).clusterName("CERT:CLUSTER:OUTOFRANGE").build();
    bool threw_out_of_range = false;
    try {
        cluster.restartMember(5);
    } catch (const std::out_of_range &) {
        threw_out_of_range = true;
    }
    testOk(threw_out_of_range, "restartMember(5) on a 2-node cluster threw std::out_of_range");
}

void testBridgeRejectsUnbuiltCluster() {
    testDiag("bridge() throws std::logic_error if either cluster is unbuilt");

    PVACMSCluster::Builder builder_a;
    auto cluster_a = builder_a.size(2).clusterName("CERT:CLUSTER:K_A").build();

    PVACMSCluster unbuilt_cluster;

    bool threw_when_target_unbuilt = false;
    try {
        bridge(cluster_a, 0, unbuilt_cluster, 0);
    } catch (const std::logic_error &) {
        threw_when_target_unbuilt = true;
    }
    testOk(threw_when_target_unbuilt,
           "bridge(built, unbuilt) threw std::logic_error");

    bool threw_when_source_unbuilt = false;
    try {
        bridge(unbuilt_cluster, 0, cluster_a, 0);
    } catch (const std::logic_error &) {
        threw_when_source_unbuilt = true;
    }
    testOk(threw_when_source_unbuilt,
           "bridge(unbuilt, built) threw std::logic_error");
}

void testBridgeOutOfRange() {
    testDiag("bridge() rejects out-of-range node indices");

    PVACMSCluster::Builder builder_a;
    PVACMSCluster::Builder builder_b;
    auto cluster_a = builder_a.size(2).clusterName("CERT:CLUSTER:OOB_A").build();
    auto cluster_b = builder_b.size(2).clusterName("CERT:CLUSTER:OOB_B").build();

    bool threw_out_of_range = false;
    try {
        bridge(cluster_a, 99, cluster_b, 0);
    } catch (const std::out_of_range &) {
        threw_out_of_range = true;
    }
    testOk(threw_out_of_range,
           "bridge with src_index=99 on a 2-node cluster threw std::out_of_range");
}

}  // namespace

MAIN(testcmstestharness) {
    pvxs::logger_config_env();

    // Cluster build/teardown cycles do not complete within the macOS
    // GitHub-hosted runner's per-test timeout.  Run only the non-
    // cluster-build subset there; the local developer machine and
    // every Linux runner exercise the full suite.
#ifdef __APPLE__
    const bool skip_cluster_builds = (getenv("CI") != nullptr);
#else
    const bool skip_cluster_builds = false;
#endif

    if (skip_cluster_builds) {
        testPlan(108);
    } else {
        testPlan(149);
    }

    testFreshPerConstruction();
    testCaArtifacts();
    testIssueDistinctCerts();
    testTempDirCleanup();
    testBorrowedFixtureSharing();

    testInitOnce();
    testSanityCheckLoopback();
    testHarnessBuildAndDestruct();
    testTwoHarnessesDistinctPorts();
    testCmsAdminClientConfigIsLoopback();
    testTestServerBuilderProducesIsolatedServer();
    testTwoTestServersDistinctPorts();
    testStopTestServerRemovesFromSnapshot();
    testTestClientConfigSnapshotSemantics();
    testTestClientConfigIsLoopback();
    testCustomizeFnAppliedPreBuild();
    testWithPVRegisters();
    testBuilderApplyEnvDefaultsFalse();
    testBorrowedPkiFixture();
    testAllowExternalBindThrowsInCI();

    testTopologyValueType();
    testTopologyMutators();
    testPeersSeenBy();
    testTopologyOutOfRange();

    testMockGatewayUpstreamRequired();
    testMockGatewayStartStop();

    if (!skip_cluster_builds) {
        testClusterDefaultFullMeshBuild();
        testClusterLinearChainBuild();
        testClusterEnvVarSuppression();
        testClusterSetUnreachableTopologyMutation();
        testRestartMemberPreservesEntityCert();
        testAdminClientSurvivesRestart();
        testRestartMemberOutOfRange();
        testBridgeRejectsUnbuiltCluster();
        testBridgeOutOfRange();
    }

    return testDone();
}
