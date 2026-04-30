/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <chrono>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include "testharness.h"
#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/data.h>
#include <pvxs/nt.h>

namespace {

using cms::test::PkiFixture;
using cms::test::PVACMSHarness;
using cms::test::TestClientOpts;
using cms::test::TestServerOpts;
using cms::test::sanityCheckLoopback;

bool dirExists(const std::string &path) {
    struct stat path_stat;
    return ::stat(path.c_str(), &path_stat) == 0 && S_ISDIR(path_stat.st_mode);
}

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

}  // namespace

MAIN(testharness) {
    testPlan(44);
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
    return testDone();
}
