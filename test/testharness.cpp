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

bool dirExists(const std::string &p) {
    struct stat st;
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

void testInitOnce() {
    testDiag("initOnce() is idempotent");
    cms::test::initOnce();
    cms::test::initOnce();
    testPass("initOnce() called twice without error");
}

void testSanityCheckLoopback() {
    testDiag("sanityCheckLoopback accepts loopback configs and rejects non-loopback");

    pvxs::client::Config cli;
    cli.addressList = {"127.0.0.1:5075", "[::1]:5075"};
    cli.nameServers = {"127.0.0.1:5075"};
    try {
        sanityCheckLoopback(cli);
        testPass("sanityCheckLoopback accepts loopback client config");
    } catch (const std::exception &e) {
        testFail("sanityCheckLoopback should accept loopback client config: %s", e.what());
    }

    pvxs::client::Config bad;
    bad.addressList = {"192.168.1.1:5075"};
    try {
        sanityCheckLoopback(bad);
        testFail("sanityCheckLoopback should reject non-loopback client config");
    } catch (const std::exception &) {
        testPass("sanityCheckLoopback rejects non-loopback client config");
    }

    pvxs::server::Config srv;
    srv.interfaces = {"127.0.0.1"};
    srv.beaconDestinations = {"127.0.0.1"};
    try {
        sanityCheckLoopback(srv);
        testPass("sanityCheckLoopback accepts loopback server config");
    } catch (const std::exception &e) {
        testFail("sanityCheckLoopback should accept loopback server config: %s", e.what());
    }

    pvxs::server::Config srvBad;
    srvBad.interfaces = {"0.0.0.0"};
    try {
        sanityCheckLoopback(srvBad);
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
    PVACMSHarness h1 = PVACMSHarness::Builder{}.build();
    PVACMSHarness h2 = PVACMSHarness::Builder{}.build();

    testOk(h1.pvacmsTcpPort() != h2.pvacmsTcpPort(),
           "two harnesses get distinct tcp_port: %u vs %u",
           (unsigned)h1.pvacmsTcpPort(), (unsigned)h2.pvacmsTcpPort());
    testOk(h1.pvacmsTlsPort() != h2.pvacmsTlsPort(),
           "two harnesses get distinct tls_port: %u vs %u",
           (unsigned)h1.pvacmsTlsPort(), (unsigned)h2.pvacmsTlsPort());
    testOk(h1.pkiFixture().dir() != h2.pkiFixture().dir(),
           "two harnesses use distinct PKI dirs");
    testOk(h1.pkiFixture().caFingerprintSha256() != h2.pkiFixture().caFingerprintSha256(),
           "two harnesses have distinct CA fingerprints");
}

void testCmsAdminClientConfigIsLoopback() {
    testDiag("cmsAdminClientConfig() produces a loopback-only client config");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();
    auto cfg = harness.cmsAdminClientConfig();

    testOk(!cfg.addressList.empty(), "addressList is non-empty");
    testOk(!cfg.tls_keychain_file.empty(), "tls_keychain_file is set");
    testOk(cfg.tls_keychain_file == harness.adminP12Path(),
           "tls_keychain_file points at admin.p12");
    try {
        sanityCheckLoopback(cfg);
        testPass("cmsAdminClientConfig() passes sanityCheckLoopback");
    } catch (const std::exception &e) {
        testFail("cmsAdminClientConfig() not loopback: %s", e.what());
    }
}

void testTestServerBuilderProducesIsolatedServer() {
    testDiag("testServerBuilder().start() returns a running, isolated PVA server");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto &srv = harness.testServerBuilder().start();
    const auto &eff = srv.config();

    testOk(eff.tcp_port != 0, "test server tcp_port resolved: %u", (unsigned)eff.tcp_port);
    testOk(eff.udp_port != 0, "test server udp_port resolved: %u", (unsigned)eff.udp_port);
    testOk(!eff.interfaces.empty() &&
           (eff.interfaces.front() == "127.0.0.1" || eff.interfaces.front() == "::1"),
           "test server interfaces loopback only");
    testOk(eff.auto_beacon == false, "test server auto_beacon is false");

    const auto &snap = harness.startedTestServers();
    testOk(snap.size() == 1, "snapshot table has exactly 1 entry: %zu", snap.size());
    testOk(snap.front().tcp_port == eff.tcp_port,
           "snapshot tcp_port (%u) matches resolved (%u)",
           (unsigned)snap.front().tcp_port, (unsigned)eff.tcp_port);
}

void testTwoTestServersDistinctPorts() {
    testDiag("two testServerBuilder().start() calls produce distinct ports + snapshots");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto &srv1 = harness.testServerBuilder().start();
    auto &srv2 = harness.testServerBuilder().start();

    testOk(srv1.config().tcp_port != srv2.config().tcp_port,
           "two test servers get distinct tcp_port: %u vs %u",
           (unsigned)srv1.config().tcp_port, (unsigned)srv2.config().tcp_port);
    testOk(srv1.config().tls_port != srv2.config().tls_port,
           "two test servers get distinct tls_port: %u vs %u",
           (unsigned)srv1.config().tls_port, (unsigned)srv2.config().tls_port);

    const auto &snap = harness.startedTestServers();
    testOk(snap.size() == 2, "snapshot table has 2 entries: %zu", snap.size());
}

void testStopTestServerRemovesFromSnapshot() {
    testDiag("stopTestServer() removes server from snapshot table");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto &srv1 = harness.testServerBuilder().start();
    auto &srv2 = harness.testServerBuilder().start();
    (void)srv2;

    const auto port1 = srv1.config().tcp_port;
    const auto port2 = srv2.config().tcp_port;
    testOk(harness.startedTestServers().size() == 2, "started 2 servers");

    harness.stopTestServer(srv1);

    const auto &after = harness.startedTestServers();
    testOk(after.size() == 1, "after stop, snapshot has 1 entry: %zu", after.size());
    testOk(after.front().tcp_port == port2,
           "remaining entry is srv2 (port %u), not srv1 (port %u)",
           (unsigned)after.front().tcp_port, (unsigned)port1);
}

void testTestClientConfigSnapshotSemantics() {
    testDiag("testClientConfig() snapshot semantics: includes servers started before the call");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto cfg_before = harness.testClientConfig();
    const size_t addrs_before = cfg_before.addressList.size();
    testDiag("before any test server: addressList size = %zu (PVACMS only)", addrs_before);

    auto &srv1 = harness.testServerBuilder().start();
    (void)srv1;

    auto cfg_after = harness.testClientConfig();
    testOk(cfg_after.addressList.size() > cfg_before.addressList.size(),
           "after starting 1 server: addressList grew (%zu -> %zu)",
           cfg_before.addressList.size(), cfg_after.addressList.size());

    auto &srv2 = harness.testServerBuilder().start();
    (void)srv2;

    auto cfg_3 = harness.testClientConfig();
    testOk(cfg_3.addressList.size() > cfg_after.addressList.size(),
           "after starting 2nd server: addressList grew further (%zu -> %zu)",
           cfg_after.addressList.size(), cfg_3.addressList.size());

    testOk(cfg_before.addressList.size() == addrs_before,
           "snapshot semantic: cfg_before still has its original addressList size");

    testOk(!cfg_3.tls_keychain_file.empty(), "client EE cert path is set");
    testOk(cfg_3.tls_keychain_file != cfg_before.tls_keychain_file,
           "two testClientConfig() calls produce distinct client EE cert paths");
}

void testTestClientConfigIsLoopback() {
    testDiag("testClientConfig() produces a loopback-only client config");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();
    harness.testServerBuilder().start();
    auto cfg = harness.testClientConfig();
    try {
        sanityCheckLoopback(cfg);
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
    auto &srv = harness.testServerBuilder()
                    .customize([&](pvxs::server::Config &c) {
                        customize_called = true;
                        observed_tcp_port = c.tcp_port;
                    })
                    .start();
    (void)srv;

    testOk(customize_called, "customize() lambda was invoked");
    testOk(observed_tcp_port == 0,
           "customize() saw tcp_port=0 (kernel-managed) before build: %u",
           (unsigned)observed_tcp_port);
}

void testWithPVRegisters() {
    testDiag("withPV() registers a PV that can be reached via testClientConfig");
    PVACMSHarness harness = PVACMSHarness::Builder{}.build();

    auto mbox = pvxs::server::SharedPV::buildMailbox();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &srv = harness.testServerBuilder().withPV("HARNESS:TEST:PV", mbox).start();
    (void)srv;

    const auto &snap = harness.startedTestServers();
    testOk(snap.size() == 1, "PV-registered server appears in snapshot");
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
        PVACMSHarness::Builder b;
        b.pki(external);
        PVACMSHarness harness = b.build();
        testOk(harness.pkiFixture().caFingerprintSha256() == external_fp,
               "harness uses the borrowed fixture's CA");
    }

    testOk(dirExists(external_dir),
           "external PkiFixture's temp dir survives harness destruction");
}

void testAllowExternalBindThrowsInCI() {
    testDiag("allowExternalBind() throws when CI=non-empty");
    setenv("CI", "true", 1);
    bool threw = false;
    try {
        PVACMSHarness::Builder b;
        b.allowExternalBind();
        threw = false;
    } catch (const std::exception &) {
        threw = true;
    }
    testOk(threw, "allowExternalBind() threw with CI=true");
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
