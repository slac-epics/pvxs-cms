/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/cms/testharness.h>
#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/unittest.h>

namespace {

using cms::test::PVACMSHarness;
using cms::test::TestServerOpts;

const char *TEST_PV = "TEST:HARNESS:PV";

void testServerOnly() {
    testDiag("=== testServerOnly: server with EE cert, client with admin cert only ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &srv = harness.testServerBuilder()
                    .opts([]{ TestServerOpts o; o.subject = "migrated-server-only"; return o; }())
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli = harness.testClientConfig().build();

    int32_t value = -1;
    bool got = false;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }
    testOk(got, "testServerOnly: GET via TLS+PVACMS succeeded");
    if (got) testEq(value, 42);

    testTrue(harness.totalSubscribes() >= 2);
    testTrue(harness.totalStatusReceived() >= 2);
    testDiag("subscribes=%u, deliveries=%u, cache-hits=%u",
             harness.totalSubscribes(),
             harness.totalDeliveries(),
             harness.totalCacheHits());
}

void testGetIntermediate() {
    testDiag("=== testGetIntermediate: mutual TLS, both server and client have EE certs ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &srv = harness.testServerBuilder()
                    .opts([]{ TestServerOpts o; o.subject = "migrated-mutual-server"; o.clientCertRequired = true; return o; }())
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli = harness.testClientConfig().build();

    int32_t value = -1;
    bool got = false;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }
    testOk(got, "testGetIntermediate: mutual-TLS GET succeeded");
    if (got) testEq(value, 42);

    testTrue(harness.totalSubscribes() >= 4);
    testTrue(harness.totalStatusReceived() >= 2);

    const auto pvs = harness.observedStatusPvs();
    testTrue(pvs.size() >= 2);

    testDiag("Mutual-TLS observation: 4 subscribes (server-entity, server-peer-of-client,");
    testDiag("client-entity, client-peer-of-server) but only %u status receipts.",
             harness.totalStatusReceived());
    testDiag("Some subscribes don't deliver in the brief test window.  Per-cert");
    testDiag("breakdown follows for diagnostics.");
    testDiag("Observed %zu unique CERT:STATUS PVs (>=2 expected: server EE + client EE)",
             pvs.size());

    for (const auto &pv : pvs) {
        testTrue(harness.subscribesFor(pv) >= 2);
    }
}

void testCertStatusGating() {
    testDiag("=== testCertStatusGating: GET only succeeds after status received for both certs ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{99}));

    auto &srv = harness.testServerBuilder()
                    .opts([]{ TestServerOpts o; o.subject = "gating-server"; o.clientCertRequired = true; return o; }())
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli = harness.testClientConfig().build();

    int32_t value = -1;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
    } catch (const std::exception &e) {
        testFail("Gating: GET failed: %s", e.what());
    }
    testEq(value, 99);

    const auto pvs = harness.observedStatusPvs();
    testOk(!pvs.empty(), "at least one CERT:STATUS PV observed");
    for (const auto &pv : pvs) {
        const auto received = harness.statusReceivedFor(pv);
        testTrue(received >= 1);
        testDiag("  %s status_received=%u (gating contract: GET-time -> received >= 1)",
                 pv.c_str(), received);
    }
}

void testTlsCredentialsOnConnect() {
    testDiag("=== testTlsCredentialsOnConnect: client receives isTLS credentials on connect ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{77}));

    auto &srv = harness.testServerBuilder()
                    .opts([]{ TestServerOpts o; o.subject = "creds-server"; o.clientCertRequired = true; return o; }())
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli = harness.testClientConfig().build();

    std::atomic<bool> saw_tls{false};
    std::atomic<bool> saw_connect{false};
    auto conn = cli.connect(TEST_PV)
                    .onConnect([&](const pvxs::client::Connected &c) {
                        saw_connect.store(true);
                        if (c.cred && c.cred->isTLS) saw_tls.store(true);
                        testDiag("onConnect: isTLS=%d method=%s account=%s",
                                 c.cred && c.cred->isTLS ? 1 : 0,
                                 c.cred ? c.cred->method.c_str() : "<null>",
                                 c.cred ? c.cred->account.c_str() : "<null>");
                    })
                    .exec();

    int32_t value = -1;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }
    testEq(value, 77);
    testOk(saw_connect.load(), "client received onConnect callback");
    testOk(saw_tls.load(), "onConnect credentials reported isTLS");
    conn.reset();
}

void testCacheHitOnRepeatedSubscribe() {
    testDiag("=== testCacheHitOnRepeatedSubscribe: same role re-subscribes same cert -> cache hit ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{1}));

    auto &srv = harness.testServerBuilder()
                    .opts([]{ TestServerOpts o; o.subject = "cache-hit-server"; o.clientCertRequired = true; return o; }())
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli_cfg = harness.testClientConfig();

    auto cli1 = cli_cfg.build();
    try {
        cli1.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const uint32_t hits_after_first = harness.totalCacheHits();

    auto cli2 = cli_cfg.build();
    try {
        cli2.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const uint32_t hits_after_second = harness.totalCacheHits();

    testTrue(hits_after_second > hits_after_first);
    testDiag("cache hits: after 1st client = %u, after 2nd client = %u (delta = %u)",
             hits_after_first, hits_after_second, hits_after_second - hits_after_first);
}

void testNoCacheBleedAcrossRoles() {
    testDiag("=== testNoCacheBleedAcrossRoles: server/client per-role caches do not bleed ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{7}));

    auto &srv = harness.testServerBuilder()
                    .opts([]{ TestServerOpts o; o.subject = "isolation-server"; o.clientCertRequired = true; return o; }())
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli = harness.testClientConfig().build();
    try {
        cli.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    testDiag("After single GET: subscribes=%u deliveries=%u cache_hits=%u",
             harness.totalSubscribes(),
             harness.totalDeliveries(),
             harness.totalCacheHits());

    testTrue(harness.totalCacheHits() == 0);
}

}  // namespace

MAIN(testtlswithcmsmigrated) {
    testPlan(20);
    pvxs::logger_config_env();
    testServerOnly();
    testGetIntermediate();
    testCertStatusGating();
    testTlsCredentialsOnConnect();
    testCacheHitOnRepeatedSubscribe();
    testNoCacheBleedAcrossRoles();
    return testDone();
}
