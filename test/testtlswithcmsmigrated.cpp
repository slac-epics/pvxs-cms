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
#include "testharness.h"
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
    testDiag("=== testServerOnly: server with Entity Cert, client with admin cert only ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "migrated-server-only";
                        return server_opts;
                    }())
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client = harness.testClientConfig().build();

    int32_t reply_value = -1;
    bool get_succeeded = false;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
        get_succeeded = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }
    testOk(get_succeeded, "testServerOnly: GET via TLS+PVACMS succeeded");
    if (get_succeeded) {
        testOk(reply_value == 42,
               "GET reply value matches the value the server published (42)");
    }

#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    testOk(harness.totalSubscribes() >= 2,
           "totalSubscribes >= 2 (got %u)", harness.totalSubscribes());
    testOk(harness.totalStatusReceived() >= 2,
           "totalStatusReceived >= 2 (got %u)", harness.totalStatusReceived());
#endif
    testDiag("subscribes=%u, deliveries=%u, cache-hits=%u",
             harness.totalSubscribes(),
             harness.totalDeliveries(),
             harness.totalCacheHits());
}

void testGetIntermediate() {
    testDiag("=== testGetIntermediate: mutual TLS, both server and client have Entity Certs ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "migrated-mutual-server";
                        server_opts.clientCertRequired = true;
                        return server_opts;
                    }())
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client = harness.testClientConfig().build();

    int32_t reply_value = -1;
    bool get_succeeded = false;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
        get_succeeded = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }
    testOk(get_succeeded, "testGetIntermediate: mutual-TLS GET succeeded");
    if (get_succeeded) {
        testOk(reply_value == 42,
               "mutual-TLS GET reply value matches the value the server published (42)");
    }

    const auto observed_status_pvs = harness.observedStatusPvs();

#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    testOk(harness.totalSubscribes() >= 4,
           "totalSubscribes >= 4 for mutual-TLS (got %u)", harness.totalSubscribes());
    testOk(harness.totalStatusReceived() >= 2,
           "totalStatusReceived >= 2 for mutual-TLS (got %u)",
           harness.totalStatusReceived());
    testOk(observed_status_pvs.size() >= 2,
           "at least 2 unique CERT:STATUS PVs observed (got %zu)",
           observed_status_pvs.size());
    for (const auto &status_pv : observed_status_pvs) {
        testOk(harness.subscribesFor(status_pv) >= 2,
               "%s has >= 2 subscribes (got %u)",
               status_pv.c_str(), harness.subscribesFor(status_pv));
    }
#endif

    testDiag("Mutual-TLS observation: subscribes=%u status_received=%u unique_pvs=%zu",
             harness.totalSubscribes(),
             harness.totalStatusReceived(),
             observed_status_pvs.size());
}

void testCertStatusGating() {
    testDiag("=== testCertStatusGating: GET only succeeds after status received for both certs ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{99}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "gating-server";
                        server_opts.clientCertRequired = true;
                        return server_opts;
                    }())
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client = harness.testClientConfig().build();

    int32_t reply_value = -1;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
    } catch (const std::exception &e) {
        testFail("Gating: GET failed: %s", e.what());
    }
    testOk(reply_value == 99,
           "Gating: GET reply value matches the value the server published (99)");

#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    const auto observed_status_pvs = harness.observedStatusPvs();
    testOk(!observed_status_pvs.empty(), "at least one CERT:STATUS PV observed");
    for (const auto &status_pv : observed_status_pvs) {
        const auto received_count = harness.statusReceivedFor(status_pv);
        testOk(received_count >= 1,
               "%s status_received >= 1 (got %u)", status_pv.c_str(), received_count);
        testDiag("  %s status_received=%u (gating contract: GET-time -> received >= 1)",
                 status_pv.c_str(), received_count);
    }
#endif
}

void testTlsCredentialsOnConnect() {
    testDiag("=== testTlsCredentialsOnConnect: client receives isTLS credentials on connect ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{77}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "creds-server";
                        server_opts.clientCertRequired = true;
                        return server_opts;
                    }())
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client = harness.testClientConfig().build();

    std::atomic<bool> on_connect_saw_tls{false};
    std::atomic<bool> on_connect_fired{false};
    auto connect_handle = client.connect(TEST_PV)
                    .onConnect([&](const pvxs::client::Connected &connected_event) {
                        on_connect_fired.store(true);
                        if (connected_event.cred && connected_event.cred->isTLS) {
                            on_connect_saw_tls.store(true);
                        }
                        testDiag("onConnect: isTLS=%d method=%s account=%s",
                                 connected_event.cred && connected_event.cred->isTLS ? 1 : 0,
                                 connected_event.cred
                                     ? connected_event.cred->method.c_str() : "<null>",
                                 connected_event.cred
                                     ? connected_event.cred->account.c_str() : "<null>");
                    })
                    .exec();

    int32_t reply_value = -1;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }
    testOk(reply_value == 77,
           "TLS-creds GET reply value matches the value the server published (77)");
    testOk(on_connect_fired.load(), "client received onConnect callback");
    testOk(on_connect_saw_tls.load(), "onConnect credentials reported isTLS");
    connect_handle.reset();
}

void testCacheHitOnRepeatedSubscribe() {
    testDiag("=== testCacheHitOnRepeatedSubscribe: same role re-subscribes same cert -> cache hit ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{1}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "cache-hit-server";
                        server_opts.clientCertRequired = true;
                        return server_opts;
                    }())
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client_config = harness.testClientConfig();

    auto first_client = client_config.build();
    try {
        first_client.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const uint32_t cache_hits_after_first_client = harness.totalCacheHits();

    auto second_client = client_config.build();
    try {
        second_client.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const uint32_t cache_hits_after_second_client = harness.totalCacheHits();

#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    testOk(cache_hits_after_second_client > cache_hits_after_first_client,
           "second client (same role, same cert) added cache hits: %u -> %u",
           cache_hits_after_first_client, cache_hits_after_second_client);
#endif
    testDiag("cache hits: after 1st client = %u, after 2nd client = %u (delta = %u)",
             cache_hits_after_first_client,
             cache_hits_after_second_client,
             cache_hits_after_second_client - cache_hits_after_first_client);
}

void testNoCacheBleedAcrossRoles() {
    testDiag("=== testNoCacheBleedAcrossRoles: server/client per-role caches do not bleed ===");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{7}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "isolation-server";
                        server_opts.clientCertRequired = true;
                        return server_opts;
                    }())
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client = harness.testClientConfig().build();
    try {
        client.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    testDiag("After single GET: subscribes=%u deliveries=%u cache_hits=%u",
             harness.totalSubscribes(),
             harness.totalDeliveries(),
             harness.totalCacheHits());

    testOk(harness.totalCacheHits() == 0,
           "no cross-role cache bleed: server cache and client cache stay isolated (got %u hits)",
           harness.totalCacheHits());
}

}  // namespace

MAIN(testtlswithcmsmigrated) {
#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    testPlan(20);
#else
    testPlan(9);
#endif
    pvxs::logger_config_env();
    testServerOnly();
    testGetIntermediate();
    testCertStatusGating();
    testTlsCredentialsOnConnect();
    testCacheHitOnRepeatedSubscribe();
    testNoCacheBleedAcrossRoles();
    return testDone();
}
