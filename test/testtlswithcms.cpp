/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Tests the TLS data-plane wired through PVACMS:
//   * stapling on/off matrix between client and server
//   * server-with-Entity-Cert + client-with-admin-cert flows
//   * mutual-TLS with both ends presenting Entity Certs
//   * cert-status gating (GET returns only after status received)
//   * status-event counter API (subscribesFor, deliveriesFor, etc.)
//   * cache-hit and cross-role-isolation invariants
//
// All tests use the in-process PVACMS harness (test/harness/) which
// provides loopback-isolated PVACMS, ephemeral PKI, and per-test
// status-event counters.

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <pvxs/config.h>
#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/unittest.h>

#include "testharness.h"

namespace {

using cms::test::PVACMSHarness;
using cms::test::TestServerOpts;

const char *TEST_PV = "TEST:HARNESS:PV";

// =====================================================================
// OCSP stapling matrix (client x server: enabled / disabled)
// =====================================================================

struct SubCounter {
    std::mutex mu;
    std::map<std::string, uint32_t> counts;

    void operator()(const std::string &pv) {
        std::lock_guard<std::mutex> lk(mu);
        ++counts[pv];
    }

    uint32_t total() {
        std::lock_guard<std::mutex> lk(mu);
        uint32_t sum = 0;
        for (auto &kv : counts) sum += kv.second;
        return sum;
    }
};

void testStaplingDisabledOnServer() {
    testDiag("Server with stapling disabled - GET via PVACMS still succeeds");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder builder;
    builder.observeStatusSubscriptions(
        [counter](const std::string &pv) { (*counter)(pv); });
    auto harness = builder.build();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts server_opts;
    server_opts.subject = "stapling-disabled-server";
    auto &test_server = harness.testServerBuilder()
                    .opts(server_opts)
                    .customize([](pvxs::server::Config &server_config) {
                        server_config.disableStapling(true);
                    })
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    testOk(test_server.config().isStaplingDisabled(),
           "server reports stapling disabled (matches customize() override)");

    auto client_config = harness.testClientConfig();
    client_config.disableStapling(false);
    auto client = client_config.build();

    bool get_succeeded = false;
    int32_t reply_value = -1;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
        get_succeeded = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(get_succeeded, "GET succeeded with server-side stapling disabled");
    if (get_succeeded) {
        testOk(reply_value == 42,
               "GET reply value matches the value the server published (42)");
    }
}

void testStaplingEnabledOnServer() {
    testDiag("Server with stapling enabled - GET via PVACMS succeeds");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder builder;
    builder.observeStatusSubscriptions(
        [counter](const std::string &pv) { (*counter)(pv); });
    auto harness = builder.build();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts server_opts;
    server_opts.subject = "stapling-enabled-server";
    auto &test_server = harness.testServerBuilder()
                    .opts(server_opts)
                    .customize([](pvxs::server::Config &server_config) {
                        server_config.disableStapling(false);
                    })
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    testOk(!test_server.config().isStaplingDisabled(),
           "server reports stapling enabled (matches customize() override)");

    auto client_config = harness.testClientConfig();
    client_config.disableStapling(false);
    auto client = client_config.build();

    bool get_succeeded = false;
    int32_t reply_value = -1;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
        get_succeeded = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(get_succeeded, "GET succeeded with server-side stapling enabled");
    if (get_succeeded) {
        testOk(reply_value == 42,
               "GET reply value matches the value the server published (42)");
    }
}

void testClientStaplingNoServerStapling() {
    testDiag("Client requests stapling but server does not - falls back to PVACMS");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder builder;
    builder.observeStatusSubscriptions(
        [counter](const std::string &pv) { (*counter)(pv); });
    auto harness = builder.build();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts server_opts;
    server_opts.subject = "no-staple-server";
    auto &test_server = harness.testServerBuilder()
                    .opts(server_opts)
                    .customize([](pvxs::server::Config &server_config) {
                        server_config.disableStapling(true);
                    })
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client_config = harness.testClientConfig();
    client_config.disableStapling(false);
    auto client = client_config.build();

    bool get_succeeded = false;
    int32_t reply_value = -1;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
        get_succeeded = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(get_succeeded,
           "client expecting stapling -> server not stapling -> GET still succeeds");
    if (get_succeeded) {
        testOk(reply_value == 42,
               "GET reply value matches the value the server published (42)");
    }
}

void testServerStaplingNoClientStapling() {
    testDiag("Server staples but client does not expect it - falls back to PVACMS");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder builder;
    builder.observeStatusSubscriptions(
        [counter](const std::string &pv) { (*counter)(pv); });
    auto harness = builder.build();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts server_opts;
    server_opts.subject = "staple-server";
    auto &test_server = harness.testServerBuilder()
                    .opts(server_opts)
                    .customize([](pvxs::server::Config &server_config) {
                        server_config.disableStapling(false);
                    })
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client_config = harness.testClientConfig();
    client_config.disableStapling(true);
    auto client = client_config.build();

    bool get_succeeded = false;
    int32_t reply_value = -1;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
        get_succeeded = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(get_succeeded,
           "server stapling -> client not expecting -> GET still succeeds");
    if (get_succeeded) {
        testOk(reply_value == 42,
               "GET reply value matches the value the server published (42)");
    }
}

// =====================================================================
// Server-with-Entity-Cert + status-event counter API
// =====================================================================

void testServerOnlyWithCounters() {
    testDiag("Server with Entity Cert, client with admin cert; status-event counters");

    PVACMSHarness::Builder builder;
    auto harness = builder.build();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts server_opts;
    server_opts.subject = "harness-server-1";
    auto &test_server = harness.testServerBuilder()
                    .opts(server_opts)
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client_config = harness.testClientConfig();
    auto client = client_config.build();

    int32_t reply_value = -1;
    bool get_succeeded = false;
    try {
        auto reply = client.get(TEST_PV).exec()->wait(10.0);
        reply_value = reply["value"].as<int32_t>();
        get_succeeded = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(get_succeeded, "GET returned a value through full TLS+PVACMS flow");
    if (get_succeeded) {
        testOk(reply_value == 42,
               "GET reply value matches the value the server published (42)");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const auto &issuer = harness.pvacmsIssuerId();
    testDiag("Issuer ID: %s", issuer.c_str());

    uint32_t total_subscribes = 0;
    uint32_t total_deliveries = 0;
    int unique_status_pvs = 0;

    {
        const auto &server_snapshot = harness.startedTestServers();
        testDiag("startedTestServers().size() = %zu", server_snapshot.size());
    }

    const auto observed_status_pvs = harness.observedStatusPvs();
    uint32_t total_cache_hits = 0;
    for (const auto &status_pv : observed_status_pvs) {
        const auto subscribes = harness.subscribesFor(status_pv);
        const auto deliveries = harness.deliveriesFor(status_pv);
        const auto cache_hits = harness.cacheHitsFor(status_pv);
        testDiag("  observed pv=%s  subscribes=%u  deliveries=%u  cache-hits=%u",
                 status_pv.c_str(), subscribes, deliveries, cache_hits);
        total_subscribes += subscribes;
        total_deliveries += deliveries;
        total_cache_hits += cache_hits;
        ++unique_status_pvs;
    }
    testOk(total_subscribes == harness.totalSubscribes(),
           "per-PV subscribe counts sum to harness totalSubscribes() (got %u, expected %u)",
           total_subscribes, harness.totalSubscribes());
    testOk(total_deliveries == harness.totalDeliveries(),
           "per-PV delivery counts sum to harness totalDeliveries() (got %u, expected %u)",
           total_deliveries, harness.totalDeliveries());
    testOk(total_cache_hits == harness.totalCacheHits(),
           "per-PV cache-hit counts sum to harness totalCacheHits() (got %u, expected %u)",
           total_cache_hits, harness.totalCacheHits());
    testOk(total_deliveries >= total_cache_hits,
           "deliveries (%u) >= cache_hits (%u): cache hits cannot exceed total deliveries",
           total_deliveries, total_cache_hits);
    testDiag("Invariant: deliveries (%u) = live (%u) + cache-hits (%u)",
             total_deliveries, total_deliveries - total_cache_hits, total_cache_hits);

#ifdef PVXS_HAS_DISK_OCSP_CACHE
    // The cert-status subscribe/deliver counters depend on pvxs's
    // per-role cache-dir override; on older pvxs without it, the shared
    // cache may pre-populate and the assertions below would underreport.
    testOk(total_subscribes >= 2,
           "Total cert-status subscribes >= 2 (got %u)", total_subscribes);
    testOk(total_deliveries >= 1,
           "Total cert-status deliveries >= 1 (got %u)", total_deliveries);
    testOk(unique_status_pvs >= 1,
           "At least one unique cert-status PV had activity (got %d)", unique_status_pvs);
#endif
    testDiag("Observed: subs=%u dels=%u unique_pvs=%d",
             total_subscribes, total_deliveries, unique_status_pvs);
}

void testCounterAPIBasics() {
    testDiag("Harness counter API basics: subscribesFor / deliveriesFor / waitX / reset");

    PVACMSHarness::Builder builder;
    auto harness = builder.build();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{1}));

    TestServerOpts server_opts;
    server_opts.subject = "counter-api-server";
    auto &test_server = harness.testServerBuilder()
                    .opts(server_opts)
                    .withPV(TEST_PV, mailbox_pv)
                    .start();
    (void)test_server;

    auto client = harness.testClientConfig().build();
    try {
        client.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const auto unknown_status_pv = std::string("CERT:STATUS:nonexistent:9999");
    testOk(harness.subscribesFor(unknown_status_pv) == 0,
           "unknown PV reports 0 subscribes");
    testOk(harness.deliveriesFor(unknown_status_pv) == 0,
           "unknown PV reports 0 deliveries");

    testOk(!harness.waitSubscribesAtLeast(unknown_status_pv, 1, 0.05),
           "waitSubscribesAtLeast returns false on timeout for unknown PV");
    testOk(!harness.waitDeliveriesAtLeast(unknown_status_pv, 1, 0.05),
           "waitDeliveriesAtLeast returns false on timeout for unknown PV");
    testOk(!harness.waitCacheHitsAtLeast(unknown_status_pv, 1, 0.05),
           "waitCacheHitsAtLeast returns false on timeout for unknown PV");

    testOk(harness.cacheHitsFor(unknown_status_pv) == 0,
           "unknown PV reports 0 cache hits");

    harness.resetStatusEventCounters();
    testOk(harness.subscribesFor(unknown_status_pv) == 0,
           "after reset: unknown PV still reports 0 subscribes");
    testOk(harness.cacheHitsFor(unknown_status_pv) == 0,
           "after reset: unknown PV still reports 0 cache hits");
}

// =====================================================================
// End-to-end TLS + cert-status flows
// =====================================================================

void testServerOnly() {
    testDiag("server with Entity Cert, client with admin cert only");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "server-only-flow";
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

#ifdef PVXS_HAS_DISK_OCSP_CACHE
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
    testDiag("mutual TLS, both server and client have Entity Certs");

    auto harness = PVACMSHarness::Builder{}.build();
    harness.resetStatusEventCounters();

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    auto &test_server = harness.testServerBuilder()
                    .opts([]{
                        TestServerOpts server_opts;
                        server_opts.subject = "mutual-tls-server";
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

#ifdef PVXS_HAS_DISK_OCSP_CACHE
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
    testDiag("GET succeeds only after status received for both ends' certs");

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

#ifdef PVXS_HAS_DISK_OCSP_CACHE
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
    testDiag("client receives isTLS credentials on connect");

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
    testDiag("same role re-subscribes same cert -> cache hit");

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

#ifdef PVXS_HAS_DISK_OCSP_CACHE
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
    testDiag("server/client per-role caches do not bleed");

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

MAIN(testtlswithcms) {
#ifdef PVXS_HAS_DISK_OCSP_CACHE
    testPlan(47);
#else
    testPlan(33);
#endif
    pvxs::logger_config_env();

#ifndef PVXS_HAS_DISK_OCSP_CACHE
    testDiag("pvxs does not advertise PVXS_HAS_DISK_OCSP_CACHE — "
             "14 cache-coverage assertions omitted from this run");
#endif

    testStaplingDisabledOnServer();
    testStaplingEnabledOnServer();
    testClientStaplingNoServerStapling();
    testServerStaplingNoClientStapling();

    testServerOnlyWithCounters();
    testCounterAPIBasics();

    testServerOnly();
    testGetIntermediate();
    testCertStatusGating();
    testTlsCredentialsOnConnect();
    testCacheHitOnRepeatedSubscribe();
    testNoCacheBleedAcrossRoles();

    return testDone();
}
