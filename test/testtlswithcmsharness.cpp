/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

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

void testServerOnlyMigrated() {
    testDiag("Migrated testServerOnly: server with Entity Cert, client with admin cert");
    testDiag("Counts cert-status subscribes/deliveries via pvxs.certs.mon.event");

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
    if (get_succeeded) testEq(reply_value, 42);

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
    testEq(total_subscribes, harness.totalSubscribes());
    testEq(total_deliveries, harness.totalDeliveries());
    testEq(total_cache_hits, harness.totalCacheHits());
    testOk(total_deliveries >= total_cache_hits,
           "deliveries (%u) >= cache_hits (%u): cache hits cannot exceed total deliveries",
           total_deliveries, total_cache_hits);
    testDiag("Invariant: deliveries (%u) = live (%u) + cache-hits (%u)",
             total_deliveries, total_deliveries - total_cache_hits, total_cache_hits);

#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    // The cert-status subscribe/deliver counters depend on pvxs's cache-dir
    // override (PR #11) to avoid cross-role cache hits silently swallowing
    // subscribe events.  On older pvxs (no override), these counters can
    // legitimately be 0 if the shared cache has prior entries.
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
    testEq(harness.subscribesFor(unknown_status_pv), 0u);
    testEq(harness.deliveriesFor(unknown_status_pv), 0u);

    testOk(!harness.waitSubscribesAtLeast(unknown_status_pv, 1, 0.05),
           "waitSubscribesAtLeast returns false on timeout for unknown PV");
    testOk(!harness.waitDeliveriesAtLeast(unknown_status_pv, 1, 0.05),
           "waitDeliveriesAtLeast returns false on timeout for unknown PV");
    testOk(!harness.waitCacheHitsAtLeast(unknown_status_pv, 1, 0.05),
           "waitCacheHitsAtLeast returns false on timeout for unknown PV");

    testEq(harness.cacheHitsFor(unknown_status_pv), 0u);

    harness.resetStatusEventCounters();
    testEq(harness.subscribesFor(unknown_status_pv), 0u);
    testEq(harness.cacheHitsFor(unknown_status_pv), 0u);
}

}  // namespace

MAIN(testtlswithcmsharness) {
#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    testPlan(17);
#else
    testPlan(14);
#endif
    pvxs::logger_config_env();
    testServerOnlyMigrated();
    testCounterAPIBasics();
    return testDone();
}
