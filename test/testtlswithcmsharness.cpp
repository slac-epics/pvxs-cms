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

    PVACMSHarness::Builder b;
    auto harness = b.build();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts opts;
    opts.subject = "harness-server-1";
    auto &srv = harness.testServerBuilder()
                    .opts(opts)
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli_cfg = harness.testClientConfig();
    auto cli = cli_cfg.build();

    int32_t value = -1;
    bool got_value = false;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got_value = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(got_value, "GET returned a value through full TLS+PVACMS flow");
    if (got_value) testEq(value, 42);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const auto &issuer = harness.pvacmsIssuerId();
    testDiag("Issuer ID: %s", issuer.c_str());

    uint32_t total_subs = 0;
    uint32_t total_dels = 0;
    int unique_pvs = 0;
    for (const auto &reg : harness.startedTestServers()) {
        (void)reg;
    }

    {
        const auto &snap = harness.startedTestServers();
        testDiag("startedTestServers().size() = %zu", snap.size());
    }

    const auto observed = harness.observedStatusPvs();
    uint32_t total_hits = 0;
    for (const auto &pv : observed) {
        const auto subs = harness.subscribesFor(pv);
        const auto dels = harness.deliveriesFor(pv);
        const auto hits = harness.cacheHitsFor(pv);
        testDiag("  observed pv=%s  subscribes=%u  deliveries=%u  cache-hits=%u",
                 pv.c_str(), subs, dels, hits);
        total_subs += subs;
        total_dels += dels;
        total_hits += hits;
        ++unique_pvs;
    }
    testEq(total_subs, harness.totalSubscribes());
    testEq(total_dels, harness.totalDeliveries());
    testEq(total_hits, harness.totalCacheHits());
    testTrue(total_dels >= total_hits);
    testDiag("Invariant: deliveries (%u) = live (%u) + cache-hits (%u)",
             total_dels, total_dels - total_hits, total_hits);

#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    // The cert-status subscribe/deliver counters depend on pvxs's cache-dir
    // override (PR #11) to avoid cross-role cache hits silently swallowing
    // subscribe events.  On older pvxs (no override), these counters can
    // legitimately be 0 if the shared cache has prior entries.
    testOk(total_subs >= 2,
           "Total cert-status subscribes >= 2 (got %u)", total_subs);
    testOk(total_dels >= 1,
           "Total cert-status deliveries >= 1 (got %u)", total_dels);
    testOk(unique_pvs >= 1,
           "At least one unique cert-status PV had activity (got %d)", unique_pvs);
#endif
    testDiag("Observed: subs=%u dels=%u unique_pvs=%d",
             total_subs, total_dels, unique_pvs);
}

void testCounterAPIBasics() {
    testDiag("Harness counter API basics: subscribesFor / deliveriesFor / waitX / reset");

    PVACMSHarness::Builder b;
    auto harness = b.build();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{1}));

    TestServerOpts opts;
    opts.subject = "counter-api-server";
    auto &srv = harness.testServerBuilder()
                    .opts(opts)
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli = harness.testClientConfig().build();
    try {
        cli.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const auto bogus_pv = std::string("CERT:STATUS:nonexistent:9999");
    testEq(harness.subscribesFor(bogus_pv), 0u);
    testEq(harness.deliveriesFor(bogus_pv), 0u);

    testOk(!harness.waitSubscribesAtLeast(bogus_pv, 1, 0.05),
           "waitSubscribesAtLeast returns false on timeout for unknown PV");
    testOk(!harness.waitDeliveriesAtLeast(bogus_pv, 1, 0.05),
           "waitDeliveriesAtLeast returns false on timeout for unknown PV");
    testOk(!harness.waitCacheHitsAtLeast(bogus_pv, 1, 0.05),
           "waitCacheHitsAtLeast returns false on timeout for unknown PV");

    testEq(harness.cacheHitsFor(bogus_pv), 0u);

    harness.resetStatusEventCounters();
    testEq(harness.subscribesFor(bogus_pv), 0u);
    testEq(harness.cacheHitsFor(bogus_pv), 0u);
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
