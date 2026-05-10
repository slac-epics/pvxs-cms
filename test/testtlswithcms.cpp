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
#include <cstdio>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#include <epicsThread.h>
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
#include "mockclustergateway.h"
#include "certstatusdb.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "openssl.h"
#include "security.h"

namespace {

using cms::test::PVACMSHarness;
using cms::test::MockClusterGateway;
using cms::test::TestClientOpts;
using cms::test::TestServerOpts;
using cms::cert::CertCreationRequest;
using cms::cert::CertStatusFactory;
using cms::cert::IdFileFactory;
using cms::cert::PENDING_APPROVAL;
using cms::cert::PENDING_RENEWAL;
using cms::cert::SCHEDULED_OFFLINE;
using cms::cert::VALID;
using cms::cert::getCertCreatePv;
using cms::cert::getCertStatusURI;
namespace members = pvxs::members;
namespace nt = pvxs::nt;

const char *TEST_PV = "TEST:HARNESS:PV";

struct ScheduleWindowSpec {
    std::string day_of_week;
    std::string start_time;
    std::string end_time;
};

std::string errorText(const std::exception &e) {
    return e.what() ? e.what() : "";
}

int currentStatusIndex(pvxs::client::Context &client, const std::string &status_pv) {
    return client.get(status_pv).exec()->wait(1.0)["value.index"].as<int32_t>();
}

std::string formatUtcMinute(int minute_of_day) {
    minute_of_day %= 24 * 60;
    if (minute_of_day < 0) minute_of_day += 24 * 60;
    const int hour = minute_of_day / 60;
    const int minute = minute_of_day % 60;
    char buf[6];
    std::snprintf(buf, sizeof(buf), "%02d:%02d", hour, minute);
    return {buf};
}

int currentUtcMinuteOfDay() {
    const auto now = std::time(nullptr);
    tm utc_now{};
    gmtime_r(&now, &utc_now);
    return utc_now.tm_hour * 60 + utc_now.tm_min;
}

ScheduleWindowSpec activeScheduleWindow() {
    const int now_minute = currentUtcMinuteOfDay();
    return {"*", formatUtcMinute(now_minute - 1), formatUtcMinute(now_minute + 2)};
}

ScheduleWindowSpec inactiveScheduleWindow() {
    const int now_minute = currentUtcMinuteOfDay();
    const int start = now_minute < 10 * 60 ? 12 * 60 : 30;
    return {"*", formatUtcMinute(start), formatUtcMinute(start + 30)};
}

ScheduleWindowSpec laterInactiveScheduleWindow() {
    const int now_minute = currentUtcMinuteOfDay();
    const int start = now_minute < 14 * 60 ? 18 * 60 : 90;
    return {"*", formatUtcMinute(start), formatUtcMinute(start + 30)};
}

pvxs::Value makeScheduleArgument(uint64_t serial,
                                 const std::vector<ScheduleWindowSpec> &windows,
                                 bool read_only = false) {
    auto arg = pvxs::TypeDef(pvxs::TypeCode::Struct, {
        members::Struct("query", {
            members::UInt64("serial"),
            members::Bool("read_only"),
            members::StructA("schedule", {
                members::String("day_of_week"),
                members::String("start_time"),
                members::String("end_time"),
            }),
        }),
    }).create();
    arg["query.serial"] = serial;
    arg["query.read_only"] = read_only;
    if (!windows.empty()) {
        pvxs::shared_array<pvxs::Value> sched_arr(windows.size());
        for (size_t i = 0; i < windows.size(); ++i) {
            sched_arr[i] = arg["query.schedule"].allocMember();
            sched_arr[i]["day_of_week"] = windows[i].day_of_week;
            sched_arr[i]["start_time"] = windows[i].start_time;
            sched_arr[i]["end_time"] = windows[i].end_time;
        }
        arg["query.schedule"] = sched_arr.freeze();
    }
    return arg;
}

size_t scheduleReplyWindowCount(const pvxs::Value &reply) {
    auto sched = reply["schedule"];
    return sched ? sched.as<pvxs::shared_array<const pvxs::Value>>().size() : 0u;
}

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
        epicsThreadSleep(0.1);
    }
    auto status = client.get(status_pv).exec()->wait(1.0);
    return status["value.index"].as<int32_t>() == expected_status;
}

pvxs::Value makeCreateArgument(const std::string &create_pv,
                               const std::string &name,
                               const std::string &country,
                               const std::string &organization,
                               const std::string &organization_unit,
                               uint16_t usage,
                               time_t not_before,
                               time_t not_after,
                               const std::string &public_key) {
    CertCreationRequest request("std", {});
    request.ccr["type"] = std::string("std");
    request.ccr["name"] = name;
    request.ccr["country"] = country;
    request.ccr["organization"] = organization;
    request.ccr["organization_unit"] = organization_unit;
    request.ccr["usage"] = usage;
    request.ccr["not_before"] = static_cast<uint64_t>(not_before);
    request.ccr["not_after"] = static_cast<uint64_t>(not_after);
    request.ccr["pub_key"] = public_key;
    request.ccr["config_uri_base"] = std::string();
    request.ccr["no_status"] = false;

    auto uri = nt::NTURI({}).build();
    uri += {members::Struct("query", CCR_PROTOTYPE(request.verifier_fields))};
    auto arg = uri.create();
    arg["path"] = create_pv;
    arg["query"].from(request.ccr);
    return arg;
}

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

    epicsThreadSleep(0.5);

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

    epicsThreadSleep(0.5);

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

    epicsThreadSleep(0.5);

    const uint32_t cache_hits_after_first_client = harness.totalCacheHits();

    auto second_client = client_config.build();
    try {
        second_client.get(TEST_PV).exec()->wait(10.0);
    } catch (const std::exception &) {
    }

    epicsThreadSleep(0.5);

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

    epicsThreadSleep(0.5);

    testDiag("After single GET: subscribes=%u deliveries=%u cache_hits=%u",
             harness.totalSubscribes(),
             harness.totalDeliveries(),
             harness.totalCacheHits());

    testOk(harness.totalCacheHits() == 0,
           "no cross-role cache bleed: server cache and client cache stay isolated (got %u hits)",
           harness.totalCacheHits());
}

void testRenewFromPendingRenewal() {
    testDiag("monitor-driven PENDING_RENEWAL renewal via standard authenticator-style CCR");

    auto builder = PVACMSHarness::Builder{};
    builder.monitorIntervalSecs(1);
    auto harness = builder.build();
    TestClientOpts original_opts;
    original_opts.subject = "renew-after-pending";
    auto original_client_config = harness.testClientConfig(original_opts);

    auto original_reader = IdFileFactory::createReader(original_client_config.tls_keychain_file);
    auto original_cert = original_reader->getCertDataFromFile();
    const auto serial = CertStatusFactory::getSerialNumber(original_cert.cert);
    const auto issuer_id = harness.pvacmsIssuerId();
    const auto status_pv = getCertStatusURI("CERT", issuer_id, serial);
    const auto create_pv = getCertCreatePv("CERT", issuer_id);
    const auto db_path = harness.pkiFixture().dir() + "/certs.db";

    auto admin_client = harness.cmsAdminClientConfig().build();
    auto initial_status = admin_client.get(status_pv).exec()->wait(5.0);
    testOk(initial_status["value.index"].as<int32_t>() == VALID,
           "registered client certificate starts VALID");

    const auto renew_by = std::time(nullptr) + 4;
    cms::test::setCertRenewBy(db_path, serial, renew_by);

    const bool saw_renewal_due = cms::test::waitForCertRecord(db_path,
                                                serial,
                                                [](const cms::test::CertRecord &row) {
                                                    return row.status == VALID && row.renewal_due == 1;
                                                },
                                                6.0);
    testOk(saw_renewal_due,
           "monitor sets renewal_due while certificate remains VALID");

    const bool saw_pending_renewal = cms::test::waitForCertRecord(db_path,
                                                    serial,
                                                    [](const cms::test::CertRecord &row) {
                                                        return row.status == PENDING_RENEWAL && row.renewal_due == 1;
                                                    },
                                                    8.0);
    testOk(saw_pending_renewal,
           "monitor changes status to PENDING_RENEWAL after renew_by passes");

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{123}));
    auto &test_server = harness.testServerBuilder()
        .opts([]{
            TestServerOpts server_opts;
            server_opts.subject = "pending-renewal-server";
            server_opts.clientCertRequired = true;
            return server_opts;
        }())
        .withPV(TEST_PV, mailbox_pv)
        .start();
    (void)test_server;

    bool operational_get_succeeded = false;
    std::string operational_get_error;
    try {
        original_client_config.build().get(TEST_PV).exec()->wait(5.0);
        operational_get_succeeded = true;
    } catch (const std::exception &e) {
        operational_get_error = errorText(e);
    }
    testOk(!operational_get_succeeded,
           "client certificate in PENDING_RENEWAL is rejected for ordinary data-plane operations");
    if (!operational_get_error.empty()) {
        testDiag("ordinary data-plane GET from PENDING_RENEWAL client failed as expected: %s",
                 operational_get_error.c_str());
    }

    auto renewal_key_pair = IdFileFactory::createKeyPair();
    const auto now = std::time(nullptr);
    auto renewal_arg = makeCreateArgument(create_pv,
                                          "renew-after-pending",
                                          "US",
                                          "pvxs-cms-test",
                                          "PkiFixture Entity",
                                          cms::ssl::kForClient,
                                          now,
                                          now + 3600,
                                          renewal_key_pair->public_key);

    testOk(waitForStatusIndex(admin_client, status_pv, PENDING_RENEWAL, 5.0),
           "status process variable remains PENDING_RENEWAL before renewal RPC");

    bool renewal_with_pending_cert_succeeded = false;
    std::string pending_cert_renewal_error;
    try {
        original_client_config.build().rpc(create_pv, renewal_arg).exec()->wait(5.0);
        renewal_with_pending_cert_succeeded = true;
    } catch (const std::exception &e) {
        pending_cert_renewal_error = errorText(e);
    }
    testOk(!renewal_with_pending_cert_succeeded,
           "renewal RPC using the PENDING_RENEWAL client certificate is rejected");
    if (!pending_cert_renewal_error.empty()) {
        testDiag("renewal RPC from PENDING_RENEWAL client failed as expected: %s",
                 pending_cert_renewal_error.c_str());
    }

    auto renewal_client_config = original_client_config;
    renewal_client_config.tls_disabled = true;
    auto renewal_client = renewal_client_config.build();
    auto renewal_reply = renewal_client.rpc(create_pv, renewal_arg).exec()->wait(10.0);
    testOk(renewal_reply["serial"].as<uint64_t>() == serial,
           "renewal reuses the original certificate serial instead of creating a new row");

    testOk(waitForStatusIndex(admin_client, status_pv, VALID, 5.0),
           "status process variable returns to VALID after renewal from PENDING_RENEWAL");
}

void testPendingApprovalGatewayCertAllowsPlainTcpThroughGateway() {
    testDiag("gateway certificate in PENDING_APPROVAL still allows plain TCP monitor through MockClusterGateway");

    auto harness = PVACMSHarness::Builder{}.build();
    auto admin_client = harness.cmsAdminClientConfig().build();
    const auto issuer_id = harness.pvacmsIssuerId();
    const auto db_path = harness.pkiFixture().dir() + "/certs.db";

    auto mailbox_pv = pvxs::server::SharedPV::buildReadonly();
    mailbox_pv.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{123}));

    const std::string server_subject = "pending-approval-server";
    auto &test_server = harness.testServerBuilder()
        .opts([&server_subject] {
            TestServerOpts server_opts;
            server_opts.subject = server_subject;
            server_opts.clientCertRequired = true;
            return server_opts;
        }())
        .withPV(TEST_PV, mailbox_pv)
        .start();

    const auto server_serial = cms::test::findCertSerialByCommonName(db_path, server_subject);
    const auto server_status_pv = getCertStatusURI("CERT", issuer_id, server_serial);
    testOk(waitForStatusIndex(admin_client, server_status_pv, VALID, 5.0),
           "server certificate status remains VALID");

    TestClientOpts client_opts;
    client_opts.subject = "pending-approval-client";
    auto plain_tcp_client_config = harness.testClientConfig(client_opts);
    auto client_reader = IdFileFactory::createReader(plain_tcp_client_config.tls_keychain_file);
    auto client_cert = client_reader->getCertDataFromFile();
    const auto client_serial = CertStatusFactory::getSerialNumber(client_cert.cert);
    const auto client_status_pv = getCertStatusURI("CERT", issuer_id, client_serial);
    testOk(waitForStatusIndex(admin_client, client_status_pv, VALID, 5.0),
           "client certificate status remains VALID");

    const auto create_pv = getCertCreatePv("CERT", issuer_id);
    auto gateway_key_pair = IdFileFactory::createKeyPair();
    const auto now = std::time(nullptr);
    auto gateway_create_arg = makeCreateArgument(create_pv,
                                                 "pending-approval-gateway-ioc",
                                                 "US",
                                                 "pvxs-cms-test",
                                                 "PkiFixture Entity",
                                                 cms::ssl::kForClientAndServer,
                                                 now,
                                                 now + 3600,
                                                 gateway_key_pair->public_key);
    auto gateway_reply = admin_client.rpc(create_pv, gateway_create_arg).exec()->wait(5.0);
    const auto gateway_serial = gateway_reply["serial"].as<uint64_t>();
    const auto gateway_status_pv = getCertStatusURI("CERT", issuer_id, gateway_serial);

    testOk(gateway_reply["value.index"].as<int32_t>() == PENDING_APPROVAL,
           "gateway IOC certificate create reply state is PENDING_APPROVAL");
    testOk(waitForStatusIndex(admin_client, gateway_status_pv, PENDING_APPROVAL, 5.0),
           "gateway IOC certificate status is PENDING_APPROVAL");

    MockClusterGateway::Options gateway_opts;
    gateway_opts.upstream_address = std::string("127.0.0.1:") +
        std::to_string(static_cast<unsigned>(test_server.config().tcp_port));
    gateway_opts.forwarded_substrings = {TEST_PV};
    MockClusterGateway gateway(gateway_opts);
    gateway.start();

    plain_tcp_client_config.tls_disabled = true;
    plain_tcp_client_config.autoAddrList = false;
    plain_tcp_client_config.addressList.clear();
    plain_tcp_client_config.nameServers = {gateway.listenAddress()};
    auto plain_tcp_client = plain_tcp_client_config.build();

    auto connected_promise = std::make_shared<std::promise<void>>();
    auto connected_future = connected_promise->get_future();
    auto plain_tcp_subscription = plain_tcp_client.monitor(TEST_PV)
        .maskConnected(false)
        .event([connected_promise](pvxs::client::Subscription &sub) {
            try {
                while (sub.pop()) {}
            } catch (pvxs::client::Connected &) {
                try { connected_promise->set_value(); } catch (...) {}
            } catch (...) {
            }
        })
        .exec();

    const bool plain_tcp_monitor_connected =
        connected_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
    testOk(plain_tcp_monitor_connected,
           "plain TCP monitor through MockClusterGateway connects while gateway cert is PENDING_APPROVAL");

    plain_tcp_subscription.reset();
    gateway.stop();

}

void testAdminScheduleStateTransitions() {
    testDiag("administrator schedule updates recompute certificate state immediately");

    auto harness = PVACMSHarness::Builder{}.build();
    TestClientOpts client_opts;
    client_opts.subject = "schedule-state-transitions";
    auto client_config = harness.testClientConfig(client_opts);

    auto reader = IdFileFactory::createReader(client_config.tls_keychain_file);
    auto cert = reader->getCertDataFromFile();
    const auto serial = CertStatusFactory::getSerialNumber(cert.cert);
    const auto& issuer_id = harness.pvacmsIssuerId();
    const auto status_pv = getCertStatusURI("CERT", issuer_id, serial);
    const auto schedule_pv = std::string("CERT:SCHEDULE:") + issuer_id;
    const auto db_path = harness.pkiFixture().dir() + "/certs.db";

    auto admin_client = harness.cmsAdminClientConfig().build();
    testOk(currentStatusIndex(admin_client, status_pv) == VALID,
           "registered certificate starts VALID before schedule changes");

    const auto active_window = activeScheduleWindow();
    const auto inactive_window = inactiveScheduleWindow();
    const auto later_inactive_window = laterInactiveScheduleWindow();

    auto add_active_reply = admin_client.rpc(schedule_pv,
                                             makeScheduleArgument(serial, {active_window}))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(add_active_reply) == 1u,
           "adding an active schedule returns one persisted window");
    testOk(waitForStatusIndex(admin_client, status_pv, VALID, 2.0),
           "adding an active schedule keeps the certificate VALID");

    auto replace_inactive_reply = admin_client.rpc(schedule_pv,
                                                   makeScheduleArgument(serial, {inactive_window}))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(replace_inactive_reply) == 1u,
           "replacing with an inactive schedule returns one persisted window");
    testOk(waitForStatusIndex(admin_client, status_pv, SCHEDULED_OFFLINE, 2.0),
           "replacing an active schedule with an inactive one emits SCHEDULED_OFFLINE");
    testOk(cms::test::waitForCertRecord(db_path,
                          serial,
                          [](const cms::test::CertRecord &row) { return row.status == SCHEDULED_OFFLINE; },
                          2.0),
           "database status changes to SCHEDULED_OFFLINE after inactive schedule is applied");

    auto replace_inactive_again_reply = admin_client.rpc(schedule_pv,
                                                         makeScheduleArgument(serial, {later_inactive_window}))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(replace_inactive_again_reply) == 1u,
           "replacing with another inactive schedule keeps one persisted window");
    testOk(waitForStatusIndex(admin_client, status_pv, SCHEDULED_OFFLINE, 2.0),
           "replacing one inactive schedule with another keeps SCHEDULED_OFFLINE");

    auto replace_active_reply = admin_client.rpc(schedule_pv,
                                                 makeScheduleArgument(serial, {active_window}))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(replace_active_reply) == 1u,
           "replacing with an active schedule returns one persisted window");
    testOk(waitForStatusIndex(admin_client, status_pv, VALID, 2.0),
           "replacing an inactive schedule with an active one emits VALID");

    auto clear_from_valid_reply = admin_client.rpc(schedule_pv,
                                                   makeScheduleArgument(serial, {}))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(clear_from_valid_reply) == 0u,
           "clearing schedule from VALID returns no persisted windows");
    testOk(waitForStatusIndex(admin_client, status_pv, VALID, 2.0),
           "removing schedule while VALID keeps the certificate VALID");

    auto add_inactive_reply = admin_client.rpc(schedule_pv,
                                               makeScheduleArgument(serial, {inactive_window}))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(add_inactive_reply) == 1u,
           "adding an inactive schedule returns one persisted window");
    testOk(waitForStatusIndex(admin_client, status_pv, SCHEDULED_OFFLINE, 2.0),
           "adding an inactive schedule emits SCHEDULED_OFFLINE immediately");

    auto clear_from_offline_reply = admin_client.rpc(schedule_pv,
                                                     makeScheduleArgument(serial, {}))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(clear_from_offline_reply) == 0u,
           "clearing schedule from SCHEDULED_OFFLINE returns no persisted windows");
    testOk(waitForStatusIndex(admin_client, status_pv, VALID, 2.0),
           "removing schedule from SCHEDULED_OFFLINE emits VALID immediately");

    auto read_only_reply = admin_client.rpc(schedule_pv,
                                            makeScheduleArgument(serial, {}, true))
        .exec()->wait(5.0);
    testOk(scheduleReplyWindowCount(read_only_reply) == 0u,
           "read-only schedule query reports no windows after clearing the schedule");
}

}  // namespace

MAIN(testtlswithcms) {
#ifdef PVXS_HAS_DISK_OCSP_CACHE
    testPlan(77);
#else
    testPlan(63);
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
    testRenewFromPendingRenewal();
    testPendingApprovalGatewayCertAllowsPlainTcpThroughGateway();
    testAdminScheduleStateTransitions();

    return testDone();
}
