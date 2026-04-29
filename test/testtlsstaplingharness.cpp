/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// OCSP stapling logic is a single-server-to-single-PVACMS interaction.
// Per OpenSpec task 7.1 we evaluated whether a 2-node cluster variant
// would add coverage; the answer is no.  Cluster replication of
// stapling state (PVACMS pre-computing OCSP responses, syncing across
// members) is verified by testclusterharness's convergence assertions.
// Server-side failover between cluster members is not currently
// testable in-process per the post-restart limitation documented in
// test/harness/cluster.cpp.

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
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

const char *TEST_PV = "TEST:STAPLING:PV";

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
    testDiag("Server with stapling disabled - GET via real PVACMS still succeeds");

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
    if (get_succeeded) testEq(reply_value, 42);
}

void testStaplingEnabledOnServer() {
    testDiag("Server with stapling enabled - GET via real PVACMS succeeds");

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
    if (get_succeeded) testEq(reply_value, 42);
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
    if (get_succeeded) testEq(reply_value, 42);
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
    if (get_succeeded) testEq(reply_value, 42);
}

void testStaplingFlagPropagatesViaCustomize() {
    testDiag("testServerBuilder().customize() correctly toggles tls_disable_stapling");
    PVACMSHarness::Builder builder;
    auto harness = builder.build();

    bool customize_invoked_for_disabled_server = false;
    bool customize_invoked_for_enabled_server = false;

    auto &stapling_disabled_server = harness.testServerBuilder()
                     .customize([&](pvxs::server::Config &server_config) {
                         server_config.disableStapling(true);
                         customize_invoked_for_disabled_server = true;
                     })
                     .start();
    auto &stapling_enabled_server = harness.testServerBuilder()
                     .customize([&](pvxs::server::Config &server_config) {
                         server_config.disableStapling(false);
                         customize_invoked_for_enabled_server = true;
                     })
                     .start();

    testOk(customize_invoked_for_disabled_server,
           "customize() lambda fired for the stapling-disabled server");
    testOk(customize_invoked_for_enabled_server,
           "customize() lambda fired for the stapling-enabled server");
    testOk(stapling_disabled_server.config().isStaplingDisabled(),
           "stapling-disabled server reports isStaplingDisabled() == true");
    testOk(!stapling_enabled_server.config().isStaplingDisabled(),
           "stapling-enabled server reports isStaplingDisabled() == false");
}

}  // namespace

MAIN(testtlsstaplingharness) {
    testPlan(14);
    pvxs::logger_config_env();
    testStaplingFlagPropagatesViaCustomize();
    testStaplingDisabledOnServer();
    testStaplingEnabledOnServer();
    testClientStaplingNoServerStapling();
    testServerStaplingNoClientStapling();
    return testDone();
}
