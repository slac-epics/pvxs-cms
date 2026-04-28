/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/client.h>
#include <cms/testharness.h>
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

    PVACMSHarness::Builder b;
    b.observeStatusSubscriptions([counter](const std::string &pv) { (*counter)(pv); });
    auto harness = b.build();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts opts;
    opts.subject = "stapling-disabled-server";
    auto &srv = harness.testServerBuilder()
                    .opts(opts)
                    .customize([](pvxs::server::Config &c) { c.disableStapling(true); })
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    testTrue(srv.config().isStaplingDisabled());

    auto cli_cfg = harness.testClientConfig();
    cli_cfg.disableStapling(false);
    auto cli = cli_cfg.build();

    bool got_value = false;
    int32_t value = -1;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got_value = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(got_value, "GET succeeded with server-side stapling disabled");
    if (got_value) testEq(value, 42);
}

void testStaplingEnabledOnServer() {
    testDiag("Server with stapling enabled - GET via real PVACMS succeeds");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder b;
    b.observeStatusSubscriptions([counter](const std::string &pv) { (*counter)(pv); });
    auto harness = b.build();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts opts;
    opts.subject = "stapling-enabled-server";
    auto &srv = harness.testServerBuilder()
                    .opts(opts)
                    .customize([](pvxs::server::Config &c) { c.disableStapling(false); })
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    testTrue(!srv.config().isStaplingDisabled());

    auto cli_cfg = harness.testClientConfig();
    cli_cfg.disableStapling(false);
    auto cli = cli_cfg.build();

    bool got_value = false;
    int32_t value = -1;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got_value = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(got_value, "GET succeeded with server-side stapling enabled");
    if (got_value) testEq(value, 42);
}

void testClientStaplingNoServerStapling() {
    testDiag("Client requests stapling but server does not - falls back to PVACMS");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder b;
    b.observeStatusSubscriptions([counter](const std::string &pv) { (*counter)(pv); });
    auto harness = b.build();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts opts;
    opts.subject = "no-staple-server";
    auto &srv = harness.testServerBuilder()
                    .opts(opts)
                    .customize([](pvxs::server::Config &c) { c.disableStapling(true); })
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli_cfg = harness.testClientConfig();
    cli_cfg.disableStapling(false);
    auto cli = cli_cfg.build();

    bool got_value = false;
    int32_t value = -1;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got_value = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(got_value, "client expecting stapling -> server not stapling -> GET still succeeds");
    if (got_value) testEq(value, 42);
}

void testServerStaplingNoClientStapling() {
    testDiag("Server staples but client does not expect it - falls back to PVACMS");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder b;
    b.observeStatusSubscriptions([counter](const std::string &pv) { (*counter)(pv); });
    auto harness = b.build();

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts opts;
    opts.subject = "staple-server";
    auto &srv = harness.testServerBuilder()
                    .opts(opts)
                    .customize([](pvxs::server::Config &c) { c.disableStapling(false); })
                    .withPV(TEST_PV, mbox)
                    .start();
    (void)srv;

    auto cli_cfg = harness.testClientConfig();
    cli_cfg.disableStapling(true);
    auto cli = cli_cfg.build();

    bool got_value = false;
    int32_t value = -1;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got_value = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(got_value, "server stapling -> client not expecting -> GET still succeeds");
    if (got_value) testEq(value, 42);
}

void testStaplingFlagPropagatesViaCustomize() {
    testDiag("testServerBuilder().customize() correctly toggles tls_disable_stapling");
    PVACMSHarness::Builder b;
    auto harness = b.build();

    bool customize_invoked_disabled = false;
    bool customize_invoked_enabled = false;

    auto &srv1 = harness.testServerBuilder()
                     .customize([&](pvxs::server::Config &c) {
                         c.disableStapling(true);
                         customize_invoked_disabled = true;
                     })
                     .start();
    auto &srv2 = harness.testServerBuilder()
                     .customize([&](pvxs::server::Config &c) {
                         c.disableStapling(false);
                         customize_invoked_enabled = true;
                     })
                     .start();

    testTrue(customize_invoked_disabled);
    testTrue(customize_invoked_enabled);
    testTrue(srv1.config().isStaplingDisabled());
    testTrue(!srv2.config().isStaplingDisabled());
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
