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
#include <pvxs/cms/testHarness.h>
#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/unittest.h>

namespace {

using pvxs::cms::test::PVACMSHarness;
using pvxs::cms::test::TestServerOpts;

const char *TEST_PV = "TEST:HARNESS:PV";

struct SubCounter {
    std::mutex mu;
    std::map<std::string, uint32_t> counts;

    void operator()(const std::string &pv) {
        std::lock_guard<std::mutex> lk(mu);
        ++counts[pv];
        testDiag("CERT:STATUS subscription observed: %s (count now %u)",
                 pv.c_str(), counts[pv]);
    }

    uint32_t get(const std::string &pv) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = counts.find(pv);
        return it == counts.end() ? 0u : it->second;
    }

    uint32_t total() {
        std::lock_guard<std::mutex> lk(mu);
        uint32_t sum = 0;
        for (auto &kv : counts) sum += kv.second;
        return sum;
    }

    size_t uniquePvs() {
        std::lock_guard<std::mutex> lk(mu);
        return counts.size();
    }
};

void testDiagnoseSubscriptionCount() {
    testDiag("Diagnose how many CERT:STATUS subscriptions reach the harness PVACMS");
    testDiag("Mirrors testtlswithcms::testServerOnly (server with EE cert,");
    testDiag("client with CA only) and counts subscriptions reaching PVACMS.");

    auto counter = std::make_shared<SubCounter>();

    PVACMSHarness::Builder b;
    b.observeStatusSubscriptions([counter](const std::string &pv) {
        (*counter)(pv);
    });
    auto harness = b.build();

    testOk(!harness.pvacmsIssuerId().empty(),
           "harness PVACMS issuer id: %s", harness.pvacmsIssuerId().c_str());

    auto mbox = pvxs::server::SharedPV::buildReadonly();
    mbox.open(pvxs::nt::NTScalar{pvxs::TypeCode::Int32}.create()
                  .update("value", int32_t{42}));

    TestServerOpts opts;
    opts.subject = "harness-server-1";
    auto &srv = harness.testServerBuilder().opts(opts).withPV(TEST_PV, mbox).start();
    (void)srv;

    auto cli_cfg = harness.testClientConfig();

    auto cli = cli_cfg.build();

    testDiag("Issuing GET on TEST:HARNESS:PV...");
    bool got_value = false;
    int32_t value = -1;
    try {
        auto reply = cli.get(TEST_PV).exec()->wait(10.0);
        value = reply["value"].as<int32_t>();
        got_value = true;
    } catch (const std::exception &e) {
        testDiag("GET failed: %s", e.what());
    }

    testOk(got_value, "GET returned a value");
    if (got_value) {
        testEq(value, 42);
    } else {
        testFail("GET timed out / failed");
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));

    auto total = counter->total();
    auto unique = counter->uniquePvs();

    testDiag("Total CERT:STATUS subscription events observed: %u", total);
    testDiag("Unique CERT:STATUS PV names observed:           %zu", unique);
    {
        std::lock_guard<std::mutex> lk(counter->mu);
        for (auto &kv : counter->counts) {
            testDiag("    %s = %u", kv.first.c_str(), kv.second);
        }
    }

    testDiag("Subscription count under harness (informational):");
    testDiag("  Original mock-CMS testtlswithcms::testServerOnly asserted 'wanted 2'");
    testDiag("  Under the real harness PVACMS, observed total=%u unique=%zu",
             total, unique);
    testDiag("  PkiFixture currently mints EE certs with cert_status_subscription");
    testDiag("  flag = NO, so the X.509 status-PV extension is NOT embedded.");
    testDiag("  Without the extension, pvxs's TLS code path skips cert-status");
    testDiag("  monitoring entirely - hence 0 subscriptions, GET still succeeds.");
    testDiag("  Setting flag = YES requires PkiFixture-issued certs to be");
    testDiag("  registered in the harness PVACMS DB (preload_cert_files or");
    testDiag("  CERT:CREATE RPC); without that, status lookup fails and TLS");
    testDiag("  handshake deadlocks. See Section 5 follow-up in tasks.md.");

    testOk(total == 0,
           "diagnostic-mode harness produces 0 CERT:STATUS subs (NO extension on EEs)");
    testOk(unique == 0,
           "no unique cert-status PVs observed (matches NO-extension diagnostic)");
}

}  // namespace

MAIN(testtlswithcmsharness) {
    testPlan(5);
    pvxs::logger_config_env();
    testDiagnoseSubscriptionCount();
    return testDone();
}
