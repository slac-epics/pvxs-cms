/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <algorithm>
#include <map>
#include <string>

#include <epicsTime.h>
#include <epicsUnitTest.h>
#include <generalTimeSup.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include "pvacms.h"

using namespace pvxs;
using namespace pvxs::certs;

namespace {

// Simulated POSIX time returned by epicsTimeGetCurrent(), and so by timeNow()
std::atomic<time_t> sim_now{0};

int testTimeCurrent(epicsTimeStamp *pDest) {
    pDest->secPastEpoch = static_cast<epicsUInt32>(sim_now.load() - POSIX_TIME_AT_EPICS_EPOCH);
    pDest->nsec = 0;
    return 0;
}

bool selected(const StatusMonitor &sm, const serial_number_t serial) {
    const auto serials = sm.getActiveSerials();
    return std::find(serials.begin(), serials.end(), serial) != serials.end();
}

}  // namespace

MAIN(teststatusmonitor) {
    testPlan(8);
    generalTimeRegisterCurrentProvider("test", 1, &testTimeCurrent);
    const time_t t0 = 1780000000;  // arbitrary POSIX time
    sim_now = t0;

    ConfigCms config{};
    config.setRequestTimeout(5.0);
    sql_ptr certs_db;
    std::string issuer_id("deadbeef");
    server::WildcardPV status_pv{server::WildcardPV::buildMailbox()};
    ossl_ptr<X509> cert_auth_cert;
    ossl_ptr<EVP_PKEY> cert_auth_pkey;
    ossl_shared_ptr<STACK_OF(X509)> cert_auth_chain;
    std::map<serial_number_t, time_t> validity;
    const StatusMonitor sm(config, certs_db, issuer_id, status_pv, cert_auth_cert, cert_auth_pkey,
                           cert_auth_chain, validity);

    // A newly connected serial (validity 0) is due for an immediate status post
    validity.emplace(1, 0);
    testTrue(selected(sm, 1)) << " new connection selected for refresh";

    // Once a status is posted its serial is not due until the validity nears its end
    sm.setValidity(1, t0 + 1800);
    testFalse(selected(sm, 1)) << " freshly posted status not re-selected";

    validity[2] = t0 + 3;       // expires within the request timeout (5s)
    validity[3] = t0 + 6;       // expires beyond the request timeout
    validity[4] = t0 - 100000;  // long expired
    testTrue(selected(sm, 2)) << " status expiring within timeout selected";
    testFalse(selected(sm, 3)) << " status expiring beyond timeout not selected";
    testTrue(selected(sm, 4)) << " long-expired status selected";

    // When the clock reaches a status's validity end, its serial becomes due again
    sim_now = t0 + 1800;
    testTrue(selected(sm, 1)) << " serial due again at validity end";

    // Re-posting pushes the serial out again
    sm.setValidity(1, t0 + 3600);
    testFalse(selected(sm, 1)) << " refreshed status not re-selected";

    // setValidity on an unknown serial is a no-op
    sm.setValidity(99, t0);
    testEq(validity.count(99), 0u) << " unknown serial not inserted";

    return testDone();
}
