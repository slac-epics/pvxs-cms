/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <epicsThread.h>
#include <epicsUnitTest.h>
#include <testMain.h>

#include "tokenbucket.h"

namespace {

using cms::cluster::TokenBucket;

void testBurstCapacityAndExhaustion()
{
    TokenBucket bucket(10.0, 5u);

    testDiag("Verify burst capacity and exhaustion");
    testOk(bucket.tryConsume(), "first token available");
    testOk(bucket.tryConsume(), "second token available");
    testOk(bucket.tryConsume(), "third token available");
    testOk(bucket.tryConsume(), "fourth token available");
    testOk(bucket.tryConsume(), "fifth token available");
    testOk(!bucket.tryConsume(), "sixth token rejected after burst exhausted");
}

void testRefillBehavior()
{
    // Use a low refill rate (2/s) so the OS scheduler's wakeup jitter
    // (often >50 ms on a contended CI runner) cannot smear the count of
    // refilled tokens across an integer boundary during the test window.
    const double rate = 2.0;
    const unsigned burst = 5u;
    TokenBucket bucket(rate, burst);

    for (unsigned i = 0; i < burst; ++i) {
        testOk(bucket.tryConsume(), "consume token %u before refill test", i + 1u);
    }
    testOk(!bucket.tryConsume(), "bucket exhausted before waiting for refill");

    // Sleep long enough that we are firmly inside [1, 2) refilled tokens
    // even if the OS oversleeps by ~250 ms.  At rate=2/s: 700 ms => 1.4
    // tokens nominal; up to ~950 ms still rounds down to 1.
    epicsThreadSleep(0.700);

    testOk(bucket.tryConsume(), "first token refilled after wait");
    // After consuming the one refilled token, the bucket must be empty
    // again (secsUntilReady > 0) and the next consume must be rejected.
    const double retry_after = bucket.secsUntilReady();
    testOk(retry_after > 0.0,
           "secsUntilReady positive after draining the single refilled token (got %.3f)",
           retry_after);
    testOk(!bucket.tryConsume(),
           "refill remains rate-limited after consuming the refilled token");
}

void testRateZeroDisablesLimiting()
{
    TokenBucket bucket(0.0, 50u);

    testDiag("Verify rate=0 disables token bucket");
    bool ok = true;
    for (unsigned i = 0; i < 100u; ++i) {
        ok = ok && bucket.tryConsume();
    }

    testOk(ok, "disabled token bucket always allows requests");
    testOk(bucket.secsUntilReady() == 0.0, "disabled token bucket has zero retry delay");
}

void testSecsUntilReadyWhenExhausted()
{
    TokenBucket bucket(5.0, 1u);

    testDiag("Verify secsUntilReady is positive when exhausted");
    testOk(bucket.tryConsume(), "initial token consumed");
    testOk(!bucket.tryConsume(), "next request rejected when exhausted");

    const double retry_after = bucket.secsUntilReady();
    testOk(retry_after > 0.0, "secsUntilReady reports positive delay (got %.3f)", retry_after);
}

}  // namespace

MAIN(testratelimiting)
{
    testPlan(20);
    testBurstCapacityAndExhaustion();
    testRefillBehavior();
    testRateZeroDisablesLimiting();
    testSecsUntilReadyWhenExhausted();
    return testDone();
}
