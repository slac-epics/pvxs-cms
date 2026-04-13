/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <chrono>
#include <thread>

#include <epicsUnitTest.h>
#include <testMain.h>

#include "tokenbucket.h"

namespace {

using pvxs::certs::TokenBucket;

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
    TokenBucket bucket(10.0, 5u);

    for (unsigned i = 0; i < 5u; ++i) {
        testOk(bucket.tryConsume(), "consume token %u before refill test", i + 1u);
    }
    testOk(!bucket.tryConsume(), "bucket exhausted before waiting for refill");

    std::this_thread::sleep_for(std::chrono::milliseconds(220));

    const double retry_after = bucket.secsUntilReady();
    const bool first_after_wait = bucket.tryConsume();
    const bool second_after_wait = bucket.tryConsume();
    const bool third_after_wait = bucket.tryConsume();

    testOk(retry_after <= 0.05, "secsUntilReady drops near zero after refill (got %.3f)", retry_after);
    testOk(first_after_wait, "first token refilled after wait");
    testOk(second_after_wait, "second token refilled after wait");
    testOk(!third_after_wait, "refill remains rate-limited after consuming refilled tokens");
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
    testPlan(21);
    testBurstCapacityAndExhaustion();
    testRefillBehavior();
    testRateZeroDisablesLimiting();
    testSecsUntilReadyWhenExhausted();
    return testDone();
}
