/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_PVACMS_TOKENBUCKET_H_
#define PVXS_PVACMS_TOKENBUCKET_H_

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>

namespace cms {
namespace cluster {

class TokenBucket {
public:
    TokenBucket()
        : TokenBucket(0.0, 0u)
    {}

    TokenBucket(double rate, uint32_t burst)
        : rate_(rate)
        , burst_(burst)
        , tokens_(static_cast<double>(burst))
        , last_refill_(Clock::now())
    {}

    void configure(double rate, uint32_t burst)
    {
        std::lock_guard<std::mutex> lock(lock_);
        rate_ = rate;
        burst_ = burst;
        tokens_ = static_cast<double>(burst_);
        last_refill_ = Clock::now();
    }

    bool tryConsume()
    {
        std::lock_guard<std::mutex> lock(lock_);
        refill();
        if (rate_ == 0.0) {
            return true;
        }
        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

    double secsUntilReady()
    {
        std::lock_guard<std::mutex> lock(lock_);
        refill();
        if (rate_ == 0.0 || tokens_ >= 1.0) {
            return 0.0;
        }
        return (1.0 - tokens_) / rate_;
    }

private:
    typedef std::chrono::steady_clock Clock;

    void refill()
    {
        if (rate_ == 0.0) {
            last_refill_ = Clock::now();
            return;
        }

        const auto now = Clock::now();
        const std::chrono::duration<double> elapsed = now - last_refill_;
        last_refill_ = now;
        tokens_ = std::min(static_cast<double>(burst_), tokens_ + elapsed.count() * rate_);
    }

    mutable std::mutex lock_;
    double rate_;
    uint32_t burst_;
    double tokens_;
    Clock::time_point last_refill_;
};

}  // namespace cluster
}  // namespace cms

#endif  // PVXS_PVACMS_TOKENBUCKET_H_
