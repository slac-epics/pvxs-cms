/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_PVACMS_PVACMSRUNTIME_H_
#define PVXS_PVACMS_PVACMSRUNTIME_H_

#include <atomic>
#include <cstdint>
#include <mutex>

#include <epicsMutex.h>

#include "tokenbucket.h"

namespace cms {

/**
 * @brief Per-instance accumulator for the average duration of CERT:CREATE
 *        RPCs. Thread-safe; record() is callable from any thread.
 */
struct CcrTimingTracker {
    mutable std::mutex mtx_;
    double total_ms_{0.0};
    uint64_t count_{0u};

    void record(double ms) {
        std::lock_guard<std::mutex> lk(mtx_);
        total_ms_ += ms;
        ++count_;
    }

    double averageMs() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return count_ > 0 ? total_ms_ / static_cast<double>(count_) : 0.0;
    }
};

/**
 * @brief Per-PVACMS-instance runtime state.
 *
 * Holds the mutexes, rate-limiter, in-flight counter, certs-created /
 * certs-revoked counters, and CCR-timing tracker that PVACMS uses while
 * running. Previously these were file-scope static state in
 * `pvacms.cpp`; lifting them into a struct lets the (test) harness run
 * multiple PVACMS instances in one process without contending on shared
 * mutexes or double-counting metrics.
 *
 * The production `pvacms` binary uses a single process-scoped
 * `PvacmsRuntime` accessed via `defaultRuntime()` in `pvacms.cpp` — its
 * observable behaviour is identical to the prior file-scope statics.
 */
struct PvacmsRuntime {
    epicsMutex status_pv_lock;
    epicsMutex status_update_lock;

    cms::cluster::TokenBucket create_certificate_rate_limiter;
    std::atomic<uint32_t> create_certificate_inflight_count{0u};

    std::atomic<uint64_t> certs_created_counter{0u};
    std::atomic<uint64_t> certs_revoked_counter{0u};

    CcrTimingTracker ccr_timing_tracker;
};

}  // namespace cms

#endif  // PVXS_PVACMS_PVACMSRUNTIME_H_
