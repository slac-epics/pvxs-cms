/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "statuseventcapture.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>

#include <errlog.h>

#include <pvxs/log.h>

namespace cms {
namespace test {
namespace internal {

namespace {

DEFINE_LOGGER(capture_log, "pvxs.cms.test.capture");

constexpr const char kEventLogPrefixSubscribe[] = " cert-status: subscribe pv=";
constexpr const char kEventLogPrefixDelivery[]  = " cert-status: delivery  pv=";
constexpr const char kEventLogPrefixCacheHit[]  = " cert-status: cache-hit pv=";

std::mutex g_registry_mu;
std::set<StatusEventCapture *> g_registry;
std::once_flag g_listener_once;
std::once_flag g_errlog_init_once;

std::string parsePvName(const char *cursor) {
    while (*cursor == ' ') ++cursor;
    const char *end = cursor;
    while (*end && *end != ' ' && *end != '\n') ++end;
    return std::string(cursor, end);
}

void errlogCallback(void * /*priv*/, const char *msg) noexcept {
    if (!msg) return;
    const char *sub_pos = std::strstr(msg, kEventLogPrefixSubscribe);
    const char *del_pos = std::strstr(msg, kEventLogPrefixDelivery);
    const char *hit_pos = std::strstr(msg, kEventLogPrefixCacheHit);
    if (!sub_pos && !del_pos && !hit_pos) return;

    StatusEventCapture::EventKind kind;
    const char *pv_start;
    if (sub_pos) {
        kind = StatusEventCapture::Subscribe;
        pv_start = sub_pos + std::strlen(kEventLogPrefixSubscribe);
    } else if (del_pos) {
        kind = StatusEventCapture::Delivery;
        pv_start = del_pos + std::strlen(kEventLogPrefixDelivery);
    } else {
        kind = StatusEventCapture::CacheHit;
        pv_start = hit_pos + std::strlen(kEventLogPrefixCacheHit);
    }

    const auto pv = parsePvName(pv_start);
    if (pv.empty()) return;

    std::lock_guard<std::mutex> lk(g_registry_mu);
    for (auto *cap : g_registry) {
        cap->record(pv, kind);
    }
}

void installListenerOnce() {
    std::call_once(g_errlog_init_once, []() {
        errlogInit2(1024 * 1024, 0);
    });
    std::call_once(g_listener_once, []() {
        errlogAddListener(&errlogCallback, nullptr);
    });
}

}  // namespace

struct StatusEventCapture::Pvt {
    mutable std::mutex mu;
    std::unordered_map<std::string, uint32_t> subscribes;
    std::unordered_map<std::string, uint32_t> deliveries;
    std::unordered_map<std::string, uint32_t> cache_hits;
    std::condition_variable cv;
};

StatusEventCapture::StatusEventCapture() : pvt_(new Pvt{}) {
    installListenerOnce();
    pvxs::logger_level_set("pvxs.certs.mon.event", pvxs::Level::Info);
    {
        std::lock_guard<std::mutex> lk(g_registry_mu);
        g_registry.insert(this);
    }
}

StatusEventCapture::~StatusEventCapture() {
    std::lock_guard<std::mutex> lk(g_registry_mu);
    g_registry.erase(this);
}

void StatusEventCapture::record(const std::string &pv_name, EventKind kind) noexcept {
    try {
        const char *kind_str = "unknown";
        std::lock_guard<std::mutex> lk(pvt_->mu);
        switch (kind) {
        case Subscribe: ++pvt_->subscribes[pv_name]; kind_str = "subscribe"; break;
        case Delivery:  ++pvt_->deliveries[pv_name]; kind_str = "delivery";  break;
        case CacheHit:  ++pvt_->cache_hits[pv_name]; kind_str = "cache-hit"; break;
        }
        pvt_->cv.notify_all();
        log_debug_printf(capture_log, "captured event: pv=%s kind=%s\n",
                         pv_name.c_str(), kind_str);
    } catch (...) {
    }
}

uint32_t StatusEventCapture::subscribesFor(const std::string &pv_name) const {
    errlogFlush();
    std::lock_guard<std::mutex> lk(pvt_->mu);
    auto it = pvt_->subscribes.find(pv_name);
    return it == pvt_->subscribes.end() ? 0u : it->second;
}

uint32_t StatusEventCapture::deliveriesFor(const std::string &pv_name) const {
    errlogFlush();
    std::lock_guard<std::mutex> lk(pvt_->mu);
    auto it = pvt_->deliveries.find(pv_name);
    return it == pvt_->deliveries.end() ? 0u : it->second;
}

uint32_t StatusEventCapture::cacheHitsFor(const std::string &pv_name) const {
    errlogFlush();
    std::lock_guard<std::mutex> lk(pvt_->mu);
    auto it = pvt_->cache_hits.find(pv_name);
    return it == pvt_->cache_hits.end() ? 0u : it->second;
}

std::vector<std::string> StatusEventCapture::observedPvs() const {
    errlogFlush();
    std::set<std::string> pvs;
    {
        std::lock_guard<std::mutex> lk(pvt_->mu);
        for (auto &kv : pvt_->subscribes) pvs.insert(kv.first);
        for (auto &kv : pvt_->deliveries) pvs.insert(kv.first);
        for (auto &kv : pvt_->cache_hits) pvs.insert(kv.first);
    }
    return std::vector<std::string>(pvs.begin(), pvs.end());
}

uint32_t StatusEventCapture::totalSubscribes() const {
    errlogFlush();
    std::lock_guard<std::mutex> lk(pvt_->mu);
    uint32_t sum = 0;
    for (auto &kv : pvt_->subscribes) sum += kv.second;
    return sum;
}

uint32_t StatusEventCapture::totalDeliveries() const {
    errlogFlush();
    std::lock_guard<std::mutex> lk(pvt_->mu);
    uint32_t sum = 0;
    for (auto &kv : pvt_->deliveries) sum += kv.second;
    return sum;
}

uint32_t StatusEventCapture::totalCacheHits() const {
    errlogFlush();
    std::lock_guard<std::mutex> lk(pvt_->mu);
    uint32_t sum = 0;
    for (auto &kv : pvt_->cache_hits) sum += kv.second;
    return sum;
}

void StatusEventCapture::reset() {
    std::lock_guard<std::mutex> lk(pvt_->mu);
    pvt_->subscribes.clear();
    pvt_->deliveries.clear();
    pvt_->cache_hits.clear();
}

bool StatusEventCapture::waitSubscribesAtLeast(const std::string &pv_name,
                                               uint32_t n,
                                               double timeout_secs) const {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(static_cast<int64_t>(timeout_secs * 1000.0));
    while (true) {
        errlogFlush();
        std::unique_lock<std::mutex> lk(pvt_->mu);
        auto it = pvt_->subscribes.find(pv_name);
        const auto current = it == pvt_->subscribes.end() ? 0u : it->second;
        if (current >= n) return true;
        const auto poll = std::chrono::milliseconds(20);
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        const auto wake = std::min(deadline, now + poll);
        pvt_->cv.wait_until(lk, wake);
    }
}

bool StatusEventCapture::waitDeliveriesAtLeast(const std::string &pv_name,
                                               uint32_t n,
                                               double timeout_secs) const {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(static_cast<int64_t>(timeout_secs * 1000.0));
    while (true) {
        errlogFlush();
        std::unique_lock<std::mutex> lk(pvt_->mu);
        auto it = pvt_->deliveries.find(pv_name);
        const auto current = it == pvt_->deliveries.end() ? 0u : it->second;
        if (current >= n) return true;
        const auto poll = std::chrono::milliseconds(20);
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        const auto wake = std::min(deadline, now + poll);
        pvt_->cv.wait_until(lk, wake);
    }
}

bool StatusEventCapture::waitCacheHitsAtLeast(const std::string &pv_name,
                                              uint32_t n,
                                              double timeout_secs) const {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(static_cast<int64_t>(timeout_secs * 1000.0));
    while (true) {
        errlogFlush();
        std::unique_lock<std::mutex> lk(pvt_->mu);
        auto it = pvt_->cache_hits.find(pv_name);
        const auto current = it == pvt_->cache_hits.end() ? 0u : it->second;
        if (current >= n) return true;
        const auto poll = std::chrono::milliseconds(20);
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return false;
        const auto wake = std::min(deadline, now + poll);
        pvt_->cv.wait_until(lk, wake);
    }
}

}  // namespace internal
}  // namespace test
}  // namespace cms
