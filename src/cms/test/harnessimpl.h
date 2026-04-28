#ifndef PVXS_CMS_TEST_HARNESS_IMPL_H
#define PVXS_CMS_TEST_HARNESS_IMPL_H

#include "pvxs/cms/testharness.h"
#include "statuseventcapture.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <pvxs/cms/pvacms.h>
#include <pvxs/server.h>

namespace pvxs {
namespace cms {
namespace test {
namespace internal {

void startWithEaddrRetry(pvxs::server::Server &srv, int max_retries = 8);

std::shared_ptr<pvxs::server::Source> makeObservingSource(
    std::shared_ptr<pvxs::server::Source> inner,
    std::function<void(const std::string &)> on_subscribe);

}  // namespace internal

struct PVACMSHarness::Impl {
    PkiFixture *pki{nullptr};
    std::unique_ptr<PkiFixture> owned_pki;

    std::unique_ptr<pvxs::cms::ServerHandle> handle;
    std::thread worker;
    std::atomic<bool> running{false};

    std::string interface_addr;
    std::string pvacms_listener_addr;
    uint16_t pvacms_tcp_port{0};
    uint16_t pvacms_tls_port{0};
    std::string pvacms_issuer_id;
    std::function<void(const std::string &)> status_subscription_observer;

    mutable std::mutex tables_mutex;
    std::vector<std::shared_ptr<pvxs::server::Server>> owned_servers;
    std::vector<RegisteredServer> snapshot_table;

    mutable std::atomic<uint64_t> test_client_counter{0};
    std::atomic<uint64_t> test_server_counter{0};

    std::unique_ptr<internal::StatusEventCapture> status_event_capture;

    PkiFixture &fixture() {
        if (!pki) throw std::logic_error("PVACMSHarness::Impl: no PKI fixture bound");
        return *pki;
    }
};

}  // namespace test
}  // namespace cms
}  // namespace pvxs

#endif
