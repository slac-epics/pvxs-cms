/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "harnessimpl.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

#include <epicsThread.h>
#include <asLib.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/source.h>
#include <pvxs/srvcommon.h>

#include "configcms.h"
#include "pvacms.h"

namespace cms {
namespace test {

namespace {

DEFINE_LOGGER(harness_log, "cms.test.harness");

bool inLoopbackV4(const std::string &addr) {
    return addr.size() >= 4 && std::strncmp(addr.c_str(), "127.", 4) == 0;
}
bool inLoopbackV6(const std::string &addr) {
    return addr == "::1";
}
bool isLoopback(const std::string &addr) {
    if (addr.empty()) return false;
    if (addr.front() == '[') {
        auto end = addr.find(']');
        if (end == std::string::npos) return false;
        return inLoopbackV6(addr.substr(1, end - 1));
    }
    if (addr.find("::") != std::string::npos) {
        auto last_colon = addr.rfind(':');
        auto port_pos = addr.find_first_of("0123456789", last_colon);
        if (last_colon != std::string::npos && port_pos != std::string::npos &&
            port_pos > last_colon) {
            return inLoopbackV6(addr.substr(0, last_colon));
        }
        return inLoopbackV6(addr);
    }
    auto slash = addr.find('/');
    auto colon = addr.find(':');
    auto bare = addr.substr(0, std::min(slash, colon));
    return inLoopbackV4(bare);
}

std::string formatLoopback(const std::string &iface, uint16_t port) {
    std::ostringstream oss;
    if (iface.find(':') != std::string::npos) {
        oss << '[' << iface << "]:" << port;
    } else {
        oss << iface << ':' << port;
    }
    return oss.str();
}

std::atomic<uint64_t> g_unique_subject_counter{0};
std::string makeUniqueSubject(const std::string &prefix) {
    return prefix + "-" + std::to_string(g_unique_subject_counter.fetch_add(1));
}



::cms::ConfigCms makeIsolatedConfigCms(const PkiFixture &pki, bool ipv6, bool apply_env) {
    ::cms::ConfigCms cfg{};
    if (apply_env) {
        cfg.applyCertsEnv();
        cfg.applyCmsEnv({});
    }

    cfg.udp_port = 0u;
    cfg.tcp_port = 0u;
    cfg.tls_port = 0u;
    cfg.auto_beacon = false;
    cfg.interfaces.clear();
    cfg.beaconDestinations.clear();
    if (ipv6) {
        cfg.interfaces.emplace_back("::1");
        cfg.beaconDestinations.emplace_back("::1");
    } else {
        cfg.interfaces.emplace_back("127.0.0.1");
        cfg.beaconDestinations.emplace_back("127.0.0.1");
    }

    cfg.tls_keychain_file = pki.serverP12Path();
    cfg.cert_auth_keychain_file = pki.caP12Path();
    cfg.admin_keychain_file = pki.adminP12Path();

    cfg.certs_db_filename = pki.dir() + "/certs.db";
    cfg.pvacms_acf_filename = pki.dir() + "/pvacms.acf";

    cfg.preload_cert_files.push_back(pki.adminP12Path());

    cfg.tls_status_cache_dir = pki.dir() + "/cache/pvacms";

    cfg.disableStatusCheck();
    cfg.disableStapling();

    cfg.cluster_mode = false;

    cfg.cluster_discovery_timeout_secs = 1;
    cfg.cluster_bidi_timeout_secs = 0;

    return cfg;
}

}  // namespace

namespace internal {

void startWithEaddrRetry(pvxs::server::Server &srv, int max_retries) {
    for (int attempt = 0; attempt < max_retries; ++attempt) {
        try {
            srv.start();
            return;
        } catch (const std::exception &e) {
            const std::string msg = e.what();
            const bool is_eaddrinuse =
                msg.find("EADDRINUSE") != std::string::npos ||
                msg.find("Address already in use") != std::string::npos ||
                msg.find("address already in use") != std::string::npos;
            if (!is_eaddrinuse || attempt + 1 >= max_retries) {
                throw;
            }
            log_warn_printf(harness_log,
                            "Server::start() EADDRINUSE on attempt %d/%d: %s\n",
                            attempt + 1, max_retries, e.what());
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    throw std::runtime_error("startWithEaddrRetry: exhausted retries");
}

}  // namespace internal

// ---------- Sanity check helpers ----------

static void checkLoopbackList(const std::vector<std::string> &addrs,
                              const char *field) {
    for (const auto &addr : addrs) {
        if (addr.empty()) continue;
        if (!isLoopback(addr)) {
            throw std::runtime_error(std::string("sanityCheckLoopback: ") +
                                     field + " contains non-loopback address: " + addr);
        }
    }
}

void sanityCheckLoopback(const pvxs::client::Config &cfg) {
    checkLoopbackList(cfg.addressList, "addressList");
    checkLoopbackList(cfg.nameServers, "nameServers");
}

void sanityCheckLoopback(const pvxs::server::Config &cfg) {
    checkLoopbackList(cfg.interfaces, "interfaces");
    checkLoopbackList(cfg.beaconDestinations, "beaconDestinations");
}

// ---------- PVACMSHarness ----------

PVACMSHarness::PVACMSHarness() : impl_(new Impl{}) {}

PVACMSHarness::PVACMSHarness(PVACMSHarness &&) noexcept = default;
PVACMSHarness &PVACMSHarness::operator=(PVACMSHarness &&) noexcept = default;

PVACMSHarness::~PVACMSHarness() {
    if (!impl_) return;
    {
        std::lock_guard<std::mutex> lk(impl_->tables_mutex);
        for (auto &srv : impl_->owned_servers) {
            try {
                if (srv) srv->stop();
            } catch (...) {
            }
        }
        impl_->owned_servers.clear();
        impl_->snapshot_table.clear();
    }
    if (impl_->handle && impl_->running.load()) {
        try {
            cms::stopServer(*impl_->handle);
        } catch (const std::exception &e) {
            log_warn_printf(harness_log, "stopServer in dtor: %s\n", e.what());
        }
    }
    if (impl_->worker.joinable()) {
        impl_->worker.join();
    }
    impl_->handle.reset();
    impl_->owned_pki.reset();
}

const std::string &PVACMSHarness::pvacmsListenerAddr() const noexcept {
    return impl_->pvacms_listener_addr;
}
uint16_t PVACMSHarness::pvacmsTcpPort() const noexcept { return impl_->pvacms_tcp_port; }
uint16_t PVACMSHarness::pvacmsTlsPort() const noexcept { return impl_->pvacms_tls_port; }

const std::string &PVACMSHarness::pvacmsIssuerId() const noexcept {
    return impl_->pvacms_issuer_id;
}

uint32_t PVACMSHarness::subscribesFor(const std::string &pv_name) const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->subscribesFor(pv_name)
        : 0u;
}

uint32_t PVACMSHarness::deliveriesFor(const std::string &pv_name) const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->deliveriesFor(pv_name)
        : 0u;
}

uint32_t PVACMSHarness::cacheHitsFor(const std::string &pv_name) const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->cacheHitsFor(pv_name)
        : 0u;
}

uint32_t PVACMSHarness::statusReceivedFor(const std::string &pv_name) const {
    return deliveriesFor(pv_name);
}

uint32_t PVACMSHarness::totalStatusReceived() const {
    return totalDeliveries();
}

std::vector<std::string> PVACMSHarness::observedStatusPvs() const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->observedPvs()
        : std::vector<std::string>{};
}

uint32_t PVACMSHarness::totalSubscribes() const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->totalSubscribes()
        : 0u;
}

uint32_t PVACMSHarness::totalDeliveries() const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->totalDeliveries()
        : 0u;
}

uint32_t PVACMSHarness::totalCacheHits() const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->totalCacheHits()
        : 0u;
}

void PVACMSHarness::resetStatusEventCounters() {
    if (impl_->status_event_capture) impl_->status_event_capture->reset();
}

bool PVACMSHarness::waitSubscribesAtLeast(const std::string &pv_name,
                                          uint32_t n,
                                          double timeout_secs) const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->waitSubscribesAtLeast(pv_name, n, timeout_secs)
        : false;
}

bool PVACMSHarness::waitDeliveriesAtLeast(const std::string &pv_name,
                                          uint32_t n,
                                          double timeout_secs) const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->waitDeliveriesAtLeast(pv_name, n, timeout_secs)
        : false;
}

bool PVACMSHarness::waitCacheHitsAtLeast(const std::string &pv_name,
                                         uint32_t n,
                                         double timeout_secs) const {
    return impl_->status_event_capture
        ? impl_->status_event_capture->waitCacheHitsAtLeast(pv_name, n, timeout_secs)
        : false;
}

bool PVACMSHarness::waitStatusReceivedAtLeast(const std::string &pv_name,
                                              uint32_t n,
                                              double timeout_secs) const {
    return waitDeliveriesAtLeast(pv_name, n, timeout_secs);
}

const std::string &PVACMSHarness::caChainPemPath() const noexcept {
    return impl_->fixture().caChainPemPath();
}
const std::string &PVACMSHarness::adminP12Path() const noexcept {
    return impl_->fixture().adminP12Path();
}
const PkiFixture &PVACMSHarness::pkiFixture() const noexcept { return impl_->fixture(); }
PkiFixture &PVACMSHarness::pkiFixture() noexcept { return impl_->fixture(); }

const std::vector<RegisteredServer> &PVACMSHarness::startedTestServers() const noexcept {
    return impl_->snapshot_table;
}

void PVACMSHarness::stopTestServer(pvxs::server::Server &srv) {
    std::lock_guard<std::mutex> lk(impl_->tables_mutex);
    for (size_t i = 0; i < impl_->owned_servers.size(); ++i) {
        if (impl_->owned_servers[i].get() == &srv) {
            try {
                srv.stop();
            } catch (...) {
            }
            impl_->owned_servers.erase(impl_->owned_servers.begin() + i);
            for (auto it = impl_->snapshot_table.begin(); it != impl_->snapshot_table.end(); ++it) {
                if (it->server == &srv) {
                    impl_->snapshot_table.erase(it);
                    break;
                }
            }
            return;
        }
    }
}

pvxs::client::Config PVACMSHarness::cmsAdminClientConfig() const {
    pvxs::client::Config cfg;
    cfg.addressList.clear();
    cfg.addressList.push_back(impl_->pvacms_listener_addr);
    cfg.nameServers.clear();
    cfg.nameServers.push_back(impl_->pvacms_listener_addr);
    cfg.tls_keychain_file = impl_->fixture().adminP12Path();
    cfg.tls_status_cache_dir = impl_->fixture().dir() + "/cache/admin";
    return cfg;
}

pvxs::client::Config PVACMSHarness::testClientConfig(const TestClientOpts &opts) const {
    SubjectSpec subj;
    subj.common_name = opts.subject.empty() ? makeUniqueSubject("test-client") : opts.subject;
    auto client_p12 = const_cast<PkiFixture &>(impl_->fixture()).issueClientCert(subj);

    if (impl_->handle) {
        impl_->handle->registerCertFromP12(client_p12);
    }

    const auto client_id = impl_->test_client_counter.fetch_add(1);

    pvxs::client::Config cfg;
    cfg.addressList.clear();
    cfg.nameServers.clear();
    {
        std::lock_guard<std::mutex> lk(impl_->tables_mutex);
        for (const auto &reg : impl_->snapshot_table) {
            auto entry = formatLoopback(reg.addr, reg.tcp_port);
            cfg.addressList.push_back(entry);
            cfg.nameServers.push_back(entry);
        }
    }
    cfg.addressList.push_back(impl_->pvacms_listener_addr);
    cfg.nameServers.push_back(impl_->pvacms_listener_addr);
    cfg.tls_keychain_file = client_p12;
    cfg.tls_status_cache_dir = impl_->fixture().dir() + "/cache/test-client-" +
                               std::to_string(client_id);
    return cfg;
}

}  // namespace test
}  // namespace cms

// ---------- Builder definition ----------

#include <cms/pvacms.h>

namespace cms {
namespace test {

struct PVACMSHarness::Builder::Pvt {
    bool ipv6{false};
    bool apply_env{false};
    bool allow_external{false};
    PkiFixture *external_pki{nullptr};
    std::function<void(const std::string &)> status_subscription_observer;
};

PVACMSHarness::Builder::Builder() : pvt_(new Pvt{}) {}
PVACMSHarness::Builder::Builder(Builder &&) noexcept = default;
PVACMSHarness::Builder &PVACMSHarness::Builder::operator=(Builder &&) noexcept = default;
PVACMSHarness::Builder::~Builder() = default;

PVACMSHarness::Builder &PVACMSHarness::Builder::ipv6(bool yes) & {
    pvt_->ipv6 = yes;
    return *this;
}
PVACMSHarness::Builder &PVACMSHarness::Builder::pki(PkiFixture &fixture) & {
    pvt_->external_pki = &fixture;
    return *this;
}
PVACMSHarness::Builder &PVACMSHarness::Builder::applyEnv(bool yes) & {
    pvt_->apply_env = yes;
    return *this;
}
PVACMSHarness::Builder &PVACMSHarness::Builder::observeStatusSubscriptions(
    std::function<void(const std::string &)> cb) & {
    pvt_->status_subscription_observer = std::move(cb);
    return *this;
}

PVACMSHarness::Builder &PVACMSHarness::Builder::allowExternalBind() & {
    pvt_->allow_external = true;
    DEFINE_LOGGER(harness_log, "cms.test.harness");
    log_warn_printf(harness_log,
                    "PVACMSHarness::Builder::allowExternalBind() called - test will bind on non-loopback interfaces!%s",
                    "\n");
    const char *ci = std::getenv("CI");
    if (ci && ci[0] != '\0') {
        throw std::runtime_error(
            "PVACMSHarness::Builder::allowExternalBind() rejected: "
            "$CI is set in the environment");
    }
    return *this;
}

PVACMSHarness PVACMSHarness::Builder::build() {
    initOnce();

    PVACMSHarness harness;
    auto &impl = *harness.impl_;

    if (pvt_->external_pki) {
        impl.pki = pvt_->external_pki;
    } else {
        impl.owned_pki.reset(new PkiFixture{});
        impl.pki = impl.owned_pki.get();
    }

    impl.status_event_capture.reset(new internal::StatusEventCapture{});

    impl.interface_addr = pvt_->ipv6 ? "::1" : "127.0.0.1";

    auto cfg = makeIsolatedConfigCms(*impl.pki, pvt_->ipv6, pvt_->apply_env);

    auto state = ::cms::prepareCmsState(cfg);
    impl.pvacms_issuer_id = state.our_issuer_id;
    impl.status_subscription_observer = pvt_->status_subscription_observer;

    if (impl.status_subscription_observer) {
        auto observer = impl.status_subscription_observer;
        state.wrap_wildcard_source =
            [observer](std::shared_ptr<pvxs::server::Source> inner)
            -> std::shared_ptr<pvxs::server::Source> {
            return internal::makeObservingSource(std::move(inner), observer);
        };
    }

    if (!cfg.pvacms_acf_filename.empty()) {
        if (auto err = asInitFile(cfg.pvacms_acf_filename.c_str(), "")) {
            DEFINE_LOGGER(harness_log, "cms.test.harness");
            log_err_printf(harness_log, "asInitFile failed: %d\n", err);
            throw std::runtime_error("asInitFile failed in PVACMSHarness::Builder::build()");
        }
    }

    impl.handle.reset(new cms::ServerHandle(
        cms::detail::prepareServerFromState(cfg, std::move(state))));

    {
        const auto &eff = impl.handle->pvaServer().config();
        impl.pvacms_tcp_port = eff.tcp_port;
        impl.pvacms_tls_port = eff.tls_port;
        impl.pvacms_listener_addr = formatLoopback(impl.interface_addr, eff.tcp_port);
    }

    impl.running.store(true);
    auto *handle_ptr = impl.handle.get();
    auto *running_ptr = &impl.running;
    impl.worker = std::thread([handle_ptr, running_ptr]() {
        try {
            cms::startCluster(*handle_ptr);
        } catch (const std::exception &e) {
            DEFINE_LOGGER(harness_log, "cms.test.harness");
            log_err_printf(harness_log, "PVACMS run loop failed: %s\n", e.what());
        }
        running_ptr->store(false);
    });

    epicsThreadSleep(0.05);

    return harness;
}

}  // namespace test
}  // namespace cms
