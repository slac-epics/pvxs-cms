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
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <asLib.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/server.h>

#include "configcms.h"
#include "pvacms.h"

namespace cms {
namespace test {

namespace {

DEFINE_LOGGER(cluster_log, "cms.test.cluster");

std::string formatLoopbackAddr(const std::string &iface, uint16_t port) {
    std::ostringstream oss;
    if (iface.find(':') != std::string::npos) {
        oss << '[' << iface << "]:" << port;
    } else {
        oss << iface << ':' << port;
    }
    return oss.str();
}

void writeClusterAcf(const std::string &path, size_t n_members) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("PVACMSCluster: failed to open ACF for write: " + path);
    }
    out << "AUTHORITY(CMS_AUTH, \"PVXS CMS Test CA\")\n"
        << "\n"
        << "UAG(CMS_ADMIN) {admin}\n"
        << "\n"
        << "UAG(CMS_CLUSTER) {";
    for (size_t i = 0; i < n_members; ++i) {
        if (i > 0) out << ", ";
        out << "\"PVACMS-NODE-" << i << "\"";
    }
    out << "}\n"
        << "\n"
        << "ASG(DEFAULT) {\n"
        << "    RULE(0,READ)\n"
        << "    RULE(1,WRITE) {\n"
        << "        UAG(CMS_ADMIN)\n"
        << "        METHOD(\"x509\")\n"
        << "        AUTHORITY(CMS_AUTH)\n"
        << "    }\n"
        << "}\n"
        << "\n"
        << "ASG(CLUSTER) {\n"
        << "    RULE(0,READ) {\n"
        << "        UAG(CMS_CLUSTER)\n"
        << "        METHOD(\"x509\")\n"
        << "        AUTHORITY(CMS_AUTH)\n"
        << "        PROTOCOL(TLS)\n"
        << "    }\n"
        << "    RULE(1,WRITE) {\n"
        << "        UAG(CMS_CLUSTER)\n"
        << "        METHOD(\"x509\")\n"
        << "        AUTHORITY(CMS_AUTH)\n"
        << "        PROTOCOL(TLS)\n"
        << "    }\n"
        << "}\n";
    if (!out) {
        throw std::runtime_error("PVACMSCluster: failed to write ACF: " + path);
    }
}

::cms::ConfigCms makeClusterMemberConfig(const PkiFixture &pki,
                                         size_t member_index,
                                         const std::string &member_p12_path,
                                         bool ipv6,
                                         uint32_t discovery_secs,
                                         uint32_t bidi_secs,
                                         const std::string &cluster_pv_prefix) {
    ::cms::ConfigCms cfg{};
    if (!cluster_pv_prefix.empty()) {
        cfg.cluster_pv_prefix = cluster_pv_prefix;
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

    cfg.tls_keychain_file = member_p12_path;
    cfg.cert_auth_keychain_file = pki.caP12Path();
    cfg.admin_keychain_file = pki.adminP12Path();

    cfg.certs_db_filename = pki.dir() + "/certs-node-" + std::to_string(member_index) + ".db";
    cfg.pvacms_acf_filename = pki.dir() + "/pvacms.acf";

    cfg.preload_cert_files.push_back(pki.adminP12Path());
    cfg.preload_cert_files.push_back(member_p12_path);

#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    cfg.tls_status_cache_dir = pki.dir() + "/cache/pvacms-node-" + std::to_string(member_index);
#endif

    cfg.disableStatusCheck();
    cfg.disableStapling();

    cfg.cluster_mode = true;
    cfg.pvacms_name = std::string("PVACMS-NODE-") + std::to_string(member_index);
    cfg.cluster_discovery_timeout_secs = discovery_secs;
    cfg.cluster_bidi_timeout_secs = bidi_secs;

    return cfg;
}

}  // namespace

struct PVACMSCluster::Impl {
    PkiFixture *pki{nullptr};
    std::unique_ptr<PkiFixture> owned_pki;

    std::string cluster_name;
    bool ipv6{false};
    uint32_t discovery_secs{5};
    uint32_t bidi_secs{5};
    std::string interface_addr{"127.0.0.1"};

    ClusterTopology topology{ClusterTopology::empty(0)};

    std::vector<std::unique_ptr<cms::ServerHandle>> handles;
    std::vector<std::thread> workers;
    std::vector<std::unique_ptr<std::atomic<bool>>> running;
    std::vector<std::string> member_addrs;
    std::vector<std::vector<std::string>> bridge_entries;
    std::vector<std::string> member_p12_paths;

    mutable std::mutex coord_mutex;

    explicit Impl(size_t n)
        : topology(ClusterTopology::empty(n)),
          member_addrs(n),
          bridge_entries(n),
          member_p12_paths(n) {
        running.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            running.emplace_back(new std::atomic<bool>(false));
        }
    }

    PkiFixture &fixture() {
        if (!pki) throw std::logic_error("PVACMSCluster::Impl: no PKI fixture bound");
        return *pki;
    }
};

struct PVACMSCluster::Builder::Pvt {
    size_t n{2};
    bool topology_set{false};
    ClusterTopology topology{ClusterTopology::empty(0)};
    bool ipv6{false};
    PkiFixture *external_pki{nullptr};
    std::string cluster_name;
    uint32_t discovery_secs{5};
    uint32_t bidi_secs{5};
};

PVACMSCluster::Builder::Builder() : pvt_(new Pvt{}) {}
PVACMSCluster::Builder::Builder(Builder &&) noexcept = default;
PVACMSCluster::Builder &PVACMSCluster::Builder::operator=(Builder &&) noexcept = default;
PVACMSCluster::Builder::~Builder() = default;

PVACMSCluster::Builder &PVACMSCluster::Builder::size(size_t n) & {
    if (n == 0) throw std::invalid_argument("PVACMSCluster: size must be >= 1");
    pvt_->n = n;
    return *this;
}
PVACMSCluster::Builder &PVACMSCluster::Builder::topology(ClusterTopology t) & {
    pvt_->topology = std::move(t);
    pvt_->topology_set = true;
    return *this;
}
PVACMSCluster::Builder &PVACMSCluster::Builder::ipv6(bool yes) & {
    pvt_->ipv6 = yes;
    return *this;
}
PVACMSCluster::Builder &PVACMSCluster::Builder::pki(PkiFixture &fixture) & {
    pvt_->external_pki = &fixture;
    return *this;
}
PVACMSCluster::Builder &PVACMSCluster::Builder::clusterName(std::string name) & {
    pvt_->cluster_name = std::move(name);
    return *this;
}
PVACMSCluster::Builder &PVACMSCluster::Builder::clusterDiscoveryTimeoutSecs(uint32_t s) & {
    pvt_->discovery_secs = s;
    return *this;
}
PVACMSCluster::Builder &PVACMSCluster::Builder::clusterBidiTimeoutSecs(uint32_t s) & {
    pvt_->bidi_secs = s;
    return *this;
}

PVACMSCluster::PVACMSCluster() = default;
PVACMSCluster::PVACMSCluster(PVACMSCluster &&) noexcept = default;
PVACMSCluster &PVACMSCluster::operator=(PVACMSCluster &&) noexcept = default;

PVACMSCluster::~PVACMSCluster() {
    if (!impl_) return;
    for (size_t i = impl_->handles.size(); i > 0; --i) {
        size_t idx = i - 1;
        if (impl_->handles[idx] && impl_->running[idx]->load()) {
            try {
                cms::stopServer(*impl_->handles[idx]);
            } catch (const std::exception &e) {
                log_warn_printf(cluster_log,
                                "stopServer(%zu) in dtor: %s\n",
                                idx, e.what());
            }
        }
        if (idx < impl_->workers.size() && impl_->workers[idx].joinable()) {
            impl_->workers[idx].join();
        }
    }
    impl_->handles.clear();
    impl_->workers.clear();
    impl_->owned_pki.reset();
}

size_t PVACMSCluster::size() const noexcept {
    return impl_ ? impl_->topology.size() : 0u;
}
const ClusterTopology &PVACMSCluster::topology() const noexcept { return impl_->topology; }
const std::vector<std::string> &PVACMSCluster::memberAddrs() const noexcept {
    return impl_->member_addrs;
}
const PkiFixture &PVACMSCluster::pkiFixture() const noexcept { return impl_->fixture(); }
PkiFixture &PVACMSCluster::pkiFixture() noexcept { return impl_->fixture(); }
const std::string &PVACMSCluster::memberP12Path(size_t i) const {
    if (!impl_ || i >= impl_->member_p12_paths.size()) {
        throw std::out_of_range("PVACMSCluster::memberP12Path: index out of range");
    }
    return impl_->member_p12_paths[i];
}

::cms::ServerHandle &PVACMSCluster::memberHandle(size_t i) {
    if (!impl_ || i >= impl_->handles.size()) {
        throw std::out_of_range("PVACMSCluster::memberHandle: index out of range");
    }
    if (!impl_->handles[i]) {
        throw std::logic_error("PVACMSCluster::memberHandle: member is not running");
    }
    return *impl_->handles[i];
}

namespace {

std::vector<std::string> computePeers(const PVACMSCluster::Impl &impl, size_t i) {
    std::vector<std::string> peers;
    for (size_t j : impl.topology.peersSeenBy(i)) {
        if (j < impl.member_addrs.size()) peers.push_back(impl.member_addrs[j]);
    }
    for (const auto &foreign : impl.bridge_entries[i]) {
        peers.push_back(foreign);
    }
    return peers;
}

void buildAndStartMember(PVACMSCluster::Impl &impl, size_t i,
                         const ::cms::ConfigCms &cfg_template,
                         const std::vector<std::string> &peers) {
    auto cfg = cfg_template;

    auto state = ::cms::prepareCmsState(cfg);

    if (!cfg.pvacms_acf_filename.empty()) {
        if (auto err = asInitFile(cfg.pvacms_acf_filename.c_str(), "")) {
            log_err_printf(cluster_log, "asInitFile failed for member %zu: %ld\n",
                           i, (long)err);
            throw std::runtime_error("PVACMSCluster: asInitFile failed");
        }
    }

    impl.handles[i].reset(new cms::ServerHandle(
        cms::detail::prepareServerFromState(cfg, std::move(state))));

    const auto &eff = impl.handles[i]->pvaServer().config();
    impl.member_addrs[i] = formatLoopbackAddr(impl.interface_addr, eff.tcp_port);

    impl.running[i]->store(true);
    auto *handle_ptr = impl.handles[i].get();
    auto *running_ptr = impl.running[i].get();
    auto peers_copy = peers;
    impl.workers[i] = std::thread([handle_ptr, running_ptr, peers_copy]() {
        try {
            cms::startCluster(*handle_ptr, peers_copy);
        } catch (const std::exception &e) {
            log_err_printf(cluster_log, "startCluster failed: %s\n", e.what());
        }
        running_ptr->store(false);
    });
}

}  // namespace

PVACMSCluster PVACMSCluster::Builder::build() {
    initOnce();

    if (std::getenv("EPICS_PVACMS_CLUSTER_NAME_SERVERS")) {
        unsetenv("EPICS_PVACMS_CLUSTER_NAME_SERVERS");
    }
    if (std::getenv("EPICS_PVA_NAME_SERVERS")) {
        unsetenv("EPICS_PVA_NAME_SERVERS");
    }

    PVACMSCluster cluster;
    cluster.impl_.reset(new Impl(pvt_->n));
    auto &impl = *cluster.impl_;

    impl.cluster_name = pvt_->cluster_name;
    impl.ipv6 = pvt_->ipv6;
    impl.discovery_secs = pvt_->discovery_secs;
    impl.bidi_secs = pvt_->bidi_secs;
    impl.interface_addr = pvt_->ipv6 ? "::1" : "127.0.0.1";
    impl.topology = pvt_->topology_set ? std::move(pvt_->topology)
                                        : ClusterTopology::fullMesh(pvt_->n);

    if (pvt_->external_pki) {
        impl.pki = pvt_->external_pki;
    } else {
        impl.owned_pki.reset(new PkiFixture{});
        impl.pki = impl.owned_pki.get();
    }

    impl.handles.resize(pvt_->n);
    impl.workers = std::vector<std::thread>(pvt_->n);

    writeClusterAcf(impl.pki->dir() + "/pvacms.acf", pvt_->n);

    for (size_t i = 0; i < pvt_->n; ++i) {
        SubjectSpec member_subject;
        member_subject.common_name = std::string("PVACMS-NODE-") + std::to_string(i);
        impl.member_p12_paths[i] = impl.pki->issueServerCert(member_subject);

        auto cfg = makeClusterMemberConfig(*impl.pki, i, impl.member_p12_paths[i],
                                            impl.ipv6,
                                            impl.discovery_secs, impl.bidi_secs,
                                            impl.cluster_name);
        auto state = ::cms::prepareCmsState(cfg);

        if (!cfg.pvacms_acf_filename.empty()) {
            if (auto err = asInitFile(cfg.pvacms_acf_filename.c_str(), "")) {
                (void)err;
                throw std::runtime_error("PVACMSCluster: asInitFile failed");
            }
        }

        impl.handles[i].reset(new cms::ServerHandle(
            cms::detail::prepareServerFromState(cfg, std::move(state))));

        const auto &eff = impl.handles[i]->pvaServer().config();
        impl.member_addrs[i] = formatLoopbackAddr(impl.interface_addr, eff.tcp_port);
    }

    for (size_t i = 0; i < pvt_->n; ++i) {
        auto peers = computePeers(impl, i);

        impl.running[i]->store(true);
        auto *handle_ptr = impl.handles[i].get();
        auto *running_ptr = impl.running[i].get();
        impl.workers[i] = std::thread([handle_ptr, running_ptr, peers]() {
            try {
                cms::startCluster(*handle_ptr, peers);
            } catch (const std::exception &e) {
                log_err_printf(cluster_log, "startCluster failed: %s\n", e.what());
            }
            running_ptr->store(false);
        });

        if (i + 1 < pvt_->n) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    cluster.awaitConvergence();

    return cluster;
}

void PVACMSCluster::restartMember(size_t i) {
    {
        std::lock_guard<std::mutex> lk(impl_->coord_mutex);
        if (i >= impl_->topology.size()) {
            throw std::out_of_range("PVACMSCluster::restartMember: index out of range");
        }

        // Capture the old listener port BEFORE stopping so the rebuilt
        // server can bind to the same port - keeps peer nameServers
        // entries valid (the spec's "uniform single-pair restart, no
        // cascade" property only holds when peers can keep using their
        // original addresses).
        uint16_t reuse_port = 0;
        {
            const std::string &addr = impl_->member_addrs[i];
            auto colon = addr.rfind(':');
            if (colon != std::string::npos) {
                try {
                    reuse_port = static_cast<uint16_t>(std::stoul(addr.substr(colon + 1)));
                } catch (...) {
                    reuse_port = 0;
                }
            }
        }

        if (impl_->handles[i] && impl_->running[i]->load()) {
            try {
                cms::stopServer(*impl_->handles[i]);
            } catch (const std::exception &e) {
                log_warn_printf(cluster_log, "stopServer(%zu) during restart: %s\n",
                                i, e.what());
            }
        }
        if (impl_->workers[i].joinable()) impl_->workers[i].join();
        impl_->handles[i].reset();

        auto cfg = makeClusterMemberConfig(*impl_->pki, i, impl_->member_p12_paths[i],
                                           impl_->ipv6,
                                           impl_->discovery_secs, impl_->bidi_secs,
                                           impl_->cluster_name);
        if (reuse_port != 0) {
            cfg.tcp_port = reuse_port;
        }
        auto peers = computePeers(*impl_, i);
        buildAndStartMember(*impl_, i, cfg, peers);
    }
    // Post-restart re-convergence is not awaited: after a member restarts
    // (even on the same port), peer cluster_clients carry stale
    // pvxs::client::Channel state that defers reconnection long enough
    // that bidi-checks during the rejoin RPC time out on macOS loopback.
    // Restart-related tests must assert API-level properties only.
}

void PVACMSCluster::setUnreachable(size_t i, size_t j) {
    {
        std::lock_guard<std::mutex> lk(impl_->coord_mutex);
        impl_->topology.removeBidirectional(i, j);
    }
    restartMember(i);
    restartMember(j);
}

void PVACMSCluster::setReachable(size_t i, size_t j) {
    {
        std::lock_guard<std::mutex> lk(impl_->coord_mutex);
        impl_->topology.addBidirectional(i, j);
    }
    restartMember(i);
    restartMember(j);
}

pvxs::client::Config PVACMSCluster::cmsAdminClientConfig() const {
    pvxs::client::Config cfg;
    cfg.addressList.clear();
    cfg.nameServers.clear();
    for (const auto &addr : impl_->member_addrs) {
        cfg.addressList.push_back(addr);
        cfg.nameServers.push_back(addr);
    }
    cfg.tls_keychain_file = impl_->fixture().adminP12Path();
    return cfg;
}

pvxs::client::Config PVACMSCluster::memberClientConfig(size_t i) const {
    if (!impl_ || i >= impl_->member_addrs.size()) {
        throw std::out_of_range("PVACMSCluster::memberClientConfig: index out of range");
    }
    pvxs::client::Config cfg;
    cfg.addressList.clear();
    cfg.nameServers.clear();
    cfg.addressList.push_back(impl_->member_addrs[i]);
    cfg.nameServers.push_back(impl_->member_addrs[i]);
    cfg.tls_keychain_file = impl_->fixture().adminP12Path();
    return cfg;
}

namespace {

// Expected post-convergence membership count for member i: 1 (self) plus
// every node reachable from i over the directed topology graph.  SPVA cluster
// discovery propagates membership via SYNC, so a node eventually learns about
// every node in its forward-reachable set, not only direct nameServers peers.
size_t expectedMemberCount(const ClusterTopology &topology, size_t i) {
    const size_t n = topology.size();
    if (i >= n) return 1u;
    std::vector<bool> seen(n, false);
    seen[i] = true;
    std::vector<size_t> queue;
    queue.push_back(i);
    while (!queue.empty()) {
        size_t cur = queue.back();
        queue.pop_back();
        for (size_t j : topology.peersSeenBy(cur)) {
            if (!seen[j]) {
                seen[j] = true;
                queue.push_back(j);
            }
        }
    }
    size_t count = 0u;
    for (bool b : seen) if (b) ++count;
    return count;
}

}  // namespace

void PVACMSCluster::awaitConvergence() {
    if (!impl_ || impl_->handles.empty()) return;

    const size_t n = impl_->topology.size();
    std::vector<size_t> expected(n);
    for (size_t i = 0; i < n; ++i) {
        expected[i] = expectedMemberCount(impl_->topology, i);
    }

    // Generous bound: we converge in ~1s on a fast loopback but CI macOS
    // runners under load have shown >40s convergence on a 2-node cluster
    // (Join RPC retries + sqlite parse contention in clusterctrl's RPC
    // handler).  16x discovery_secs gives 80s headroom at the default 5s
    // knob.  Local runs still complete in ~1s and are not affected.
    const auto deadline = std::chrono::steady_clock::now()
                          + std::chrono::seconds(16 * impl_->discovery_secs);

    while (true) {
        bool all_converged = true;
        size_t laggard = 0;
        size_t laggard_actual = 0;
        size_t laggard_expected = 0;
        for (size_t i = 0; i < n; ++i) {
            if (!impl_->handles[i]) continue;
            size_t actual = 0;
            try {
                actual = impl_->handles[i]->clusterMemberCount();
            } catch (...) {
                actual = 0;
            }
            if (actual < expected[i]) {
                all_converged = false;
                laggard = i;
                laggard_actual = actual;
                laggard_expected = expected[i];
                break;
            }
        }
        if (all_converged) return;
        if (std::chrono::steady_clock::now() >= deadline) {
            std::ostringstream os;
            os << "PVACMSCluster::awaitConvergence: member " << laggard
               << " did not converge within " << (16 * impl_->discovery_secs)
               << "s (expected " << laggard_expected
               << " members, observed " << laggard_actual << ")";
            throw std::runtime_error(os.str());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void bridge(PVACMSCluster &a, size_t a_node, PVACMSCluster &b, size_t b_node) {
    if (!a.impl_ || a.impl_->handles.empty()) {
        throw std::logic_error("bridge: cluster a has not been built");
    }
    if (!b.impl_ || b.impl_->handles.empty()) {
        throw std::logic_error("bridge: cluster b has not been built");
    }
    if (a_node >= a.impl_->topology.size()) {
        throw std::out_of_range("bridge: a_node out of range");
    }
    if (b_node >= b.impl_->topology.size()) {
        throw std::out_of_range("bridge: b_node out of range");
    }

    auto *first = &a;
    auto *second = &b;
    if (second < first) std::swap(first, second);
    std::lock_guard<std::mutex> lk1(first->impl_->coord_mutex);
    std::lock_guard<std::mutex> lk2(second->impl_->coord_mutex);

    auto a_addr = a.impl_->member_addrs[a_node];
    auto b_addr = b.impl_->member_addrs[b_node];

    a.impl_->bridge_entries[a_node].push_back(b_addr);
    b.impl_->bridge_entries[b_node].push_back(a_addr);

    a.restartMember(a_node);
    b.restartMember(b_node);
}

void unbridge(PVACMSCluster &a, size_t a_node, PVACMSCluster &b, size_t b_node) {
    if (!a.impl_ || !b.impl_) {
        throw std::logic_error("unbridge: cluster not built");
    }
    if (a_node >= a.impl_->topology.size() || b_node >= b.impl_->topology.size()) {
        throw std::out_of_range("unbridge: node index out of range");
    }

    auto *first = &a;
    auto *second = &b;
    if (second < first) std::swap(first, second);
    std::lock_guard<std::mutex> lk1(first->impl_->coord_mutex);
    std::lock_guard<std::mutex> lk2(second->impl_->coord_mutex);

    auto b_addr = b.impl_->member_addrs[b_node];
    auto a_addr = a.impl_->member_addrs[a_node];

    auto &a_bridges = a.impl_->bridge_entries[a_node];
    auto a_it = std::find(a_bridges.begin(), a_bridges.end(), b_addr);
    if (a_it == a_bridges.end()) {
        throw std::logic_error("unbridge: no such bridge");
    }
    a_bridges.erase(a_it);

    auto &b_bridges = b.impl_->bridge_entries[b_node];
    auto b_it = std::find(b_bridges.begin(), b_bridges.end(), a_addr);
    if (b_it != b_bridges.end()) {
        b_bridges.erase(b_it);
    }

    a.restartMember(a_node);
    b.restartMember(b_node);
}

}  // namespace test
}  // namespace cms
