/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "harnessimpl.h"

#include <atomic>
#include <stdexcept>

#include <pvxs/client.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>

#include "configcms.h"

namespace cms {
namespace test {

namespace {

std::atomic<uint64_t> g_server_counter{0};

}  // namespace

struct TestServerBuilder::Pvt {
    PVACMSHarness *harness{nullptr};
    TestServerOpts opts;
    std::function<void(pvxs::server::Config &)> customize_fn;
    std::vector<std::pair<std::string, pvxs::server::SharedPV>> pvs;
    std::vector<std::pair<std::string, std::shared_ptr<pvxs::server::Source>>> sources;
    bool consumed{false};
};

TestServerBuilder::TestServerBuilder(PVACMSHarness &harness) : pvt_(new Pvt{}) {
    pvt_->harness = &harness;
}
TestServerBuilder::TestServerBuilder(TestServerBuilder &&) noexcept = default;
TestServerBuilder &TestServerBuilder::operator=(TestServerBuilder &&) noexcept = default;
TestServerBuilder::~TestServerBuilder() = default;

TestServerBuilder &&TestServerBuilder::opts(const TestServerOpts &o) && {
    pvt_->opts = o;
    return std::move(*this);
}
TestServerBuilder &&TestServerBuilder::customize(std::function<void(pvxs::server::Config &)> fn) && {
    pvt_->customize_fn = std::move(fn);
    return std::move(*this);
}
TestServerBuilder &&TestServerBuilder::withPV(const std::string &name, pvxs::server::SharedPV pv) && {
    pvt_->pvs.emplace_back(name, std::move(pv));
    return std::move(*this);
}
TestServerBuilder &&TestServerBuilder::withSource(const std::string &name,
                                                  std::shared_ptr<pvxs::server::Source> source) && {
    pvt_->sources.emplace_back(name, std::move(source));
    return std::move(*this);
}

pvxs::server::Server &TestServerBuilder::start() && {
    if (pvt_->consumed) {
        throw std::logic_error("TestServerBuilder::start(): builder already consumed");
    }
    pvt_->consumed = true;
    auto &harness = *pvt_->harness;
    auto &impl = *harness.impl_;

    SubjectSpec subj;
    subj.common_name = pvt_->opts.subject.empty()
        ? std::string("test-server-") + std::to_string(g_server_counter.fetch_add(1))
        : pvt_->opts.subject;
    auto entity_p12 = impl.fixture().issueServerCert(subj);

    if (impl.handle) {
        impl.handle->registerCertFromP12(entity_p12);
    }

    pvxs::server::Config cfg;
    cfg.tcp_port = 0;
    cfg.udp_port = 0;
    cfg.tls_port = 0;
    cfg.auto_beacon = false;
    cfg.interfaces.clear();
    cfg.beaconDestinations.clear();
    if (pvt_->opts.ipv6) {
        cfg.interfaces.emplace_back("::1");
        cfg.beaconDestinations.emplace_back("::1");
    } else {
        cfg.interfaces.emplace_back("127.0.0.1");
        cfg.beaconDestinations.emplace_back("127.0.0.1");
    }
    cfg.tls_keychain_file = entity_p12;
#ifdef PVXS_HAS_TLS_STATUS_CACHE_DIR
    cfg.tls_status_cache_dir = impl.fixture().dir() + "/cache/test-server-" +
                               std::to_string(impl.test_server_counter.fetch_add(1));
#else
    (void)impl.test_server_counter.fetch_add(1);
#endif

    if (pvt_->customize_fn) {
        pvt_->customize_fn(cfg);
    }

    std::shared_ptr<pvxs::server::Server> srv(new pvxs::server::Server(cfg.build()));
    for (auto &p : pvt_->pvs) {
        srv->addPV(p.first, p.second);
    }
    for (auto &s : pvt_->sources) {
        srv->addSource(s.first, s.second);
    }

    internal::startWithEaddrRetry(*srv);

    const auto &eff = srv->config();

    {
        std::lock_guard<std::mutex> lk(impl.tables_mutex);
        impl.owned_servers.push_back(srv);
        RegisteredServer reg;
        reg.addr = pvt_->opts.ipv6 ? "::1" : "127.0.0.1";
        reg.tcp_port = eff.tcp_port;
        reg.udp_port = eff.udp_port;
        reg.tls_port = eff.tls_port;
        reg.entity_subject = subj.common_name;
        reg.server = srv.get();
        impl.snapshot_table.push_back(reg);
    }

    return *srv;
}

TestServerBuilder PVACMSHarness::testServerBuilder() {
    return TestServerBuilder(*this);
}

}  // namespace test
}  // namespace cms
