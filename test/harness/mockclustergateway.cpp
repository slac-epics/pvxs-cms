/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "mockclustergateway.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/source.h>

DEFINE_LOGGER(mockgw_log, "cms.test.mockgw");

namespace cms {
namespace test {

namespace {

class ForwardingSource : public server::Source {
public:
    ForwardingSource(client::Context upstream,
                     std::vector<std::string> substrings)
        : upstream_(std::move(upstream))
        , substrings_(std::move(substrings))
    {}

    bool matches(const std::string &name) const {
        for (const auto &needle : substrings_) {
            if (name.find(needle) != std::string::npos) return true;
        }
        return false;
    }

    void onSearch(Search &op) override {
        for (auto &name : op) {
            if (matches(name.name())) {
                name.claim();
                log_debug_printf(mockgw_log, "search claim: %s\n", name.name());
            }
        }
    }

    void onCreate(std::unique_ptr<server::ChannelControl> &&op) override {
        const std::string pv_name = op->name();
        if (!matches(pv_name)) return;

        log_debug_printf(mockgw_log, "channel create: %s\n", pv_name.c_str());

        // Capture upstream client by value so it stays alive as long
        // as the channel does.
        auto upstream = upstream_;

        // Hand the channel to two handlers — one for RPC (used by
        // cluster join), one for monitor (used by sync ingest).  The
        // pvxs ChannelControl API allows both to be installed; only
        // the one matching the inbound op type fires.
        op->onRPC([upstream, pv_name](std::unique_ptr<server::ExecOp> &&exec,
                                      pvxs::Value &&args) mutable {
            // Forward the RPC to upstream and reply with the result.
            std::fprintf(stderr, "MOCKGW forwarding RPC on %s\n", pv_name.c_str());
            std::shared_ptr<server::ExecOp> exec_holder(exec.release());
            try {
                upstream.rpc(pv_name, args)
                    .result([exec_holder, pv_name](client::Result &&res) {
                        try {
                            exec_holder->reply(res());
                        } catch (const std::exception &e) {
                            log_warn_printf(mockgw_log,
                                "upstream RPC on %s failed: %s\n",
                                pv_name.c_str(), e.what());
                            exec_holder->error(e.what());
                        }
                    })
                    .exec();
            } catch (const std::exception &e) {
                log_warn_printf(mockgw_log,
                    "RPC dispatch on %s failed: %s\n",
                    pv_name.c_str(), e.what());
                exec_holder->error(e.what());
            }
        });

        op->onSubscribe([upstream, pv_name](
                std::unique_ptr<server::MonitorSetupOp> &&setup) mutable {
            log_debug_printf(mockgw_log, "forwarding monitor on %s\n", pv_name.c_str());

            // Hold setup; we call connect() on first inbound update
            // because we need the type prototype from upstream.
            auto setup_shared = std::shared_ptr<server::MonitorSetupOp>(setup.release());
            auto control = std::make_shared<std::shared_ptr<server::MonitorControlOp>>();

            // Open upstream subscription
            try {
                auto upstream_sub = upstream.monitor(pv_name)
                    .maskConnected(false)
                    .maskDisconnected(false)
                    .event([setup_shared, control, pv_name]
                           (client::Subscription &sub) {
                        try {
                            while (auto val = sub.pop()) {
                                if (!*control) {
                                    // First update: clone the type and
                                    // accept downstream.
                                    try {
                                        *control = setup_shared->connect(val.cloneEmpty());
                                    } catch (const std::exception &e) {
                                        log_warn_printf(mockgw_log,
                                            "downstream connect on %s failed: %s\n",
                                            pv_name.c_str(), e.what());
                                        return;
                                    }
                                }
                                (*control)->tryPost(val);
                            }
                        } catch (client::Connected &) {
                            // upstream connected — nothing extra to do
                        } catch (client::Disconnect &) {
                            log_debug_printf(mockgw_log,
                                "upstream monitor on %s disconnected\n",
                                pv_name.c_str());
                            if (*control) (*control)->finish();
                        } catch (const std::exception &e) {
                            log_warn_printf(mockgw_log,
                                "upstream monitor on %s error: %s\n",
                                pv_name.c_str(), e.what());
                        }
                    })
                    .exec();

                // Stash subscription on the setup so it lives as long as
                // the downstream subscription does.
                auto sub_holder = std::make_shared<std::shared_ptr<client::Subscription>>(
                    std::move(upstream_sub));
                setup_shared->onClose([sub_holder, pv_name](const std::string &) {
                    log_debug_printf(mockgw_log,
                        "downstream monitor on %s closed; dropping upstream\n",
                        pv_name.c_str());
                    sub_holder->reset();
                });
            } catch (const std::exception &e) {
                log_warn_printf(mockgw_log,
                    "monitor dispatch on %s failed: %s\n",
                    pv_name.c_str(), e.what());
                setup_shared->error(e.what());
            }
        });
    }

private:
    client::Context upstream_;
    std::vector<std::string> substrings_;
};

}  // namespace

struct MockClusterGateway::Impl {
    Options opts;
    std::mutex mtx;
    std::shared_ptr<server::Server> srv;
    client::Context upstream;
    std::shared_ptr<ForwardingSource> source;
    std::string listen_addr;
    std::atomic<bool> running{false};

    explicit Impl(Options o) : opts(std::move(o)) {}
};

MockClusterGateway::MockClusterGateway(Options opts)
    : impl_(new Impl(std::move(opts)))
{
    if (impl_->opts.upstream_address.empty()) {
        throw std::runtime_error(
            "MockClusterGateway: upstream_address is required");
    }
}

MockClusterGateway::~MockClusterGateway() {
    try {
        stop();
    } catch (...) {
        // destructor must not throw
    }
}

void MockClusterGateway::start() {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    if (impl_->running.load()) return;

    // Build the upstream client targeting the configured backend.
    pvxs::client::Config client_cfg;
    client_cfg.tls_disabled = true;
    client_cfg.autoAddrList = false;
    client_cfg.addressList.clear();
    client_cfg.nameServers = {impl_->opts.upstream_address};
    impl_->upstream = client_cfg.build();

    // Build the listener server.  Loopback only, ephemeral or pinned port.
    pvxs::server::Config srv_cfg;
    srv_cfg.tls_disabled = true;
    srv_cfg.auto_beacon = false;
    srv_cfg.tcp_port = impl_->opts.listen_port;
    srv_cfg.udp_port = 0;
    srv_cfg.interfaces = {impl_->opts.listen_interface};
    srv_cfg.beaconDestinations = {};
    impl_->srv = std::make_shared<server::Server>(srv_cfg.build());

    // Install the forwarding source.  pvxs's __server source has order=0
    // and includes built-in PVs (server stats); use order=1 so we run AFTER
    // it but still before the wildcard fallback.
    impl_->source = std::make_shared<ForwardingSource>(
        impl_->upstream, impl_->opts.forwarded_substrings);
    impl_->srv->addSource("mockgw", impl_->source, 1);

    impl_->srv->start();

    auto eff = impl_->srv->config();
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s:%u",
                  impl_->opts.listen_interface.c_str(),
                  static_cast<unsigned>(eff.tcp_port));
    impl_->listen_addr = buf;
    impl_->opts.listen_port = eff.tcp_port;  // remember so restart pins port
    impl_->running.store(true);

    log_info_printf(mockgw_log,
        "MockClusterGateway listening on %s, forwarding to %s\n",
        impl_->listen_addr.c_str(), impl_->opts.upstream_address.c_str());
}

void MockClusterGateway::stop() {
    std::shared_ptr<server::Server> srv;
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        if (!impl_->running.load()) return;
        srv.swap(impl_->srv);
        impl_->source.reset();
        impl_->upstream = client::Context{};
        impl_->running.store(false);
    }
    if (srv) {
        try {
            srv->stop();
        } catch (const std::exception &e) {
            log_warn_printf(mockgw_log, "server stop: %s\n", e.what());
        }
        srv.reset();
    }
    log_info_printf(mockgw_log, "MockClusterGateway stopped (was %s)\n",
                    impl_->listen_addr.c_str());
}

std::string MockClusterGateway::listenAddress() const {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    return impl_->listen_addr;
}

bool MockClusterGateway::isRunning() const {
    return impl_->running.load();
}

}  // namespace test
}  // namespace cms
