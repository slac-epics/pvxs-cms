/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "harnessImpl.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <pvxs/server.h>
#include <pvxs/source.h>
#include <pvxs/srvcommon.h>

namespace pvxs {
namespace server {

namespace {

class ObservingSource final : public Source {
    std::shared_ptr<Source> next_;
    std::function<void(const std::string &)> on_subscribe_;

    struct WrapChan final : public ChannelControl {
        std::unique_ptr<ChannelControl> inner_;
        std::function<void(const std::string &)> on_subscribe_;

        WrapChan(std::unique_ptr<ChannelControl> &&inner,
                 std::function<void(const std::string &)> cb)
            : ChannelControl(inner->name(), inner->credentials(), inner->op()),
              inner_(std::move(inner)),
              on_subscribe_(std::move(cb)) {}

#ifdef PVXS_HAS_SIGNAL_RIGHTS
        void signalRights(bool writable) override {
            if (inner_) inner_->signalRights(writable);
        }
#endif

        void onOp(std::function<void(std::unique_ptr<ConnectOp> &&)> &&fn) override {
            inner_->onOp(std::move(fn));
        }

        void onRPC(std::function<void(std::unique_ptr<ExecOp> &&, Value &&)> &&fn) override {
            inner_->onRPC(std::move(fn));
        }

        void onSubscribe(std::function<void(std::unique_ptr<MonitorSetupOp> &&)> &&fn) override {
            auto cb = on_subscribe_;
            auto fnptr = std::make_shared<std::function<void(std::unique_ptr<MonitorSetupOp> &&)>>(std::move(fn));
            inner_->onSubscribe([cb, fnptr](std::unique_ptr<MonitorSetupOp> &&setup) mutable {
                if (cb) cb(setup->name());
                (*fnptr)(std::move(setup));
            });
        }

        void onClose(std::function<void(const std::string &)> &&fn) override {
            inner_->onClose(std::move(fn));
        }

        void close() override { inner_->close(); }

       private:
        void _updateInfo(const std::shared_ptr<const ReportInfo> &info) override {
#ifdef PVXS_EXPERT_API_ENABLED
            inner_->updateInfo(info);
#else
            (void)info;
#endif
        }
    };

   public:
    ObservingSource(std::shared_ptr<Source> next,
                    std::function<void(const std::string &)> cb)
        : next_(std::move(next)), on_subscribe_(std::move(cb)) {}

    void onSearch(Search &op) override { next_->onSearch(op); }
    List onList() override { return next_->onList(); }
    void show(std::ostream &strm) override { next_->show(strm); }
    void onCreate(std::unique_ptr<ChannelControl> &&op) override {
        std::unique_ptr<ChannelControl> wrapped(new WrapChan(std::move(op), on_subscribe_));
        next_->onCreate(std::move(wrapped));
    }
};

}  // namespace

}  // namespace server
}  // namespace pvxs

namespace pvxs {
namespace cms {
namespace test {
namespace internal {

std::shared_ptr<pvxs::server::Source> makeObservingSource(
    std::shared_ptr<pvxs::server::Source> inner,
    std::function<void(const std::string &)> on_subscribe) {
    return std::make_shared<pvxs::server::ObservingSource>(std::move(inner),
                                                           std::move(on_subscribe));
}

}  // namespace internal
}  // namespace test
}  // namespace cms
}  // namespace pvxs
