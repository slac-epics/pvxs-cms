#ifndef PVXS_CMS_TEST_STATUS_EVENT_CAPTURE_H
#define PVXS_CMS_TEST_STATUS_EVENT_CAPTURE_H

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace pvxs {
namespace cms {
namespace test {
namespace internal {

class StatusEventCapture {
public:
    StatusEventCapture();
    StatusEventCapture(const StatusEventCapture &) = delete;
    StatusEventCapture &operator=(const StatusEventCapture &) = delete;
    ~StatusEventCapture();

    void record(const std::string &pv_name, bool is_subscribe) noexcept;

    uint32_t subscribesFor(const std::string &pv_name) const;
    uint32_t deliveriesFor(const std::string &pv_name) const;
    std::vector<std::string> observedPvs() const;
    uint32_t totalSubscribes() const;
    uint32_t totalDeliveries() const;
    void reset();
    bool waitSubscribesAtLeast(const std::string &pv_name, uint32_t n,
                               double timeout_secs) const;
    bool waitDeliveriesAtLeast(const std::string &pv_name, uint32_t n,
                               double timeout_secs) const;

private:
    struct Pvt;
    std::unique_ptr<Pvt> pvt_;
};

}  // namespace internal
}  // namespace test
}  // namespace cms
}  // namespace pvxs

#endif
