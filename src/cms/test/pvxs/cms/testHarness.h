/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CMS_TESTHARNESS_H
#define PVXS_CMS_TESTHARNESS_H

#include <memory>
#include <string>
#include <vector>

#if defined(__GNUC__) || defined(__clang__)
#  define PVXS_CMS_TEST_API __attribute__((visibility("default")))
#else
#  define PVXS_CMS_TEST_API
#endif

namespace pvxs {
namespace cms {
namespace test {

class PkiFixture;

class PVACMSHarness;
class PVACMSCluster;
class TestServerBuilder;
struct TestServerOpts;
struct TestClientOpts;
struct RegisteredServer;

struct SubjectSpec {
    std::string common_name;
    std::string country;
    std::string organization;
    std::string organizational_unit;
};

class PVXS_CMS_TEST_API PkiFixture {
public:
    PkiFixture();
    PkiFixture(const PkiFixture &) = delete;
    PkiFixture &operator=(const PkiFixture &) = delete;
    PkiFixture(PkiFixture &&) noexcept;
    PkiFixture &operator=(PkiFixture &&) noexcept;
    ~PkiFixture();

    const std::string &dir() const noexcept;

    const std::string &caP12Path() const noexcept;
    const std::string &caChainPemPath() const noexcept;
    const std::string &serverP12Path() const noexcept;
    const std::string &adminP12Path() const noexcept;

    std::string caFingerprintSha256() const;

    std::string issueServerEE(const SubjectSpec &subject);
    std::string issueClientEE(const SubjectSpec &subject);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace test
}  // namespace cms
}  // namespace pvxs

#endif  // PVXS_CMS_TESTHARNESS_H
