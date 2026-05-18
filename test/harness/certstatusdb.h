/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef CMS_TEST_CERTSTATUSDB_H
#define CMS_TEST_CERTSTATUSDB_H

#include <cstdint>
#include <functional>
#include <string>

namespace cms {
namespace test {

struct CertRecord {
    int status{0};
    std::int64_t renew_by{0};
    int renewal_due{0};
};

std::uint64_t findCertSerialByCommonName(const std::string &db_path, const std::string &common_name);
void setCertStatus(const std::string &db_path, std::uint64_t serial, int status);
void setCertRenewBy(const std::string &db_path, std::uint64_t serial, std::int64_t renew_by);
CertRecord loadCertRecord(const std::string &db_path, std::uint64_t serial);
bool waitForCertRecord(const std::string &db_path, std::uint64_t serial, const std::function<bool(const CertRecord &)>& predicate, double timeout_secs);

}  // namespace test
}  // namespace cms

#endif
