/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGAUTHN_H_
#define PVXS_CONFIGAUTHN_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <pvxs/client.h>
#include <pvxs/config.h>

#include "security.h"

namespace pvxs {
namespace certs {

class ConfigAuthN : public client::Config {
   public:
    std::string name{};
    std::string organization{};
    std::string organizational_unit{};
    std::string country{"US"};
    bool no_status{false};
    std::string issuer_id{};

    std::string server_name{};
    std::string server_organization{};
    std::string server_organizational_unit{};
    std::string server_country{"US"};

    std::string tls_srv_keychain_file{};
    std::string tls_srv_keychain_pwd{};

    int64_t cert_validity_mins = 0; // Minutes for Custom Duration of requested certificate
    std::vector<SanEntry> san_entries;
    std::vector<SanEntry> server_san_entries;
    std::vector<ScheduleWindow> schedule_windows;

void fromAuthEnv(const std::map<std::string, std::string>& defs);
static std::string getIPAddress();
void updateDefs(defs_t& defs) const;
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGAUTHN_H_
