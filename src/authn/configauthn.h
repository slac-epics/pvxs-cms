/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGAUTHN_H_
#define PVXS_CONFIGAUTHN_H_

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
    //! Organizational units, innermost first: the first sits inside the second, and so on.
    std::vector<std::string> organizational_unit{};
    std::string country{"US"};
    bool no_status{false};
    //! Certificate authorities named on this invocation, in the order they were named. The first
    //! is asked to mint; the rest matter only when trust is being established.
    std::vector<std::string> issuer_ids{};

    //! The authority asked to mint on this invocation, or an empty string when none was named.
    //!
    //! Named separately from the list so that the difference between the one authority that
    //! mints and the set of roots a keychain trusts is visible at every call site.
    std::string mintingIssuerId() const { return issuer_ids.empty() ? std::string() : issuer_ids.front(); }

    std::string server_name{};
    std::string server_organization{};
    //! Organizational units, innermost first: the first sits inside the second, and so on.
    std::vector<std::string> server_organizational_unit{};
    std::string server_country{"US"};

    std::string tls_srv_keychain_file{};
    std::string tls_srv_keychain_pwd{};

    int64_t cert_validity_mins = 0; // Minutes for Custom Duration of requested certificate

void fromAuthEnv(const std::map<std::string, std::string>& defs);
static std::string getIPAddress();
void updateDefs(defs_t& defs) const;
};

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGAUTHN_H_
