/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGAUTHN_H_
#define PVXS_CONFIGAUTHN_H_

#include <iosfwd>
#include <type_traits>

#include <pvxs/client.h>
#include <pvxs/config.h>

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

    /**
     * @brief The PV prefix used to contact PVACMS (must match the PVACMS
     * --cert-pv-prefix).  Default "CERT".
     */
    std::string cert_pv_prefix{"CERT"};

    /**
     * @brief Set the certificate PV prefix
     * @param prefix the certificate PV prefix
     */
    void setCertPvPrefix(const std::string& prefix) { cert_pv_prefix = prefix; }

    /**
     * @brief Get the certificate PV prefix
     */
    std::string getCertPvPrefix() const { return cert_pv_prefix; }

    /**
     * @brief The request timeout, in seconds, for authenticator client
     * operations.  Not settable via an environment variable, only
     * programmatically or from a command line tool.
     */
    double request_timeout{5.0};

    /**
     * @brief Set the request timeout
     * @param timeout the request timeout in seconds
     */
    void setRequestTimeout(const double timeout) { request_timeout = timeout; }

    /**
     * @brief Get the request timeout
     */
    double getRequestTimeout() const { return request_timeout; }

void fromAuthEnv(const std::map<std::string, std::string>& defs);
static std::string getIPAddress();
void updateDefs(defs_t& defs) const;
};

//! Print the authenticator-relevant subset of a definitions map to a stream.
//! Shared by the operator<< of each concrete authenticator config type.
void printAuthNDefs(std::ostream& strm, const client::Config::defs_t& defs);

//! Print the full effective configuration for any authenticator config type.
//! A function template (rather than a single ConfigAuthN overload) so that the
//! concrete type's non-virtual updateDefs() is called and no derived-class
//! definitions are sliced away.
template <typename ConfigT, typename std::enable_if<std::is_base_of<ConfigAuthN, ConfigT>::value, int>::type = 0>
std::ostream& operator<<(std::ostream& strm, const ConfigT& conf) {
    client::Config::defs_t defs;
    conf.updateDefs(defs);
    printAuthNDefs(strm, defs);
    return strm;
}

}  // namespace certs
}  // namespace pvxs
#endif  // PVXS_CONFIGAUTHN_H_
