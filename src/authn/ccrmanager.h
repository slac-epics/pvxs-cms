/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CCRMANAGER_H_
#define PVXS_CCRMANAGER_H_

#include "certfilefactory.h"
#include "security.h"

namespace pvxs {
namespace certs {

class CCRManager {
   public:
    static std::tuple<time_t, std::string> createCertificate(const std::shared_ptr<CertCreationRequest>& cert_creation_request,
                                                             const std::string &cert_pv_prefix,
                                                             const std::string &issuer_id,
                                                             double timeout,
                                                             const std::shared_ptr<KeyPair> &key_pair = {},
                                                             const CertData &held_before_request = {},
                                                             const std::string &expected_issuer_id = {});

    /**
     * @brief Refuse a certificate that does not carry the organizational units that were asked for.
     *
     * A certificate manager that predates repeated units reads only the single-value field and
     * issues a certificate carrying the innermost unit alone. Because the units are a containment
     * path, such a certificate does not merely lose values: it asserts a shorter ancestry, which
     * access control reads as a different and broader identity. There is no capability negotiation
     * to lean on, so the only way to notice is to read the subject that came back.
     *
     * @param requested the organizational units that were asked for, innermost first
     * @param pem_string the certificate, and its chain, as they were returned
     * @throws std::runtime_error if the units differ from those asked for, in value or in order
     */
    static void checkIssuedOrganizationalUnits(const std::vector<std::string> &requested, const std::string &pem_string);
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CCRMANAGER_H_
