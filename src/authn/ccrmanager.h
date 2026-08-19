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
                                                             const CertData &held_before_request = {});
};
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CCRMANAGER_H_
