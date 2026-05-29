/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CCRMANAGER_H_
#define PVXS_CCRMANAGER_H_

#include <pvxs/data.h>

#include "security.h"

namespace pvxs {
namespace certs {

class CCRManager {
   public:
    static std::tuple<time_t, std::string> createCertificate(const std::shared_ptr<CertCreationRequest>& cert_creation_request, const std::string &cert_pv_prefix, const std::string &issuer_id, double timeout);
};

/** Decode a CCR-reply renew_by field, which the server publishes in EPICS-epoch
 *  seconds, into a Unix time_t. Returns 0 when absent or zero (no renewal date). */
time_t renewByFromCcrReply(const Value& reply);
}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CCRMANAGER_H_
