/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CLUSTERTYPES_H_
#define PVXS_CLUSTERTYPES_H_

#include <string>

#include <openssl/evp.h>

#include <pvxs/data.h>

#include "certstatus.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

Value makeClusterSyncValue();
Value makeClusterCtrlValue();
Value makeJoinRequestValue();
Value makeJoinResponseValue();

bool isValidStatusTransition(certstatus_t local_status, certstatus_t remote_status);

std::string canonicalizeSync(const Value &payload);
std::string canonicalizeCtrl(const Value &payload);
std::string canonicalizeJoinRequest(const Value &payload);
std::string canonicalizeJoinResponse(const Value &payload);

void clusterSign(const ossl_ptr<EVP_PKEY> &cert_auth_pkey, Value &payload, const std::string &canonical);
bool clusterVerify(const ossl_ptr<EVP_PKEY> &cert_auth_pub_key, const Value &payload, const std::string &canonical);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERTYPES_H_
