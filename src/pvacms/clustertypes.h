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

/**
 * @brief Set the EPICS timeStamp sub-structure to the current wall-clock time.
 * @param parent  Value containing the timeStamp field to populate.
 * @param field   Name of the timeStamp field (default "timeStamp").
 */
void setTimeStamp(Value &parent, const char *field = "timeStamp");

/**
 * @brief Extract the EPICS epoch secondsPastEpoch from a timeStamp sub-structure.
 * @param parent  Value containing the timeStamp field.
 * @param field   Name of the timeStamp field (default "timeStamp").
 * @return EPICS epoch seconds (seconds since 1990-01-01 UTC).
 */
int64_t getTimeStamp(const Value &parent, const char *field = "timeStamp");

/**
 * @brief Create a PVXS Value prototype for cluster sync snapshots.
 * @return Empty Value with node_id, timeStamp, members[], certs[], and signature fields.
 */
Value makeClusterSyncValue();

/**
 * @brief Create a PVXS Value prototype for the cluster control PV.
 * @return Empty Value with version, issuer_id, members[], and signature fields.
 */
Value makeClusterCtrlValue();

/**
 * @brief Create a PVXS Value prototype for cluster join RPC requests.
 * @return Empty Value with version, node_id, sync_pv, nonce, and signature fields.
 */
Value makeJoinRequestValue();

/**
 * @brief Create a PVXS Value prototype for cluster join RPC responses.
 * @return Empty Value with version, issuer_id, timeStamp, members[], nonce, and signature fields.
 */
Value makeJoinResponseValue();

/**
 * @brief Check whether a certificate status transition from local to remote is valid for sync.
 * @param local_status   Current status of the certificate in the local database.
 * @param remote_status  Status received from a remote cluster peer.
 * @return true if the transition is permitted.
 */
bool isValidStatusTransition(certstatus_t local_status, certstatus_t remote_status);

/**
 * @brief Produce a deterministic byte sequence from a cluster sync Value for signing/verification.
 * @param payload  The sync snapshot Value to canonicalize.
 * @return Binary canonical form suitable for signature input.
 */
std::string canonicalizeSync(const Value &payload);

/**
 * @brief Produce a deterministic byte sequence from a cluster ctrl Value for signing/verification.
 * @param payload  The ctrl PV Value to canonicalize.
 * @return Binary canonical form suitable for signature input.
 */
std::string canonicalizeCtrl(const Value &payload);

/**
 * @brief Produce a deterministic byte sequence from a join request Value for signing/verification.
 * @param payload  The join request Value to canonicalize.
 * @return Binary canonical form suitable for signature input.
 */
std::string canonicalizeJoinRequest(const Value &payload);

/**
 * @brief Produce a deterministic byte sequence from a join response Value for signing/verification.
 * @param payload  The join response Value to canonicalize.
 * @return Binary canonical form suitable for signature input.
 */
std::string canonicalizeJoinResponse(const Value &payload);

/**
 * @brief Sign a cluster Value by computing a signature over its canonical form.
 * @param cert_auth_pkey  CA private key used for signing.
 * @param payload         Value to sign; its "signature" field is populated in place.
 * @param canonical       Pre-computed canonical byte string of the payload.
 */
void clusterSign(const ossl_ptr<EVP_PKEY> &cert_auth_pkey, Value &payload, const std::string &canonical);

/**
 * @brief Verify the signature on a cluster Value against its canonical form.
 * @param cert_auth_pub_key  CA public key used for verification.
 * @param payload            Value whose "signature" field is checked.
 * @param canonical          Pre-computed canonical byte string of the payload.
 * @return true if the signature is valid.
 */
bool clusterVerify(const ossl_ptr<EVP_PKEY> &cert_auth_pub_key, const Value &payload, const std::string &canonical);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERTYPES_H_
