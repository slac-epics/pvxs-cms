/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CLUSTERTYPES_H_
#define PVXS_CLUSTERTYPES_H_

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include <pvxs/data.h>

#include "certstatus.h"
#include "ownedptr.h"

namespace cms {
    using pvxs::Value;
    using pvxs::TypeDef;
    using pvxs::TypeCode;
    using pvxs::Member;
    using cms::cert::certstatus_t;
    using cms::cert::VALID;
    using cms::cert::PENDING;
    using cms::cert::PENDING_APPROVAL;
    using cms::cert::PENDING_RENEWAL;
    using cms::cert::SCHEDULED_OFFLINE;
    using cms::cert::EXPIRED;
    using cms::cert::REVOKED;
    using cms::cert::UNKNOWN;
    using cms::detail::ossl_ptr;

enum SyncUpdateType : int32_t {
    SYNC_INCREMENTAL  = 0,
    SYNC_FULL_SNAPSHOT = 1,
};

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
 * @brief Encode a cluster Value into a deterministic byte buffer for signing/verification.
 *
 * Creates a copy of the payload with the "signature" field cleared, then encodes it
 * using pvxs::xcode::encodeFull() to produce a deterministic byte representation.
 *
 * @param payload  The cluster message Value to encode.
 * @return Binary encoding suitable for signature input.
 */
std::vector<uint8_t> clusterEncode(Value &payload);

/**
 * @brief Sign a cluster Value using xcode encoding.
 *
 * Encodes the payload (minus signature) with clusterEncode(), signs the resulting
 * bytes with the CA private key, and stores the signature in the payload's
 * "signature" field.
 *
 * @param cert_auth_pkey  CA private key used for signing.
 * @param payload         Value to sign; its "signature" field is populated in place.
 */
void clusterSign(const ossl_ptr<EVP_PKEY> &cert_auth_pkey, Value &payload);

/**
 * @brief Verify the signature on a cluster Value using xcode encoding.
 *
 * Encodes the payload (minus signature) with clusterEncode() and verifies the
 * stored signature against the CA public key.
 *
 * @param cert_auth_pub_key  CA public key used for verification.
 * @param payload            Value whose "signature" field is checked.
 * @return true if the signature is valid.
 */
bool clusterVerify(const ossl_ptr<EVP_PKEY> &cert_auth_pub_key, Value &payload);

}  // namespace cms

#endif  // PVXS_CLUSTERTYPES_H_
