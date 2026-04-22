/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clustertypes.h"

#include <vector>

#include <epicsTime.h>

#include <pvxs/nt.h>

#include "certfactory.h"

namespace pvxs {
namespace certs {

using namespace pvxs::members;

/** @brief Set the EPICS timeStamp sub-structure to the current wall-clock time. */
void setTimeStamp(Value &parent, const char *field) {
    epicsTimeStamp now;
    epicsTimeGetCurrent(&now);
    parent[std::string(field) + ".secondsPastEpoch"] = static_cast<int64_t>(now.secPastEpoch);
    parent[std::string(field) + ".nanoseconds"] = static_cast<int32_t>(now.nsec);
}

/** @brief Extract the EPICS epoch secondsPastEpoch from a timeStamp sub-structure. */
int64_t getTimeStamp(const Value &parent, const char *field) {
    return parent[std::string(field) + ".secondsPastEpoch"].as<int64_t>();
}

/** @brief Create a PVXS Value prototype for cluster sync snapshots. */
Value makeClusterSyncValue() {
    return TypeDef(TypeCode::Struct, {
        String("node_id"),
        nt::TimeStamp{}.build().as("timeStamp"),
        Int64("sequence"),
        Int32("update_type"),
        StructA("members", {
            String("node_id"),
            String("sync_pv"),
            UInt32("version_major"),
            UInt32("version_minor"),
            UInt32("version_patch"),
            Bool("connected"),
        }),
        StructA("certs", {
            Int64("serial"),
            String("skid"),
            String("cn"),
            String("o"),
            String("ou"),
            String("c"),
            Int32("approved"),
            Int64("not_before"),
            Int64("not_after"),
            Int64("renew_by"),
            Int32("renewal_due"),
            Int32("status"),
            Int64("status_date"),
            String("san"),
        }),
        StructA("cert_schedules", {
            Int64("serial"),
            String("day_of_week"),
            String("start_time"),
            String("end_time"),
        }),
        UInt8A("signature"),
    }).create();
}

/** @brief Create a PVXS Value prototype for the cluster control PV. */
Value makeClusterCtrlValue() {
    return TypeDef(TypeCode::Struct, {
        UInt32("version_major"),
        UInt32("version_minor"),
        UInt32("version_patch"),
        String("issuer_id"),
        StructA("members", {
            String("node_id"),
            String("sync_pv"),
            UInt32("version_major"),
            UInt32("version_minor"),
            UInt32("version_patch"),
        }),
        UInt8A("signature"),
    }).create();
}

/** @brief Create a PVXS Value prototype for cluster join RPC requests. */
Value makeJoinRequestValue() {
    return TypeDef(TypeCode::Struct, {
        UInt32("version_major"),
        UInt32("version_minor"),
        UInt32("version_patch"),
        String("node_id"),
        String("sync_pv"),
        UInt8A("nonce"),
        UInt8A("signature"),
    }).create();
}

/** @brief Create a PVXS Value prototype for cluster join RPC responses. */
Value makeJoinResponseValue() {
    return TypeDef(TypeCode::Struct, {
        UInt32("version_major"),
        UInt32("version_minor"),
        UInt32("version_patch"),
        String("issuer_id"),
        nt::TimeStamp{}.build().as("timeStamp"),
        StructA("members", {
            String("node_id"),
            String("sync_pv"),
            UInt32("version_major"),
            UInt32("version_minor"),
            UInt32("version_patch"),
        }),
        UInt8A("nonce"),
        UInt8A("signature"),
    }).create();
}

/**
 * @brief Check whether a certificate status transition from local to remote is valid for sync.
 * @param local_status   Current status in the local database.
 * @param remote_status  Status received from a remote cluster peer.
 * @return true if the transition is permitted.
 */
bool isValidStatusTransition(certstatus_t local_status, certstatus_t remote_status) {
    if (local_status == remote_status)
        return true;

    // Only operator/CCR-driven transitions are synced.  Time-based transitions
    // (PENDING->VALID, VALID->PENDING_RENEWAL, *->EXPIRED) are computed
    // independently by every node so they never arrive via sync.
    switch (local_status) {
    case PENDING:
        return remote_status == REVOKED;
    case PENDING_APPROVAL:
        return remote_status == VALID ||
               remote_status == PENDING ||
               remote_status == REVOKED;
    case VALID:
        return remote_status == REVOKED ||
               remote_status == SCHEDULED_OFFLINE;
    case SCHEDULED_OFFLINE:
        return remote_status == VALID ||
               remote_status == REVOKED;
    case PENDING_RENEWAL:
        return remote_status == VALID ||
               remote_status == REVOKED;
    case EXPIRED:
    case REVOKED:
    case UNKNOWN:
    default:
        return false;
    }
}

std::vector<uint8_t> clusterEncode(Value &payload) {
    // Mark all fields so encodeFull serializes real data, not defaults.
    // Monitor deltas have unmarked fields filled by cache_sync, but
    // encodeFull on a cloneEmpty+assign copy would miss them since
    // assign() only copies marked Struct fields.
    for (auto fld : payload.iall()) {
        fld.mark();
    }

    auto sig = payload["signature"].as<shared_array<const uint8_t>>();
    shared_array<uint8_t> empty_sig(0);
    payload["signature"] = empty_sig.freeze();

    std::vector<uint8_t> buf;
    xcode::encodeFull(buf, payload);

    payload["signature"] = sig;
    return buf;
}

void clusterSign(const ossl_ptr<EVP_PKEY> &cert_auth_pkey, Value &payload) {
    const auto sig = CertFactory::sign(cert_auth_pkey, clusterEncode(payload));
    shared_array<uint8_t> sig_bytes(sig.begin(), sig.end());
    payload["signature"] = sig_bytes.freeze();
}

bool clusterVerify(const ossl_ptr<EVP_PKEY> &cert_auth_pub_key, Value &payload) {
    auto sig_arr = payload["signature"].as<shared_array<const uint8_t>>();
    std::vector<uint8_t> sig(sig_arr.begin(), sig_arr.end());
    return CertFactory::verifySignature(cert_auth_pub_key, clusterEncode(payload), sig);
}

}  // namespace certs
}  // namespace pvxs
