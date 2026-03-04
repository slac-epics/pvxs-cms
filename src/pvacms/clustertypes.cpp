/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clustertypes.h"

#include <epicsTime.h>

#include <pvxs/nt.h>

#include "certfactory.h"

namespace {

void appendU32(std::string &buf, uint32_t val) {
    uint8_t bytes[4];
    bytes[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    bytes[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    bytes[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    bytes[3] = static_cast<uint8_t>(val & 0xFF);
    buf.append(reinterpret_cast<const char *>(bytes), 4);
}

void appendI32(std::string &buf, int32_t val) {
    appendU32(buf, static_cast<uint32_t>(val));
}

void appendU64(std::string &buf, uint64_t val) {
    uint8_t bytes[8];
    bytes[0] = static_cast<uint8_t>((val >> 56) & 0xFF);
    bytes[1] = static_cast<uint8_t>((val >> 48) & 0xFF);
    bytes[2] = static_cast<uint8_t>((val >> 40) & 0xFF);
    bytes[3] = static_cast<uint8_t>((val >> 32) & 0xFF);
    bytes[4] = static_cast<uint8_t>((val >> 24) & 0xFF);
    bytes[5] = static_cast<uint8_t>((val >> 16) & 0xFF);
    bytes[6] = static_cast<uint8_t>((val >> 8) & 0xFF);
    bytes[7] = static_cast<uint8_t>(val & 0xFF);
    buf.append(reinterpret_cast<const char *>(bytes), 8);
}

void appendI64(std::string &buf, int64_t val) {
    appendU64(buf, static_cast<uint64_t>(val));
}

void appendString(std::string &buf, const std::string &s) {
    appendU32(buf, static_cast<uint32_t>(s.size()));
    buf.append(s);
}

void appendBytes(std::string &buf, const pvxs::shared_array<const uint8_t> &bytes) {
    appendU32(buf, static_cast<uint32_t>(bytes.size()));
    buf.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

}  // namespace

namespace pvxs {
namespace certs {

using namespace pvxs::members;

void setTimeStamp(Value &parent, const char *field) {
    auto now = std::time(nullptr);
    parent[std::string(field) + ".secondsPastEpoch"] = static_cast<int64_t>(now) - POSIX_TIME_AT_EPICS_EPOCH;
    parent[std::string(field) + ".nanoseconds"] = static_cast<int32_t>(0);
}

int64_t getTimeStampAsUnix(const Value &parent, const char *field) {
    auto secs = parent[std::string(field) + ".secondsPastEpoch"].as<int64_t>();
    return secs + POSIX_TIME_AT_EPICS_EPOCH;
}

Value makeClusterSyncValue() {
    return TypeDef(TypeCode::Struct, {
        String("node_id"),
        nt::TimeStamp{}.build().as("timeStamp"),
        StructA("members", {
            String("node_id"),
            String("sync_pv"),
            UInt32("version_major"),
            UInt32("version_minor"),
            UInt32("version_patch"),
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
        }),
        UInt8A("signature"),
    }).create();
}

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
        return remote_status == REVOKED;
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

std::string canonicalizeSync(const Value &payload) {
    std::string buf;
    appendString(buf, payload["node_id"].as<std::string>());
    appendI64(buf, payload["timeStamp.secondsPastEpoch"].as<int64_t>());
    appendI32(buf, payload["timeStamp.nanoseconds"].as<int32_t>());

    auto members_arr = payload["members"].as<shared_array<const Value>>();
    appendU32(buf, static_cast<uint32_t>(members_arr.size()));
    for (const auto & elem : members_arr) {
        appendString(buf, elem["node_id"].as<std::string>());
        appendString(buf, elem["sync_pv"].as<std::string>());
        appendU32(buf, elem["version_major"].as<uint32_t>());
        appendU32(buf, elem["version_minor"].as<uint32_t>());
        appendU32(buf, elem["version_patch"].as<uint32_t>());
    }

    auto certs_arr = payload["certs"].as<shared_array<const Value>>();
    appendU32(buf, static_cast<uint32_t>(certs_arr.size()));
    for (const auto & elem : certs_arr) {
        appendI64(buf, elem["serial"].as<int64_t>());
        appendString(buf, elem["skid"].as<std::string>());
        appendString(buf, elem["cn"].as<std::string>());
        appendString(buf, elem["o"].as<std::string>());
        appendString(buf, elem["ou"].as<std::string>());
        appendString(buf, elem["c"].as<std::string>());
        appendI32(buf, elem["approved"].as<int32_t>());
        appendI64(buf, elem["not_before"].as<int64_t>());
        appendI64(buf, elem["not_after"].as<int64_t>());
        appendI64(buf, elem["renew_by"].as<int64_t>());
        appendI32(buf, elem["renewal_due"].as<int32_t>());
        appendI32(buf, elem["status"].as<int32_t>());
        appendI64(buf, elem["status_date"].as<int64_t>());
    }

    return buf;
}

std::string canonicalizeCtrl(const Value &payload) {
    std::string buf;
    appendU32(buf, payload["version_major"].as<uint32_t>());
    appendU32(buf, payload["version_minor"].as<uint32_t>());
    appendU32(buf, payload["version_patch"].as<uint32_t>());
    appendString(buf, payload["issuer_id"].as<std::string>());

    auto members_arr = payload["members"].as<shared_array<const Value>>();
    appendU32(buf, static_cast<uint32_t>(members_arr.size()));
    for (const auto & elem : members_arr) {
        appendString(buf, elem["node_id"].as<std::string>());
        appendString(buf, elem["sync_pv"].as<std::string>());
        appendU32(buf, elem["version_major"].as<uint32_t>());
        appendU32(buf, elem["version_minor"].as<uint32_t>());
        appendU32(buf, elem["version_patch"].as<uint32_t>());
    }

    return buf;
}

std::string canonicalizeJoinRequest(const Value &payload) {
    std::string buf;
    appendU32(buf, payload["version_major"].as<uint32_t>());
    appendU32(buf, payload["version_minor"].as<uint32_t>());
    appendU32(buf, payload["version_patch"].as<uint32_t>());
    appendString(buf, payload["node_id"].as<std::string>());
    appendString(buf, payload["sync_pv"].as<std::string>());
    appendBytes(buf, payload["nonce"].as<shared_array<const uint8_t>>());
    return buf;
}

std::string canonicalizeJoinResponse(const Value &payload) {
    std::string buf;
    appendU32(buf, payload["version_major"].as<uint32_t>());
    appendU32(buf, payload["version_minor"].as<uint32_t>());
    appendU32(buf, payload["version_patch"].as<uint32_t>());
    appendString(buf, payload["issuer_id"].as<std::string>());
    appendI64(buf, payload["timeStamp.secondsPastEpoch"].as<int64_t>());
    appendI32(buf, payload["timeStamp.nanoseconds"].as<int32_t>());

    auto members_arr = payload["members"].as<shared_array<const Value>>();
    appendU32(buf, static_cast<uint32_t>(members_arr.size()));
    for (const auto & elem : members_arr) {
        appendString(buf, elem["node_id"].as<std::string>());
        appendString(buf, elem["sync_pv"].as<std::string>());
        appendU32(buf, elem["version_major"].as<uint32_t>());
        appendU32(buf, elem["version_minor"].as<uint32_t>());
        appendU32(buf, elem["version_patch"].as<uint32_t>());
    }

    appendBytes(buf, payload["nonce"].as<shared_array<const uint8_t>>());
    return buf;
}

void clusterSign(const ossl_ptr<EVP_PKEY> &cert_auth_pkey, Value &payload, const std::string &canonical) {
    std::string sig_str = CertFactory::sign(cert_auth_pkey, canonical);
    shared_array<uint8_t> sig_bytes(sig_str.size());
    std::memcpy(sig_bytes.data(), sig_str.data(), sig_str.size());
    payload["signature"] = sig_bytes.freeze();
}

bool clusterVerify(const ossl_ptr<EVP_PKEY> &cert_auth_pub_key, const Value &payload, const std::string &canonical) {
    auto sig_bytes = payload["signature"].as<shared_array<const uint8_t>>();
    std::string sig_str(reinterpret_cast<const char *>(sig_bytes.data()), sig_bytes.size());
    return CertFactory::verifySignature(cert_auth_pub_key, canonical, sig_str);
}

}  // namespace certs
}  // namespace pvxs
