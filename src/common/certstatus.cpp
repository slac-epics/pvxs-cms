/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The certificate status functions
 *
 *   certstatus.cpp
 *
 * Definitions that also exist in the upstream pvxs library (certstatus.cpp
 * inside libpvxs) are marked __attribute__((weak)) so the linker silently
 * discards them when statically linking against libpvxs.a.
 */

#include "certstatus.h"

#include "certstatusmanager.h"

// Portable weak-symbol annotation (GCC / Clang).
// MSVC does not need this: Windows builds skip pvacms entirely.
#if defined(__GNUC__) || defined(__clang__)
#  define PVXS_WEAK __attribute__((weak))
#else
#  define PVXS_WEAK
#endif

namespace pvxs {
namespace certs {

PVXS_WEAK
OCSPStatus::OCSPStatus(ocspcertstatus_t ocsp_status, const shared_array<const uint8_t> &ocsp_bytes, CertDate status_date, CertDate status_valid_until_time,
                       CertDate revocation_time)
    : ocsp_bytes(ocsp_bytes),
      ocsp_status(ocsp_status),
      status_date(status_date),
      status_valid_until_date(status_valid_until_time),
      revocation_date(revocation_time) {};

/**
 * @brief Initialise the OCSPStatus object
 *
 * @param trusted_store_ptr the trusted store to use for parsing the OCSP response
 */
void OCSPStatus::init(X509_STORE *trusted_store_ptr) {
    if (ocsp_bytes.empty()) {
        ocsp_status = OCSPCertStatus(OCSP_CERTSTATUS_UNKNOWN);
        status_date = time(nullptr);
    } else {
        const auto parsed_status = CmsStatusManager::parse(ocsp_bytes, trusted_store_ptr);
        ocsp_status = std::move(parsed_status.ocsp_status);
        status_date = std::move(parsed_status.status_date);
        status_valid_until_date = std::move(parsed_status.status_valid_until_date);
        revocation_date = std::move(parsed_status.revocation_date);
    }
}

PVXS_WEAK
PVACertificateStatus::operator CertificateStatus() const noexcept {
    return (status == UNKNOWN) ? static_cast<CertificateStatus>(UnknownCertificateStatus{}) : static_cast<CertificateStatus>(CertifiedCertificateStatus{*this});
}

PVXS_WEAK
OCSPStatus::operator CertificateStatus() const noexcept {
    return (ocsp_status == OCSP_CERTSTATUS_UNKNOWN) ? static_cast<CertificateStatus>(UnknownCertificateStatus{})
                                                    : static_cast<CertificateStatus>(CertifiedCertificateStatus{*this});
}

PVXS_WEAK
bool OCSPStatus::operator==(const CertificateStatus &rhs) const {
    return this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date && this->status_valid_until_date == rhs.status_valid_until_date &&
           this->revocation_date == rhs.revocation_date;
}

PVXS_WEAK
bool OCSPStatus::operator==(const PVACertificateStatus &rhs) const { return (CertificateStatus) * this == rhs; }

PVXS_WEAK
bool PVACertificateStatus::operator==(const CertificateStatus &rhs) const {
    return this->status == rhs.status && this->ocsp_status == rhs.ocsp_status && this->status_date == rhs.status_date &&
           this->status_valid_until_date == rhs.status_valid_until_date && this->revocation_date == rhs.revocation_date;
}

PVXS_WEAK bool operator==(ocspcertstatus_t &lhs, PVACertificateStatus &rhs) { return rhs == lhs; };
PVXS_WEAK bool operator!=(ocspcertstatus_t &lhs, PVACertificateStatus &rhs) { return rhs != lhs; };
PVXS_WEAK bool operator==(certstatus_t &lhs, PVACertificateStatus &rhs) { return rhs == lhs; };
PVXS_WEAK bool operator!=(certstatus_t &lhs, PVACertificateStatus &rhs) { return rhs != lhs; };
PVXS_WEAK bool operator==(ocspcertstatus_t &lhs, OCSPStatus &rhs) { return rhs == lhs; };
PVXS_WEAK bool operator!=(ocspcertstatus_t &lhs, OCSPStatus &rhs) { return rhs != lhs; };
PVXS_WEAK bool operator==(certstatus_t &lhs, OCSPStatus &rhs) { return rhs == lhs; };
PVXS_WEAK bool operator!=(certstatus_t &lhs, OCSPStatus &rhs) { return rhs != lhs; };

PVXS_WEAK
CertificateStatus ParsedOCSPStatus::status() {
    return {true, (PVACertStatus)(ocsp_status == OCSP_CERTSTATUS_GOOD ? VALID : UNKNOWN), ocsp_status, status_date, status_valid_until_date, revocation_date};
}
}  // namespace certs
}  // namespace pvxs
