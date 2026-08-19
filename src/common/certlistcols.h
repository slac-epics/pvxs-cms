/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERTLISTCOLS_H_
#define PVXS_CERTLISTCOLS_H_

namespace pvxs {
namespace certs {

/**
 * @brief The field names the certificate listing table carries.
 *
 * This is the agreement between the certificate manager that fills the table in and whatever
 * reads it back, so both sides name the same columns from one declaration.
 *
 * It is kept apart from the rest of the listing because that half also declares the database
 * queries behind it, and reaching those means reaching SQLite. A tool only reads the served
 * table: it has no database and, on Windows and on the cross-compiled builds, no SQLite
 * headers to find. Naming a column must not require either.
 */
namespace certlistcol {
constexpr const char *kCertId = "cert_id";
constexpr const char *kType = "type";
constexpr const char *kSubject = "subject";
constexpr const char *kStatus = "status";
constexpr const char *kExpires = "expires";
constexpr const char *kIssued = "issued";
constexpr const char *kStatusChanged = "status_changed";
constexpr const char *kRenewBy = "renew_by";
constexpr const char *kRequestId = "request_id";
}  // namespace certlistcol

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTLISTCOLS_H_
