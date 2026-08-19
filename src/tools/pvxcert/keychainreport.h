/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_KEYCHAIN_REPORT_H
#define PVXS_KEYCHAIN_REPORT_H

#include <iosfwd>
#include <string>

#include "certfilefactory.h"

namespace cms {
namespace cert {

/**
 * @brief Print the keychain file report for `pvxcert -f`.
 *
 * When the keychain holds an identity certificate, prints the certificate details block
 * (headers and separators on `err`, the details and any `Config URI` line on `out`), then the
 * trust anchor block on `out`, and returns the status PV name to query.
 *
 * When the keychain holds trust anchors but no identity certificate, prints
 * `No identity certificate; trust anchors only:` on `err` and the anchor block on `out`, and
 * returns an empty string; the caller then skips the status query.
 *
 * When the keychain holds neither an identity certificate nor any trust anchor, throws
 * `std::runtime_error("Failed to read certificate from file")` so the caller's existing
 * failure handling reports it unchanged.
 *
 * @param cert_data the keychain contents as read from the file
 * @param out where the report is printed
 * @param err where the headers, separators, and the no-identity notice are printed
 * @return the status PV name, or an empty string when there is no identity certificate
 */
std::string printKeychainReport(const pvxs::certs::CertData &cert_data, std::ostream &out, std::ostream &err);

}  // namespace cert
}  // namespace cms

#endif  // PVXS_KEYCHAIN_REPORT_H
