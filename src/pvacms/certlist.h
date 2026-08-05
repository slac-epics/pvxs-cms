/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERTLIST_H_
#define PVXS_CERTLIST_H_

#include <ctime>
#include <string>
#include <vector>

#include <sqlite3.h>

#include <pvxs/data.h>

namespace pvxs {
namespace certs {

/**
 * @brief Which certificates a listing covers.
 *
 * The three monitored views take no parameter - a display tool can parse only a field
 * clause out of a process variable name, so it has no way to send one - which is why each
 * view is its own fixed name rather than one name with an argument.
 */
enum class CertListView {
    All,              //!< Every certificate. Readable by everyone.
    PendingApproval,  //!< Awaiting an administrator's decision. Administrators only.
    Expiring,         //!< Expiring inside the server's window. Readable by everyone.
};

/** The columns a listing carries, in the order they appear. */
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

/**
 * @brief One certificate, with every column already rendered as the string it is served as.
 *
 * Rendered here rather than at the point of serving because the normative table carries only
 * scalar arrays and has nowhere to put per-column units or display form, so what the server
 * puts in the column is exactly what a viewer shows.
 */
struct CertListRow {
    std::string cert_id;         //!< issuer id and serial, the form a status channel name accepts
    std::string type;            //!< what the certificate is for, from its stored usage
    std::string subject;         //!< CN=...,OU=...,O=...,C=..., canonical order, empty parts omitted
    std::string status;          //!< status by name, including UNKNOWN
    std::string expires;         //!< fixed-width year-first date
    std::string issued;          //!< fixed-width year-first date
    std::string status_changed;  //!< fixed-width year-first date
    std::string renew_by;        //!< fixed-width year-first date
    std::string request_id;      //!< empty unless the caller is an administrator and one exists
};

/**
 * @brief Render a subject in the one canonical order, whatever order the certificate carries.
 *
 * `CN=...,OU=...,O=...,C=...`, omitting parts that are empty. Canonical rather than copied:
 * certificates issued before the leaf-first subject order change carry common name, country,
 * organization, unit, and a certificate from another authority can carry any order at all, so
 * printing each certificate's own order would show one identity two different ways. The point
 * of the column is that its text can be pasted into an access security file.
 *
 * Multiple organizational unit values keep their relative order among themselves.
 */
std::string renderSubject(const std::string &common_name, const std::string &organizational_unit,
                          const std::string &organization, const std::string &country);

/**
 * @brief Name what a certificate is for, from its stored key usage and extended key usage.
 *
 * A certificate stored before those were recorded has neither, and is named as unknown rather
 * than being silently reported as the most common kind.
 */
std::string renderCertType(const std::string &key_usage, const std::string &extended_key_usage);

/**
 * @brief Read the certificates a view covers, in the order the view serves them.
 *
 * @param certs_db      open certificate database
 * @param view          which certificates to read
 * @param issuer_id     the serving issuer, used to build the certificate identifier column
 * @param with_request_id  fill the request identifier column; left empty for everyone else
 * @param expiry_window_secs  how far ahead Expiring looks, ignored by the other views
 * @return the rows, already rendered
 */
std::vector<CertListRow> queryCertList(sqlite3 *certs_db, CertListView view, const std::string &issuer_id,
                                       bool with_request_id, time_t expiry_window_secs);

/**
 * @brief Build the normative table a listing is served as.
 *
 * Every column is a scalar array: the helper rejects an array element type outright, and the
 * normative type is defined as scalar arrays plus labels and the optional structures. So a
 * subject stays one rendered string and repeated organizations cannot become a nested list.
 *
 * @param rows           the rows to serve
 * @param with_request_id  include the request identifier column
 * @param expiry_window_secs  stated in the Expires label where the view is the expiring one,
 *                            since the structure has nowhere else to put it; zero for the others
 * @return a `epics:nt/NTTable:1.0` value with its timeStamp set to now
 */
Value buildCertListTable(const std::vector<CertListRow> &rows, bool with_request_id, time_t expiry_window_secs);

/** The column names a listing carries, in order. */
std::vector<std::string> certListColumns(bool with_request_id);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTLIST_H_
