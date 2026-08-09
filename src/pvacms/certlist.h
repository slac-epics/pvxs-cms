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

#include "certfilter.h"
#include "certlistcols.h"
#include "certstatus.h"

namespace pvxs {
namespace certs {

/**
 * The columns every certificate listing reads, and the order every listing returns.
 *
 * The request identifier is joined in rather than selected from certs: it lives in its own
 * table and is absent for any certificate created before it existed, so the outer join
 * leaves it null and the handler renders that as an empty string.
 *
 * Ordered by created_date descending, ties broken on the serial so the order is total. The
 * order has to be stable under an update, because a monitored table that re-sorts itself
 * moves the row the operator was about to click. created_date is the only column that
 * qualifies: it is never written twice, whereas the serial is random rather than monotonic
 * and not_before is the start of validity, which for a certificate issued with a future
 * start date is later than the moment it was created.
 */
#define SQL_LIST_CERTS_COLUMNS        \
    "SELECT c.serial "                \
    "     , c.CN "                    \
    "     , c.O "                     \
    "     , c.OU "                    \
    "     , c.C "                     \
    "     , c.status "                \
    "     , c.status_date "           \
    "     , c.not_before "            \
    "     , c.not_after "             \
    "     , c.renew_by "              \
    "     , c.created_date "          \
    "     , c.key_usage "             \
    "     , c.extended_key_usage "    \
    "     , IFNULL(r.request_id, '') AS request_id " \
    "FROM certs c "                   \
    "LEFT JOIN cert_request_ids r ON r.serial = c.serial "

#define SQL_LIST_CERTS_ORDER          \
    "ORDER BY c.created_date DESC, c.serial ASC"

// A certificate's organizational units are read with their own statement, one indexed lookup per
// listed row (SQL_GET_SUBJECT_UNITS in certsubjectunits.h), rather than joined into the query
// above: joining would have to paste the values into one string, and a value may legally contain
// whatever separator was chosen, so the listing could not tell one unit from two.

/** Every certificate. */
#define SQL_LIST_CERTS_ALL            \
    SQL_LIST_CERTS_COLUMNS            \
    SQL_LIST_CERTS_ORDER

/** Certificates awaiting an administrator's decision. */
#define SQL_LIST_CERTS_PENDING_APPROVAL \
    SQL_LIST_CERTS_COLUMNS              \
    "WHERE c.status = :pending_approval " \
    SQL_LIST_CERTS_ORDER

/** Certificates whose expiry falls inside the server's expiry window. */
#define SQL_LIST_CERTS_EXPIRING       \
    SQL_LIST_CERTS_COLUMNS            \
    "WHERE c.not_after >= :now AND c.not_after <= :window_end " \
    SQL_LIST_CERTS_ORDER


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

/**
 * @brief One certificate, with every column already rendered as the string it is served as.
 *
 * Rendered here rather than at the point of serving because the normative table carries only
 * scalar arrays and has nowhere to put per-column units or display form, so what the server
 * puts in the column is exactly what a viewer shows.
 */
/**
 * @brief The facility root, for the listing.
 *
 * No certificate manager issued it, and none can be asked about it: a status answer about the
 * trust anchor would be carried over a connection that anchor underwrites. It is therefore not
 * in the certificates database and cannot be selected by a query, so it is assembled from the
 * certificate the manager loaded and offered to the same view and filter tests as every other
 * row.
 *
 * It is listed because of when it expires. Every certificate beneath it stops working the day
 * it does, and an authority that appears in no listing is one nobody is watching the calendar
 * for.
 */
struct RootAuthority {
    bool names_responder{false};  //!< whether the certificate says where its revocation is published
    certstatus_t standing{UNKNOWN};  //!< what that responder says, or UNKNOWN when there is none
    std::string cert_id;          //!< its own subject key identifier and serial, since it issued itself
    std::string common_name, organization, country;
    std::vector<std::string> organizational_units;
    uint64_t serial{0};
    time_t not_before{0}, not_after{0};
};

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
std::string renderSubject(const std::string &common_name, const std::vector<std::string> &organizational_units,
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
 * @param filter         narrows the result; the condition it gives is only an optimisation, so
 *                       every row that comes back is still checked against the whole expression
 * @return the rows, already rendered, in the order the view serves them
 */
std::vector<CertListRow> queryCertList(sqlite3 *certs_db, CertListView view, const std::string &issuer_id,
                                       bool with_request_id, time_t expiry_window_secs,
                                       const CertFilter *filter = nullptr,
                                       const RootAuthority *root = nullptr);

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
