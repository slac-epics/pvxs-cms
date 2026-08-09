/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certlist.h"

#include <stdexcept>

#include <pvxs/nt.h>

#include "certdate.h"
#include "certstatus.h"
#include "certsubjectunits.h"
#include "sqlitestmt.h"

namespace pvxs {
namespace certs {

namespace {

/** Column label text. Any unit belongs here: the structure has nowhere else to put one. */
struct ColumnSpec {
    const char *name;
    const char *label;
};

const ColumnSpec kColumns[] = {
    {certlistcol::kCertId, "Certificate"},
    {certlistcol::kType, "Type"},
    {certlistcol::kSubject, "Subject"},
    {certlistcol::kStatus, "Status"},
    {certlistcol::kExpires, "Expires"},
    {certlistcol::kIssued, "Issued"},
    {certlistcol::kStatusChanged, "Status changed"},
    {certlistcol::kRenewBy, "Renew by"},
};

/** Reads a text column, giving an empty string where the database holds null. */
std::string columnText(sqlite3_stmt *statement, const int column) {
    const auto *text = sqlite3_column_text(statement, column);
    return text ? reinterpret_cast<const char *>(text) : "";
}

/** Renders a stored time as the fixed-width year-first string every date column carries. */
std::string renderDate(const time_t when) { return when ? CertDate(when).s : std::string{}; }

}  // namespace

std::string renderSubject(const std::string &common_name, const std::vector<std::string> &organizational_units,
                          const std::string &organization, const std::string &country) {
    std::string subject;
    const auto append = [&subject](const char *key, const std::string &value) {
        if (value.empty()) return;
        if (!subject.empty()) subject += ",";
        subject += key;
        subject += "=";
        subject += value;
    };
    append("CN", common_name);
    // One part per unit, innermost first, the same order the certificate subject itself carries.
    // Read left to right the whole thing is a containment path: each part encloses the one before.
    for (const auto &organizational_unit : organizational_units) append("OU", organizational_unit);
    append("O", organization);
    append("C", country);
    return subject;
}

std::string renderCertType(const std::string &key_usage, const std::string &extended_key_usage) {
    // Nothing stored means the certificate predates the type being recorded. Say so, rather
    // than let it read as the most common kind and be believed.
    if (key_usage.empty() && extended_key_usage.empty()) return "UNKNOWN";

    // Signing other certificates is decided first, because it is the one capability nothing
    // else has. An authority is normally also allowed to serve and to connect - every
    // intermediate this system issues carries both web authentication usages - so asking what
    // it serves before asking whether it signs reports an authority as an ordinary controller.
    if (key_usage.find("Certificate Sign") != std::string::npos ||
        key_usage.find("keyCertSign") != std::string::npos) {
        return "CERT_AUTH";
    }

    const bool serves = extended_key_usage.find("TLS Web Server Authentication") != std::string::npos ||
                        extended_key_usage.find("serverAuth") != std::string::npos;
    const bool connects = extended_key_usage.find("TLS Web Client Authentication") != std::string::npos ||
                          extended_key_usage.find("clientAuth") != std::string::npos;

    // A certificate that does both is what an input/output controller is issued: it serves its
    // own process variables and connects onward as a client.
    if (serves && connects) return "IOC";
    if (serves) return "SERVER";
    if (connects) return "CLIENT";

    return "UNKNOWN";
}

/** What the Type column says for the facility root: an authority that issued itself. */
const char *const kRootAuthorityType = "ROOT_AUTH";

std::vector<std::string> certListColumns(const bool with_request_id) {
    std::vector<std::string> names;
    names.reserve(sizeof(kColumns) / sizeof(kColumns[0]) + 1);
    for (const auto &column : kColumns) names.emplace_back(column.name);
    if (with_request_id) names.emplace_back(certlistcol::kRequestId);
    return names;
}

std::vector<CertListRow> queryCertList(sqlite3 *const certs_db, const CertListView view, const std::string &issuer_id,
                                       const bool with_request_id, const time_t expiry_window_secs,
                                       const CertFilter *const filter, const RootAuthority *const root) {
    // A filter naming another certificate authority cannot match a row here, so say so rather
    // than run a query that cannot return one.
    if (filter && !filter->possibleFor(issuer_id)) return {};

    std::string sql_text;
    switch (view) {
        case CertListView::PendingApproval:
            sql_text = SQL_LIST_CERTS_COLUMNS "WHERE c.status = :pending_approval ";
            break;
        case CertListView::Expiring:
            sql_text = SQL_LIST_CERTS_COLUMNS "WHERE c.not_after >= :now AND c.not_after <= :window_end ";
            break;
        case CertListView::All:
        default:
            sql_text = SQL_LIST_CERTS_COLUMNS;
            break;
    }

    // The filter's condition narrows what comes back. It may only widen relative to the whole
    // expression, so the pass below is what actually decides.
    if (filter && !filter->whereClause().empty() && filter->whereClause() != "1") {
        sql_text += (view == CertListView::All ? "WHERE " : "AND ") + filter->whereClause() + " ";
    }
    sql_text += SQL_LIST_CERTS_ORDER;
    const char *const sql = sql_text.c_str();

    SqliteStmt statement;
    if (sqlite3_prepare_v2(certs_db, sql, -1, statement.acquire(), nullptr) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Failed to prepare the certificate listing: " << sqlite3_errmsg(certs_db));
    }

    if (view == CertListView::PendingApproval) {
        sqlite3_bind_int(statement, sqlite3_bind_parameter_index(statement, ":pending_approval"), PENDING_APPROVAL);
    } else if (view == CertListView::Expiring) {
        const auto now = timeNow();
        sqlite3_bind_int64(statement, sqlite3_bind_parameter_index(statement, ":now"), now);
        sqlite3_bind_int64(statement, sqlite3_bind_parameter_index(statement, ":window_end"), now + expiry_window_secs);
    }

    // The filter's values, bound in the order its condition uses them. Positional parameters
    // start after the named ones the view itself uses.
    if (filter) {
        int position = sqlite3_bind_parameter_count(statement) - static_cast<int>(filter->bindings().size());
        for (const auto &value : filter->bindings()) {
            ++position;
            switch (value.kind) {
                case FilterValueKind::Text:
                case FilterValueKind::Regex:
                    sqlite3_bind_text(statement, position, value.text.c_str(), -1, SQLITE_TRANSIENT);
                    break;
                default:
                    sqlite3_bind_int64(statement, position, value.number);
                    break;
            }
        }
    }

    // Prepared once and reused for every listed row, so the units cost one indexed lookup a row
    SqliteStmt units_statement;
    if (sqlite3_prepare_v2(certs_db, SQL_GET_SUBJECT_UNITS, -1, units_statement.acquire(), nullptr) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Failed to prepare the organizational unit read: " << sqlite3_errmsg(certs_db));
    }
    const auto unitsFor = [&units_statement](const int64_t db_serial) {
        std::vector<std::string> units;
        sqlite3_reset(units_statement);
        sqlite3_clear_bindings(units_statement);
        sqlite3_bind_int64(units_statement, sqlite3_bind_parameter_index(units_statement, ":serial"), db_serial);
        while (sqlite3_step(units_statement) == SQLITE_ROW) units.push_back(columnText(units_statement, 0));
        return units;
    };

    std::vector<CertListRow> rows;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto serial = static_cast<uint64_t>(sqlite3_column_int64(statement, 0));
        const auto organizational_units = unitsFor(sqlite3_column_int64(statement, 0));

        CertListRow row;
        // Built from the serving issuer and the serial, not from the stored subject key
        // identifier, and through the same helper every parser uses: a display concatenates
        // this column into a status channel name, so the two cannot be allowed to drift.
        row.cert_id = getCertId(issuer_id, serial);
        row.subject = renderSubject(columnText(statement, 1), organizational_units, columnText(statement, 2),
                                    columnText(statement, 4));
        row.status = CERT_STATE(sqlite3_column_int(statement, 5));
        row.status_changed = renderDate(sqlite3_column_int64(statement, 6));
        row.issued = renderDate(sqlite3_column_int64(statement, 7));
        row.expires = renderDate(sqlite3_column_int64(statement, 8));
        row.renew_by = renderDate(sqlite3_column_int64(statement, 9));
        row.type = renderCertType(columnText(statement, 11), columnText(statement, 12));
        // Present either way; carries a value only for an administrator.
        row.request_id = with_request_id ? columnText(statement, 13) : std::string{};

        // The whole expression, over every row the condition let through. This is where a test
        // the database cannot express - a pattern, or the certificate identifier - is decided.
        if (filter) {
            if (rows.size() >= kFilterMaxRows) break;  // a filter cannot be made to scan forever
            FilterRow candidate;
            candidate.cert_id = row.cert_id;
            candidate.serial = serial;
            candidate.common_name = columnText(statement, 1);
            candidate.organization = columnText(statement, 2);
            // Every unit, so `unit:beamline` matches a certificate for staff inside beamline
            candidate.organizational_units = organizational_units;
            candidate.country = columnText(statement, 4);
            // The same word the Type column shows, so a filter matches what an operator reads.
            candidate.type = row.type;
            candidate.status = sqlite3_column_int(statement, 5);
            candidate.status_date = sqlite3_column_int64(statement, 6);
            candidate.not_before = sqlite3_column_int64(statement, 7);
            candidate.not_after = sqlite3_column_int64(statement, 8);
            candidate.renew_by = sqlite3_column_int64(statement, 9);
            if (!filter->matches(candidate)) continue;
        }

        rows.push_back(std::move(row));
    }

    // The facility root, which no query can reach because it is in no table. It is offered to
    // the same two tests every other row passed: the view, and then the whole filter
    // expression. Nothing that was never requested can be awaiting a decision, so the view of
    // requests awaiting one is the only place it can never appear.
    if (root && view != CertListView::PendingApproval) {
        const auto now = time(nullptr);
        const bool within_view = view != CertListView::Expiring ||
                                 (root->not_after >= now && root->not_after <= now + expiry_window_secs);
        bool wanted = within_view;
        if (wanted && filter) {
            FilterRow candidate;
            candidate.cert_id = root->cert_id;
            candidate.serial = root->serial;
            candidate.common_name = root->common_name;
            candidate.organization = root->organization;
            candidate.organizational_units = root->organizational_units;
            candidate.country = root->country;
            candidate.type = kRootAuthorityType;
            candidate.status = static_cast<int>(root->standing);
            candidate.status_date = 0;
            candidate.not_before = root->not_before;
            candidate.not_after = root->not_after;
            candidate.renew_by = 0;
            wanted = filter->matches(candidate);
        }
        if (wanted) {
            CertListRow row;
            row.cert_id = root->cert_id;
            row.type = kRootAuthorityType;
            row.subject = renderSubject(root->common_name, root->organizational_units, root->organization,
                                        root->country);
            row.status = CERT_STATE(static_cast<int>(root->standing));
            row.issued = renderDate(root->not_before);
            row.expires = renderDate(root->not_after);
            // Nothing here changed its standing and nothing here will renew it: both are the
            // authority's own business, which is what the request column says.
            row.status_changed = renderDate(0);
            row.renew_by = renderDate(0);
            if (with_request_id) row.request_id = root->names_responder ? "EXTERN OCSP" : "EXTERN";
            rows.push_back(std::move(row));
        }
    }

    return rows;
}

Value buildCertListTable(const std::vector<CertListRow> &rows, const bool with_request_id,
                         const time_t expiry_window_secs) {
    nt::NTTable builder;

    // The window the expiring view uses goes in the label, because a normative table carries
    // no per-column display information and there is nowhere else for it.
    std::string expires_label{"Expires"};
    if (expiry_window_secs > 0) {
        expires_label += " (within ";
        expires_label += std::to_string(expiry_window_secs / (24 * 60 * 60));
        expires_label += " days)";
    }

    for (const auto &column : kColumns) {
        const char *label = column.label;
        if (column.name == std::string(certlistcol::kExpires)) label = expires_label.c_str();
        builder.add_column(TypeCode::String, column.name, label);
    }
    if (with_request_id) {
        builder.add_column(TypeCode::String, certlistcol::kRequestId, "Request");
    }

    auto table = builder.create();

    const auto fill = [&rows, &table](const char *name, std::string CertListRow::*field) {
        shared_array<std::string> values(rows.size());
        for (size_t i = 0; i < rows.size(); ++i) values[i] = rows[i].*field;
        table["value"][name] = values.freeze();
    };

    fill(certlistcol::kCertId, &CertListRow::cert_id);
    fill(certlistcol::kType, &CertListRow::type);
    fill(certlistcol::kSubject, &CertListRow::subject);
    fill(certlistcol::kStatus, &CertListRow::status);
    fill(certlistcol::kExpires, &CertListRow::expires);
    fill(certlistcol::kIssued, &CertListRow::issued);
    fill(certlistcol::kStatusChanged, &CertListRow::status_changed);
    fill(certlistcol::kRenewBy, &CertListRow::renew_by);
    if (with_request_id) fill(certlistcol::kRequestId, &CertListRow::request_id);

    // The one real time in this result: when the listing was made. Every other time here is a
    // property of a certificate, and is carried as a rendered string in its own column.
    const auto generated = timeNow();
    table["timeStamp.secondsPastEpoch"] = generated;
    table["timeStamp.nanoseconds"] = 0u;

    return table;
}

}  // namespace certs
}  // namespace pvxs
