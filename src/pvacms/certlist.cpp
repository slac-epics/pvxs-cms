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
#include "pvacms.h"
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

std::string renderSubject(const std::string &common_name, const std::string &organizational_unit,
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
    append("OU", organizational_unit);
    append("O", organization);
    append("C", country);
    return subject;
}

std::string renderCertType(const std::string &key_usage, const std::string &extended_key_usage) {
    // Nothing stored means the certificate predates the type being recorded. Say so, rather
    // than let it read as the most common kind and be believed.
    if (key_usage.empty() && extended_key_usage.empty()) return "UNKNOWN";

    const bool serves = extended_key_usage.find("TLS Web Server Authentication") != std::string::npos ||
                        extended_key_usage.find("serverAuth") != std::string::npos;
    const bool connects = extended_key_usage.find("TLS Web Client Authentication") != std::string::npos ||
                          extended_key_usage.find("clientAuth") != std::string::npos;

    // A certificate that does both is what an input/output controller is issued: it serves its
    // own process variables and connects onward as a client.
    if (serves && connects) return "IOC";
    if (serves) return "SERVER";
    if (connects) return "CLIENT";

    // A certificate authority signs rather than serves or connects.
    if (key_usage.find("Certificate Sign") != std::string::npos ||
        key_usage.find("keyCertSign") != std::string::npos) {
        return "CERT_AUTH";
    }
    return "UNKNOWN";
}

std::vector<std::string> certListColumns(const bool with_request_id) {
    std::vector<std::string> names;
    names.reserve(sizeof(kColumns) / sizeof(kColumns[0]) + 1);
    for (const auto &column : kColumns) names.emplace_back(column.name);
    if (with_request_id) names.emplace_back(certlistcol::kRequestId);
    return names;
}

std::vector<CertListRow> queryCertList(sqlite3 *const certs_db, const CertListView view, const std::string &issuer_id,
                                       const bool with_request_id, const time_t expiry_window_secs) {
    const char *sql;
    switch (view) {
        case CertListView::PendingApproval:
            sql = SQL_LIST_CERTS_PENDING_APPROVAL;
            break;
        case CertListView::Expiring:
            sql = SQL_LIST_CERTS_EXPIRING;
            break;
        case CertListView::All:
        default:
            sql = SQL_LIST_CERTS_ALL;
            break;
    }

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

    std::vector<CertListRow> rows;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const auto serial = static_cast<uint64_t>(sqlite3_column_int64(statement, 0));

        CertListRow row;
        // Built from the serving issuer and the serial, not from the stored subject key
        // identifier, and through the same helper every parser uses: a display concatenates
        // this column into a status channel name, so the two cannot be allowed to drift.
        row.cert_id = getCertId(issuer_id, serial);
        row.subject = renderSubject(columnText(statement, 1), columnText(statement, 3), columnText(statement, 2),
                                    columnText(statement, 4));
        row.status = CERT_STATE(sqlite3_column_int(statement, 5));
        row.status_changed = renderDate(sqlite3_column_int64(statement, 6));
        row.issued = renderDate(sqlite3_column_int64(statement, 7));
        row.expires = renderDate(sqlite3_column_int64(statement, 8));
        row.renew_by = renderDate(sqlite3_column_int64(statement, 9));
        row.type = renderCertType(columnText(statement, 11), columnText(statement, 12));
        // Present either way; carries a value only for an administrator.
        row.request_id = with_request_id ? columnText(statement, 13) : std::string{};

        rows.push_back(std::move(row));
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
