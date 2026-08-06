/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certreview.h"

#include <algorithm>
#include <iomanip>
#include <istream>
#include <ostream>
#include <sstream>

#include "certlistcols.h"
#include "certrequestid.h"

namespace pvxs {
namespace certs {

namespace {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return std::tolower(c); });
    return text;
}

std::string trim(const std::string &text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

const char *decisionName(const ReviewDecision decision) {
    switch (decision) {
        case ReviewDecision::Approve: return "APPROVE";
        case ReviewDecision::Deny: return "DENY";
        case ReviewDecision::Revoke: return "REVOKE";
        default: return "-";
    }
}

/** What the certificate becomes, for the review only. */
std::string resultingStatus(const ReviewRow &row, const ReviewDecision decision, const std::string &now) {
    switch (decision) {
        // The certificate manager writes REVOKED for a denial as well as for a revocation.
        case ReviewDecision::Deny:
        case ReviewDecision::Revoke:
            return "REVOKED";
        case ReviewDecision::Approve:
            return projectedApprovedStatus(row.issued, row.expires, now);
        default:
            return "-";
    }
}

//! One row of the listing, as it is shown before the prompt.
void printRow(std::ostream &out, const ReviewRow &row, const ReviewMode mode, const size_t index, const size_t total) {
    out << "\n[" << index << "/" << total << "] " << row.cert_id << "\n"
        << "  Subject        : " << row.subject << "\n"
        << "  Status         : " << row.status << "\n";
    if (mode == ReviewMode::Approval) {
        out << "  Request ID     : "
            << (row.request_id.empty() ? std::string("(none)") : requestIdForDisplay(row.request_id)) << "\n"
            << "  Status changed : " << row.status_changed << "\n";
    } else {
        out << "  Expires        : " << row.expires << "\n";
    }
    if (!row.ineligible_reason.empty()) out << "  Not offered    : " << row.ineligible_reason << "\n";
}

enum class Answer { Decide, Skip, Stop, Cancel, Again };

/** Read one answer. The mode decides which words mean a decision.
 *
 *  "s" is refused rather than guessed at: it begins both skip and stop, and those differ in
 *  whether the remaining certificates are offered at all.
 */
Answer readAnswer(std::istream &in, std::ostream &out, const ReviewMode mode, ReviewDecision &decision) {
    std::string line;
    if (!std::getline(in, line)) return Answer::Cancel;  // end of input is cancel
    const auto answer = lower(trim(line));

    if (answer.empty()) return Answer::Again;
    if (answer == "s") {
        out << "  \"s\" could mean skip or stop. Write the word you mean.\n";
        return Answer::Again;
    }
    if (answer == "skip") return Answer::Skip;
    if (answer == "stop") return Answer::Stop;
    if (answer == "cancel" || answer == "c") return Answer::Cancel;

    if (mode == ReviewMode::Approval) {
        if (answer == "approve" || answer == "a") { decision = ReviewDecision::Approve; return Answer::Decide; }
        if (answer == "deny" || answer == "d") { decision = ReviewDecision::Deny; return Answer::Decide; }
    } else {
        if (answer == "revoke" || answer == "r") { decision = ReviewDecision::Revoke; return Answer::Decide; }
    }
    return Answer::Again;
}

const char *prompt(const ReviewMode mode) {
    return mode == ReviewMode::Approval ? "  approve / deny / skip / stop / cancel ? "
                                        : "  revoke / skip / stop / cancel ? ";
}

}  // namespace

std::vector<ReviewRow> reviewRowsFromTable(const Value &table) {
    std::vector<ReviewRow> rows;
    const auto value = table["value"];
    if (!value) return rows;

    const auto column = [&value](const char *name) {
        shared_array<const std::string> out;
        if (const auto field = value[name]) out = field.as<shared_array<const std::string>>();
        return out;
    };
    const auto cert_id = column(certlistcol::kCertId);
    const auto subject = column(certlistcol::kSubject);
    const auto status = column(certlistcol::kStatus);
    const auto request_id = column(certlistcol::kRequestId);
    const auto issued = column(certlistcol::kIssued);
    const auto expires = column(certlistcol::kExpires);
    const auto status_changed = column(certlistcol::kStatusChanged);

    const auto at = [](const shared_array<const std::string> &c, const size_t i) {
        return i < c.size() ? c[i] : std::string();
    };
    for (size_t i = 0; i < cert_id.size(); i++) {
        ReviewRow row;
        row.cert_id = cert_id[i];
        row.subject = at(subject, i);
        row.status = at(status, i);
        row.request_id = at(request_id, i);
        row.issued = at(issued, i);
        row.expires = at(expires, i);
        row.status_changed = at(status_changed, i);
        rows.push_back(std::move(row));
    }
    return rows;
}

bool tableNamesRequestIds(const Value &table) {
    const auto value = table["value"];
    if (!value) return false;
    return static_cast<bool>(value[certlistcol::kRequestId]);
}

std::string projectedApprovedStatus(const std::string &issued, const std::string &expires, const std::string &now) {
    // The dates are fixed-width and year-first, so ordering them as plain text orders them in
    // time. Comparing them this way avoids parsing a rendered date back into a time.
    if (!issued.empty() && now < issued) return "PENDING";
    if (!expires.empty() && now >= expires) return "EXPIRED";
    return "VALID";
}

bool isRevocable(const std::string &status) {
    return status == "VALID" || status == "PENDING" || status == "PENDING_APPROVAL";
}

int runReview(std::vector<ReviewRow> &rows, const ReviewOptions &options, const ReviewCallbacks &callbacks, std::istream &in,
              std::ostream &out, std::ostream &err) {
    const auto eligible = [](const ReviewRow &row) { return row.ineligible_reason.empty(); };

    if (rows.empty()) {
        out << "No certificates to review.\n";
        return 0;
    }

    // Asking for an interactive run with nothing able to type into it, and no decision given up
    // front, is a command line mistake rather than something to guess at. The listing is still
    // printed, because that much was unambiguous.
    if (!options.interactive && options.all == ReviewDecision::Undecided) {
        size_t index = 0;
        for (const auto &row : rows) printRow(out, row, options.mode, ++index, rows.size());
        err << "\nNothing to read answers from, and no --all given. Nothing was written.\n";
        return 3;
    }

    if (options.mode == ReviewMode::Approval && options.all == ReviewDecision::Undecided) {
        out << "Compare the request identifier shown below against the one the requester sent you "
               "before approving.\n";
    }

    // ---- ask ----
    bool cancelled = false, stopped = false;
    size_t index = 0;
    for (auto &row : rows) {
        ++index;
        if (!eligible(row)) {
            printRow(out, row, options.mode, index, rows.size());
            continue;
        }
        if (options.all != ReviewDecision::Undecided) {
            row.decision = options.all;
            continue;
        }
        if (stopped) continue;

        printRow(out, row, options.mode, index, rows.size());
        for (;;) {
            out << prompt(options.mode) << std::flush;
            ReviewDecision decision{ReviewDecision::Undecided};
            switch (readAnswer(in, out, options.mode, decision)) {
                case Answer::Decide: row.decision = decision; break;
                case Answer::Skip: break;
                case Answer::Stop: stopped = true; break;
                case Answer::Cancel: cancelled = true; break;
                case Answer::Again: continue;
            }
            break;
        }
        if (cancelled) break;
    }

    if (cancelled) {
        out << "\nCancelled. Nothing was written.\n";
        return 0;
    }

    // ---- re-read, then review ----
    std::vector<ReviewRow *> to_write;
    for (auto &row : rows) {
        if (row.decision == ReviewDecision::Undecided) continue;
        if (callbacks.currentStatus) {
            const auto now_status = callbacks.currentStatus(row.cert_id);
            // An unreadable status is not a reason to drop the certificate: the write itself
            // will refuse it if it has moved, and the server's message is the better answer.
            const bool moved = !now_status.empty() && now_status != row.status;
            if (moved) {
                row.changed_to = now_status;
                continue;
            }
        }
        to_write.push_back(&row);
    }

    for (const auto &row : rows) {
        if (!row.changed_to.empty())
            out << "\n" << row.cert_id << " changed since listing: " << row.status << " -> " << row.changed_to
                << ", so it will not be written.\n";
    }

    if (to_write.empty()) {
        out << "\nNothing left to change. Nothing was written.\n";
        return 0;
    }

    out << "\nAbout to change " << to_write.size() << " certificate" << (to_write.size() == 1 ? "" : "s") << ":\n";
    for (const auto *row : to_write) {
        out << "  " << row->cert_id << "  " << row->subject << "\n"
            << "      " << row->status << " -> " << resultingStatus(*row, row->decision, options.now) << "  (" << decisionName(row->decision)
            << ")\n";
    }
    if (options.mode == ReviewMode::Approval) {
        out << "  The certificate manager decides the final value for an approval, from the "
               "certificate's own dates.\n";
    }

    // ---- confirm ----
    if (!options.assume_yes) {
        out << (options.mode == ReviewMode::Approval ? "\nApply these " : "\nRevoke these ") << to_write.size()
            << (options.mode == ReviewMode::Approval ? " changes? [y/N] " : " certificates? [y/N] ") << std::flush;
        std::string line;
        if (!std::getline(in, line)) line.clear();
        const auto answer = lower(trim(line));
        if (answer != "y" && answer != "yes") {
            out << "Cancelled. Nothing was written.\n";
            return 0;
        }
    }

    // ---- write ----
    bool any_failed = false;
    for (auto *row : to_write) {
        row->failure = callbacks.apply ? callbacks.apply(row->cert_id, row->decision) : std::string("no way to write");
        row->written = row->failure.empty();
        if (!row->written) any_failed = true;
    }

    out << "\n";
    for (const auto *row : to_write) {
        out << "  " << row->cert_id << "  " << (row->written ? "done" : "FAILED: " + row->failure) << "\n";
    }
    return any_failed ? 5 : 0;
}

}  // namespace certs
}  // namespace pvxs
