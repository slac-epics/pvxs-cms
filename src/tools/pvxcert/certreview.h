/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERT_REVIEW_H
#define PVXS_CERT_REVIEW_H

#include <functional>
#include <iosfwd>
#include <string>
#include <vector>

#include <pvxs/data.h>

namespace pvxs {
namespace certs {

/** What an administrator decided about one certificate. */
enum class ReviewDecision {
    Undecided,  //!< skipped, stopped before, or never eligible
    Approve,
    Deny,
    Revoke,
};

/** Which question the run is asking. */
enum class ReviewMode {
    Approval,    //!< certificates awaiting a decision: approve, deny
    Revocation,  //!< certificates already issued: revoke
};

/** One certificate as the listing described it, plus what was decided about it.
 *
 *  The dates are the fixed-width year-first strings the listing serves. They compare correctly
 *  as plain text, which is what lets the projected status be worked out without parsing them.
 */
struct ReviewRow {
    std::string cert_id;
    std::string subject;
    std::string status;          //!< status when the listing was taken
    std::string request_id;      //!< empty unless the caller is an administrator and one exists
    std::string issued;          //!< start of validity
    std::string expires;
    std::string status_changed;

    ReviewDecision decision{ReviewDecision::Undecided};

    //! Why this certificate was never offered, empty when it was. Set before the run.
    std::string ineligible_reason;
    //! Filled in during the final review when the status moved since the listing.
    std::string changed_to;
    //! Filled in after writing: empty on success, otherwise the server's message verbatim.
    std::string failure;
    bool written{false};
};

/** What the session needs from the outside world, so the decision logic can be driven in a
 *  test without a certificate manager.
 */
struct ReviewCallbacks {
    /** Read a certificate's status now. Return an empty string when it cannot be read, which
     *  is treated as "unchanged" rather than as a reason to drop the certificate. */
    std::function<std::string(const std::string &cert_id)> currentStatus;

    /** Apply one decision. Return an empty string on success, otherwise the server's message
     *  verbatim so the administrator sees what the certificate manager actually said. */
    std::function<std::string(const std::string &cert_id, ReviewDecision)> apply;
};

struct ReviewOptions {
    ReviewMode mode{ReviewMode::Approval};
    /** Whether there is a terminal to type into. */
    bool interactive{true};
    /** --all: apply this decision to every eligible certificate without asking. */
    ReviewDecision all{ReviewDecision::Undecided};
    /** --yes: answer the one final confirmation. */
    bool assume_yes{false};
    /** The current time, rendered exactly as the listing renders its dates, so the projected
     *  status of an approval can be worked out by comparing the strings. */
    std::string now;
};

/** Turn the served listing table into review rows, column by column.
 *
 *  @param table the normative table the listing operation returns
 *  @return one row per certificate, in the order the table serves them
 */
std::vector<ReviewRow> reviewRowsFromTable(const Value &table);


/** The status the certificate manager will compute for a certificate it approves.
 *
 *  It derives the status from the dates rather than storing the requested one, so an approved
 *  certificate whose validity has not started yet becomes PENDING and one whose validity has
 *  passed becomes EXPIRED. Worked out here only so the review can say what is about to happen;
 *  the certificate manager decides the value that is actually written.
 *
 *  @param issued start of validity, fixed-width year-first
 *  @param expires end of validity, fixed-width year-first
 *  @param now the current time in the same format
 *  @return PENDING, EXPIRED or VALID
 */
std::string projectedApprovedStatus(const std::string &issued, const std::string &expires, const std::string &now);

/** Statuses a certificate can be revoked from. */
bool isRevocable(const std::string &status);

/** Run one review: ask, review, confirm, write.
 *
 *  Writes nothing until the single confirmation is answered, and writes through the callbacks
 *  so the caller owns every network operation.
 *
 *  @return the process exit code: 0 did what was asked (including cancelled and nothing to do),
 *          3 the command line asked for something that cannot be done, 5 some writes failed.
 */
int runReview(std::vector<ReviewRow> &rows, const ReviewOptions &options, const ReviewCallbacks &callbacks, std::istream &in,
              std::ostream &out, std::ostream &err);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERT_REVIEW_H
