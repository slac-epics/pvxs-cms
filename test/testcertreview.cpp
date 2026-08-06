/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Reviewing certificates one at a time is the only place in this tool where an administrator
 * decides something irreversible about several certificates at once, so what matters is not
 * that it writes, but that it writes exactly what was agreed and nothing else: nothing before
 * the single confirmation, nothing that moved underneath, and nothing after a cancel.
 *
 * The decision logic is driven here from a scripted input stream with the writes captured, so
 * every one of those properties is checked without a certificate manager.
 */

#include <sstream>
#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/nt.h>
#include <pvxs/unittest.h>

#include "certlistcols.h"
#include "certreview.h"
#include "certstatus.h"

using namespace pvxs;
using namespace pvxs::certs;

namespace {

constexpr const char *kNow = "2026-08-05 12:00:00 UTC";

//! Records every write the session made, in order.
struct Writes {
    std::vector<std::string> applied;
    std::string fail_this;  //!< cert_id whose write fails, empty for none

    ReviewCallbacks callbacks(const std::string &changed_id = {}, const std::string &changed_to = {}) {
        ReviewCallbacks cb;
        cb.currentStatus = [changed_id, changed_to](const std::string &cert_id) -> std::string {
            if (!changed_id.empty() && cert_id == changed_id) return changed_to;
            return {};  // unchanged
        };
        cb.apply = [this](const std::string &cert_id, const ReviewDecision decision) -> std::string {
            applied.push_back(cert_id + "=" + (decision == ReviewDecision::Approve   ? "APPROVED"
                                               : decision == ReviewDecision::Deny    ? "DENIED"
                                                                                     : "REVOKED"));
            if (!fail_this.empty() && cert_id == fail_this) return "Invalid state transition or invalid serial number";
            return {};
        };
        return cb;
    }
};

std::vector<ReviewRow> pendingRows(const size_t count) {
    std::vector<ReviewRow> rows;
    for (size_t i = 0; i < count; i++) {
        ReviewRow row;
        row.cert_id = "aabbccdd:" + std::to_string(1000 + i);
        row.subject = "CN=user" + std::to_string(i) + ",O=epics.org,C=US";
        row.status = "PENDING_APPROVAL";
        row.request_id = "ABCD-EFGH-IJKL-000" + std::to_string(i);
        row.issued = "2026-08-01 00:00:00 UTC";
        row.expires = "2027-08-01 00:00:00 UTC";
        row.status_changed = "2026-08-01 00:00:00 UTC";
        rows.push_back(row);
    }
    return rows;
}

//! Run one session against a scripted answer stream; returns the exit code.
int run(std::vector<ReviewRow> &rows, ReviewOptions options, const ReviewCallbacks &cb, const std::string &script,
        std::string *transcript = nullptr) {
    std::istringstream in(script);
    std::ostringstream out, err;
    options.now = kNow;
    const int code = runReview(rows, options, cb, in, out, err);
    if (transcript) *transcript = out.str() + err.str();
    return code;
}

ReviewOptions approving() {
    ReviewOptions o;
    o.mode = ReviewMode::Approval;
    o.interactive = true;
    return o;
}

ReviewOptions revoking() {
    ReviewOptions o;
    o.mode = ReviewMode::Revocation;
    o.interactive = true;
    return o;
}

std::string joined(const std::vector<std::string> &v) {
    std::string out("[");
    for (size_t i = 0; i < v.size(); i++) { if (i) out += ", "; out += v[i]; }
    return out + "]";
}

// Two decisions then a confirmation: exactly those two writes, in the order listed.
void testTwoDecisionsAreWritten() {
    testDiag("approve, approve, confirm writes both");

    auto rows = pendingRows(2);
    Writes w;
    testEq(run(rows, approving(), w.callbacks(), "approve\napprove\ny\n"), 0);
    testEq(joined(w.applied), joined({"aabbccdd:1000=APPROVED", "aabbccdd:1001=APPROVED"}));
}

// Stop means leave this one and every one after it undecided, and go to the review.
void testStopLeavesTheRestUndecided() {
    testDiag("approve then stop reaches the review with one certificate");

    auto rows = pendingRows(5);
    Writes w;
    testEq(run(rows, approving(), w.callbacks(), "approve\nstop\ny\n"), 0);
    testEq(joined(w.applied), joined({"aabbccdd:1000=APPROVED"}));
}

// Cancel abandons everything, including decisions already made, and is not an error.
void testCancelWritesNothing() {
    testDiag("approve, approve, cancel writes nothing and exits zero");

    auto rows = pendingRows(3);
    Writes w;
    testEq(run(rows, approving(), w.callbacks(), "approve\napprove\ncancel\n"), 0);
    testEq(joined(w.applied), joined({}));
}

// The confirmation defaults to no, so a bare newline writes nothing.
void testDecliningTheConfirmationWritesNothing() {
    testDiag("a bare newline at the confirmation writes nothing");

    auto rows = pendingRows(2);
    Writes w;
    testEq(run(rows, approving(), w.callbacks(), "approve\napprove\n\n"), 0);
    testEq(joined(w.applied), joined({}));

    auto rows2 = pendingRows(1);
    Writes w2;
    testEq(run(rows2, approving(), w2.callbacks(), "approve\nno\n"), 0);
    testEq(joined(w2.applied), joined({}));
}

// End of input is a cancel, not an accidental approval of whatever was decided so far.
void testEndOfInputCancels() {
    testDiag("end of input during the questions cancels");

    auto rows = pendingRows(3);
    Writes w;
    testEq(run(rows, approving(), w.callbacks(), "approve\n"), 0);
    testEq(joined(w.applied), joined({}));
}

// "s" begins both skip and stop, and they differ in whether the rest is offered at all.
void testSIsAmbiguous() {
    testDiag("\"s\" is refused and names both words");

    auto rows = pendingRows(1);
    Writes w;
    std::string transcript;
    testEq(run(rows, approving(), w.callbacks(), "s\napprove\ny\n", &transcript), 0);
    testTrue(transcript.find("skip or stop") != std::string::npos);
    testEq(joined(w.applied), joined({"aabbccdd:1000=APPROVED"}));
}

// Unrecognised and empty answers re-prompt rather than being taken as a decision.
void testUnrecognisedAnswersRePrompt() {
    testDiag("an empty or unknown answer asks again");

    auto rows = pendingRows(1);
    Writes w;
    testEq(run(rows, approving(), w.callbacks(), "\nwhat\ndeny\ny\n"), 0);
    testEq(joined(w.applied), joined({"aabbccdd:1000=DENIED"}));
}

// A certificate someone else decided while this run was asking must not be written over.
void testACertificateThatMovedIsNotWritten() {
    testDiag("a certificate decided elsewhere is reported and not written");

    auto rows = pendingRows(2);
    Writes w;
    std::string transcript;
    const auto cb = w.callbacks("aabbccdd:1000", "VALID");
    testEq(run(rows, approving(), cb, "approve\napprove\ny\n", &transcript), 0);
    testEq(joined(w.applied), joined({"aabbccdd:1001=APPROVED"}));
    testTrue(transcript.find("changed since listing") != std::string::npos);
}

// A failed write must not stop the ones after it, and must be reported as a partial batch.
void testAFailedWriteDoesNotStopTheRest() {
    testDiag("the certificates after a failure are still written, and the run exits 5");

    auto rows = pendingRows(3);
    Writes w;
    w.fail_this = "aabbccdd:1001";
    std::string transcript;
    testEq(run(rows, approving(), w.callbacks(), "approve\napprove\napprove\ny\n", &transcript), 5);
    testEq(joined(w.applied),
           joined({"aabbccdd:1000=APPROVED", "aabbccdd:1001=APPROVED", "aabbccdd:1002=APPROVED"}));
    // the certificate manager's own words reach the administrator
    testTrue(transcript.find("Invalid state transition or invalid serial number") != std::string::npos);
}

// Without a terminal and without --all there is nothing to read answers from: a command line
// mistake, not something to guess at.
void testNoTerminalAndNoAllIsRefused() {
    testDiag("no terminal and no --all prints the listing and writes nothing");

    auto rows = pendingRows(2);
    Writes w;
    auto options = approving();
    options.interactive = false;
    std::string transcript;
    testEq(run(rows, options, w.callbacks(), "", &transcript), 3);
    testEq(joined(w.applied), joined({}));
    testTrue(transcript.find("aabbccdd:1000") != std::string::npos);  // the listing was still shown
}

void testAllAndYesNeedNoTerminal() {
    testDiag("--all with --yes decides and confirms without asking anything");

    auto rows = pendingRows(3);
    Writes w;
    auto options = approving();
    options.interactive = false;
    options.all = ReviewDecision::Approve;
    options.assume_yes = true;
    testEq(run(rows, options, w.callbacks(), ""), 0);
    testEq(w.applied.size(), size_t(3));
}

// The review says what each certificate becomes. An approval becomes whatever the dates say,
// because that is what the certificate manager computes; a denial becomes REVOKED.
void testTheReviewSaysWhatEachBecomes() {
    testDiag("the review shows the resulting status, dates and all");

    testEq(projectedApprovedStatus("2026-08-01 00:00:00 UTC", "2027-08-01 00:00:00 UTC", kNow), std::string("VALID"));
    testEq(projectedApprovedStatus("2026-09-01 00:00:00 UTC", "2027-08-01 00:00:00 UTC", kNow), std::string("PENDING"));
    testEq(projectedApprovedStatus("2026-01-01 00:00:00 UTC", "2026-02-01 00:00:00 UTC", kNow), std::string("EXPIRED"));

    auto rows = pendingRows(1);
    Writes w;
    std::string transcript;
    run(rows, approving(), w.callbacks(), "deny\ny\n", &transcript);
    testTrue(transcript.find("PENDING_APPROVAL -> REVOKED") != std::string::npos);
}

// ---- revocation ----

std::vector<ReviewRow> issuedRows() {
    std::vector<ReviewRow> rows;
    const char *states[] = {"VALID", "EXPIRED", "PENDING"};
    for (size_t i = 0; i < 3; i++) {
        ReviewRow row;
        row.cert_id = "aabbccdd:" + std::to_string(2000 + i);
        row.subject = "CN=ioc" + std::to_string(i) + ",O=epics.org,C=US";
        row.status = states[i];
        row.issued = "2026-08-01 00:00:00 UTC";
        row.expires = "2027-08-01 00:00:00 UTC";
        if (!isRevocable(row.status)) row.ineligible_reason = "status " + row.status + " cannot be revoked";
        rows.push_back(row);
    }
    return rows;
}

void testOnlyRevocableCertificatesAreOffered() {
    testDiag("a certificate that cannot be revoked is shown with a reason and never asked about");

    // Tied to the server's own default rather than repeated by hand, so that changing the set
    // the certificate manager will accept a revocation from, without changing the tool, fails
    // here instead of only showing up as a refusal the administrator has already been asked to
    // confirm. The declaration is pvacms.h updateCertificateStatus's valid_status default.
    const std::vector<certstatus_t> server_revocable = {PENDING_APPROVAL, PENDING, VALID};
    for (const auto status : server_revocable) testTrue(isRevocable(CERT_STATE(status)));

    // Walking every status the server defines, rather than a list repeated here, so that a new
    // status added to CERT_STATUS_LIST is refused by default and has to be considered. The
    // enumerators are consecutive from UNKNOWN, and REVOKED is declared last.
    for (int status = UNKNOWN; status <= REVOKED; ++status) {
        const auto expected = std::find(server_revocable.begin(), server_revocable.end(),
                                        static_cast<certstatus_t>(status)) != server_revocable.end();
        testEq(expected, isRevocable(CERT_STATE(status)));
    }

    auto rows = issuedRows();
    Writes w;
    std::string transcript;
    // two questions only: the EXPIRED certificate is never offered
    testEq(run(rows, revoking(), w.callbacks(), "revoke\nrevoke\ny\n", &transcript), 0);
    testEq(joined(w.applied), joined({"aabbccdd:2000=REVOKED", "aabbccdd:2002=REVOKED"}));
    testTrue(transcript.find("cannot be revoked") != std::string::npos);
}

void testRevocationAnswers() {
    testDiag("revoke, skip, stop and cancel in the revocation mode");

    auto rows = issuedRows();
    Writes w;
    testEq(run(rows, revoking(), w.callbacks(), "skip\nrevoke\ny\n"), 0);
    testEq(joined(w.applied), joined({"aabbccdd:2002=REVOKED"}));

    auto rows2 = issuedRows();
    Writes w2;
    testEq(run(rows2, revoking(), w2.callbacks(), "revoke\ncancel\n"), 0);
    testEq(joined(w2.applied), joined({}));

    // approve is not an answer here
    auto rows3 = issuedRows();
    Writes w3;
    testEq(run(rows3, revoking(), w3.callbacks(), "approve\nrevoke\nstop\ny\n"), 0);
    testEq(joined(w3.applied), joined({"aabbccdd:2000=REVOKED"}));
}

//! A listing table shaped the way the certificate manager serves one, with or without the
//! request identifier column it adds only for a caller its rules let decide.
Value listingTable(const bool with_request_id) {
    nt::NTTable builder;
    builder.add_column(TypeCode::String, certlistcol::kCertId, "Certificate");
    builder.add_column(TypeCode::String, certlistcol::kSubject, "Subject");
    builder.add_column(TypeCode::String, certlistcol::kStatus, "Status");
    if (with_request_id) builder.add_column(TypeCode::String, certlistcol::kRequestId, "Request");
    return builder.create();
}

void testOnlyAnAdministratorIsToldTheirOwnCertificate() {
    testDiag("the request identifier column is what says the caller may decide");

    // An ordinary user may revoke their own certificate, and doing so is the point of the
    // operation for them. Only an administrator is refused their own, so only an administrator
    // should have it withheld - and the served table is the one thing that says which we are.
    testTrue(tableNamesRequestIds(listingTable(true)));
    testFalse(tableNamesRequestIds(listingTable(false)));

    // A reply that carried no table at all is not an administrator's.
    testFalse(tableNamesRequestIds(Value()));

    // The column is what matters, not whether a row filled it in: a certificate the manager
    // issued to itself has no request identifier to show, and an administrator listing only
    // those would otherwise look like an ordinary user.
    auto empty_for_every_row = listingTable(true);
    shared_array<std::string> blanks(2);
    empty_for_every_row["value"][certlistcol::kRequestId] = blanks.freeze();
    testTrue(tableNamesRequestIds(empty_for_every_row));
}

void testNothingToReview() {
    testDiag("an empty listing writes nothing and is not an error");

    std::vector<ReviewRow> rows;
    Writes w;
    testEq(run(rows, approving(), w.callbacks(), ""), 0);
    testEq(joined(w.applied), joined({}));
}

}  // namespace

MAIN(testcertreview) {
    testPlan(57);
    testTwoDecisionsAreWritten();
    testStopLeavesTheRestUndecided();
    testCancelWritesNothing();
    testDecliningTheConfirmationWritesNothing();
    testEndOfInputCancels();
    testSIsAmbiguous();
    testUnrecognisedAnswersRePrompt();
    testACertificateThatMovedIsNotWritten();
    testAFailedWriteDoesNotStopTheRest();
    testNoTerminalAndNoAllIsRefused();
    testAllAndYesNeedNoTerminal();
    testTheReviewSaysWhatEachBecomes();
    testOnlyRevocableCertificatesAreOffered();
    testRevocationAnswers();
    testOnlyAnAdministratorIsToldTheirOwnCertificate();
    testNothingToReview();
    return testDone();
}
