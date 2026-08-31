/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * The certificate listing is consumed by a control room display that cannot sort, filter or
 * reformat what it is given, so what the server puts in a column is exactly what an operator
 * sees, and the certificate identifier column is concatenated into a channel name that a
 * decision is written to. These check the parts that has to get right.
 */

#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include "certdate.h"
#include "certfilter.h"
#include "certlist.h"
#include "certlistprint.h"
#include "certstatus.h"

using namespace pvxs;
using namespace pvxs::certs;

namespace {

// The column exists so its text can be pasted into an access security file, so the same
// identity has to render one way whatever order the certificate happens to carry.
void testSubjectIsCanonical() {
    testDiag("A subject renders in one canonical order");

    testEq(renderSubject("testioc", {"controls"}, "epics.org", "US"),
           std::string("CN=testioc,OU=controls,O=epics.org,C=US"));

    // A nested unit renders as one part per value, innermost first, so the text reads as the
    // containment path it is and can still be pasted into an access security file.
    testEq(renderSubject("testioc", {"staff", "controls"}, "epics.org", "US"),
           std::string("CN=testioc,OU=staff,OU=controls,O=epics.org,C=US"));

    // Empty parts are left out rather than rendered as an empty pair.
    testEq(renderSubject("testioc", {}, "epics.org", "US"), std::string("CN=testioc,O=epics.org,C=US"));
    testEq(renderSubject("testioc", {}, "", ""), std::string("CN=testioc"));
    testEq(renderSubject("", {}, "", ""), std::string(""));
}

void testCertTypeNamesWhatItIsFor() {
    testDiag("The type column names what a certificate is for");

    testEq(renderCertType("Digital Signature", "TLS Web Client Authentication"), std::string("CLIENT"));
    testEq(renderCertType("Digital Signature", "TLS Web Server Authentication"), std::string("SERVER"));
    testEq(renderCertType("Digital Signature", "TLS Web Client Authentication, TLS Web Server Authentication"),
           std::string("IOC"));
    testEq(renderCertType("Certificate Sign, CRL Sign", ""), std::string("CERT_AUTH"));

    // An authority is almost never only an authority. These are the usages the intermediate
    // certificate authority this system issues actually carries: it may sign, and it may also
    // serve and connect. Asking what it serves first called it an IOC, which left CERT_AUTH
    // unreachable for every authority in the listing and quietly wrong in type:IOC.
    testEq(renderCertType("Digital Signature, Certificate Sign, CRL Sign",
                          "TLS Web Server Authentication, TLS Web Client Authentication, OCSP Signing"),
           std::string("CERT_AUTH"));
    testEq(renderCertType("keyCertSign, cRLSign", "serverAuth, clientAuth"), std::string("CERT_AUTH"));

    // The service certificate the same manager issues itself carries the same two web
    // authentication usages but may not sign, so it stays an IOC.
    testEq(renderCertType("Digital Signature, Key Encipherment",
                          "TLS Web Server Authentication, TLS Web Client Authentication, OCSP Signing"),
           std::string("IOC"));

    // A certificate stored before the type was recorded has neither, and says UNKNOWN.
    testEq(renderCertType("", ""), std::string("UNKNOWN"));
}

std::vector<CertListRow> twoRows() {
    CertListRow first;
    first.cert_id = getCertId("a76e613b", 12345);
    first.type = "IOC";
    first.subject = "CN=testioc,O=epics.org,C=US";
    first.status = "VALID";
    first.expires = "2027-02-04 17:53:26 UTC";
    first.issued = "2026-08-04 17:53:26 UTC";
    first.status_changed = "2026-08-04 18:00:00 UTC";
    first.renew_by = "2026-11-04 17:53:26 UTC";
    first.request_id = "YV6Q-56SG-JTVZ-HKP3";

    CertListRow second;
    second.cert_id = getCertId("a76e613b", 67890);
    second.type = "CLIENT";
    second.subject = "CN=operator,O=epics.org,C=US";
    second.status = "PENDING_APPROVAL";
    second.expires = "2027-01-01 00:00:00 UTC";
    second.issued = "2026-07-01 00:00:00 UTC";
    second.status_changed = "2026-07-01 00:00:00 UTC";
    second.renew_by = "2026-10-01 00:00:00 UTC";
    second.request_id = "QYW0-9QCR-BPPK-RVT5";

    return {first, second};
}

// A display renders this with no support written for it, which only happens if the result is
// actually the normative type. These are the properties that make it one.
void testTableIsNormative() {
    testDiag("The served table is a normative table");

    const auto rows = twoRows();
    const auto table = buildCertListTable(rows, false, 0);

    testEq(table.id(), std::string("epics:nt/NTTable:1.0"));

    const auto labels = table["labels"].as<shared_array<const std::string>>();
    const auto columns = certListColumns(false);
    testEq(labels.size(), columns.size());

    bool every_label_set = true;
    for (const auto &label : labels) {
        if (label.empty()) every_label_set = false;
    }
    testOk(every_label_set, "Every column carries a label (%zu labels)", labels.size());

    // Equal length matters: a table whose columns disagree has rows that do not line up.
    bool all_same_length = true;
    for (const auto &name : columns) {
        const auto column = table["value"][name].as<shared_array<const std::string>>();
        if (column.size() != rows.size()) all_same_length = false;
    }
    testOk(all_same_length, "Every column has one entry per row (%zu rows)", rows.size());

    testOk(table["timeStamp.secondsPastEpoch"].as<uint64_t>() > 0, "The table says when it was generated");
}

void testRequestIdColumnIsOptional() {
    testDiag("The request identifier column is present only where it belongs");

    const auto rows = twoRows();

    const auto without = buildCertListTable(rows, false, 0);
    testOk(!without["value"][certlistcol::kRequestId].valid(), "Omitted where the caller may not see it");

    const auto with = buildCertListTable(rows, true, 0);
    const auto column = with["value"][certlistcol::kRequestId].as<shared_array<const std::string>>();
    testEq(column.size(), rows.size());
    testEq(column[0], std::string("YV6Q-56SG-JTVZ-HKP3"));
}

// The window is a server setting the caller cannot see any other way: a normative table has
// no per-column display information, so the label is the only place to put it.
void testExpiryWindowIsStatedInTheLabel() {
    testDiag("The expiring view states its window in the column label");

    const auto table = buildCertListTable(twoRows(), false, 30 * 24 * 60 * 60);
    const auto labels = table["labels"].as<shared_array<const std::string>>();

    bool window_stated = false;
    for (const auto &label : labels) {
        if (label.find("30 days") != std::string::npos) window_stated = true;
    }
    testOk(window_stated, "The window appears in a label");
}

// A display builds the channel it writes a decision to by concatenating this column, so the
// printed form has to be the form the status channel accepts.
void testCertIdIsTheFormAStatusChannelAccepts() {
    testDiag("The certificate identifier is the form a status channel name accepts");

    const auto table = buildCertListTable(twoRows(), false, 0);
    const auto ids = table["value"][certlistcol::kCertId].as<shared_array<const std::string>>();

    testEq(ids[0], getCertId("a76e613b", 12345));
    // Padded to twenty digits: the help example showing it unpadded is wrong.
    testEq(ids[0], std::string("a76e613b:00000000000000012345"));
    testEq(getCertStatusURI("CERT", ids[0]), std::string("CERT:a76e613b:00000000000000012345"));
}

void testEmptyListingIsStillATable() {
    testDiag("An empty listing is still a well formed table");

    const auto table = buildCertListTable({}, true, 0);
    testEq(table.id(), std::string("epics:nt/NTTable:1.0"));
    const auto ids = table["value"][certlistcol::kCertId].as<shared_array<const std::string>>();
    testEq(ids.size(), size_t(0));
    testEq(table["labels"].as<shared_array<const std::string>>().size(), certListColumns(true).size());
}


// A subject contains commas, so the comma separated form has to quote it or a reader splits
// one identity into several fields.
void testCsvSurvivesACommaInASubject() {
    testDiag("Comma separated output quotes a field containing a comma");

    auto rows = twoRows();
    rows[0].subject = "CN=testioc,OU=controls,O=epics.org,C=US";
    std::ostringstream out;
    printCertList(out, buildCertListTable(rows, false, 0), CertListFormat::Csv);
    const auto text = out.str();

    testOk(text.find("\"CN=testioc,OU=controls,O=epics.org,C=US\"") != std::string::npos,
           "The subject is quoted");

    // Every line has the same number of fields once quoting is honoured, which is the
    // property a reader depends on.
    std::istringstream lines(text);
    std::string line;
    bool all_rows_same_width = true;
    size_t expected = 0;
    while (std::getline(lines, line)) {
        size_t fields = 1;
        bool quoted = false;
        for (const char c : line) {
            if (c == '"') quoted = !quoted;
            else if (c == ',' && !quoted) ++fields;
        }
        if (!expected) expected = fields;
        else if (fields != expected) all_rows_same_width = false;
    }
    testOk(all_rows_same_width, "Every line has %zu fields", expected);
}

void testJsonUsesTheServedFieldNames() {
    testDiag("JavaScript Object Notation output uses the served field names");

    std::ostringstream out;
    printCertList(out, buildCertListTable(twoRows(), true, 0), CertListFormat::Json);
    const auto text = out.str();

    for (const auto &name : certListColumns(true)) {
        if (text.find("\"" + name + "\":") == std::string::npos) {
            testFail("field name %s is missing from the output", name.c_str());
            return;
        }
    }
    testPass("Every served column name appears as a field name");
}

void testUnknownFormatIsRefused() {
    testDiag("An unrecognised format is refused rather than guessed at");
    CertListFormat format{CertListFormat::Csv};
    testOk1(!parseCertListFormat("xml", format));
    testOk1(parseCertListFormat("csv", format) && format == CertListFormat::Csv);
    testOk1(parseCertListFormat("json", format) && format == CertListFormat::Json);
    testOk1(parseCertListFormat("columns", format) && format == CertListFormat::Columns);
}

// The order is the server's: it picks a key that cannot change while a row is in the view.
void testPrintedOrderIsTheServedOrder() {
    testDiag("The printed order is the served order");

    std::ostringstream out;
    printCertList(out, buildCertListTable(twoRows(), false, 0), CertListFormat::Csv);
    const auto text = out.str();

    const auto first = text.find(getCertId("a76e613b", 12345));
    const auto second = text.find(getCertId("a76e613b", 67890));
    testOk(first != std::string::npos && second != std::string::npos && first < second,
           "Rows appear in the order they were served");
}


// These run against a real database rather than a stand-in, so they exercise the query and
// its ordering, which is where the behaviour a display depends on actually lives.
struct ListDb {
    std::string path;
    sqlite3 *db{nullptr};

    ListDb() : path("testcertlist_query.db") {
        std::remove(path.c_str());
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) { db = nullptr; return; }
        // The columns the listing reads. Kept here rather than shared with the server so a
        // change to the real schema that breaks the listing shows up as a failure.
        sqlite3_exec(db,
                     "CREATE TABLE certs(serial INTEGER PRIMARY KEY, skid TEXT, CN TEXT, O TEXT, OU TEXT, C TEXT,"
                     " approved INTEGER, not_before INTEGER, not_after INTEGER, renew_by INTEGER,"
                     " renewal_due INTEGER, status INTEGER, status_date INTEGER, created_date INTEGER,"
                     " key_usage TEXT, extended_key_usage TEXT);"
                     "CREATE TABLE cert_request_ids(serial INTEGER PRIMARY KEY, request_id TEXT NOT NULL,"
                     " pub_key_digest TEXT NOT NULL, created INTEGER NOT NULL);"
                     "CREATE TABLE cert_subject_units(serial INTEGER NOT NULL, position INTEGER NOT NULL,"
                     " value TEXT NOT NULL);",
                     nullptr, nullptr, nullptr);
    }
    ~ListDb() {
        if (db) sqlite3_close(db);
        std::remove(path.c_str());
    }
    ListDb(const ListDb &) = delete;
    ListDb &operator=(const ListDb &) = delete;

    void add(const uint64_t serial, const char *cn, const certstatus_t status, const time_t created,
             const time_t not_before, const time_t not_after, const char *request_id = nullptr,
             const std::vector<std::string> &organizational_units = {},
             const char *key_usage = "Digital Signature",
             const char *extended_key_usage = "TLS Web Client Authentication") {
        char sql[1024];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO certs (serial, CN, O, OU, C, status, status_date, not_before, not_after, renew_by,"
                 " created_date, key_usage, extended_key_usage) VALUES (%lld, '%s', 'epics.org', '', 'US', %d,"
                 " %lld, %lld, %lld, %lld, %lld, '%s', '%s');",
                 static_cast<long long>(serial), cn, static_cast<int>(status), static_cast<long long>(created),
                 static_cast<long long>(not_before), static_cast<long long>(not_after),
                 static_cast<long long>(not_after), static_cast<long long>(created), key_usage,
                 extended_key_usage);
        sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
        if (request_id) {
            snprintf(sql, sizeof(sql),
                     "INSERT INTO cert_request_ids (serial, request_id, pub_key_digest, created)"
                     " VALUES (%lld, '%s', 'digest', %lld);",
                     static_cast<long long>(serial), request_id, static_cast<long long>(created));
            sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
        }
        // One row per unit, innermost first, exactly as the server writes them
        for (size_t position = 0; position < organizational_units.size(); position++) {
            snprintf(sql, sizeof(sql),
                     "INSERT INTO cert_subject_units (serial, position, value) VALUES (%lld, %d, '%s');",
                     static_cast<long long>(serial), static_cast<int>(position),
                     organizational_units[position].c_str());
            sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
        }
    }
};

// The key has to be one that cannot change while a row is in the view. A certificate whose
// validity starts in the future is the case that separates creation time from start of
// validity.
void testRowOrderIsByCreationNotValidity() {
    testDiag("Rows are ordered by when a certificate was created, newest first");

    ListDb store;
    testOk(store.db != nullptr, "Opened a database to query");
    if (!store.db) return;

    const time_t now = 1785888000;
    store.add(100, "oldest", VALID, now - 3000, now, now + 86400);
    // Created in the middle, valid much later.
    store.add(200, "future-start", PENDING, now - 2000, now + 500000, now + 900000);
    store.add(300, "newest", VALID, now - 1000, now, now + 86400);

    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", false, 0);
    testEq(rows.size(), size_t(3));
    if (rows.size() != 3) return;

    testEq(rows[0].subject, std::string("CN=newest,O=epics.org,C=US"));
    testEq(rows[1].subject, std::string("CN=future-start,O=epics.org,C=US"));
    testEq(rows[2].subject, std::string("CN=oldest,O=epics.org,C=US"));
}

// A certificate subject may name a nested organizational unit. The listing has to show the whole
// path, so the column can be pasted into an access security file and an outer unit finds what
// sits under it.
void testTheListingShowsEveryOrganizationalUnit() {
    testDiag("A listed subject carries every unit, innermost first");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(3, "no database"); return; }

    const time_t now = 1785888000;
    store.add(100, "alice", VALID, now - 3000, now, now + 86400, nullptr, {"staff", "beamline"});
    store.add(200, "bob", VALID, now - 2000, now, now + 86400, nullptr, {"beamline"});
    store.add(300, "carol", VALID, now - 1000, now, now + 86400);

    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", false, 0);
    testEq(rows.size(), size_t(3));
    if (rows.size() != 3) { testSkip(3, "wrong row count"); return; }

    testEq(rows[2].subject, std::string("CN=alice,OU=staff,OU=beamline,O=epics.org,C=US"));
    testEq(rows[1].subject, std::string("CN=bob,OU=beamline,O=epics.org,C=US"));
    testEq(rows[0].subject, std::string("CN=carol,O=epics.org,C=US"));
}

// The filter asks a containment question, not an identity one: naming the beamline finds
// everyone under it, including someone in a staff group inside it.
void testAFilterFindsAnOuterUnit() {
    testDiag("A filter naming an outer unit finds a certificate nested under it");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(2, "no database"); return; }

    const time_t now = 1785888000;
    store.add(100, "alice", VALID, now - 3000, now, now + 86400, nullptr, {"staff", "beamline"});
    store.add(200, "dave", VALID, now - 2000, now, now + 86400, nullptr, {"workshop"});

    const auto filter = CertFilter::parse("unit:beamline", now);
    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", false, 0, &filter);
    testEq(rows.size(), size_t(1));
    if (rows.size() != 1) { testSkip(1, "wrong row count"); return; }
    testEq(rows[0].subject, std::string("CN=alice,OU=staff,OU=beamline,O=epics.org,C=US"));
}

void testPendingViewShowsOnlyWhatAwaitsADecision() {
    testDiag("The pending view shows only certificates awaiting a decision");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(3, "no database"); return; }

    const time_t now = 1785888000;
    store.add(100, "valid", VALID, now - 3000, now, now + 86400);
    store.add(200, "waiting", PENDING_APPROVAL, now - 2000, now, now + 86400, "YV6Q-56SG-JTVZ-HKP3");

    const auto rows = queryCertList(store.db, CertListView::PendingApproval, "a76e613b", true, 0);
    testEq(rows.size(), size_t(1));
    if (rows.empty()) { testSkip(2, "no rows"); return; }
    testEq(rows[0].status, std::string("PENDING_APPROVAL"));
    testEq(rows[0].request_id, std::string("YV6Q-56SG-JTVZ-HKP3"));
}

// The facility root is in no table, because no certificate manager issued it and none can be
// asked about it. It is listed anyway, because the day it expires every certificate beneath it
// stops working, and an authority in no listing is one nobody is watching the calendar for.
RootAuthority aRoot(const time_t not_after, const bool names_responder = true,
                    const certstatus_t standing = VALID) {
    RootAuthority root;
    root.names_responder = names_responder;
    root.standing = standing;
    root.cert_id = "5ed0fe96:00000000009876543212";
    root.common_name = "EPICS Root Certificate Authority";
    root.organization = "certs.epics.org";
    root.country = "US";
    root.serial = 9876543212;
    root.not_before = not_after - 3650 * 86400;
    root.not_after = not_after;
    return root;
}

void testTheRootIsListedAmongWhatWasIssued() {
    testDiag("== %s", __func__);
    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(4, "no database"); return; }

    const time_t now = time(nullptr);
    store.add(100, "issued", VALID, now - 3000, now, now + 86400);
    const auto root = aRoot(now + 365 * 86400);

    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", true, 0, nullptr, &root);
    testEq(rows.size(), size_t(2));
    if (rows.size() < 2) { testSkip(3, "no root row"); return; }
    testEq(rows[1].type, std::string("ROOT_AUTH"));
    testEq(rows[1].cert_id, std::string("5ed0fe96:00000000009876543212"));
    // The request identifier column says where its standing comes from: something outside
    // publishes its revocation.
    testEq(rows[1].request_id, std::string("EXTERN OCSP"));
}

void testARootNamingNoResponderSaysSo() {
    testDiag("== %s", __func__);
    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(2, "no database"); return; }

    const auto root = aRoot(time(nullptr) + 365 * 86400, false, UNKNOWN);
    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", true, 0, nullptr, &root);
    testEq(rows.size(), size_t(1));
    if (rows.empty()) { testSkip(1, "no root row"); return; }
    // Nothing establishes its standing, so nothing is claimed about it.
    testEq(rows[0].status, std::string("UNKNOWN"));
}

void testTheRootIsNeverAwaitingADecision() {
    testDiag("== %s", __func__);
    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(1, "no database"); return; }

    const auto root = aRoot(time(nullptr) + 365 * 86400);
    // It was never requested, so it cannot be waiting for anyone to decide about it.
    const auto rows = queryCertList(store.db, CertListView::PendingApproval, "a76e613b", true, 0, nullptr, &root);
    testEq(rows.size(), size_t(0));
}

void testTheRootFollowsTheExpiryWindowLikeAnyRow() {
    testDiag("== %s", __func__);
    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(2, "no database"); return; }

    const time_t now = time(nullptr);
    const auto distant = aRoot(now + 200 * 86400);
    const auto soon = aRoot(now + 10 * 86400);

    testEq(queryCertList(store.db, CertListView::Expiring, "a76e613b", false, 30 * 86400, nullptr, &distant).size(),
           size_t(0));
    testEq(queryCertList(store.db, CertListView::Expiring, "a76e613b", false, 30 * 86400, nullptr, &soon).size(),
           size_t(1));
}

void testAFilterDecidesOnTheRootToo() {
    testDiag("== %s", __func__);
    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(2, "no database"); return; }

    const auto root = aRoot(time(nullptr) + 365 * 86400);
    const auto wanted = CertFilter::parse("type:ROOT_AUTH", time(nullptr));
    const auto unwanted = CertFilter::parse("type:IOC", time(nullptr));

    testEq(queryCertList(store.db, CertListView::All, "a76e613b", false, 0, &wanted, &root).size(), size_t(1));
    testEq(queryCertList(store.db, CertListView::All, "a76e613b", false, 0, &unwanted, &root).size(), size_t(0));
}

// A root nothing here issued has no row of its own, so the only status anyone can offer is
// what the responder named in the certificate last said, and no date here belongs to it.
void testARootThisManagerDoesNotHoldReportsItsResponder() {
    testDiag("== %s", __func__);
    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(4, "no database"); return; }

    const auto root = aRoot(time(nullptr) + 365 * 86400);  // responder, VALID, absent from certs
    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", true, 0, nullptr, &root);
    testEq(rows.size(), size_t(1));
    if (rows.empty()) { testSkip(3, "no root row"); return; }
    testEq(rows[0].status, std::string("VALID"));
    testEq(rows[0].request_id, std::string("EXTERN OCSP"));
    // Nothing here changed its standing and nothing here will renew it.
    testOk(rows[0].status_changed.empty() && rows[0].renew_by.empty(),
           "No date that belongs to this manager is claimed (status changed '%s', renew by '%s')",
           rows[0].status_changed.c_str(), rows[0].renew_by.c_str());
}

// A manager that signs with its own self-signed root lists that one certificate twice: once as
// the authority it signs with, once as the anchor everything terminates at. The same
// certificate saying two different things about itself is what this stops.
void testARootThisManagerIssuedAgreesWithItsOwnRow() {
    testDiag("== %s", __func__);
    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(4, "no database"); return; }

    const time_t now = time(nullptr);
    const uint64_t serial = 4134050803232140903ULL;
    const char *const common_name = "EPICS ML Root Certificate Authority";
    store.add(serial, common_name, VALID, now - 3000, now - 3000, now + 365 * 86400, nullptr, {},
              "Digital Signature, Certificate Sign, CRL Sign", "TLS Web Server Authentication");

    RootAuthority root;
    // What currentRootAuthority() builds for a self-signed root that names no responder: it
    // knows nothing about its own standing, because nothing outside is publishing one.
    root.names_responder = false;
    root.standing = UNKNOWN;
    root.cert_id = getCertId("a76e613b", serial);
    root.common_name = common_name;
    root.organization = "epics.org";
    root.country = "US";
    root.serial = serial;
    root.not_before = now - 3000;
    root.not_after = now + 365 * 86400;

    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", true, 0, nullptr, &root);
    testEq(rows.size(), size_t(2));
    if (rows.size() != 2) { testSkip(3, "wrong row count"); return; }

    testEq(rows[1].type, std::string("ROOT_AUTH"));
    // Not EXTERN: this manager issued it, and the column must not say it came from outside.
    testEq(rows[1].request_id, std::string("SELF"));

    const auto &authority = rows[0];
    const auto &anchor = rows[1];
    const bool agree = anchor.cert_id == authority.cert_id && anchor.subject == authority.subject &&
                       anchor.status == authority.status && anchor.expires == authority.expires &&
                       anchor.issued == authority.issued &&
                       anchor.status_changed == authority.status_changed &&
                       anchor.renew_by == authority.renew_by;
    testOk(agree,
           "Every column but Type and Request matches (%s/%s, status %s/%s, changed '%s'/'%s', renew '%s'/'%s')",
           authority.type.c_str(), anchor.type.c_str(), authority.status.c_str(), anchor.status.c_str(),
           authority.status_changed.c_str(), anchor.status_changed.c_str(), authority.renew_by.c_str(),
           anchor.renew_by.c_str());
}

// The identifier is a search key an administrator uses to find a row and read it.
void testRequestIdIsWithheldFromNonAdministrators() {
    testDiag("The request identifier is withheld unless the caller is an administrator");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(1, "no database"); return; }

    const time_t now = 1785888000;
    store.add(200, "waiting", PENDING_APPROVAL, now - 2000, now, now + 86400, "YV6Q-56SG-JTVZ-HKP3");

    const auto withheld = queryCertList(store.db, CertListView::All, "a76e613b", false, 0);
    testEq(withheld.at(0).request_id, std::string(""));
    const auto given = queryCertList(store.db, CertListView::All, "a76e613b", true, 0);
    testEq(given.at(0).request_id, std::string("YV6Q-56SG-JTVZ-HKP3"));
}

void testExpiringViewFollowsItsWindow() {
    testDiag("Changing the window changes which rows the expiring view shows");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(1, "no database"); return; }

    const auto now = timeNow();
    store.add(100, "soon", VALID, now - 3000, now - 100, now + 5 * 86400);
    store.add(200, "later", VALID, now - 2000, now - 100, now + 100 * 86400);

    const auto narrow = queryCertList(store.db, CertListView::Expiring, "a76e613b", false, 30 * 86400);
    testEq(narrow.size(), size_t(1));
    const auto wide = queryCertList(store.db, CertListView::Expiring, "a76e613b", false, 200 * 86400);
    testEq(wide.size(), size_t(2));
}

// A display compares date bounds as plain text, with no parsing, which only works if the
// rendering is fixed width and year first. A partial bound has to work by prefix.
void testDatesCompareAsPlainText() {
    testDiag("A date bound selects by plain string comparison, including a partial bound");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(2, "no database"); return; }

    // 2026-06-15, 2026-07-15 and 2026-08-15, as expiry dates.
    store.add(100, "june", VALID, 1000, 0, 1781000000);
    store.add(200, "july", VALID, 2000, 0, 1783500000);
    store.add(300, "august", VALID, 3000, 0, 1786000000);

    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", false, 0);
    testEq(rows.size(), size_t(3));

    // Every rendered date is the same width, which is what makes the comparison valid.
    bool same_width = true;
    for (const auto &row : rows) {
        if (row.expires.size() != rows.front().expires.size()) same_width = false;
    }
    testOk(same_width, "Every rendered date is %zu characters", rows.front().expires.size());

    // A partial bound by prefix: everything expiring in or after July.
    size_t from_july = 0;
    for (const auto &row : rows) {
        if (row.expires >= "2026-07") ++from_july;
    }
    testOk(from_july >= 1 && from_july < rows.size(), "A partial bound selects a subset (%zu of %zu)", from_july,
           rows.size());
}

// The interactive approval and revocation modes read nothing but this listing, so the columns
// they decide from have to be present and mean what those modes assume.
void testColumnsTheInteractiveModesDecideFrom() {
    testDiag("The columns the interactive modes decide from are present");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(3, "no database"); return; }

    const auto now = timeNow();
    store.add(100, "valid", VALID, now - 3000, now - 86400, now + 86400);
    store.add(200, "revoked", REVOKED, now - 2000, now - 86400, now + 86400);

    const auto rows = queryCertList(store.db, CertListView::All, "a76e613b", false, 0);
    testEq(rows.size(), size_t(2));

    // Approval computes its outcome from the certificate's own dates against the current
    // time, so those three have to carry a value.
    bool dates_present = true;
    for (const auto &row : rows) {
        if (row.issued.empty() || row.expires.empty() || row.renew_by.empty()) dates_present = false;
    }
    testOk(dates_present, "Issued, Expires and Renew by all carry a value");

    // Revocation is accepted for awaiting-approval, pending and valid, so the status column
    // tells a client in advance which rows it applies to.
    const auto revocable = [](const std::string &status) {
        return status == "PENDING_APPROVAL" || status == "PENDING" || status == "VALID";
    };
    testOk(revocable(rows[1].status) != revocable(rows[0].status),
           "The status column tells the two apart (%s, %s)", rows[0].status.c_str(), rows[1].status.c_str());
}


// Filtering removes rows and never reorders them, so an operator narrowing a search twice sees
// the rows they already saw in the same places.
void testFilteringPreservesTheOrder() {
    testDiag("A filter removes rows without moving the ones it keeps");

    ListDb store;
    if (!store.db) { testFail("no database"); testSkip(1, "no database"); return; }

    const time_t now = 1785888000;
    store.add(100, "alpha", VALID, now - 5000, now, now + 86400);
    store.add(200, "beta", REVOKED, now - 4000, now, now + 86400);
    store.add(300, "gamma", VALID, now - 3000, now, now + 86400);
    store.add(400, "delta", REVOKED, now - 2000, now, now + 86400);

    const auto all = queryCertList(store.db, CertListView::All, "a76e613b", false, 0);
    const auto filter = CertFilter::parse("state:VALID", now);
    const auto kept = queryCertList(store.db, CertListView::All, "a76e613b", false, 0, &filter);

    testEq(kept.size(), size_t(2));

    // Every row the filter kept appears in the unfiltered result, in the same relative order.
    size_t at = 0;
    bool order_held = true;
    for (const auto &row : kept) {
        bool found = false;
        while (at < all.size()) {
            if (all[at++].cert_id == row.cert_id) { found = true; break; }
        }
        if (!found) order_held = false;
    }
    testOk(order_held, "The kept rows are in the order they were served");
}

}  // namespace

MAIN(testcertlist) {
    testPlan(81);
    testSubjectIsCanonical();
    testCertTypeNamesWhatItIsFor();
    testTableIsNormative();
    testRequestIdColumnIsOptional();
    testExpiryWindowIsStatedInTheLabel();
    testCertIdIsTheFormAStatusChannelAccepts();
    testEmptyListingIsStillATable();
    testCsvSurvivesACommaInASubject();
    testJsonUsesTheServedFieldNames();
    testUnknownFormatIsRefused();
    testPrintedOrderIsTheServedOrder();
    testRowOrderIsByCreationNotValidity();
    testTheListingShowsEveryOrganizationalUnit();
    testAFilterFindsAnOuterUnit();
    testPendingViewShowsOnlyWhatAwaitsADecision();
    testRequestIdIsWithheldFromNonAdministrators();
    testExpiringViewFollowsItsWindow();
    testDatesCompareAsPlainText();
    testColumnsTheInteractiveModesDecideFrom();
    testFilteringPreservesTheOrder();
    testTheRootIsListedAmongWhatWasIssued();
    testARootNamingNoResponderSaysSo();
    testTheRootIsNeverAwaitingADecision();
    testTheRootFollowsTheExpiryWindowLikeAnyRow();
    testAFilterDecidesOnTheRootToo();
    testARootThisManagerDoesNotHoldReportsItsResponder();
    testARootThisManagerIssuedAgreesWithItsOwnRow();
    return testDone();
}
