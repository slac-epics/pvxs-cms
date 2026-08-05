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

#include <sstream>
#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

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

    testEq(renderSubject("testioc", "controls", "epics.org", "US"),
           std::string("CN=testioc,OU=controls,O=epics.org,C=US"));

    // Empty parts are left out rather than rendered as an empty pair.
    testEq(renderSubject("testioc", "", "epics.org", "US"), std::string("CN=testioc,O=epics.org,C=US"));
    testEq(renderSubject("testioc", "", "", ""), std::string("CN=testioc"));
    testEq(renderSubject("", "", "", ""), std::string(""));
}

void testCertTypeNamesWhatItIsFor() {
    testDiag("The type column names what a certificate is for");

    testEq(renderCertType("Digital Signature", "TLS Web Client Authentication"), std::string("CLIENT"));
    testEq(renderCertType("Digital Signature", "TLS Web Server Authentication"), std::string("SERVER"));
    testEq(renderCertType("Digital Signature", "TLS Web Client Authentication, TLS Web Server Authentication"),
           std::string("IOC"));
    testEq(renderCertType("Certificate Sign, CRL Sign", ""), std::string("CERT_AUTH"));

    // A certificate stored before the type was recorded has neither. Saying UNKNOWN is the
    // point: reporting it as the most common kind would be believed.
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

// The order is the server's: it picks a key that cannot change while a row is in the view, so
// a client that re-sorted would undo the property the choice exists for.
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

}  // namespace

MAIN(testcertlist) {
    testPlan(32);
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
    return testDone();
}
