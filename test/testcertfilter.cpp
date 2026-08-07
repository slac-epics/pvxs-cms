/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * The filter is meant to be readable aloud by a control room operator, and is reachable by any
 * client that can reach the certificate manager. These check the rules that make it safe to
 * read that way and safe to serve: how the words bind, what happens when a query cannot express
 * a test, and what an operator is told when they get it wrong.
 */

#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include "certfilter.h"
#include "certstatus.h"

using namespace pvxs;
using namespace pvxs::certs;

namespace {

// A fixed moment, so a period lands somewhere a test can predict.
constexpr time_t kNow = 1785844800;  // 2026-08-04 12:00:00 UTC

FilterRow rowFor(const char *cn, const char *org, const std::vector<std::string> &units, const certstatus_t status,
                 const time_t not_after = kNow + 86400, const char *type = "CLIENT") {
    FilterRow row;
    row.type = type;
    row.cert_id = getCertId("a76e613b", 12345);
    row.serial = 12345;
    row.common_name = cn;
    row.organization = org;
    row.organizational_units = units;
    row.country = "US";
    row.status = static_cast<int>(status);
    row.not_before = kNow - 86400;
    row.not_after = not_after;
    row.renew_by = not_after - 3600;
    row.status_date = kNow - 3600;
    return row;
}

// A test always contains a colon, so a joining word can only be a joining word where one is
// expected. That is what lets a value be the word "and" without any special case.
void testAJoiningWordCanBeAValue() {
    testDiag("A joining word is only an operator where one is expected");

    const auto filter = CertFilter::parse("org:and", kNow);
    testOk1(filter.matches(rowFor("a", "and", {}, VALID)));
    testOk1(!filter.matches(rowFor("a", "SLAC", {}, VALID)));
}

// Read aloud, "a or b and c" groups the way people say it: the "and" binds tighter.
void testPrecedence() {
    testDiag("not binds tightest, then and, then or");

    const auto either = CertFilter::parse("org:LBNL or org:SLAC and name:beam", kNow);
    testOk(either.matches(rowFor("anything", "LBNL", {}, VALID)), "The left side alone is enough");
    testOk(!either.matches(rowFor("other", "SLAC", {}, VALID)), "The right side needs both of its parts");
    testOk(either.matches(rowFor("beam", "SLAC", {}, VALID)), "The right side with both parts matches");

    const auto negated = CertFilter::parse("not org:SLAC and country:US", kNow);
    testOk(!negated.matches(rowFor("a", "SLAC", {}, VALID)), "not applies to the test, not the whole expression");
    testOk(negated.matches(rowFor("a", "LBNL", {}, VALID)), "and still has to hold");
}

// What a certificate is for is stored, and the listing prints it, so it can be filtered on.
// It is derived from the recorded key usage rather than held in a column, which is why it is
// matched in memory and never appears in the query.
void testTypeMatchesTheWordTheListingPrints() {
    testDiag("type: matches the word shown in the Type column");

    const auto ioc = CertFilter::parse("type:IOC", kNow);
    testOk1(ioc.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "IOC")));
    testOk1(!ioc.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "CLIENT")));

    // The column is printed in capitals; nobody should have to shout at the tool.
    const auto folded = CertFilter::parse("type:ioc", kNow);
    testOk(folded.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "IOC")), "Case is ignored");

    // A certificate issued before the usage was recorded reads as UNKNOWN, and can be found.
    const auto unknown = CertFilter::parse("type:UNKNOWN", kNow);
    testOk1(unknown.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "UNKNOWN")));
    testOk1(!unknown.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "SERVER")));
}

void testTypeTakesTheSameValueFormsAsAnyText() {
    testDiag("type: takes alternatives, wildcards and patterns like any other text field");

    const auto either = CertFilter::parse("type:IOC|SERVER", kNow);
    testOk1(either.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "IOC")));
    testOk1(either.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "SERVER")));
    testOk1(!either.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "CLIENT")));

    const auto authority = CertFilter::parse("type:CERT_*", kNow);
    testOk(authority.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "CERT_AUTH")), "A wildcard matches");

    const auto pattern = CertFilter::parse("type:/^(IOC|CLIENT)$/", kNow);
    testOk1(pattern.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "CLIENT")));
    testOk1(!pattern.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "SERVER")));
}

// A derived field cannot be asked of the database, so the condition has to let its rows
// through and leave the decision to matches(). Getting this wrong would silently drop rows.
void testTypeIsDecidedInMemoryNotInTheQuery() {
    testDiag("A type test widens the condition rather than narrowing it");

    const auto filter = CertFilter::parse("type:IOC", kNow);
    testOk(filter.whereClause().find("type") == std::string::npos,
           "The query does not mention a column that does not exist");
    testOk1(filter.bindings().empty());
}

void testTypeCombinesWithTheRestOfAnExpression() {
    testDiag("type: joins the other fields with and, or and not");

    const auto both = CertFilter::parse("type:IOC and state:VALID", kNow);
    testOk1(both.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "IOC")));
    testOk(!both.matches(rowFor("a", "SLAC", {}, REVOKED, kNow + 86400, "IOC")), "Both parts must hold");

    const auto negated = CertFilter::parse("not type:CLIENT", kNow);
    testOk1(negated.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "IOC")));
    testOk1(!negated.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "CLIENT")));

    // and binds tighter than or, for a derived field as for any other.
    const auto mixed = CertFilter::parse("org:LBNL or type:IOC and state:REVOKED", kNow);
    testOk(mixed.matches(rowFor("a", "LBNL", {}, VALID, kNow + 86400, "CLIENT")), "The left side alone is enough");
    testOk(!mixed.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400, "IOC")), "The right side needs both parts");
    testOk1(mixed.matches(rowFor("a", "SLAC", {}, REVOKED, kNow + 86400, "IOC")));

    const auto grouped = CertFilter::parse("(org:LBNL or type:IOC) and state:REVOKED", kNow);
    testOk(!grouped.matches(rowFor("a", "LBNL", {}, VALID, kNow + 86400, "CLIENT")),
           "Brackets make the status apply to both alternatives");
}

void testBracketsOverridePrecedence() {
    testDiag("Brackets override precedence");
    const auto filter = CertFilter::parse("(org:LBNL or org:SLAC) and name:beam", kNow);
    testOk1(filter.matches(rowFor("beam", "SLAC", {}, VALID)));
    testOk1(!filter.matches(rowFor("other", "SLAC", {}, VALID)));
}

void testSeveralValuesMeanAnyOfThem() {
    testDiag("Values separated by a bar mean any of them");
    const auto filter = CertFilter::parse("state:VALID|PENDING_APPROVAL", kNow);
    testOk1(filter.matches(rowFor("a", "SLAC", {}, VALID)));
    testOk1(filter.matches(rowFor("a", "SLAC", {}, PENDING_APPROVAL)));
    testOk1(!filter.matches(rowFor("a", "SLAC", {}, REVOKED)));
}

void testCaseIsIgnoredWhereItShouldBe() {
    testDiag("Field names, joining words and status names ignore case");
    const auto filter = CertFilter::parse("STATE:valid AND Org:slac", kNow);
    testOk1(filter.matches(rowFor("a", "SLAC", {}, VALID)));
}

void testWildcards() {
    testDiag("An asterisk matches any run of characters, and an escaped one is literal");
    testOk1(CertFilter::parse("name:beam*", kNow).matches(rowFor("beamline", "SLAC", {}, VALID)));
    testOk1(!CertFilter::parse("name:beam*", kNow).matches(rowFor("upstream", "SLAC", {}, VALID)));
    testOk1(CertFilter::parse("name:\\*", kNow).matches(rowFor("*", "SLAC", {}, VALID)));
    testOk1(!CertFilter::parse("name:\\*", kNow).matches(rowFor("anything", "SLAC", {}, VALID)));
}

// A value that looks like a pattern to the database must not be treated as one.
void testTextThatLooksLikeAPatternIsLiteral() {
    testDiag("A value containing the database's own wildcards matches only itself");
    const auto filter = CertFilter::parse("org:100%", kNow);
    testOk1(filter.matches(rowFor("a", "100%", {}, VALID)));
    testOk1(!filter.matches(rowFor("a", "100 percent", {}, VALID)));
    testOk(filter.whereClause().find("ESCAPE") == std::string::npos ||
               filter.whereClause().find("LIKE") != std::string::npos,
           "The condition treats it as an exact value or escapes it");
}

void testRegularExpressions() {
    testDiag("A value wrapped in slashes is a pattern");
    const auto filter = CertFilter::parse("name:/^beam.*line$/", kNow);
    testOk1(filter.matches(rowFor("beam-2-line", "SLAC", {}, VALID)));
    testOk1(!filter.matches(rowFor("upstream", "SLAC", {}, VALID)));
    // The database cannot run one, so the condition must let everything through and leave it
    // to the pass over the rows.
    testOk(filter.whereClause() == "1", "A pattern is not pushed into the query (%s)",
           filter.whereClause().c_str());
}

// A "before" field looks forward from now and an "after" field looks back, so both read the way
// they are said.
void testPeriodDirectionFollowsTheField() {
    testDiag("A period reaches forward for before, and back for after");

    const auto expiring = CertFilter::parse("expires_before:30d", kNow);
    testOk(expiring.matches(rowFor("a", "SLAC", {}, VALID, kNow + 10 * 86400)), "Expiring inside the period matches");
    testOk(!expiring.matches(rowFor("a", "SLAC", {}, VALID, kNow + 60 * 86400)), "Expiring later does not");

    const auto recent = CertFilter::parse("issued_after:7d", kNow);
    testOk(recent.matches(rowFor("a", "SLAC", {}, VALID)), "Issued inside the period matches");
}

// The shared duration reader treats a bare number as minutes, which would silently turn
// "thirty days" into thirty minutes.
void testAPeriodWithoutAUnitIsRefused() {
    testDiag("A period without a unit letter is refused rather than guessed at");
    try {
        CertFilter::parse("expires_before:30", kNow);
        testFail("a unitless period was accepted");
    } catch (const CertFilterError &e) {
        const std::string message = e.what();
        testOk(message.find("unit") != std::string::npos, "The message asks for a unit letter");
        testOk(message.find("m minutes") != std::string::npos && message.find("M months") != std::string::npos,
               "It says which letter is which");
    }
}

void testBareDateMatchesTheWholeDay() {
    testDiag("A bare date matches that whole day");
    // kNow is noon on 2026-08-04, so a certificate expiring then falls inside that day and
    // one expiring a day later does not.
    const auto filter = CertFilter::parse("expires:2026-08-04", kNow);
    testOk1(filter.matches(rowFor("a", "SLAC", {}, VALID, kNow)));
    testOk1(!filter.matches(rowFor("a", "SLAC", {}, VALID, kNow + 86400)));
}

// A certificate may carry several organizational units, and a test matches when any one does,
// so a negated test means none of them does.
void testUnitMatchesAnyValue() {
    testDiag("An organizational unit test matches when any one value matches");
    const auto filter = CertFilter::parse("unit:beamline", kNow);
    testOk1(filter.matches(rowFor("a", "SLAC", {"staff", "beamline"}, VALID)));
    testOk1(!filter.matches(rowFor("a", "SLAC", {"staff", "admin"}, VALID)));

    const auto negated = CertFilter::parse("not unit:beamline", kNow);
    testOk(!negated.matches(rowFor("a", "SLAC", {"staff", "beamline"}, VALID)), "One matching value defeats it");
    testOk(negated.matches(rowFor("a", "SLAC", {"staff"}, VALID)), "No matching value satisfies it");
}

// The identifier an operator types back is the one they read, so it is matched through the same
// helper the listing prints with rather than a padding rule written here.
void testIdMatchesThePrintedForm() {
    testDiag("An identifier test matches the printed form");
    const auto printed = getCertId("a76e613b", 12345);
    testOk1(CertFilter::parse("id:" + printed, kNow).matches(rowFor("a", "SLAC", {}, VALID)));
    // The identifier holds a colon, and a test splits at its first colon, so the value keeps it.
    testOk(printed.find(':') != std::string::npos, "The identifier contains a colon");
}

// Replacing a test with "always true" is only safe with no negation above it, which is what
// negation normal form guarantees. A row the condition lets through but the expression rejects
// has to be dropped.
void testTheConditionOnlyWidens() {
    testDiag("The query condition may only widen; the pass over rows decides");

    const auto filter = CertFilter::parse("org:SLAC and name:/^beam/", kNow);
    testOk(filter.whereClause().find("O = ?") != std::string::npos, "The column test is pushed into the query");

    // Both rows satisfy the pushed part; only one satisfies the whole expression.
    testOk1(filter.matches(rowFor("beamline", "SLAC", {}, VALID)));
    testOk1(!filter.matches(rowFor("upstream", "SLAC", {}, VALID)));
}

void testNegationNormalFormDistributes() {
    testDiag("A negated group becomes negated parts");
    const auto filter = CertFilter::parse("not (org:SLAC and state:REVOKED)", kNow);
    testOk1(filter.matches(rowFor("a", "LBNL", {}, REVOKED)));
    testOk1(filter.matches(rowFor("a", "SLAC", {}, VALID)));
    testOk1(!filter.matches(rowFor("a", "SLAC", {}, REVOKED)));
}

void testDoubleNegationCollapses() {
    testDiag("Two negations cancel");
    const auto filter = CertFilter::parse("not not org:SLAC", kNow);
    testOk1(filter.matches(rowFor("a", "SLAC", {}, VALID)));
    testOk1(!filter.matches(rowFor("a", "LBNL", {}, VALID)));
}

// A filter naming another certificate authority cannot match anything here, and says so rather
// than running a query that cannot return a row.
void testIssuerNamingElsewhereIsEmpty() {
    testDiag("A filter naming another authority is answered without a query");
    testOk1(!CertFilter::parse("issuer:d7421bfe", kNow).possibleFor("a76e613b"));
    testOk1(CertFilter::parse("issuer:a76e613b", kNow).possibleFor("a76e613b"));
}

void testAnIssuerIsReadInEveryFormItIsWrittenIn() {
    testDiag("An authority identifier is read however a certificate printed it");

    const std::string full = "807feda5e03690086b8d04be73a7ca68495afaee";

    // The eight digits a channel name carries, the whole identifier, in capitals, and split by
    // colons the way the tools that print certificates lay it out. All the same authority.
    testEq(readIssuerId("807feda5"), std::string("807feda5"));
    testEq(readIssuerId(full), full);
    testEq(readIssuerId("807FEDA5E03690086B8D04BE73A7CA68495AFAEE"), full);
    testEq(readIssuerId("80:7F:ED:A5:E0:36:90:08:6B:8D:04:BE:73:A7:CA:68:49:5A:FA:EE"), full);

    // Nothing given stays nothing given, which is how "ask whoever answers" is said.
    testEq(readIssuerId(""), std::string(""));

    // Whatever length it was given in, a channel name carries the digits it carries. Without
    // this, naming an authority in full builds a name nothing serves and the request is never
    // answered rather than refused.
    testEq(issuerIdForPvName(full), std::string("807feda5"));
    testEq(getCertCreatePv("CERT", full), std::string("CERT:CREATE:807feda5"));
    testEq(getCertCreatePv("CERT", "807FEDA5"), std::string("CERT:CREATE:807feda5"));
    testEq(getCertListPv("CERT", full), std::string("CERT:LIST:807feda5"));

    // Not an identifier at all, and too little of one to name an authority, are both refused
    // rather than turned into a name that goes unanswered.
    testThrows<std::runtime_error>([] { readIssuerId("not-hex-at-all"); });
    testThrows<std::runtime_error>([] { readIssuerId("807fed"); });
}

void testAnAuthorityCanBeNamedInFull() {
    testDiag("The whole identifier and the eight digits of it name the same authority");

    // What a certificate prints, and what a channel name carries, are the same authority.
    testOk1(CertFilter::parse("issuer:a76e613bd1c58c1b9ba0f3d17c1d3a0f4e5c6d7e", kNow).possibleFor("a76e613b"));
    testOk1(CertFilter::parse("issuer:A76E613BD1C58C1B9BA0F3D17C1D3A0F4E5C6D7E", kNow).possibleFor("a76e613b"));

    // Naming somewhere else in full is still somewhere else.
    testOk1(!CertFilter::parse("issuer:d7421bfed1c58c1b9ba0f3d17c1d3a0f4e5c6d7e", kNow).possibleFor("a76e613b"));

    // A pattern is left as written rather than shortened on the caller's behalf.
    testOk1(CertFilter::parse("issuer:a76e*", kNow).possibleFor("a76e613b"));
}

void testValuesAreBoundNotPastedIn() {
    testDiag("A value never appears in the condition text");
    const auto filter = CertFilter::parse("org:'; DROP TABLE certs; --'", kNow);
    testOk(filter.whereClause().find("DROP") == std::string::npos, "The value is not in the condition (%s)",
           filter.whereClause().c_str());
    testEq(filter.bindings().size(), size_t(1));
}

/////////////////////////////////////////////////////////////////////////////
// What an operator is told when they get it wrong
/////////////////////////////////////////////////////////////////////////////

std::string messageFor(const std::string &expression) {
    try {
        CertFilter::parse(expression, kNow);
    } catch (const CertFilterError &e) {
        return e.what();
    }
    return "";
}

void testAMistakeIsShownWhereItIs() {
    testDiag("A message shows the expression with a caret under the place");
    const auto message = messageFor("state:VALID and orgg:SLAC");
    testOk(message.find("^") != std::string::npos, "There is a caret line");
    testOk(message.find("state:VALID and orgg:SLAC") != std::string::npos, "The expression is shown");

    // The caret sits under the field that is wrong, which is what makes the position useful.
    const auto caret_line = message.substr(message.rfind('^'));
    const auto lines_before = message.substr(0, message.rfind('^'));
    const auto caret_column = message.rfind('^') - lines_before.rfind('\n') - 1;
    testEq(caret_column, std::string("  state:VALID and ").size());
}

void testANearMissIsSuggested() {
    testDiag("A near miss suggests what was probably meant");
    testOk(messageFor("orgg:SLAC").find("\"org\"") != std::string::npos, "A field name is suggested");
    testOk(messageFor("state:VALDI").find("VALID") != std::string::npos, "A status name is suggested");
}

void testAnUnclosedThingPointsAtWhereItOpened() {
    testDiag("An unclosed bracket or quote points at where it was opened");

    const auto bracket = messageFor("(org:SLAC and state:VALID");
    testOk(bracket.find("never closed") != std::string::npos, "It says the bracket is not closed");

    const auto quote = messageFor("org:'SLAC and state:VALID");
    testOk(quote.find("never closed") != std::string::npos, "It says the quote is not closed");
}

void testAMissingJoiningWordIsNamedInWords() {
    testDiag("A missing joining word is named in words");
    const auto message = messageFor("org:SLAC state:VALID");
    testOk(message.find("and") != std::string::npos && message.find("or") != std::string::npos,
           "The message names the joining words");
}

// A message an operator cannot act on is worse than none: it sends them to a programmer.
void testMessagesCarryNoParserVocabulary() {
    testDiag("No message uses parser vocabulary or the text of an exception");

    const std::vector<std::string> bad_expressions{
        "orgg:SLAC", "state:VALDI", "(org:SLAC", "org:'SLAC", "org:SLAC state:VALID",
        "expires_before:30", "expires:notadate", "serial:abc", "typ:CLIENT",
    };
    const std::vector<std::string> forbidden{
        "token", "Token", "parse error", "std::", "exception", "nullptr", "regex_error", "AST", "EOF",
    };

    for (const auto &expression : bad_expressions) {
        const auto message = messageFor(expression);
        if (message.empty()) {
            testFail("expression '%s' was accepted", expression.c_str());
            return;
        }
        for (const auto &word : forbidden) {
            if (message.find(word) != std::string::npos) {
                testFail("message for '%s' contains '%s'", expression.c_str(), word.c_str());
                return;
            }
        }
    }
    testPass("No message uses parser vocabulary");
}

// The type is a real field that cannot be answered yet. Reporting it as unknown would send an
// operator looking for a spelling mistake that is not there.
void testLimitsAreRefusedPlainly() {
    testDiag("A filter past a limit is refused with something an operator can act on");

    std::string too_long(kFilterMaxLength + 1, 'a');
    const auto long_message = messageFor("org:" + too_long);
    testOk(long_message.find("too long") != std::string::npos, "Length is refused plainly");

    std::string deep;
    for (size_t i = 0; i <= kFilterMaxDepth + 1; ++i) deep += "(";
    deep += "org:SLAC";
    for (size_t i = 0; i <= kFilterMaxDepth + 1; ++i) deep += ")";
    testOk(!messageFor(deep).empty(), "Nesting depth is refused");

    std::string many_patterns;
    for (size_t i = 0; i <= kFilterMaxRegexes; ++i) {
        many_patterns += (i ? " or " : "") + std::string("name:/a/");
    }
    testOk(messageFor(many_patterns).find("patterns") != std::string::npos, "Too many patterns is refused plainly");
}

}  // namespace

MAIN(testcertfilter) {
    testPlan(96);
    testAJoiningWordCanBeAValue();
    testPrecedence();
    testBracketsOverridePrecedence();
    testTypeMatchesTheWordTheListingPrints();
    testTypeTakesTheSameValueFormsAsAnyText();
    testTypeIsDecidedInMemoryNotInTheQuery();
    testTypeCombinesWithTheRestOfAnExpression();
    testSeveralValuesMeanAnyOfThem();
    testCaseIsIgnoredWhereItShouldBe();
    testWildcards();
    testTextThatLooksLikeAPatternIsLiteral();
    testRegularExpressions();
    testPeriodDirectionFollowsTheField();
    testAPeriodWithoutAUnitIsRefused();
    testBareDateMatchesTheWholeDay();
    testUnitMatchesAnyValue();
    testIdMatchesThePrintedForm();
    testTheConditionOnlyWidens();
    testNegationNormalFormDistributes();
    testDoubleNegationCollapses();
    testIssuerNamingElsewhereIsEmpty();
    testAnIssuerIsReadInEveryFormItIsWrittenIn();
    testAnAuthorityCanBeNamedInFull();
    testValuesAreBoundNotPastedIn();
    testAMistakeIsShownWhereItIs();
    testANearMissIsSuggested();
    testAnUnclosedThingPointsAtWhereItOpened();
    testAMissingJoiningWordIsNamedInWords();
    testMessagesCarryNoParserVocabulary();
    testLimitsAreRefusedPlainly();
    return testDone();
}
