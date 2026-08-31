/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * A certificate subject may name several organizational units, read innermost first, so that a
 * staff group inside a beamline can be written down. The order is the meaning: every unit is an
 * ancestor of the common name, so dropping the outer ones does not narrow the identity, it
 * widens it. These check the rules that keep that meaning intact from the environment and the
 * command line, through the request and its signature, into the issued subject and back out.
 */

#include <limits.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include <sqlite3.h>

#include "auth.h"
#include "ccrmanager.h"
#include "certfactory.h"
#include "certsubjectunits.h"
#include "configauthn.h"
// pvacms.h is not self-contained: it names sql_ptr, which ownedptr.h only defines once
// sqlite3.h has been seen. pvacms.cpp happens to include both first; do the same here.
#include <sqlite3.h>
#include "ownedptr.h"
#include "pvacms.h"
#include "security.h"

using namespace pvxs;
using namespace pvxs::certs;

namespace {

// ccrToString is protected because only an authenticator has cause to sign with it. Reaching it
// the way a subclass does is the only way to check that both overloads say the same thing.
struct PayloadProbe : Auth {
    PayloadProbe() : Auth("probe", {}) {}
    std::shared_ptr<AuthnCredentials> getCredentials(const client::Config &, bool) const override { return {}; }
    bool verify(Value &, time_t &) const override { return false; }
    void fromEnv(std::unique_ptr<client::Config> &) override {}
    std::string getOptionsPlaceholderText() override { return {}; }
    void addOptions(CLI::App &, std::map<const std::string, std::unique_ptr<client::Config>> &) override {}
    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<AuthnCredentials> &credentials,
                                                                   const std::shared_ptr<KeyPair> &key_pair, const uint16_t &usage,
                                                                   const ConfigAuthN &config) const override {
        return Auth::createCertCreationRequest(credentials, key_pair, usage, config);
    }

    static std::string fromCredentials(const std::shared_ptr<CertCreationRequest> &ccr, const uint16_t usage) { return ccrToString(ccr, usage); }
    static std::string fromWire(const Value &ccr) { return ccrToString(ccr); }
};

// The certificate creation request as a client that predates repeated units builds it: the
// repeatable field is not merely unset, it is absent from the type altogether.
#define OLD_CCR_PROTOTYPE(VERIFIER)            \
    {                                          \
        members::String("type"),               \
        members::String("name"),               \
        members::String("country"),            \
        members::String("organization"),       \
        members::String("organization_unit"),  \
        members::UInt16("usage"),              \
        members::UInt64("not_before"),         \
        members::UInt64("not_after"),          \
        members::String("pub_key"),            \
        members::String("config_uri_base"),    \
        members::Bool("no_status"),            \
        members::Struct("verifier", VERIFIER), \
    }

const PayloadProbe probe;

std::shared_ptr<CertCreationRequest> requestFor(const std::vector<std::string> &units, const std::shared_ptr<KeyPair> &key_pair) {
    const auto credentials = std::make_shared<AuthnCredentials>();
    credentials->name = "alice";
    credentials->country = "US";
    credentials->organization = "lbnl";
    credentials->organization_unit = units;
    const ConfigAuthN config;
    return probe.createCertCreationRequest(credentials, key_pair, ssl::kForClient, config);
}

// Rendered so a failure says which units came back, and in what order. Built here, so a fault
// in joinOrganizationalUnits cannot hide one in the reading.
std::string show(const std::vector<std::string> &units) {
    std::string out("[");
    for (size_t i = 0; i < units.size(); i++) {
        if (i) out += ", ";
        out += units[i];
    }
    return out + "]";
}

bool refuses(const std::function<void()> &fn) {
    try {
        fn();
    } catch (const std::exception &) {
        return true;
    }
    return false;
}

// Order is the meaning, so a list read out of a string must come back in the order it went in.
void testTheEnvironmentCarriesAList() {
    testDiag("A separated environment value gives the units innermost first");

    testEq(show(parseOrganizationalUnits("staff;beamline")), show({"staff", "beamline"}));
    testEq(show(parseOrganizationalUnits(" staff ; beamline ")), show({"staff", "beamline"}));
    testEq(show(parseOrganizationalUnits("beamline")), show({"beamline"}));
    testEq(show(parseOrganizationalUnits("")), show({}));
    // An empty value is no unit, so a stray separator is forgiven
    testEq(show(parseOrganizationalUnits("staff;;beamline")), show({"staff", "beamline"}));
}

// Anything a request could have carried before must produce exactly the string it produced
// before, or an older client's signature stops verifying against a newer certificate manager.
void testJoiningIsTheInverseOfParsing() {
    testDiag("Joining reproduces what parsing was given");

    testEq(joinOrganizationalUnits({}), std::string(""));
    testEq(joinOrganizationalUnits({"beamline"}), std::string("beamline"));
    testEq(joinOrganizationalUnits({"staff", "beamline"}), std::string("staff;beamline"));
}

// A unit inside itself is a statement nothing can satisfy, and is refused where it is written.
void testAUnitCannotContainItself() {
    testDiag("A repeated value is refused, after trimming");

    std::vector<std::string> repeated{"beamline", "beamline"};
    testTrue(refuses([&] { normalizeOrganizationalUnits(repeated); }));

    std::vector<std::string> repeated_with_spaces{" beamline ", "beamline"};
    testTrue(refuses([&] { normalizeOrganizationalUnits(repeated_with_spaces); }));

    // Different values that merely look alike are two units, and case is not folded
    std::vector<std::string> distinct{"beamline", "Beamline"};
    testFalse(refuses([&] { normalizeOrganizationalUnits(distinct); }));
    testEq(show(distinct), show({"beamline", "Beamline"}));
}

// The separator is what joins the units into one string, in the environment and in the payload
// that is signed. A value containing one could not be told apart from two values.
void testASeparatorInsideAValueIsRefused() {
    testDiag("A value containing the separator is refused");

    std::vector<std::string> awkward{"a;b"};
    testTrue(refuses([&] { normalizeOrganizationalUnits(awkward); }));
}

void testTheConfigurationReadsTheEnvironment() {
    testDiag("Both environment variables take a list and give it back unchanged");

    const std::map<std::string, std::string> unused;  // fromAuthEnv reads the real environment

    setenv("EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT", "staff;beamline", 1);
    setenv("EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT", "operators;controls", 1);
    ConfigAuthN config;
    config.fromAuthEnv(unused);
    testEq(show(config.organizational_unit), show({"staff", "beamline"}));
    testEq(show(config.server_organizational_unit), show({"operators", "controls"}));

    std::map<std::string, std::string> defs;
    config.updateDefs(defs);
    testEq(defs["EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"], std::string("staff;beamline"));
    testEq(defs["EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT"], std::string("operators;controls"));

    unsetenv("EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT");
    unsetenv("EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT");
}

// The single-value field is what a certificate manager that predates this change reads, so it
// must always carry the innermost unit, whatever else the request holds.
void testTheRequestCarriesBothForms(const std::shared_ptr<KeyPair> &key_pair) {
    testDiag("The request carries the whole list and the innermost value");

    const auto request = requestFor({"staff", "beamline"}, key_pair);
    const auto units = request->ccr["organization_units"].as<shared_array<const std::string>>();
    testEq(units.size(), size_t(2));
    testEq(std::string(units[0]), std::string("staff"));
    testEq(std::string(units[1]), std::string("beamline"));
    testEq(request->ccr["organization_unit"].as<std::string>(), std::string("staff"));
    testEq(show(getOrganizationalUnits(request->ccr)), show({"staff", "beamline"}));
}

// A request whose two fields disagree is the shape a verification bypass takes: leave an
// authorised value where the verifier looks, put unauthorised values where the subject is built
// from. Reading the units is what compares them, so no caller can act on one field alone.
void testDisagreeingFieldsAreRefused(const std::shared_ptr<KeyPair> &key_pair) {
    testDiag("A request whose two unit fields disagree is refused");

    auto request = requestFor({"staff", "beamline"}, key_pair);
    request->ccr["organization_units"] = shared_array<const std::string>({std::string("admin"), std::string("beamline")});
    testTrue(refuses([&] { getOrganizationalUnits(request->ccr); }));

    // The bypass itself: nothing where the verifier looks, everything in the list
    request = requestFor({"staff", "beamline"}, key_pair);
    request->ccr["organization_unit"] = "";
    testTrue(refuses([&] { getOrganizationalUnits(request->ccr); }));

    // And the reverse: a unit named, but a list that is present and says there is none
    request = requestFor({"staff", "beamline"}, key_pair);
    request->ccr["organization_units"] = shared_array<const std::string>();
    testTrue(refuses([&] { getOrganizationalUnits(request->ccr); }));
}

// The payload covers every unit, which is a containment path and decides which access rules
// apply to the holder.
void testTheSignaturePayloadCoversEveryUnit(const std::shared_ptr<KeyPair> &key_pair) {
    testDiag("Both sides compute the same payload, and it changes when a unit is added");

    const auto request = requestFor({"staff", "beamline"}, key_pair);
    testEq(PayloadProbe::fromCredentials(request, ssl::kForClient), PayloadProbe::fromWire(request->ccr));

    const auto honest = PayloadProbe::fromWire(request->ccr);
    request->ccr["organization_units"] =
        shared_array<const std::string>({std::string("staff"), std::string("beamline"), std::string("admin")});
    testNotEq(PayloadProbe::fromWire(request->ccr), honest);
}

// A client that predates the repeatable field signs a payload built without it. A newer
// certificate manager reads that request and must arrive at the same string.
void testAnOlderRequestStillVerifies(const std::shared_ptr<KeyPair> &key_pair) {
    testDiag("A request carrying no units, or one, signs what it always signed");

    for (const std::vector<std::string> &units : {std::vector<std::string>{}, std::vector<std::string>{"beamline"}}) {
        const auto request = requestFor(units, key_pair);

        auto old_ccr = TypeDef(TypeCode::Struct, OLD_CCR_PROTOTYPE(std::vector<Member>{})).create();
        for (const char *field : {"type", "name", "country", "organization", "organization_unit", "pub_key", "config_uri_base"})
            old_ccr[field] = request->ccr[field].as<std::string>();
        old_ccr["usage"] = request->ccr["usage"].as<uint16_t>();
        old_ccr["not_before"] = request->ccr["not_before"].as<uint64_t>();
        old_ccr["not_after"] = request->ccr["not_after"].as<uint64_t>();

        testFalse(static_cast<bool>(old_ccr["organization_units"]));
        testEq(show(getOrganizationalUnits(old_ccr)), show(units));
        testEq(PayloadProbe::fromWire(old_ccr), PayloadProbe::fromCredentials(request, ssl::kForClient));
    }
}

// One entry per unit, in the order supplied, which is where the meaning is.
void testTheIssuedSubjectNamesEveryUnitInOrder(const std::shared_ptr<KeyPair> &key_pair) {
    testDiag("Each unit is its own subject entry, innermost first");

    CertFactory factory(1234, key_pair, "alice", "US", "lbnl", {"staff", "beamline"}, time(nullptr), time(nullptr) + 3600, 0,
                        ssl::kForClient, "CERT");
    const auto cert = factory.create();
    auto *subject = X509_get_subject_name(cert.get());

    testEq(show(getSubjectOrganizationalUnits(subject)), show({"staff", "beamline"}));

    int entries = 0;
    for (int i = 0; i < X509_NAME_entry_count(subject); i++)
        if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, i))) == NID_organizationalUnitName) entries++;
    testEq(entries, 2);
}

// Reading a subject back with X509_NAME_get_text_by_NID returns the first occurrence and
// silently discards the rest, which is how a nested unit disappears on the way into the database.
void testASubjectIsReadBackWhole(const std::shared_ptr<KeyPair> &key_pair) {
    testDiag("A subject naming one unit, or none, reads back correctly too");

    CertFactory one(1235, key_pair, "alice", "US", "lbnl", {"beamline"}, time(nullptr), time(nullptr) + 3600, 0, ssl::kForClient, "CERT");
    const auto with_one = one.create();
    testEq(show(getSubjectOrganizationalUnits(X509_get_subject_name(with_one.get()))), show({"beamline"}));

    CertFactory none(1236, key_pair, "alice", "US", "lbnl", {}, time(nullptr), time(nullptr) + 3600, 0, ssl::kForClient, "CERT");
    const auto with_none = none.create();
    testEq(show(getSubjectOrganizationalUnits(X509_get_subject_name(with_none.get()))), show({}));

    testEq(show(getSubjectOrganizationalUnits(nullptr)), show({}));
}

// The case this exists for: a certificate manager that predates repeated units reads only the
// single-value field, so the certificate comes back naming the innermost unit alone. That is not
// a lost value, it is a shorter ancestry, which an access rule reads as a different and broader
// identity. Silent loss has to become a loud failure before the keychain file is written.
void testAShortenedSubjectIsRefused(const std::shared_ptr<KeyPair> &key_pair) {
    testDiag("A certificate carrying fewer units than were asked for is refused");

    const auto pemFor = [&key_pair](const std::vector<std::string> &units, const uint64_t serial) {
        CertFactory factory(serial, key_pair, "alice", "US", "lbnl", units, time(nullptr), time(nullptr) + 3600, 0, ssl::kForClient, "CERT");
        const auto cert = factory.create();
        return CertFactory::certAndCasToPemString(cert, nullptr);
    };

    const std::vector<std::string> asked{"staff", "beamline"};

    // What an older certificate manager sends back: the innermost unit alone
    const auto shortened = pemFor({"staff"}, 2001);
    testTrue(refuses([&] { CCRManager::checkIssuedOrganizationalUnits(asked, shortened); }));

    // The same values in the other order are a different identity, not the same one
    const auto reordered = pemFor({"beamline", "staff"}, 2002);
    testTrue(refuses([&] { CCRManager::checkIssuedOrganizationalUnits(asked, reordered); }));

    // A certificate manager that understands the list passes without complaint
    const auto whole = pemFor(asked, 2003);
    testFalse(refuses([&] { CCRManager::checkIssuedOrganizationalUnits(asked, whole); }));

    // Something that is no certificate at all is refused
    testTrue(refuses([&] { CCRManager::checkIssuedOrganizationalUnits(asked, "not a certificate"); }));
}

// A database with the certificate table only, as an installation running the current release
// has it. The organizational units are added the way the server adds them on startup.
struct SubjectDb {
    std::string path{"testorgunits_subject.db"};
    sqlite3 *db{nullptr};

    SubjectDb() {
        std::remove(path.c_str());
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            db = nullptr;
            return;
        }
        sqlite3_exec(db,
                     "CREATE TABLE certs(serial INTEGER PRIMARY KEY, CN TEXT, O TEXT, OU TEXT, C TEXT,"
                     " status INTEGER, status_date INTEGER, approved INTEGER);",
                     nullptr, nullptr, nullptr);
    }
    ~SubjectDb() {
        if (db) sqlite3_close(db);
        std::remove(path.c_str());
    }
    SubjectDb(const SubjectDb &) = delete;
    SubjectDb &operator=(const SubjectDb &) = delete;

    //! A certificate row as the current release writes it: one unit, in the single column.
    void addOldStyleCert(const int64_t serial, const char *cn, const char *unit) {
        char sql[512];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO certs (serial, CN, O, OU, C, status, status_date, approved)"
                 " VALUES (%lld, '%s', 'lbnl', '%s', 'US', 1, 100, 1);",
                 static_cast<long long>(serial), cn, unit);
        sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
    }

    //! What the server runs on startup: create the table and bring existing rows forward.
    bool migrate() { return sqlite3_exec(db, SQL_CREATE_SUBJECT_UNITS_TABLE, nullptr, nullptr, nullptr) == SQLITE_OK; }

    //! How many certificates match the subject, using the certificate manager's own duplicate
    //! query, so an edit to SQL_DUPS_SUBJECT is caught here.
    int countMatching(const char *cn, const std::vector<std::string> &units) {
        std::string sql(SQL_DUPS_SUBJECT);
        sql += getOrganizationalUnitsClause(units);
        sqlite3_stmt *stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return -1;
        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":CN"), cn, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":O"), "lbnl", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":C"), "US", -1, SQLITE_TRANSIENT);
        bindOrganizationalUnitsClause(stmt, units);
        const int count = sqlite3_step(stmt) == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
        sqlite3_finalize(stmt);
        return count;
    }
};

// Every certificate written before this change carries at most one unit, so there is no order to
// reconstruct. The migration must add a row for each, drop nothing, and be safe to run again.
void testAnExistingDatabaseIsBroughtForward() {
    testDiag("An existing database gains a unit row per certificate, and twice is harmless");

    SubjectDb store;
    if (!store.db) { testFail("no database"); testSkip(5, "no database"); return; }

    store.addOldStyleCert(100, "alice", "beamline");
    store.addOldStyleCert(200, "bob", "");  // no unit at all
    testTrue(store.migrate());

    testEq(show(getSubjectUnits(store.db, 100)), show({"beamline"}));
    // An empty value is no unit, so it gets no row
    testEq(show(getSubjectUnits(store.db, 200)), show({}));

    // Running it again must not double the rows, and must not disturb a certificate that has
    // since been given a nested unit by the new code.
    storeSubjectUnits(store.db, 300, {"staff", "beamline"});
    testTrue(store.migrate());
    testEq(show(getSubjectUnits(store.db, 100)), show({"beamline"}));
    testEq(show(getSubjectUnits(store.db, 300)), show({"staff", "beamline"}));
}

// The comparison the three subject-equality queries make. Order is containment, so the same
// values in another order are a different holder, and a shorter path is a different holder.
void testTheOrderedComparisonIsAnIdentityTest() {
    testDiag("Two subjects match only on the same units in the same order");

    SubjectDb store;
    if (!store.db) { testFail("no database"); testSkip(7, "no database"); return; }

    // The table on an empty database, then a certificate written the way the server writes one:
    // the row, with the innermost unit in its column, and one child row per unit.
    testTrue(store.migrate());
    store.addOldStyleCert(100, "alice", "staff");
    storeSubjectUnits(store.db, 100, {"staff", "beamline"});  // alice is staff inside beamline

    testEq(store.countMatching("alice", {"staff", "beamline"}), 1);

    // The same values the other way round say beamline sits inside staff: a different holder
    testEq(store.countMatching("alice", {"beamline", "staff"}), 0);
    // A shorter path claims a staff group that is not inside any beamline: also different
    testEq(store.countMatching("alice", {"staff"}), 0);
    // And a longer one is different again
    testEq(store.countMatching("alice", {"staff", "beamline", "lbnl"}), 0);
    // Naming no unit at all must not match a certificate that names two
    testEq(store.countMatching("alice", {}), 0);

    // A certificate with no units is matched by asking for none, and only by that
    store.addOldStyleCert(200, "bob", "");
    testEq(store.countMatching("bob", {}), 1);
    testEq(store.countMatching("bob", {"beamline"}), 0);
}

// The generated fixture: a real keychain file on disk whose subject names two units. Everything
// above builds its certificates in process, so nothing until now proves that a subject written
// by one program and read back by another survives the round trip.
void testAGeneratedKeychainCarriesBothUnits() {
    testDiag("The ioc1 fixture carries a nested unit, innermost first");

    const auto cert_data = IdFileFactory::createReader("ioc1.p12")->getCertDataFromFile();
    testTrue(static_cast<bool>(cert_data.cert));
    if (!cert_data.cert) { testSkip(2, "no certificate"); return; }

    testEq(show(getSubjectOrganizationalUnits(X509_get_subject_name(cert_data.cert.get()))),
           show({"beamline", "epics.org Certificate Authority"}));

    // and a fixture that was not given one is unchanged: a single unit, as before
    const auto plain = IdFileFactory::createReader("client1.p12")->getCertDataFromFile();
    testEq(show(getSubjectOrganizationalUnits(X509_get_subject_name(plain.cert.get()))),
           show({"epics.org Certificate Authority"}));
}

// Those two fixtures are generated into the architecture build directory and opened by name, so
// they are only found when that is the working directory. Started elsewhere the reader returns
// nothing and a single assertion fails, which reads as a fault in the code under test rather
// than a fault in how the test was started.
void requireFixture(const char *name) {
    if (access(name, R_OK) == 0) return;
    char directory[PATH_MAX];
    if (!getcwd(directory, sizeof(directory))) directory[0] = '\0';
    testAbort(
        "the generated test keychain \"%s\" was not found in the working directory \"%s\". Run this test from the "
        "test/O.<architecture> build directory, where the test keychain files are generated.",
        name, directory);
}

}  // namespace

MAIN(testorgunits) {
    requireFixture("ioc1.p12");
    requireFixture("client1.p12");

    testPlan(59);
    const auto key_pair = IdFileFactory::createKeyPair();

    testTheEnvironmentCarriesAList();
    testJoiningIsTheInverseOfParsing();
    testAUnitCannotContainItself();
    testASeparatorInsideAValueIsRefused();
    testTheConfigurationReadsTheEnvironment();
    testTheRequestCarriesBothForms(key_pair);
    testDisagreeingFieldsAreRefused(key_pair);
    testTheSignaturePayloadCoversEveryUnit(key_pair);
    testAnOlderRequestStillVerifies(key_pair);
    testTheIssuedSubjectNamesEveryUnitInOrder(key_pair);
    testASubjectIsReadBackWhole(key_pair);
    testAShortenedSubjectIsRefused(key_pair);
    testAGeneratedKeychainCarriesBothUnits();
    testAnExistingDatabaseIsBroughtForward();
    testTheOrderedComparisonIsAnIdentityTest();
    return testDone();
}
