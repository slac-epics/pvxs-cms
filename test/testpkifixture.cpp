/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <fstream>
#include <set>
#include <string>
#include <sys/stat.h>

#include <epicsUnitTest.h>
#include <testMain.h>

#include "testharness.h"

namespace {

using cms::test::PkiFixture;
using cms::test::SubjectSpec;

bool fileExists(const std::string &p) {
    struct stat st;
    return ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool dirExists(const std::string &p) {
    struct stat st;
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

void testFreshPerConstruction() {
    testDiag("Two PkiFixtures produce different CA fingerprints + distinct temp dirs");
    PkiFixture a;
    PkiFixture b;

    testOk(!a.dir().empty() && dirExists(a.dir()), "fixture A temp dir exists: %s", a.dir().c_str());
    testOk(!b.dir().empty() && dirExists(b.dir()), "fixture B temp dir exists: %s", b.dir().c_str());
    testOk(a.dir() != b.dir(), "two fixtures use distinct temp directories");

    const auto fa = a.caFingerprintSha256();
    const auto fb = b.caFingerprintSha256();
    testOk(!fa.empty() && fa.size() == 64, "fingerprint A is a 64-char hex string");
    testOk(fa != fb, "fixture A and B have distinct CA fingerprints");
}

void testCaArtifacts() {
    testDiag("CA, server, admin P12s and CA chain PEM exist after construction");
    PkiFixture pki;
    testOk(fileExists(pki.caP12Path()), "ca.p12 exists: %s", pki.caP12Path().c_str());
    testOk(fileExists(pki.caChainPemPath()), "ca-chain.pem exists: %s", pki.caChainPemPath().c_str());
    testOk(fileExists(pki.serverP12Path()), "pvacms-server.p12 exists: %s", pki.serverP12Path().c_str());
    testOk(fileExists(pki.adminP12Path()), "admin.p12 exists: %s", pki.adminP12Path().c_str());
}

void testIssueDistinctEEs() {
    testDiag("issueServerCert and issueClientCert produce distinct files per call");
    PkiFixture pki;

    SubjectSpec sub_a{"server-a", {}, {}, {}};
    SubjectSpec sub_b{"server-b", {}, {}, {}};
    SubjectSpec sub_c{"client-c", {}, {}, {}};

    auto a1 = pki.issueServerCert(sub_a);
    auto a2 = pki.issueServerCert(sub_b);
    auto c1 = pki.issueClientCert(sub_c);

    std::set<std::string> seen{a1, a2, c1};
    testOk(seen.size() == 3, "three issued Entity Cert paths are distinct");
    testOk(fileExists(a1), "issued server Entity Cert 1 exists: %s", a1.c_str());
    testOk(fileExists(a2), "issued server Entity Cert 2 exists: %s", a2.c_str());
    testOk(fileExists(c1), "issued client Entity Cert exists: %s", c1.c_str());
}

void testTempDirCleanup() {
    testDiag("Destructor removes temp directory and all files within");
    std::string captured_dir;
    std::string captured_ca;
    std::string captured_entity;
    {
        PkiFixture pki;
        captured_dir = pki.dir();
        captured_ca = pki.caP12Path();
        captured_entity = pki.issueServerCert({"throwaway", {}, {}, {}});

        testOk(dirExists(captured_dir), "temp dir present during fixture lifetime");
        testOk(fileExists(captured_ca), "CA file present during fixture lifetime");
        testOk(fileExists(captured_entity), "issued Entity Cert file present during fixture lifetime");
    }
    testOk(!dirExists(captured_dir), "temp dir removed after fixture destruction");
    testOk(!fileExists(captured_ca), "CA file removed after fixture destruction");
    testOk(!fileExists(captured_entity), "issued Entity Cert removed after fixture destruction");
}

void testBorrowedFixtureSharing() {
    testDiag("A single PkiFixture issues multiple EEs; both share the same CA fingerprint");
    PkiFixture pki;
    const auto base_fp = pki.caFingerprintSha256();

    auto entity1 = pki.issueServerCert({"shared-srv-1", {}, {}, {}});
    auto entity2 = pki.issueClientCert({"shared-cli-1", {}, {}, {}});

    testOk(fileExists(entity1), "first Entity Cert issued under shared fixture");
    testOk(fileExists(entity2), "second Entity Cert issued under shared fixture");
    testOk(pki.caFingerprintSha256() == base_fp, "CA fingerprint stable across multiple issuances");
}

}  // namespace

MAIN(testpkifixture) {
    testPlan(22);
    testFreshPerConstruction();
    testCaArtifacts();
    testIssueDistinctEEs();
    testTempDirCleanup();
    testBorrowedFixtureSharing();
    return testDone();
}
