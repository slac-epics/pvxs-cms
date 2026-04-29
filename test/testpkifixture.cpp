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

bool fileExists(const std::string &path) {
    struct stat path_stat;
    return ::stat(path.c_str(), &path_stat) == 0 && S_ISREG(path_stat.st_mode);
}

bool dirExists(const std::string &path) {
    struct stat path_stat;
    return ::stat(path.c_str(), &path_stat) == 0 && S_ISDIR(path_stat.st_mode);
}

void testFreshPerConstruction() {
    testDiag("Two PkiFixtures produce different CA fingerprints + distinct temp dirs");
    PkiFixture first_fixture;
    PkiFixture second_fixture;

    testOk(!first_fixture.dir().empty() && dirExists(first_fixture.dir()),
           "first fixture temp dir exists: %s", first_fixture.dir().c_str());
    testOk(!second_fixture.dir().empty() && dirExists(second_fixture.dir()),
           "second fixture temp dir exists: %s", second_fixture.dir().c_str());
    testOk(first_fixture.dir() != second_fixture.dir(),
           "two fixtures use distinct temp directories");

    const auto first_fingerprint = first_fixture.caFingerprintSha256();
    const auto second_fingerprint = second_fixture.caFingerprintSha256();
    testOk(!first_fingerprint.empty() && first_fingerprint.size() == 64,
           "first fingerprint is a 64-char hex string");
    testOk(first_fingerprint != second_fingerprint,
           "two fixtures have distinct CA fingerprints");
}

void testCaArtifacts() {
    testDiag("CA, server, admin P12s and CA chain PEM exist after construction");
    PkiFixture pki;
    testOk(fileExists(pki.caP12Path()), "ca.p12 exists: %s", pki.caP12Path().c_str());
    testOk(fileExists(pki.caChainPemPath()), "ca-chain.pem exists: %s", pki.caChainPemPath().c_str());
    testOk(fileExists(pki.serverP12Path()), "pvacms-server.p12 exists: %s", pki.serverP12Path().c_str());
    testOk(fileExists(pki.adminP12Path()), "admin.p12 exists: %s", pki.adminP12Path().c_str());
}

void testIssueDistinctCerts() {
    testDiag("issueServerCert and issueClientCert produce distinct files per call");
    PkiFixture pki;

    SubjectSpec server_a_subject{"server-a", {}, {}, {}};
    SubjectSpec server_b_subject{"server-b", {}, {}, {}};
    SubjectSpec client_c_subject{"client-c", {}, {}, {}};

    auto server_a_cert_path = pki.issueServerCert(server_a_subject);
    auto server_b_cert_path = pki.issueServerCert(server_b_subject);
    auto client_c_cert_path = pki.issueClientCert(client_c_subject);

    std::set<std::string> distinct_cert_paths{
        server_a_cert_path, server_b_cert_path, client_c_cert_path};
    testOk(distinct_cert_paths.size() == 3, "three issued Entity Cert paths are distinct");
    testOk(fileExists(server_a_cert_path),
           "issued server Entity Cert (server-a) exists: %s", server_a_cert_path.c_str());
    testOk(fileExists(server_b_cert_path),
           "issued server Entity Cert (server-b) exists: %s", server_b_cert_path.c_str());
    testOk(fileExists(client_c_cert_path),
           "issued client Entity Cert (client-c) exists: %s", client_c_cert_path.c_str());
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
    testDiag("A single PkiFixture issues multiple Entity Certs; both share the same CA fingerprint");
    PkiFixture pki;
    const auto baseline_fingerprint = pki.caFingerprintSha256();

    auto first_entity_cert_path = pki.issueServerCert({"shared-srv-1", {}, {}, {}});
    auto second_entity_cert_path = pki.issueClientCert({"shared-cli-1", {}, {}, {}});

    testOk(fileExists(first_entity_cert_path),
           "first Entity Cert issued under shared fixture");
    testOk(fileExists(second_entity_cert_path),
           "second Entity Cert issued under shared fixture");
    testOk(pki.caFingerprintSha256() == baseline_fingerprint,
           "CA fingerprint stable across multiple issuances");
}

}  // namespace

MAIN(testpkifixture) {
    testPlan(22);
    testFreshPerConstruction();
    testCaArtifacts();
    testIssueDistinctCerts();
    testTempDirCleanup();
    testBorrowedFixtureSharing();
    return testDone();
}
