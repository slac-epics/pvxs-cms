/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
// OpenSSL on Windows requires applink.c for FILE* operations in DLL builds
#ifdef _MSC_VER
#  include <openssl/applink.c>
#endif

#include <iostream>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <openssl/crypto.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <pvxs/log.h>
#include <pvxs/unittest.h>

#include "certcontext.h"
#include "certfactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "certstatusmanager.h"
#include "auth.h"
#include "configcms.h"
#include "openssl.h"
#include "opensslgbl.h"
#include "ownedptr.h"
#include "serverev.h"
#include "testcertprefix.h"
#include "wildcardpv.h"

namespace {
using namespace pvxs;
using namespace pvxs::certs;

struct Tester {
    // Pristine values
    const CertDate now;
    const CertDate status_valid_until_time;
    const CertDate revocation_date;
    const Value status_value_prototype{CertStatus::getStatusPrototype()};

    CertCtx<tag::cert_auth> cert_auth;
    CertCtx<tag::server1>   server1;
    CertCtx<tag::client1>   client1;

    const std::string issuer_id{CertStatus::getSkId(cert_auth.cert.cert)};

    server::WildcardPV status_pv{server::WildcardPV::buildMailbox()};
    server::ServerEv pvacms;
    client::Context client;
    CounterMap cert_status_request_counters;
    epicsMutex counter_lock;

    Tester()
        : now(time(nullptr)),
          status_valid_until_time(now.t + STATUS_VALID_FOR_SECS),
          revocation_date(now.t - REVOKED_SINCE_SECS) {
        if (!cert_auth.cert.cert || !cert_auth.cert.pkey || !server1.cert.cert || !server1.cert.pkey || !client1.cert.cert || !client1.cert.pkey) {
            testFail("Error loading one or more certificates");
            return;
        }

        auto source = server::WildcardSource::build();
        source->add(getCertStatusPv(TEST_CERT_PV_PREFIX, issuer_id), status_pv);
        // Set up mock source that counts actual certificate-status subscriptions
        const auto pvacms_mock = std::make_shared<server::MockSource>(source, [this](std::string const& pv_name) {
            if (cert_status_request_counters.find(pv_name) == cert_status_request_counters.end()) {
                cert_status_request_counters[pv_name] = std::make_shared<std::atomic<uint32_t>>(0);
            }
            cert_status_request_counters[pv_name]->fetch_add(1);

        });

        pvacms = ConfigCms::mockCms().build().addSource("__wildcard", pvacms_mock);
        client = pvacms.clientConfig().build();

        testShow() << "Testing TLS Status Functions:\n";
    }

    ~Tester() = default;

    void initialisation() const {
        testShow() << __func__;
        testEq(now.t, status_valid_until_time.t - STATUS_VALID_FOR_SECS);
        testEq(now.t, revocation_date.t + REVOKED_SINCE_SECS);
    }

    void ocspPayload() {
        testShow() << __func__;
        try {
            const auto cert_status_creator(CertStatusFactory(cert_auth.cert.cert, cert_auth.cert.pkey, cert_auth.cert.chain, 0, STATUS_VALID_FOR_SECS));
            createCertStatus(cert_auth, {VALID},cert_status_creator, now,{});
            createCertStatus(server1, {PENDING},cert_status_creator, now,{});
            createCertStatus(client1, {REVOKED},cert_status_creator, now,revocation_date);
        } catch (std::exception &e) {
            testFail("Failed to read certificate in from file: %s\n", e.what());
        }
    }

    void parse() const {
        testShow() << __func__;
        try {
            testDiag("Parsing OCSP Response: %s", "Client certificate");
            auto parsed_response = CmsStatusManager::parse(client1.status.ocsp_bytes, client1.cert.trusted_store.get());
            testDiag("Parsed OCSP Response: %s", "Client certificate");

            testEq(parsed_response.serial, client1.serial());
            testEq(parsed_response.ocsp_status.i, OCSP_CERTSTATUS_REVOKED);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, revocation_date.t);
        } catch (std::exception &e) {
            testFail("Failed to parse Client OCSP response: %s", e.what());
        }

        try {
            testDiag("Parsing OCSP Response: %s", "Server certificate");
            auto parsed_response = CmsStatusManager::parse(server1.status.ocsp_bytes, server1.cert.trusted_store.get());
            testDiag("Parsed OCSP Response: %s", "Server certificate");

            testEq(parsed_response.serial, server1.serial());
            testEq(parsed_response.ocsp_status.i, OCSP_CERTSTATUS_UNKNOWN);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, 0);
        } catch (std::exception &e) {
            testFail("Failed to parse Server OCSP response: %s", e.what());
        }

        try {
            testDiag("Parsing OCSP Response: %s", "Certificate Authority Certificate");
            auto parsed_response = CmsStatusManager::parse(cert_auth.status.ocsp_bytes, cert_auth.cert.trusted_store.get());
            testDiag("Parsed OCSP Response: %s", "Certificate Authority Certificate");

            testEq(parsed_response.serial, cert_auth.serial());
            testEq(parsed_response.ocsp_status.i, OCSP_CERTSTATUS_GOOD);
            testEq(parsed_response.status_date.t, now.t);
            testEq(parsed_response.status_valid_until_date.t, status_valid_until_time.t);
            testEq(parsed_response.revocation_date.t, 0);
        } catch (std::exception &e) {
            testFail("Failed to parse Certificate Authority OCSP response: %s", e.what());
        }
    }

    void makeStatusResponses() {
        testShow() << __func__;
        const auto cert_status_creator(CertStatusFactory(cert_auth.cert.cert, cert_auth.cert.pkey, cert_auth.cert.chain, 0, STATUS_VALID_FOR_SECS));
        makeStatusResponse(cert_auth,cert_status_creator,now,revocation_date);
        makeStatusResponse(server1,cert_status_creator,now,revocation_date);
        makeStatusResponse(client1,cert_status_creator,now,revocation_date);
    }

    void testStatusConversions() {
        testShow() << __func__;
        try {
            auto unknown_status = UnknownCertificateStatus();
            {
                testDiag("PVACertificateStatus ==> CertificateStatus");
                auto client_cs = static_cast<CertifiedCertificateStatus>(client1.status);
                auto server_cs = static_cast<CertifiedCertificateStatus>(server1.status);
                auto cert_auth_cs = static_cast<CertifiedCertificateStatus>(cert_auth.status);

                testDiag("CertificateStatus == PVACertificateStatus");
                testOk1(client_cs == client1.status);                   // REVOKED == REVOKED
                testOk1(server_cs == server1.status);                   // PENDING == PENDING
                testOk1(cert_auth_cs == cert_auth.status);              // VALID == VALID

                testDiag("PVACertificateStatus == CertificateStatus");
                testOk1(client1.status == client_cs);                   // REVOKED == REVOKED
                testOk1(server1.status == server_cs);                   // PENDING == PENDING
                testOk1(cert_auth.status == cert_auth_cs);              // VALID == VALID

                testDiag("CertificateStatus != PVACertificateStatus");
                testOk1(client_cs != cert_auth.status);                 // REVOKED != VALID
                testOk1(server_cs != client1.status);                   // PENDING != REVOKED
                testOk1(cert_auth_cs != server1.status);                // VALID != PENDING

                testDiag("PVACertificateStatus != CertificateStatus");
                testOk1(cert_auth.status != client_cs);                 // VALID != REVOKED
                testOk1(client1.status != server_cs);                   // REVOKED != UNKNOWN
                testOk1(server1.status != cert_auth_cs);                // PENDING != VALID
            }

            {
                testDiag("PVACertificateStatus ==> OCSPStatus");
                auto client_ocs = static_cast<OCSPStatus>(client1.status);
                auto server_ocs = static_cast<OCSPStatus>(server1.status);
                auto cert_auth_ocs = static_cast<OCSPStatus>(cert_auth.status);

                testDiag("OCSPStatus == PVACertificateStatus");
                testOk1(client_ocs == client1.status);  // REVOKED == REVOKED
                testOk1(cert_auth_ocs == cert_auth.status);           // VALID == VALID

                testDiag("PVACertificateStatus == OCSPStatus");
                testOk1(client1.status == client_ocs);  // REVOKED == REVOKED
                testOk1(cert_auth.status == cert_auth_ocs);           // VALID == VALID

                testDiag("OCSPStatus != PVACertificateStatus");
                testOk1(client_ocs != cert_auth.status);   // REVOKED != VALID
                testOk1(cert_auth_ocs != server1.status);  // VALID != PENDING

                testOk1(server_ocs != server1.status);  // UNKNOWN == PENDING
                testOk1(server_ocs != client1.status);  // UNKNOWN != REVOKED

                testDiag("PVACertificateStatus != OCSPStatus");
                testOk1(cert_auth.status != client_ocs);   // VALID != REVOKED
                testOk1(server1.status != cert_auth_ocs);  // PENDING != VALID

                testOk1(server1.status != server_ocs);  // PENDING == UNKNOWN
                testOk1(client1.status != server_ocs);  // REVOKED != UNKNOWN
            }

            {
                testDiag("PVACertificateStatus ==> certstatus_t");
                auto client_cs_t = static_cast<certstatus_t>(client1.status.status.i);
                auto server_cs_t = static_cast<certstatus_t>(server1.status.status.i);
                auto cert_auth_cs_t = static_cast<certstatus_t>(cert_auth.status.status.i);

                testDiag("certstatus_t == PVACertificateStatus");
                testOk1(client_cs_t == client1.status);  // REVOKED == REVOKED
                testOk1(server_cs_t == server1.status);  // PENDING == PENDING
                testOk1(cert_auth_cs_t == cert_auth.status);           // VALID == VALID

                testDiag("PVACertificateStatus == certstatus_t");
                testOk1(client1.status == client_cs_t);  // REVOKED == REVOKED
                testOk1(server1.status == server_cs_t);  // PENDING == PENDING
                testOk1(cert_auth.status == cert_auth_cs_t);           // VALID == VALID

                testDiag("certstatus_t != PVACertificateStatus");
                testOk1(client_cs_t != cert_auth.status);       // REVOKED != VALID
                testOk1(server_cs_t != client1.status);  // PENDING != REVOKED
                testOk1(cert_auth_cs_t != server1.status);      // VALID != PENDING

                testDiag("PVACertificateStatus != certstatus_t");
                testOk1(cert_auth.status != client_cs_t);       // VALID != REVOKED
                testOk1(client1.status != server_cs_t);  // REVOKED != UNKNOWN
                testOk1(server1.status != cert_auth_cs_t);      // PENDING != VALID
            }

            {
                testDiag("PVACertificateStatus ==> certstatus_t & OCSPStatus");
                auto client_cs_t = static_cast<certstatus_t>(client1.status.status.i);
                auto server_cs_t = static_cast<certstatus_t>(server1.status.status.i);
                auto cert_auth_cs_t = static_cast<certstatus_t>(cert_auth.status.status.i);

                auto client_ocs = static_cast<OCSPStatus>(client1.status);
                auto server_ocs = static_cast<OCSPStatus>(server1.status);
                auto cert_auth_ocs = static_cast<OCSPStatus>(cert_auth.status);

                testDiag("OCSPStatus == certstatus_t");
                testOk1(client_ocs == client_cs_t);  // REVOKED == REVOKED
                testOk1(server_ocs != server_cs_t);  // UNKNOWN != PENDING
                testOk1(cert_auth_ocs == cert_auth_cs_t);          // VALID == VALID

                testDiag("certstatus_t == OCSPStatus");
                testOk1(client_cs_t == client_ocs);  // REVOKED == REVOKED
                testOk1(server_cs_t != server_ocs);  // PENDING != UNKNOWN
                testOk1(cert_auth_cs_t == cert_auth_ocs);          // VALID == VALID

                testDiag("certstatus_t != OCSPStatus");
                testOk1(client_ocs != cert_auth_cs_t);      // REVOKED != VALID
                testOk1(server_ocs != client_cs_t);  // UNKNOWN != REVOKED
                testOk1(cert_auth_ocs != server_cs_t);      // VALID != PENDING

                testDiag("OCSPStatus != certstatus_t");
                testOk1(client_cs_t != cert_auth_ocs);      // VALID != REVOKED
                testOk1(server_cs_t != client_ocs);  // REVOKED != UNKNOWN
                testOk1(cert_auth_cs_t != server_ocs);      // PENDING != VALID
            }

        } catch (std::exception &e) {
            testFail("Failed test status conversions: %s", e.what());
        }
    }

    void makeStatusRequest() {
        testShow() << __func__;
        try {
            testDiag("Setting up: %s", "Mock PVACMS Server");

            status_pv.onFirstConnect([this](server::WildcardPV &pv, const std::string &pv_name, const std::list<std::string> &parameters) {
                auto it = parameters.begin();
                const std::string &serial_string = *it;
                const serial_number_t serial = std::stoull(serial_string);

                if (
                    postValueCase(serial, pv, pv_name, cert_auth,true) ||
                    postValueCase(serial, pv, pv_name, server1,true) ||
                    postValueCase(serial, pv, pv_name, client1,true)
                    )
                    ; // handled
                else
                    testFail("Unknown PV Accessed for Status Request: %s", pv_name.c_str());

                testDiag("Posted Value for request: %s", pv_name.c_str());
            });
            status_pv.onLastDisconnect([](server::WildcardPV &pv, const std::string &pv_name, const std::list<std::string> &) {
                testOk(1, "Closing Status Request Connection: %s", pv_name.c_str());
                pv.close(pv_name);
            });

            pvacms.start();

            testDiag("Set up: %s", "Mock PVACMS Server");

            testStatusRequest(cert_auth, client, cert_auth.cert.trusted_store.get());
            testStatusRequest(client1, client, client1.cert.trusted_store.get());
            testStatusRequest(server1, client, server1.cert.trusted_store.get());

            testDiag("Stop Mock PVACMS server");
            pvacms.stop();
        } catch (std::exception &e) {
            testFail("Failed to set up Mock PVACMS Server: %s", e.what());
        }
    }
};

}  // namespace

MAIN(testtlsstatus) {
    testPlan(111);

    // A certificate says who it is twice: in the subject key identifier extension, which whoever
    // made it simply wrote down, and in its public key, from which the same identifier can be
    // computed. Deciding whether an authority is the expected one has to use the second, or an
    // attacker substituting its own authority just writes the expected value into the first.
    {
        // A certificate carrying a subject key identifier extension that its key does not justify.
        ossl_ptr<EVP_PKEY> key(EVP_RSA_gen(2048), false);
        testOk(key.get() != nullptr, "Generated a key for the forged-identifier certificate");

        ossl_ptr<X509> forged(X509_new(), false);
        X509_set_version(forged.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(forged.get()), 1);
        X509_gmtime_adj(X509_getm_notBefore(forged.get()), 0);
        X509_gmtime_adj(X509_getm_notAfter(forged.get()), 3600);
        X509_set_pubkey(forged.get(), key.get());
        auto *name = X509_get_subject_name(forged.get());
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("impostor"), -1, -1, 0);
        X509_set_issuer_name(forged.get(), name);

        // Claim an identifier of our choosing, as an attacker would.
        const std::string claimed_hex = "0123456789abcdef0123456789abcdef01234567";
        std::vector<unsigned char> claimed_bytes;
        for (size_t i = 0; i + 1 < claimed_hex.size(); i += 2)
            claimed_bytes.push_back(static_cast<unsigned char>(std::stoi(claimed_hex.substr(i, 2), nullptr, 16)));
        ossl_ptr<ASN1_OCTET_STRING> claimed(ASN1_OCTET_STRING_new(), false);
        ASN1_OCTET_STRING_set(claimed.get(), claimed_bytes.data(), static_cast<int>(claimed_bytes.size()));
        X509_add1_ext_i2d(forged.get(), NID_subject_key_identifier, claimed.get(), 0, 0);
        X509_sign(forged.get(), key.get(), EVP_sha256());

        // What the certificate claims, and what its key actually gives.
        const std::string claimed_id = CertStatus::getSkId(forged.get());
        const std::string computed_id = CertStatus::getFullSkId(forged.get());
        testEq(claimed_id, claimed_hex.substr(0, 8));
        testOk(computed_id.compare(0, 8, claimed_id) != 0,
               "The key gives a different identifier (%s) from the one claimed (%s)",
               computed_id.substr(0, 8).c_str(), claimed_id.c_str());

        // Presented as the authority the caller committed to, it must be refused.
        ossl_shared_ptr<STACK_OF(X509)> no_chain;
        CertData delivered;
        delivered.cert = std::move(forged);
        delivered.cert_auth_chain = no_chain;
        testThrows<std::runtime_error>([&delivered, &claimed_hex] {
            verifyDeliveredIssuerId(delivered, claimed_hex.substr(0, 8));
        }) << "a certificate claiming an identifier its key does not give is refused";

        // Its own computed identifier is of course accepted.
        bool accepted = true;
        try {
            verifyDeliveredIssuerId(delivered, computed_id);
        } catch (...) {
            accepted = false;
        }
        testOk(accepted, "The identifier computed from the key is accepted");
    }

    // An honestly made certificate says the same thing both ways, so computing the identifier
    // rather than reading it changes nothing for anyone behaving properly. The certificate
    // factory writes the extension with OpenSSL's "hash", which is the same definition.
    {
        ossl_ptr<EVP_PKEY> key(EVP_RSA_gen(2048), false);
        ossl_ptr<X509> honest(X509_new(), false);
        X509_set_version(honest.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(honest.get()), 2);
        X509_gmtime_adj(X509_getm_notBefore(honest.get()), 0);
        X509_gmtime_adj(X509_getm_notAfter(honest.get()), 3600);
        X509_set_pubkey(honest.get(), key.get());
        auto *hname = X509_get_subject_name(honest.get());
        X509_NAME_add_entry_by_txt(hname, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("honest"), -1, -1, 0);
        X509_set_issuer_name(honest.get(), hname);

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, honest.get(), honest.get(), nullptr, nullptr, 0);
        ossl_ptr<X509_EXTENSION> ext(
            X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, const_cast<char *>("hash")), false);
        X509_add_ext(honest.get(), ext.get(), -1);
        X509_sign(honest.get(), key.get(), EVP_sha256());

        testEq(CertStatus::getSkId(honest.get()), CertStatus::getFullSkId(honest.get()).substr(0, 8));
    }

    // How much of the identifier is compared is how much the caller committed to.
    {
        const std::string full = "0123456789abcdef0123456789abcdef01234567";
        const std::string same_prefix_different_rest = "01234567ffffffffffffffffffffffffffffffff";
        testOk1(issuerIdIsExpected("01234567", full));
        testOk1(issuerIdIsExpected(full, full));
        testOk(issuerIdIsExpected("01234567", same_prefix_different_rest),
               "The published short form can only compare the digits it carries");
        testOk(!issuerIdIsExpected(full, same_prefix_different_rest),
               "Committing to the whole identifier catches a match on the first 8 digits alone");
        testOk(!issuerIdIsExpected("", full), "Committing to nothing matches nothing");
        testOk(!issuerIdIsExpected(full + "00", full), "More than the identifier holds cannot match");
        testOk(issuerIdIsExpected("0123ABCD", full.substr(0, 4) + "abcd" + full.substr(8)),
               "Compared without regard to case");
    }
    testSetup();
    logger_config_env();
    const auto tester = new Tester();
    tester->initialisation();
    tester->ocspPayload();
    tester->parse();
    tester->makeStatusResponses();
    tester->testStatusConversions();
    tester->makeStatusRequest();
    delete tester;
    cleanup_for_valgrind();
    return testDone();
}
