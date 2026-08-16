/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * What a certificate manager makes of the responder its trust anchor names.
 *
 * The responder here is part of the test rather than a separate program, and it is bound to a
 * port the operating system chooses on the loopback interface. Two things follow. Nothing is
 * reachable from off the machine, and nothing collides with another test, another job on the
 * same machine, or a demonstration laboratory the developer happens to have running - which
 * uses a fixed port and would otherwise be answered instead of this.
 *
 * The address goes inside the certificate, so the order is forced: bind first to learn the
 * port, then mint the root that names it.
 */

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#include <epicsUnitTest.h>
#include <osiSock.h>
#include <testMain.h>

#include <pvxs/log.h>
#include <pvxs/unittest.h>

#include "authoritymonitor.h"
#include "certstatus.h"
#include "ownedptr.h"

using namespace pvxs;
using cms::cert::AuthorityMonitor;
using pvxs::certs::cert_authority_standing_t;

namespace {

/** How long a test will wait for a poll to land before calling it a failure. */
constexpr auto answer_timeout = std::chrono::seconds(20);

/** What the responder tells a caller its answer is good for. Short, so a re-poll is not a wait. */
constexpr int seconds_answer_is_good_for = 2;

struct KeyAndCert {
    ossl_ptr<EVP_PKEY> key;
    ossl_ptr<X509> cert;
};

/** Generates a key of the size the rest of the certificate machinery uses. */
ossl_ptr<EVP_PKEY> generateKey() {
    const ossl_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (EVP_PKEY_keygen_init(ctx.get()) != 1) throw std::runtime_error("keygen_init");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) != 1) throw std::runtime_error("keygen_bits");
    ossl_ptr<EVP_PKEY> key;
    if (EVP_PKEY_keygen(ctx.get(), key.acquire()) != 1) throw std::runtime_error("keygen");
    return key;
}

void addExtension(X509* cert, const int nid, const char* value, X509* issuer) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer ? issuer : cert, cert, nullptr, nullptr, 0);
    const ossl_ptr<X509_EXTENSION> ext(X509V3_EXT_conf_nid(nullptr, &ctx, nid, value));
    if (X509_add_ext(cert, ext.get(), -1) != 1) throw std::runtime_error("X509_add_ext");
}

/**
 * @brief Mints a certificate, self-signed when no issuer is given.
 *
 * @param common_name the name the certificate carries
 * @param serial its serial number, which is what a responder is asked about
 * @param is_authority whether it may issue
 * @param responder_uri the responder that publishes this certificate's own revocation, or empty
 * @param extended_use an extended key usage, or null
 * @param issuer the certificate that signs this one, or null for self-signed
 */
KeyAndCert mint(const char* common_name, const uint64_t serial, const bool is_authority,
                const std::string& responder_uri, const char* extended_use, const KeyAndCert* issuer) {
    KeyAndCert made;
    made.key = generateKey();
    made.cert = ossl_ptr<X509>(X509_new());

    X509* const cert = made.cert.get();
    X509_set_version(cert, 2);
    X509_set_pubkey(cert, made.key.get());

    X509_NAME* const subject = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0);

    X509* const issuer_cert = issuer ? issuer->cert.get() : cert;
    EVP_PKEY* const issuer_key = issuer ? issuer->key.get() : made.key.get();
    X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert));

    const ossl_ptr<ASN1_INTEGER> serial_number(ASN1_INTEGER_new());
    ASN1_INTEGER_set_uint64(serial_number.get(), serial);
    X509_set_serialNumber(cert, serial_number.get());

    const time_t now = time(nullptr);
    const ossl_ptr<ASN1_TIME> not_before(ASN1_TIME_new());
    const ossl_ptr<ASN1_TIME> not_after(ASN1_TIME_new());
    ASN1_TIME_set(not_before.get(), now - 3600);
    ASN1_TIME_set(not_after.get(), now + 365 * 24 * 3600);
    X509_set1_notBefore(cert, not_before.get());
    X509_set1_notAfter(cert, not_after.get());

    addExtension(cert, NID_subject_key_identifier, "hash", issuer_cert);
    addExtension(cert, NID_basic_constraints, is_authority ? "critical,CA:TRUE" : "CA:FALSE", issuer_cert);
    if (is_authority) addExtension(cert, NID_key_usage, "critical,keyCertSign,cRLSign", issuer_cert);
    if (extended_use) addExtension(cert, NID_ext_key_usage, extended_use, issuer_cert);
    if (!responder_uri.empty()) {
        addExtension(cert, NID_info_access, ("OCSP;URI:" + responder_uri).c_str(), issuer_cert);
    }

    if (X509_sign(cert, issuer_key, EVP_sha256()) == 0) throw std::runtime_error("X509_sign");
    return made;
}

/**
 * @brief A responder that answers about one certificate, on a port the operating system chose.
 *
 * It signs with a certificate the anchor authorised for the purpose, which is what a facility
 * does and what the demonstration laboratory does, so the delegated signature is covered rather
 * than the simpler case of an anchor answering for itself.
 *
 * The answer it gives can be changed between polls, and it can be silenced altogether, which is
 * a different thing from answering that the anchor is revoked.
 */
class Responder {
   public:
    /** Binds, so the port is known before anything is minted to name it. */
    Responder() : socket_(epicsSocketCreate(AF_INET, SOCK_STREAM, 0)) {
        if (socket_ == INVALID_SOCKET) throw std::runtime_error("cannot make a socket");

        osiSockAddr address;
        memset(&address, 0, sizeof(address));
        address.ia.sin_family = AF_INET;
        address.ia.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.ia.sin_port = 0;  // the operating system chooses, so nothing collides
        if (bind(socket_, &address.sa, sizeof(address.ia)) != 0) throw std::runtime_error("cannot bind");

        osiSocklen_t length = sizeof(address.ia);
        if (getsockname(socket_, &address.sa, &length) != 0) throw std::runtime_error("cannot read the port");
        port_ = ntohs(address.ia.sin_port);

        if (listen(socket_, 4) != 0) throw std::runtime_error("cannot listen");
    }

    ~Responder() {
        stop();
        if (socket_ != INVALID_SOCKET) epicsSocketDestroy(socket_);
    }

    /** The address to write into the certificate that names this responder. */
    std::string uri() const { return "http://127.0.0.1:" + std::to_string(port_); }

    /** Who it answers about, and what it signs with. */
    void answersFor(X509* subject, X509* issuer, X509* signer, EVP_PKEY* signer_key) {
        subject_ = subject;
        issuer_ = issuer;
        signer_ = signer;
        signer_key_ = signer_key;
    }

    /** V_OCSP_CERTSTATUS_GOOD, _REVOKED or _UNKNOWN. */
    void answer(const int status) { answer_.store(status); }

    /**
     * @brief Drops the next `n` callers without answering, then answers as usual.
     *
     * What a single-threaded responder does to a second caller while it is busy with the
     * first, which is routine where more than one service polls the same responder.
     */
    void dropFirst(const int n) { drop_remaining_.store(n); }

    void start() {
        running_.store(true);
        worker_ = std::thread([this] { serve(); });
    }

    /** Stops answering without changing what the answer would have been. */
    void stop() {
        if (!worker_.joinable()) return;
        running_.store(false);
        worker_.join();
    }

    /**
     * @brief Takes the responder away entirely, so connections are refused.
     *
     * This is what stopping the service does. It is a different thing from a responder that
     * accepts a connection and then says nothing, which is what `stop()` alone leaves behind:
     * the address is still listening, so the caller is accepted and then left waiting.
     */
    void goAway() {
        stop();
        if (socket_ != INVALID_SOCKET) {
            epicsSocketDestroy(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

   private:
    void serve() {
        while (running_.load()) {
            // A short wait rather than a blocking accept, so stopping does not depend on a
            // connection arriving to unblock it.
            fd_set waiting;
            FD_ZERO(&waiting);
            FD_SET(socket_, &waiting);
            timeval patience{0, 50000};
            if (select(static_cast<int>(socket_) + 1, &waiting, nullptr, nullptr, &patience) <= 0) continue;

            const SOCKET caller = accept(socket_, nullptr, nullptr);
            if (caller == INVALID_SOCKET) continue;
            if (drop_remaining_.load() > 0) {
                drop_remaining_--;
                epicsSocketDestroy(caller);
                continue;
            }
            try {
                answerOne(caller);
            } catch (...) {
                // A caller that goes away mid-question is not this test's concern.
            }
            epicsSocketDestroy(caller);
        }
    }

    void answerOne(const SOCKET caller) {
        // Read the request. The body is what matters, and the client states its length.
        std::string received;
        char buffer[4096];
        size_t body_wanted = 0;
        size_t header_end = std::string::npos;
        while (true) {
            const int got = recv(caller, buffer, sizeof(buffer), 0);
            if (got <= 0) return;
            received.append(buffer, static_cast<size_t>(got));
            if (header_end == std::string::npos) {
                header_end = received.find("\r\n\r\n");
                if (header_end == std::string::npos) continue;
                const auto marker = received.find("Content-Length:");
                if (marker == std::string::npos) return;
                body_wanted = static_cast<size_t>(std::stoul(received.substr(marker + 15)));
                header_end += 4;
            }
            if (received.size() >= header_end + body_wanted) break;
        }

        const auto* body = reinterpret_cast<const unsigned char*>(received.data() + header_end);
        const ossl_ptr<OCSP_REQUEST> request(d2i_OCSP_REQUEST(nullptr, &body, static_cast<long>(body_wanted)), false);
        if (!request) return;

        // Answer about the certificate we were told to answer about, naming it the way the
        // caller does so the reply matches the question.
        const ossl_ptr<OCSP_BASICRESP> basic(OCSP_BASICRESP_new());
        const ossl_ptr<OCSP_CERTID> id(OCSP_cert_to_id(nullptr, subject_, issuer_));

        const time_t now = time(nullptr);
        const ossl_ptr<ASN1_TIME> this_update(ASN1_TIME_adj(nullptr, now, 0, 0));
        const ossl_ptr<ASN1_TIME> next_update(ASN1_TIME_adj(nullptr, now + seconds_answer_is_good_for, 0, 0));
        const ossl_ptr<ASN1_TIME> revoked_at(ASN1_TIME_adj(nullptr, now - 60, 0, 0));

        const int status = answer_.load();
        OCSP_basic_add1_status(basic.get(), id.get(), status, 0,
                               status == V_OCSP_CERTSTATUS_REVOKED ? revoked_at.get() : nullptr,
                               this_update.get(), next_update.get());
        OCSP_basic_add1_cert(basic.get(), signer_);
        OCSP_basic_sign(basic.get(), signer_, signer_key_, EVP_sha256(), nullptr, 0);

        const ossl_ptr<OCSP_RESPONSE> response(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get()));
        unsigned char* encoded = nullptr;
        const int encoded_length = i2d_OCSP_RESPONSE(response.get(), &encoded);
        if (encoded_length <= 0) return;

        std::string reply = "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: " +
                            std::to_string(encoded_length) + "\r\n\r\n";
        reply.append(reinterpret_cast<const char*>(encoded), static_cast<size_t>(encoded_length));
        OPENSSL_free(encoded);

        size_t sent = 0;
        while (sent < reply.size()) {
            const int wrote = send(caller, reply.data() + sent, static_cast<int>(reply.size() - sent), 0);
            if (wrote <= 0) return;
            sent += static_cast<size_t>(wrote);
        }
    }

    SOCKET socket_{INVALID_SOCKET};
    unsigned short port_{0};
    X509* subject_{nullptr};
    X509* issuer_{nullptr};
    X509* signer_{nullptr};
    EVP_PKEY* signer_key_{nullptr};
    std::atomic<int> answer_{V_OCSP_CERTSTATUS_GOOD};
    std::atomic<int> drop_remaining_{0};
    std::atomic<bool> running_{false};
    std::thread worker_;
};

/** Waits for the monitor to reach a standing, so a test states what it wants rather than a delay. */
bool reaches(const AuthorityMonitor& monitor, const cert_authority_standing_t wanted) {
    const auto give_up_at = std::chrono::steady_clock::now() + answer_timeout;
    while (std::chrono::steady_clock::now() < give_up_at) {
        if (monitor.standing() == wanted) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

/** As above, but within a stated time, for a test that is about how long something takes. */
bool reachesWithin(const AuthorityMonitor& monitor, const cert_authority_standing_t wanted,
                   const std::chrono::seconds patience) {
    const auto give_up_at = std::chrono::steady_clock::now() + patience;
    while (std::chrono::steady_clock::now() < give_up_at) {
        if (monitor.standing() == wanted) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

/** Waits for a standing to be established at all, whatever it turns out to be. */
bool settles(const AuthorityMonitor& monitor) { return reaches(monitor, cert_authority_standing_t::STANDING); }

const char* nameOf(const cert_authority_standing_t standing) {
    switch (standing) {
        case cert_authority_standing_t::STANDING: return "STANDING";
        case cert_authority_standing_t::REVOKED: return "REVOKED";
        default: return "UNKNOWN";
    }
}

/** The anchor, the responder that answers for it, and the signer it authorised. */
struct Laboratory {
    Responder responder;
    KeyAndCert root;
    KeyAndCert signer;

    Laboratory() {
        // The address is inside the certificate, so the port has to exist before the root does.
        root = mint("Test Facility Root", 1, true, responder.uri(), nullptr, nullptr);
        signer = mint("Test Facility Root OCSP Responder", 2, false, "", "OCSPSigning", &root);
        responder.answersFor(root.cert.get(), root.cert.get(), signer.cert.get(), signer.key.get());
    }
};

void testAnchorStands() {
    testDiag("== an anchor whose responder says it stands");
    Laboratory lab;
    lab.responder.answer(V_OCSP_CERTSTATUS_GOOD);
    lab.responder.start();

    AuthorityMonitor monitor(lab.root.cert.get(), false);
    testOk(monitor.isActive(), "the responder named by the anchor is watched: %s", monitor.responderUri().c_str());
    monitor.start();

    testOk(reaches(monitor, cert_authority_standing_t::STANDING), "the anchor stands, on a delegated signature");
}

void testAnchorRevoked() {
    testDiag("== an anchor whose responder says it has been revoked");
    Laboratory lab;
    lab.responder.answer(V_OCSP_CERTSTATUS_REVOKED);
    lab.responder.start();

    AuthorityMonitor monitor(lab.root.cert.get(), false);
    monitor.start();

    testOk(reaches(monitor, cert_authority_standing_t::REVOKED), "the anchor is reported revoked");
}

void testResponderSaysUnknown() {
    testDiag("== a responder that will not say");
    Laboratory lab;
    lab.responder.answer(V_OCSP_CERTSTATUS_UNKNOWN);
    lab.responder.start();

    AuthorityMonitor monitor(lab.root.cert.get(), false);
    monitor.start();

    testOk(reaches(monitor, cert_authority_standing_t::UNKNOWN), "a responder that will not say leaves it unknown");
}

void testResponderUnreachable() {
    testDiag("== a responder that cannot be reached");
    Laboratory lab;
    lab.responder.goAway();  // as stopping the service does: the address refuses

    AuthorityMonitor monitor(lab.root.cert.get(), false);
    monitor.start();

    testOk(reaches(monitor, cert_authority_standing_t::UNKNOWN),
           "an unreachable responder leaves the standing unknown, which denies connections");
}

void testBusyResponderAskedAgain() {
    testDiag("== a responder busy with somebody else when it is first called");
    Laboratory lab;
    lab.responder.answer(V_OCSP_CERTSTATUS_GOOD);
    // Fewer drops than one poll has attempts, so the answer must come from that same poll.
    lab.responder.dropFirst(4);
    lab.responder.start();

    AuthorityMonitor monitor(lab.root.cert.get(), false);
    monitor.start();

    // Well inside the wait before a failed poll would be tried again, so only asking again
    // within the one poll can satisfy this. A single dropped call must not be allowed to
    // report the authority unknown and stop every connection the service underwrites.
    testOk(reachesWithin(monitor, cert_authority_standing_t::STANDING, std::chrono::seconds(5)),
           "a responder that drops the first calls is asked again, and the standing is established");
}

void testResponderAcceptsAndSaysNothing() {
    testDiag("== a responder that takes the call and then says nothing");
    Laboratory lab;
    // Bound and listening, but nothing is accepting, so the caller is connected and then left.
    // Without a bound on the exchange this never returns: the standing would freeze wherever it
    // was and the service could not shut down, because stopping waits for the poll in flight.

    AuthorityMonitor monitor(lab.root.cert.get(), false);
    monitor.start();

    testOk(reaches(monitor, cert_authority_standing_t::UNKNOWN),
           "a silent responder is given up on, and counts as not knowing");
}

void testLastAnswerHeld() {
    testDiag("== a responder that goes away, where the site would rather keep the last answer");
    Laboratory lab;
    lab.responder.answer(V_OCSP_CERTSTATUS_GOOD);
    lab.responder.start();

    AuthorityMonitor monitor(lab.root.cert.get(), true);
    monitor.start();
    if (!settles(monitor)) {
        testFail("the anchor was never established as standing, so there is nothing to hold");
        testSkip(1, "no answer to hold");
        return;
    }

    lab.responder.goAway();

    // Long enough for a second poll to have been made and failed. The responder says its answer
    // is good for two seconds, but the monitor will not ask more often than every ten, and a
    // refused connection fails at once.
    std::this_thread::sleep_for(std::chrono::seconds(12));
    testOk(monitor.standing() == cert_authority_standing_t::STANDING,
           "the last verified answer is kept: %s", nameOf(monitor.standing()));
}

void testAnchorNamesNoResponder() {
    testDiag("== an anchor that names no responder");
    const auto root = mint("Test Facility Root", 1, true, "", nullptr, nullptr);

    AuthorityMonitor monitor(root.cert.get(), false);
    testOk(!monitor.isActive(), "an anchor naming no responder is not watched");

    monitor.start();  // does nothing, and must not be an error
    testPass("a manager under such an anchor starts as it did before");
}

void testAnchorNotSelfSigned() {
    testDiag("== something at the top of the chain that is not a trust anchor");
    Responder responder;
    const auto root = mint("Test Facility Root", 1, true, "", nullptr, nullptr);
    // Names a responder, but is issued by something else, so no answer about it could be trusted.
    const auto intermediate = mint("Test Intermediate", 2, true, responder.uri(), nullptr, &root);

    const AuthorityMonitor monitor(intermediate.cert.get(), false);
    testOk(!monitor.isActive(), "a certificate that is not self-signed is not watched");
}

}  // namespace

MAIN(testauthoritystatus) {
    testPlan(11);
    logger_config_env();

    try {
        testAnchorStands();
        testAnchorRevoked();
        testResponderSaysUnknown();
        testResponderUnreachable();
        testBusyResponderAskedAgain();
        testResponderAcceptsAndSaysNothing();
        testLastAnswerHeld();
        testAnchorNamesNoResponder();
        testAnchorNotSelfSigned();
    } catch (std::exception& e) {
        testAbort("Unexpected exception: %s", e.what());
    }

    return testDone();
}
