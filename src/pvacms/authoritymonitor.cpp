/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authoritymonitor.h"

#include <chrono>
#include <memory>
#include <thread>

#include <osiSock.h>

#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#include <pvxs/log.h>

#include "certstatusmanager.h"

DEFINE_LOGGER(authmonitor, "cms.certs.status.authority");

namespace cms {
namespace cert {

namespace {

/**
 * How long to wait before asking again when the responder could not be reached.
 *
 * Short, because a responder that did not answer has said nothing about when it will have
 * something to say, and because the alternative to asking again is to keep denying
 * connections. It is also what covers a responder that starts a moment after this service.
 */
constexpr time_t retry_after_failure_secs = 15;

/** Bound on the wait, so that a responder promising a distant next update is still re-checked. */
constexpr time_t longest_wait_secs = 60 * 60;

/** Shortest wait, so that a responder promising an immediate next update is not asked in a spin. */
constexpr time_t shortest_wait_secs = 10;

/**
 * How long one exchange with the responder may take, from connecting to a complete answer.
 *
 * A responder that accepts a connection and then says nothing would otherwise hold this thread
 * for as long as it cared to, which would freeze the authority's standing at whatever was last
 * established and leave the service unable to shut down, since stopping waits for the poll in
 * flight. The transfer is bounded so that a silent responder is simply a responder that did not
 * answer, which is a case already handled.
 */
constexpr auto responder_patience = std::chrono::seconds(10);

/**
 * How many times one poll asks before concluding that the responder could not be reached.
 *
 * A responder is often a single-threaded program - openssl's own is - so a service that is
 * already answering somebody else refuses or drops the next caller. That is a busy responder,
 * not an unreachable one, and the two are worth telling apart: reporting the standing as
 * unknown stops every connection the service underwrites, which is far too much to conclude
 * from one refused connection. A facility with two certificate managers polling the same
 * responder makes this collision routinely.
 *
 * The attempts share the one deadline above, so a poll still takes no longer than it did and
 * shutting down still waits no longer. That also settles what to retry and what not to: a
 * refusal costs almost nothing and leaves room for several more, while a responder that
 * accepts the call and then says nothing consumes the deadline on its own and is asked once,
 * which is right - it was reached, and it said nothing.
 */
constexpr int attempts_per_poll = 5;

/** A pause between attempts, so a busy responder is given a moment rather than hammered. */
constexpr auto pause_between_attempts = std::chrono::milliseconds(250);

using request_ctx_ptr = std::unique_ptr<OCSP_REQ_CTX, decltype(&OCSP_REQ_CTX_free)>;

using pvxs::certs::cert_authority_standing_t;

using aia_ptr = std::unique_ptr<AUTHORITY_INFO_ACCESS, decltype(&AUTHORITY_INFO_ACCESS_free)>;

/**
 * @brief Waits until the exchange with the responder can go further, or the deadline passes.
 *
 * @param bio the connection, which states whether it is waiting to read or to write
 * @param deadline when to give up
 * @return whether the exchange may continue
 */
bool waitForProgress(BIO *bio, const std::chrono::steady_clock::time_point deadline) {
    int fd = -1;
    if (BIO_get_fd(bio, &fd) < 0 || fd < 0) return false;

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return false;
    const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now).count();

    timeval patience;
    patience.tv_sec = static_cast<decltype(patience.tv_sec)>(remaining / 1000000);
    patience.tv_usec = static_cast<decltype(patience.tv_usec)>(remaining % 1000000);

    fd_set readable, writable;
    FD_ZERO(&readable);
    FD_ZERO(&writable);
    // Before a connection is made neither is stated, so watch for either.
    const bool wants_read = BIO_should_read(bio) != 0;
    const bool wants_write = BIO_should_write(bio) != 0;
    if (wants_read || !wants_write) FD_SET(fd, &readable);
    if (wants_write || !wants_read) FD_SET(fd, &writable);

    return select(fd + 1, &readable, &writable, nullptr, &patience) > 0;
}

/**
 * @brief Reads the first responder address out of a certificate's Authority Information Access
 * extension.
 *
 * The extension may also name the addresses at which the issuer's own certificate can be
 * fetched; those entries are passed over. The first responder entry wins, which is the common
 * reading of a list whose entries are alternatives.
 *
 * @param cert the certificate to read
 * @return the responder address, or an empty string when the certificate names none
 */
std::string responderUriOf(X509 *cert) {
    const aia_ptr aia(static_cast<AUTHORITY_INFO_ACCESS *>(X509_get_ext_d2i(cert, NID_info_access, nullptr, nullptr)),
                      &AUTHORITY_INFO_ACCESS_free);
    if (!aia) return {};

    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia.get()); ++i) {
        const ACCESS_DESCRIPTION *entry = sk_ACCESS_DESCRIPTION_value(aia.get(), i);
        if (OBJ_obj2nid(entry->method) != NID_ad_OCSP) continue;
        if (entry->location->type != GEN_URI) continue;
        const ASN1_IA5STRING *uri = entry->location->d.uniformResourceIdentifier;
        return {reinterpret_cast<const char *>(ASN1_STRING_get0_data(uri)),
                static_cast<size_t>(ASN1_STRING_length(uri))};
    }
    return {};
}

/**
 * @brief Asks the responder once, and hands back what it said.
 *
 * Everything that can go wrong between here and an answer in hand is thrown, so that the
 * caller can decide whether to ask again. A reply that arrives and cannot be believed is not
 * thrown from here: that is an answer, and asking again would only be told the same thing.
 *
 * @param host_port where the responder is
 * @param request_path the path it answers on
 * @param request what to ask
 * @param deadline when to give up, shared by every attempt in one poll
 * @return the responder's reply, still to be verified
 */
pvxs::ossl_ptr<OCSP_RESPONSE> askOnce(const std::string &host_port, const std::string &request_path,
                                      OCSP_REQUEST *request, const std::chrono::steady_clock::time_point deadline) {
    const pvxs::ossl_ptr<BIO> connection(BIO_new_connect(host_port.c_str()));
    if (!connection) throw std::runtime_error("cannot make a connection");
    BIO_set_nbio(connection.get(), 1);
    while (BIO_do_connect(connection.get()) <= 0) {
        if (!BIO_should_retry(connection.get()) || !waitForProgress(connection.get(), deadline)) {
            throw std::runtime_error(pvxs::SB() << "cannot reach the responder at " << host_port);
        }
    }

    OCSP_RESPONSE *answer = nullptr;
    const request_ctx_ptr exchange(OCSP_sendreq_new(connection.get(), request_path.c_str(), request, -1),
                                   &OCSP_REQ_CTX_free);
    if (!exchange) throw std::runtime_error("cannot begin asking");
    while (OCSP_sendreq_nbio(&answer, exchange.get()) == -1) {
        if (!waitForProgress(connection.get(), deadline)) {
            throw std::runtime_error(pvxs::SB() << "the responder at " << host_port << " did not answer in time");
        }
    }

    pvxs::ossl_ptr<OCSP_RESPONSE> response(answer, false);
    if (!response) throw std::runtime_error("the responder gave no answer");
    return response;
}

}  // namespace

AuthorityMonitor::AuthorityMonitor(X509 *trust_anchor, const bool hold_last_known)
    : responder_uri_(responderUriOf(trust_anchor)), hold_last_known_(hold_last_known) {
    if (responder_uri_.empty()) return;

    // A responder's answer about an anchor is signed by the anchor's issuer. A trust anchor is
    // its own issuer, which is what lets it be asked about at all. Anything else at the top of
    // the chain is not an anchor, and this service has no way to trust an answer about it.
    if (X509_NAME_cmp(X509_get_subject_name(trust_anchor), X509_get_issuer_name(trust_anchor)) != 0) {
        log_warn_printf(authmonitor,
                        "Authority status: %s names a responder but is not self-signed; not watching\n",
                        responder_uri_.c_str());
        responder_uri_.clear();
        return;
    }

    // Keep our own reference: the certificate is read from the polling thread and should not
    // depend on the caller's copy staying put.
    X509_up_ref(trust_anchor);
    cert_ = pvxs::ossl_ptr<X509>(trust_anchor);

    // The anchor is the only certificate that can have signed a trustworthy answer about itself.
    trusted_store_ = pvxs::ossl_ptr<X509_STORE>(X509_STORE_new());
    X509_STORE_add_cert(trusted_store_.get(), cert_.get());
}

AuthorityMonitor::~AuthorityMonitor() { stop(); }

void AuthorityMonitor::start() {
    if (!isActive() || worker_.joinable()) return;
    log_info_printf(authmonitor, "Authority status: watching %s\n", responder_uri_.c_str());
    worker_ = std::thread([this] { run(); });
}

void AuthorityMonitor::stop() {
    if (!worker_.joinable()) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_.store(true, std::memory_order_release);
    }
    wakeup_.notify_all();
    worker_.join();
}

void AuthorityMonitor::run() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stopping_.load(std::memory_order_acquire)) {
        time_t next_update;
        {
            // The question is asked without the lock held: it is network input and output with a
            // service that may be slow, and stop() must not wait on it to be answered.
            lock.unlock();
            next_update = pollOnce();
            lock.lock();
        }
        if (stopping_.load(std::memory_order_acquire)) break;

        time_t wait_secs = retry_after_failure_secs;
        if (next_update > 0) {
            const time_t now = time(nullptr);
            wait_secs = next_update > now ? next_update - now : shortest_wait_secs;
        }
        if (wait_secs < shortest_wait_secs) wait_secs = shortest_wait_secs;
        if (wait_secs > longest_wait_secs) wait_secs = longest_wait_secs;

        wakeup_.wait_for(lock, std::chrono::seconds(wait_secs), [this] { return stopping_.load(std::memory_order_acquire); });
    }
}

time_t AuthorityMonitor::pollOnce() {
    char *host = nullptr, *port = nullptr, *path = nullptr;
    int use_ssl = 0;
    if (!OCSP_parse_url(responder_uri_.c_str(), &host, &port, &path, &use_ssl)) {
        log_err_printf(authmonitor, "Authority status: cannot read responder address %s\n", responder_uri_.c_str());
        if (!hold_last_known_) standing_.store(cert_authority_standing_t::UNKNOWN, std::memory_order_release);
        return 0;
    }
    // OCSP_parse_url hands back three separately allocated strings; free them however we leave.
    const std::string host_port = std::string(host) + ":" + port;
    const std::string request_path = path;
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);

    const cert_authority_standing_t previous = standing();
    try {
        if (use_ssl) throw std::runtime_error("responder address names a protocol we do not speak");

        // Ask about the anchor. A self-signed anchor is its own issuer, which is what names it
        // to the responder.
        const pvxs::ossl_ptr<OCSP_REQUEST> request(OCSP_REQUEST_new());
        OCSP_CERTID *cert_id = OCSP_cert_to_id(nullptr, cert_.get(), cert_.get());
        if (!cert_id) throw std::runtime_error("cannot name the trust anchor to the responder");
        if (!OCSP_request_add0_id(request.get(), cert_id)) {
            OCSP_CERTID_free(cert_id);
            throw std::runtime_error("cannot assemble the request");
        }

        const auto deadline = std::chrono::steady_clock::now() + responder_patience;

        pvxs::ossl_ptr<OCSP_RESPONSE> response;
        for (int attempt = 1;; ++attempt) {
            try {
                response = askOnce(host_port, request_path, request.get(), deadline);
                if (attempt > 1) {
                    log_debug_printf(authmonitor, "Authority status: answered on attempt %d\n", attempt);
                }
                break;
            } catch (const std::exception &e) {
                // Out of attempts, out of time, or on the way down: the caller reports it.
                if (attempt >= attempts_per_poll || stopping_.load(std::memory_order_acquire) ||
                    std::chrono::steady_clock::now() >= deadline) {
                    throw;
                }
                log_debug_printf(authmonitor, "Authority status: %s; asking again (%d of %d)\n", e.what(), attempt + 1,
                                 attempts_per_poll);
                std::this_thread::sleep_for(pause_between_attempts);
            }
        }

        // The same decode, signature check and freshness check the service already applies to
        // every status it receives.
        const auto parsed = pvxs::certs::CmsStatusManager::parse(response, trusted_store_.get());

        const auto reported = parsed.ocsp_status == pvxs::certs::OCSP_CERTSTATUS_REVOKED ? cert_authority_standing_t::REVOKED
                              : parsed.ocsp_status == pvxs::certs::OCSP_CERTSTATUS_GOOD  ? cert_authority_standing_t::STANDING
                                                                                         : cert_authority_standing_t::UNKNOWN;
        standing_.store(reported, std::memory_order_release);

        if (reported != previous) {
            log_warn_printf(authmonitor, "Authority status: the facility root %s\n",
                            reported == cert_authority_standing_t::REVOKED ? "has been revoked"
                            : reported == cert_authority_standing_t::STANDING ? "stands"
                                                                             : "cannot be established");
        }
        return parsed.status_valid_until_date.t;
    } catch (const std::exception &e) {
        if (hold_last_known_) {
            log_warn_printf(authmonitor, "Authority status: %s; holding the last answer\n", e.what());
        } else {
            standing_.store(cert_authority_standing_t::UNKNOWN, std::memory_order_release);
            if (previous != cert_authority_standing_t::UNKNOWN) {
                log_warn_printf(authmonitor, "Authority status: %s; now UNKNOWN\n", e.what());
            } else {
                log_debug_printf(authmonitor, "Authority status: %s\n", e.what());
            }
        }
        return 0;
    }
}

}  // namespace cert
}  // namespace cms
