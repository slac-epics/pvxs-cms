/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "ocspstatusmonitor.h"

#include <chrono>
#include <memory>
#include <thread>

#include <epicsThread.h>
#include <osiSock.h>

// select() and the descriptor sets it works on. osiSock.h reaches these on this platform by
// way of <sys/types.h>, but only because the feature macros this build happens to set make
// glibc declare them there; POSIX puts them here, and elsewhere they are not reached at all.
// Windows gets them from winsock, which osiSock.h already brings in.
#ifndef _WIN32
#  include <sys/select.h>
#endif

#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#include <pvxs/log.h>

#include "certstatusmanager.h"

DEFINE_LOGGER(ocspmonitor, "cms.certs.status.ocsp");

namespace cms {
namespace cert {

namespace {

/**
 * How soon to ask again when a poll came back with nothing.
 *
 * Short, because nothing was learned and the answer already held is running down. It is also
 * what covers a responder that starts a moment after this service.
 */
constexpr time_t retry_after_failure_secs = 15;

/** Bound on the wait, so that a responder promising a distant next update is still re-checked. */
constexpr time_t longest_wait_secs = 60 * 60;

/**
 * Shortest wait, so that a responder promising an immediate next update is not asked in a spin.
 *
 * A second, because this is a floor: how often to ask follows from how long an answer lasts.
 */
constexpr time_t shortest_wait_secs = 1;

/**
 * What fraction of an answer's life to wait before asking for the next one.
 *
 * Asking at the moment one runs out leaves a single attempt between a busy responder
 * and a facility that stops. Asking at a third of the way leaves two spare attempts, and each
 * one that comes back with nothing costs nothing at all, because the answer already held is
 * still good. That is what replaces retrying: not asking harder, but asking sooner.
 */
constexpr int ask_again_after_fraction = 3;

/**
 * How long one exchange with the responder may take, from connecting to a complete answer.
 *
 * Stopping the service waits for a poll in flight, so one exchange is bounded.
 */
constexpr auto responder_patience = std::chrono::seconds(10);

using pvxs::certs::ocspcertstatus_t;

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
    const pvxs::ossl_ptr<AUTHORITY_INFO_ACCESS> aia(
        static_cast<AUTHORITY_INFO_ACCESS *>(X509_get_ext_d2i(cert, NID_info_access, nullptr, nullptr)), false);
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
 * thrown from here: that is an answer.
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
    const pvxs::ossl_ptr<OCSP_REQ_CTX> exchange(OCSP_sendreq_new(connection.get(), request_path.c_str(), request, -1));
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

OcspStatusMonitor::OcspStatusMonitor(X509 *trust_anchor, const bool hold_last_known)
    : responder_uri_(responderUriOf(trust_anchor)), hold_last_known_(hold_last_known) {
    if (responder_uri_.empty()) return;

    // A responder's answer about an anchor is signed by the anchor's issuer. A trust anchor is
    // its own issuer, which is what lets it be asked about at all. Anything else at the top of
    // the chain is not an anchor, and this service has no way to trust an answer about it.
    if (X509_NAME_cmp(X509_get_subject_name(trust_anchor), X509_get_issuer_name(trust_anchor)) != 0) {
        log_warn_printf(ocspmonitor,
                        "OCSP status: %s names a responder but is not self-signed; not watching\n",
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

    // Its own loop, on a named EPICS thread, and made only for an anchor worth watching so an
    // inactive monitor costs no thread at all. Asking is network input and output and must not
    // run on the server's loop, which is answering process variables.
    poll_loop_ = pvxs::impl::evbase("PVACMSAUTH", epicsThreadPriorityCAServerLow - 2);
    poll_timer_ = pvxs::impl::evevent(__FILE__, __LINE__,
                                      event_new(poll_loop_.base, -1, EV_TIMEOUT, &OcspStatusMonitor::pollTimer, this));
}

OcspStatusMonitor::~OcspStatusMonitor() { stop(); }

void OcspStatusMonitor::start() {
    if (!isActive() || !poll_timer_) return;
    log_info_printf(ocspmonitor, "OCSP status: watching %s\n", responder_uri_.c_str());
    // Ask at once, then on whatever schedule each answer sets.
    static constexpr timeval immediately{0, 0};
    if (event_add(poll_timer_.get(), &immediately)) {
        log_err_printf(ocspmonitor, "OCSP status: cannot start watching %s\n", responder_uri_.c_str());
    }
}

void OcspStatusMonitor::stop() {
    if (!poll_timer_) return;
    // On the loop's own thread, so it cannot race a poll that is being armed.
    poll_loop_.call([this]() { event_del(poll_timer_.get()); });
}

void OcspStatusMonitor::pollTimer(evutil_socket_t, short, void *raw) {
    auto self = static_cast<OcspStatusMonitor *>(raw);
    time_t wait_secs = retry_after_failure_secs;
    try {
        self->poll();
        wait_secs = self->askAgainIn();
    } catch (const std::exception &e) {
        // Sooner than the usual retry when the answer in hand is close to running out, so the
        // attempts that remain are spent before it does rather than after.
        const time_t before_it_lapses = self->askAgainIn();
        if (before_it_lapses < wait_secs) wait_secs = before_it_lapses;
        // Nothing is recorded: the answer already held goes on being the answer until it runs
        // out, and this is simply one of the attempts there were before that happens.
        log_debug_printf(ocspmonitor, "OCSP status: %s\n", e.what());
    }
    if (wait_secs < shortest_wait_secs) wait_secs = shortest_wait_secs;
    if (wait_secs > longest_wait_secs) wait_secs = longest_wait_secs;

    const timeval next{static_cast<decltype(timeval::tv_sec)>(wait_secs), 0};
    if (event_add(self->poll_timer_.get(), &next)) {
        log_err_printf(ocspmonitor, "OCSP status: cannot arrange to ask again%s\n", "");
    }
}

time_t OcspStatusMonitor::askAgainIn() const {
    const time_t valid_until = answer_valid_until_.load(std::memory_order_acquire);
    const time_t now = time(nullptr);
    // A share of what is left, so there are attempts in hand before it runs out.
    return valid_until > now ? (valid_until - now) / ask_again_after_fraction : 0;
}

void OcspStatusMonitor::poll() {
    // OCSP_parse_url hands back three separately allocated strings; owning them means they go
    // back however this leaves, including by the throw below.
    pvxs::ossl_ptr<char> host, port, path;
    int use_ssl = 0;
    if (!OCSP_parse_url(responder_uri_.c_str(), host.acquire(), port.acquire(), path.acquire(), &use_ssl)) {
        throw std::runtime_error(pvxs::SB() << "cannot read responder address " << responder_uri_);
    }
    const std::string host_port = std::string(host.get()) + ":" + port.get();
    const std::string request_path = path.get();

    if (use_ssl) throw std::runtime_error("responder address names a protocol we do not speak");

    // Ask about the anchor. A self-signed anchor is its own issuer, which is what names it
    // to the responder.
    const pvxs::ossl_ptr<OCSP_REQUEST> request(OCSP_REQUEST_new());
    pvxs::ossl_ptr<OCSP_CERTID> cert_id(OCSP_cert_to_id(nullptr, cert_.get(), cert_.get()));
    if (!cert_id) throw std::runtime_error("cannot name the trust anchor to the responder");
    // add0 takes it on success and leaves it ours on failure, so it is released only once the
    // request has actually taken it.
    if (!OCSP_request_add0_id(request.get(), cert_id.get())) {
        throw std::runtime_error("cannot assemble the request");
    }
    cert_id.release();

    const auto deadline = std::chrono::steady_clock::now() + responder_patience;
    const auto response = askOnce(host_port, request_path, request.get(), deadline);

    // The same decode, signature check and freshness check the service already applies to
    // every status it receives.
    const auto parsed = pvxs::certs::CmsStatusManager::parse(response, trusted_store_.get());

    const auto reported = parsed.ocsp_status == pvxs::certs::OCSP_CERTSTATUS_REVOKED ? ocspcertstatus_t::OCSP_CERTSTATUS_REVOKED
                          : parsed.ocsp_status == pvxs::certs::OCSP_CERTSTATUS_GOOD  ? ocspcertstatus_t::OCSP_CERTSTATUS_GOOD
                                                                                     : ocspcertstatus_t::OCSP_CERTSTATUS_UNKNOWN;
    const auto previous = ocspStatus();
    answer_valid_until_.store(parsed.status_valid_until_date.t, std::memory_order_release);
    answer_.store(reported, std::memory_order_release);

    if (reported != previous) {
        log_warn_printf(ocspmonitor, "OCSP status: the facility root %s\n",
                        reported == ocspcertstatus_t::OCSP_CERTSTATUS_REVOKED    ? "has been revoked"
                        : reported == ocspcertstatus_t::OCSP_CERTSTATUS_GOOD ? "stands"
                                                                          : "cannot be established");
    }
}

}  // namespace cert
}  // namespace cms
