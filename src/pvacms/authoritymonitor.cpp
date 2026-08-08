/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authoritymonitor.h"

#include <chrono>
#include <memory>

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

using aia_ptr = std::unique_ptr<AUTHORITY_INFO_ACCESS, decltype(&AUTHORITY_INFO_ACCESS_free)>;

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
        stopping_ = true;
    }
    wakeup_.notify_all();
    worker_.join();
}

void AuthorityMonitor::run() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stopping_) {
        time_t next_update;
        {
            // The question is asked without the lock held: it is network input and output with a
            // service that may be slow, and stop() must not wait on it to be answered.
            lock.unlock();
            next_update = pollOnce();
            lock.lock();
        }
        if (stopping_) break;

        time_t wait_secs = retry_after_failure_secs;
        if (next_update > 0) {
            const time_t now = time(nullptr);
            wait_secs = next_update > now ? next_update - now : shortest_wait_secs;
        }
        if (wait_secs < shortest_wait_secs) wait_secs = shortest_wait_secs;
        if (wait_secs > longest_wait_secs) wait_secs = longest_wait_secs;

        wakeup_.wait_for(lock, std::chrono::seconds(wait_secs), [this] { return stopping_; });
    }
}

time_t AuthorityMonitor::pollOnce() {
    char *host = nullptr, *port = nullptr, *path = nullptr;
    int use_ssl = 0;
    if (!OCSP_parse_url(responder_uri_.c_str(), &host, &port, &path, &use_ssl)) {
        log_err_printf(authmonitor, "Authority status: cannot read responder address %s\n", responder_uri_.c_str());
        if (!hold_last_known_) state_.store(authority_state_t::UNKNOWN, std::memory_order_release);
        return 0;
    }
    // OCSP_parse_url hands back three separately allocated strings; free them however we leave.
    const std::string host_port = std::string(host) + ":" + port;
    const std::string request_path = path;
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);

    const authority_state_t previous = state();
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

        const pvxs::ossl_ptr<BIO> connection(BIO_new_connect(host_port.c_str()));
        if (BIO_do_connect(connection.get()) <= 0) {
            throw std::runtime_error(pvxs::SB() << "cannot reach the responder at " << host_port);
        }

        const pvxs::ossl_ptr<OCSP_RESPONSE> response(OCSP_sendreq_bio(connection.get(), request_path.c_str(), request.get()),
                                               false);
        if (!response) throw std::runtime_error("the responder gave no answer");

        // The same decode, signature check and freshness check the service already applies to
        // every status it receives.
        const auto parsed = pvxs::certs::CmsStatusManager::parse(response, trusted_store_.get());

        const auto reported = parsed.ocsp_status == pvxs::certs::OCSP_CERTSTATUS_REVOKED  ? authority_state_t::REVOKED
                              : parsed.ocsp_status == pvxs::certs::OCSP_CERTSTATUS_GOOD   ? authority_state_t::GOOD
                                                                             : authority_state_t::UNKNOWN;
        state_.store(reported, std::memory_order_release);

        if (reported != previous) {
            log_warn_printf(authmonitor, "Authority status: now %s\n",
                            reported == authority_state_t::REVOKED ? "REVOKED"
                            : reported == authority_state_t::GOOD  ? "GOOD"
                                                                   : "UNKNOWN");
        }
        return parsed.status_valid_until_date.t;
    } catch (const std::exception &e) {
        if (hold_last_known_) {
            log_warn_printf(authmonitor, "Authority status: %s; holding the last answer\n", e.what());
        } else {
            state_.store(authority_state_t::UNKNOWN, std::memory_order_release);
            if (previous != authority_state_t::UNKNOWN) {
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
