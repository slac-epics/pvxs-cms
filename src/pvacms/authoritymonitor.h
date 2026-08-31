/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTHORITYMONITOR_H
#define PVXS_AUTHORITYMONITOR_H

#include <atomic>
#include <string>

#include <openssl/x509.h>

#include "evhelper.h"

#include "certstatus.h"
#include "ownedptr.h"

namespace cms {
namespace cert {

/**
 * @brief Watches the responder named by the trust anchor, so that revocation of the anchor
 * itself becomes visible to the certificates issued beneath it.
 *
 * A certificate authority publishes revocation of its own certificate through a responder whose
 * address it carries in its Authority Information Access extension. A facility root therefore
 * states where its own revocation can be learned. This class asks that question on a schedule
 * the responder sets, and holds the answer for the status service to apply.
 *
 * The anchor has no status channel of its own, so the answer reaches endpoints through the
 * per-certificate status they already subscribe to. The result is held in memory and derived
 * afresh at each start: no certificate's stored status is altered on account of its authority.
 *
 * An anchor naming no responder leaves the monitor inactive, and the service runs as before.
 */
class AuthorityMonitor {
   public:
    /**
     * @brief Reads the responder address out of the trust anchor.
     *
     * @param trust_anchor the self-signed certificate at the top of this service's chain
     * @param hold_last_known when the responder cannot be reached, keep serving the last
     *        verified answer instead of reporting the standing as unknown
     */
    AuthorityMonitor(X509 *trust_anchor, bool hold_last_known);
    ~AuthorityMonitor();

    AuthorityMonitor(const AuthorityMonitor &) = delete;
    AuthorityMonitor &operator=(const AuthorityMonitor &) = delete;

    /** @brief Whether the anchor named a responder to ask. */
    bool isActive() const noexcept { return !responder_uri_.empty(); }

    /** @brief The responder address read from the anchor, empty when it named none. */
    const std::string &responderUri() const noexcept { return responder_uri_; }

    /**
     * @brief The authority's standing, worked out from the last answer and the moment it runs
     * out.
     *
     * `UNKNOWN` is what an answer that has run out with nothing to replace it comes to, along
     * with a reply that could not be verified and one that said as much. A site that would
     * rather keep the last verified answer than stop sets `hold_last_known`, and then only
     * a responder that says so changes it.
     */
    pvxs::certs::cert_authority_standing_t standing() const noexcept {
        const auto answer = answer_.load(std::memory_order_acquire);
        if (answer == pvxs::certs::cert_authority_standing_t::UNKNOWN || hold_last_known_) return answer;
        return time(nullptr) < answer_valid_until_.load(std::memory_order_acquire)
                   ? answer
                   : pvxs::certs::cert_authority_standing_t::UNKNOWN;
    }

    /** @brief Begins polling. Does nothing when the anchor named no responder. */
    void start();

    /** @brief Stops polling, and waits for a poll in flight to finish. */
    void stop();

   private:
    /** @brief The timer callback: asks once, records what came back, and arms itself again. */
    static void pollTimer(evutil_socket_t fd, short evt, void *raw);

    /** @brief One question and answer, on the polling loop's own thread. */
    void poll();

    /** @brief How long to leave it, so several attempts fall inside the answer's own life. */
    time_t askAgainIn() const;

    std::string responder_uri_;
    const bool hold_last_known_;
    pvxs::ossl_ptr<X509> cert_;
    pvxs::ossl_ptr<X509_STORE> trusted_store_;

    /**
     * The last answer this service verified, and the moment it stops being one.
     *
     * The operational status is derived from these, so a poll that came back with nothing records
     * nothing and the answer already held stands until it runs out.
     */
    std::atomic<pvxs::certs::cert_authority_standing_t> answer_{pvxs::certs::cert_authority_standing_t::UNKNOWN};
    std::atomic<time_t> answer_valid_until_{0};

    /** Its own event loop, on a named EPICS thread, so nothing here runs on the server's. */
    pvxs::impl::evbase poll_loop_;
    pvxs::impl::evevent poll_timer_;
};

}  // namespace cert
}  // namespace cms

#endif  // PVXS_AUTHORITYMONITOR_H
