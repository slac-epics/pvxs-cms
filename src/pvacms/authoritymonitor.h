/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTHORITYMONITOR_H
#define PVXS_AUTHORITYMONITOR_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include <openssl/x509.h>

#include "ownedptr.h"

namespace cms {
namespace cert {

/**
 * @brief What the trust anchor's own responder says about the trust anchor.
 *
 * These are the three answers the Online Certificate Status Protocol can carry, narrowed to
 * what this service acts on. `UNKNOWN` is also the answer when the responder could not be
 * reached or its reply could not be trusted: in each case the authority's standing is not known.
 */
enum class authority_state_t { GOOD, REVOKED, UNKNOWN };

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

    /** @brief The authority's standing as most recently established. */
    authority_state_t state() const noexcept { return state_.load(std::memory_order_acquire); }

    /** @brief Begins polling. Does nothing when the anchor named no responder. */
    void start();

    /** @brief Stops polling and waits for the poll in flight to finish. */
    void stop();

   private:
    /** @brief Polls, then waits until the responder says it will have something new to say. */
    void run();

    /** @brief One question and answer. Returns the responder's own next-update time, or 0. */
    time_t pollOnce();

    std::string responder_uri_;
    const bool hold_last_known_;
    pvxs::ossl_ptr<X509> cert_;
    pvxs::ossl_ptr<X509_STORE> trusted_store_;

    std::atomic<authority_state_t> state_{authority_state_t::UNKNOWN};

    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable wakeup_;
    bool stopping_{false};
};

}  // namespace cert
}  // namespace cms

#endif  // PVXS_AUTHORITYMONITOR_H
