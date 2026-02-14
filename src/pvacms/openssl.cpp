/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "openssl.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <tuple>

#include <epicsExit.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#include <pvxs/log.h>

#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusmanager.h"
#include "evhelper.h"
#include "ownedptr.h"
#include "opensslgbl.h"
#include "serverconn.h"
#include "utilpvt.h"

#ifndef TLS1_3_VERSION
#error TLS 1.3 support required.  Upgrade to openssl >= 1.1.0
#endif

DEFINE_LOGGER(watcher, "pvxs.certs.mon");
DEFINE_LOGGER(io, "pvxs.ossl.io");
DEFINE_LOGGER(status_cli, "pvxs.st.cli");
DEFINE_LOGGER(status_svr, "pvxs.st.svr");

namespace pvxs {
namespace ossl {


/**
 * @brief Called back when the entity certificate status becomes invalid
 * @param fd
 * @param evt
 * @param raw
 */
void SSLContext::statusValidityTimerCallback(evutil_socket_t fd, short evt, void* raw) {
    auto* ctx = static_cast<SSLContext*>(raw);
    log_debug_printf(watcher, "Certificate status validity expired - marking status as %s\n", "UNKNOWN");

    // Set certificate state to UNKNOWN
    ctx->setTlsOrTcpMode();
}

/**
 * @brief Set degraded mode
 *
 * Clear all monitors and statuses, then set tls context state to Degraded
 */
void SSLContext::setDegradedMode(const bool clear) {
    log_debug_printf(watcher, "Permanently switching TLS state to Degraded%s\n", "");
    Guard G(lock);
    if (clear) {
        cert_monitor.reset();   // Unsubscribe from the certificate status monitor if any
        cert_status = {};    // Set the certificate status to be UNKNOWN
    }
    state = DegradedMode;
    log_debug_printf(is_client ? status_cli : status_svr, "%24.24s = %-11s : SSLContext::setDegradedMode()\n", "SSLContext::state", "DegradedMode");
}

/**
 * @brief Transition TLS mode based on the given certificate status
 *
 * Will never be called if cert is EXPIRED of REVOKED so we can set to TcpReady if NOT GOOD because it may become GOOD again later
 *
 * @param cert_status_class the given cert status class
 */
void SSLContext::setTlsOrTcpMode(const certs::cert_status_class_t cert_status_class) {
    log_debug_printf(watcher, "Received a %s certificate status from the status monitor\n", cert_status.status.s.c_str());
    if (state == DegradedMode) {
        log_warn_printf(watcher, "Logic Error. Should not be monitoring certificate status: Because the context state is %s\n", "DegradedMode");
        return;
    }

    switch (cert_status_class) {
        case certs::cert_status_class_t::GOOD:
            switch (state) {
                case Init:
                case TcpReady:
                    log_debug_printf(watcher, "Setting TLS Ready State%s\n", "");
                    {
                        Guard G(lock);
                        state = TlsReady;
                        log_debug_printf(is_client ? status_cli : status_svr, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", "TlsReady", "SSLContext::setTlsOrTcpMode()", this);
                    }
                    break;
                case TlsReady:
                default:
                    log_debug_printf(watcher, "Skipping setting TLS Ready State: Because the state is already%s\n", "TlsReady");
                    break;
            }
            break;
        case certs::cert_status_class_t::BAD:
            setDegradedMode();
            break;
        case certs::cert_status_class_t::UNKNOWN:
        default:
            switch (state) {
                case Init:
                    log_debug_printf(watcher, "Keeping Init state until a VALID status is received%s\n", "");
                    break;
                case TlsReady:
                    log_debug_printf(watcher, "Switching TLS state to TcpReady until a new VALID status is received%s\n", "");
                    {
                        Guard G(lock);
                        state = TcpReady;
                        log_debug_printf(is_client ? status_cli : status_svr, "%24.24s = %-12s : %-41s: %p\n", "SSLContext::state", "TcpReady", "SSLContext::setTlsOrTcpMode()", this);
                    }
                case TcpReady:
                default:
                    log_debug_printf(watcher, "Skipping setting TCP Ready State: Because the state is already%s\n", "TcpReady");
                    break;
            }
            break;
    }
}

/**
 * @brief Transition TLS mode when entity certificate status changes
 */
void SSLContext::setTlsOrTcpMode() {
    const auto status = static_cast<certs::CertificateStatus>(cert_status);
    setTlsOrTcpMode(status.getEffectiveStatusClass());
}

SSLContext::SSLContext(const impl::evbase loop, const bool is_client) : loop(loop), is_client(is_client)
    , status_validity_timer(event_new(loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))
{}

SSLContext::SSLContext(const SSLContext &o)
    : loop(o.loop)
    , ctx(o.ctx)
    , is_client(o.is_client)
    , state(o.state)
    , status_check_disabled(o.status_check_disabled)
    , stapling_disabled(o.stapling_disabled)
    , cert_monitor(o.cert_monitor)  // Copy the monitor
    , cert_status(o.cert_status)    // Copy the status
    , status_validity_timer(event_new(loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create a new timer for this instance
{
    // If the original timer was pending, restart ours with the remaining time
    if (o.status_validity_timer.get() && event_pending(o.status_validity_timer.get(), EV_TIMEOUT, nullptr)) {
        restartStatusValidityTimerFromCertStatus();
    }
}

SSLContext::SSLContext(SSLContext &o) noexcept
    : loop(o.loop)
    , ctx(std::move(o.ctx))
    , is_client(o.is_client)
    , state(o.state)
    , status_check_disabled(o.status_check_disabled)
    , stapling_disabled(o.stapling_disabled)
    , cert_monitor(std::move(o.cert_monitor))  // Move the monitor
    , cert_status(std::move(o.cert_status))    // Move the status
    , status_validity_timer(event_new(loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create new timer
{
    // If the original timer was pending, restart ours and cancel the original
    if (o.status_validity_timer.get() && event_pending(o.status_validity_timer.get(), EV_TIMEOUT, nullptr)) {
        restartStatusValidityTimerFromCertStatus();
        // Cancel the timer in the source object since we're moving
        event_del(o.status_validity_timer.get());
    }

}

void SSLContext::restartStatusValidityTimerFromCertStatus() const {
    if (!status_validity_timer.get()) {
        return; // Timer is not initialized
    }

    // Calculate the remaining time from the status validity date
    if (cert_status.status_valid_until_date.t > 0) {
        const time_t now = time(nullptr);
        if (cert_status.status_valid_until_date.t > now) {
            timeval delay{};
            delay.tv_sec = cert_status.status_valid_until_date.t - now;
            delay.tv_usec = 0;
            event_add(status_validity_timer.get(), &delay);
        }
    }
}

SSLContext::~SSLContext() {
    if (status_validity_timer.get()) {
        event_del(status_validity_timer.get());
    }
}

CertStatusExData::~CertStatusExData() noexcept = default;

#ifdef PVXS_ENABLE_SSLKEYLOGFILE
void sslkeylogfile_log(const SSL *, const char *line) noexcept {
    if (!ossl_gbl) return;
    auto gbl = ossl_gbl;
    try {
        epicsGuard<epicsMutex> G(gbl->keylock);
        if(gbl->keylog) {
            FLock lk(gbl->keylog.get(), true);
            int pos = fseek(gbl->keylog.get(), 0, SEEK_END);
            if(pos==-1)
                throw std::runtime_error("seek");
            auto ret = fprintf(gbl->keylog.get(), "%s\n", line);
            if(ret>=0)
                ret = fflush(gbl->keylog.get());
            else
                ret = -1;
            if(ret) {
                throw std::runtime_error("I/O");
            }
        }
    } catch (std::exception &e) {
        static bool once = false;
        if (!once) {
            fprintf(stderr, "Error while writing to SSLKEYLOGFILE\n");
            once = true;
        }
    }
}
#endif  // PVXS_ENABLE_SSLKEYLOGFILE

/**
 * @brief Called when last  peer connection is being destroyed to remove the
 * peer status and monitor from the tls context's list of statuses and monitors
 */
SSLPeerStatusAndMonitor::~SSLPeerStatusAndMonitor() {
    if (status_validity_timer) {
        Guard G(lock);
        event_del(status_validity_timer.get());
    }
    {
        Guard G(lock);
        // Remove self from the global list of peer statuses
        ex_data_ptr->removePeerStatusAndMonitor(serial_number);
    }
    subscribed = false;
}

/**
 * @brief Callback triggered when the certificate status validity timer expires
 *
 * This function is invoked when the certificate status validity timer expires, indicating
 * that the certificate status has become invalid. It notifies any registered listeners about
 * this change in status.
 *
 * @param fd The file descriptor associated with the event (not used in this function)
 * @param evt The event type that triggered the callback
 * @param raw Pointer to the SSLPeerStatusAndMonitor instance managing the certificate status
 */
void SSLPeerStatusAndMonitor::statusValidityTimerCallback(evutil_socket_t fd, short evt, void* raw) {
    const auto* peer_status_and_monitor = static_cast<SSLPeerStatusAndMonitor*>(raw);
    log_debug_printf(watcher, "Certificate status validity expired - notifying listeners%s\n", "");

    // Set notify listeners that status has changed
    if (peer_status_and_monitor->fn) peer_status_and_monitor->fn(certs::cert_status_class_t::UNKNOWN);
}

/**
 * @brief Restart the status validity timer based on the validity of the certificate.
 *
 * This method handles restarting a timer that monitors the validity of a peer certificate status.
 * It ensures that any existing timers are canceled and calculates the remaining status validity
 * duration to set up a new timer accordingly.
 *
 * If the certificate is marked as non-permanent and has a status valid expiration date
 * greater than the current time, then the timer is scheduled to trigger after the remaining
 * status validity period. Logs are generated for debugging purposes to indicate the countdown.
 */
void SSLPeerStatusAndMonitor::restartStatusValidityTimerFromCertStatus() {
    if (!status_validity_timer.get()) return; // Timer is not initialized

    // Cancel any existing status validity timer
    if (event_pending(status_validity_timer.get(), EV_TIMEOUT, nullptr)) {
        Guard G(lock);
        event_del(status_validity_timer.get());
    }

    // Calculate the remaining time from the status validity date
    if (!status.isPermanent() && status.status_valid_until_date.t > 0) {
        const time_t now = time(nullptr);
        if (status.status_valid_until_date.t > now) {
            const auto status_validity_seconds_remaining = status.status_valid_until_date.t - now;
            log_debug_printf(watcher, "Counting down Peer Certificate validity: %ld seconds\n", status_validity_seconds_remaining);
            const timeval delay{status_validity_seconds_remaining};
            event_add(status_validity_timer.get(), &delay);
        }
    }
}

/**
 * @brief Sets the peer status for the given peer certificate
 * @param peer_cert_ptr - Peer certificate pointer
 * @param new_status - Certificate status
 * @param fn function to be configured to be called for updates
 * @return The peer status that was set
 */
std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::setPeerStatus(X509 *peer_cert_ptr,
    const certs::CertificateStatus &new_status, const std::function<void(certs::cert_status_class_t)> &fn) {
    const auto serial_number = getSerialNumber(peer_cert_ptr);
    std::shared_ptr<SSLPeerStatusAndMonitor> peer_status_and_monitor;
    if (status_check_enabled && fn) {
        const auto status_pv = certs::CertStatusManager::getStatusPvFromCert(peer_cert_ptr);
        peer_status_and_monitor = getOrCreatePeerStatus(serial_number, status_pv, fn);
    } else {
        peer_status_and_monitor = getOrCreatePeerStatus(serial_number);
    }

    peer_status_and_monitor->updateStatus(new_status);
    return peer_status_and_monitor;
}

std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::getOrCreatePeerStatus(const serial_number_t serial_number, const std::string &status_pv, const std::function<void(certs::cert_status_class_t)> &fn) {
    // Create a holder for peer status or return current holder if already exists
    auto peer_status = createPeerStatus(serial_number, fn);

    // Subscribe if we have a pv and a function and we're not yet subscribed
    if (!status_pv.empty() && fn && status_check_enabled && !peer_status->isSubscribed()) {
        // Subscribe to certificate status updates
        std::weak_ptr<SSLPeerStatusAndMonitor> weak_peer_status = peer_status;
        {
            Guard G(peer_status->lock);
            peer_status->subscribed = true;
        }
        peer_status->cert_status_manager =
            certs::CertStatusManager::subscribe(client, trusted_store_ptr, status_pv, [weak_peer_status](const certs::PVACertificateStatus &status) {
                log_debug_printf(watcher, "Received: %s PEER certificate status\n", status.status.s.c_str());
                const auto peer_status_update = weak_peer_status.lock();
                if (!status.isGood())
                    log_warn_printf(watcher, "Peer certificate not VALID: %s\n", status.status.s.c_str());
                // Update the cached state
                if (peer_status_update) peer_status_update->updateStatus(static_cast<const certs::CertificateStatus>(status));
            });
    }
    return peer_status;
}

/**
 * @brief Create a peer status in the list of statuses or return an existing one
 * @param serial_number the serial number to index into the list
 * @param fn optional function that will be called as status changes if provided
 * @return the existing or new peer status
 */
std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::createPeerStatus(serial_number_t serial_number, const std::function<void(certs::cert_status_class_t)> &fn) {
    const auto existing_peer_status_entry = peer_statuses.find(serial_number);
    if (existing_peer_status_entry != peer_statuses.end()) {
        auto peer_status (existing_peer_status_entry->second.lock());
        if (peer_status) {
            return peer_status;
        }
        peer_statuses.erase(serial_number);
    }

    std::shared_ptr<SSLPeerStatusAndMonitor> new_peer_status;
    if (fn) new_peer_status = std::make_shared<SSLPeerStatusAndMonitor>(serial_number, this, fn);
    else new_peer_status = std::make_shared<SSLPeerStatusAndMonitor>(serial_number, this, nullptr);
    peer_statuses.emplace(serial_number, new_peer_status);
    return new_peer_status;
};

SSLPeerStatusAndMonitor::SSLPeerStatusAndMonitor(const serial_number_t serial_number, CertStatusExData* ex_data_ptr, const std::function<void(certs::cert_status_class_t)>& fn)
    : fn(fn), serial_number{serial_number}, ex_data_ptr{ex_data_ptr}
    , status_validity_timer(event_new(ex_data_ptr->loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create a new timer for this instance
    {}

SSLPeerStatusAndMonitor::SSLPeerStatusAndMonitor(const serial_number_t serial_number, CertStatusExData* ex_data_ptr, const certs::CertificateStatus& status)
    : serial_number{serial_number}, ex_data_ptr{ex_data_ptr}, status{status}
    , status_validity_timer(event_new(ex_data_ptr->loop.base, -1, EV_TIMEOUT, &statusValidityTimerCallback, this))  // Create a new timer for this instance
    {}

/**
 * @brief Update the status with the given value and call the callback if supplied and restart the status validity timer
 * @param new_status the new status to set
 */
void SSLPeerStatusAndMonitor::updateStatus(const certs::CertificateStatus &new_status) {
    if (!new_status.isStatusCurrent()) // Ignore expired status results
        return;

    // Status updates (and the associated timer operations) must happen in the SSL context's event loop.
    // Cert status updates may originate from other threads (eg. a client context used to query PVACMS).
    // Use call()/tryCall() (not dispatch) to avoid adding avoidable latency for connection bring-up.
    // This matters for first-time status fetch in CI where tests have tight timeouts.
    auto self = shared_from_this();
    if(!ex_data_ptr->loop.tryCall([self, new_status]() {
        certs::cert_status_class_t prior_status_class;
        certs::cert_status_class_t status_class;
        {
            Guard G(self->lock);
            prior_status_class = self->status.getStatusClass();
            self->status = new_status;
            status_class = self->status.getStatusClass();
        }

        // Call the callback if there has been any change in the cert status class
        if (self->fn && status_class != prior_status_class)
            self->fn(status_class);

        // Restart status validity countdown timer for this new status
        self->restartStatusValidityTimerFromCertStatus();
    })) {
        // ignore during shutdown
        return;
    }
}

std::shared_ptr<SSLPeerStatusAndMonitor> CertStatusExData::subscribeToPeerCertStatus(X509 *cert_ptr, const std::function<void(certs::cert_status_class_t)> &fn) {
    Guard G(lock);
    assert(cert_ptr && "Peer Cert NULL");
    return setPeerStatus(cert_ptr, fn);
}

/**
 * @brief Get the CertStatusExData from the SSL session
 *
 * This function retrieves the CertStatusExData from the SSL context associated with the given SSL session.
 * This is the custom data that is added to the SSL context during tls context creation.
 *
 * @param ssl the SSL session to get the CertStatusExData from
 * @return the CertStatusExData
 */
CertStatusExData *CertStatusExData::fromSSL(SSL *ssl) {
    if (!ssl) {
        return nullptr;
    }
    SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
    return fromSSL_CTX(ssl_ctx);
}

/**
 * @brief Get the CertStatusExData from the SSL context
 *
 * This function retrieves the CertStatusExData from the SSL context. This is the
 * custom data that is added to the SSL context during tls context creation.
 *
 * @param ssl_ctx the SSL context to get the CertStatusExData from
 * @return the CertStatusExData
 */
CertStatusExData *CertStatusExData::fromSSL_CTX(SSL_CTX *ssl_ctx) {
    if (!ssl_ctx) {
        return nullptr;
    }
    return static_cast<CertStatusExData *>(SSL_CTX_get_ex_data(ssl_ctx, ossl_gbl->SSL_CTX_ex_idx));
}

/**
 * @brief Get the CertStatusExData from the PVXS SSL context
 *
 * This function retrieves the CertStatusExData from the SSL context associated with the PVXS SSL context.
 * This is the custom data that is added to the SSL context during tls context creation.
 *
 * @return the CertStatusExData
 */
CertStatusExData *SSLContext::getCertStatusExData() const { return CertStatusExData::fromSSL_CTX(ctx.get()); }

/**
 * @brief Get the entity certificate from the custom data in the SSL context
 *
 * This function retrieves the entity certificate from the custom data in the SSL context.
 * During tls context creation the entity certificate is added to the custom data if TLS is configured
 *
 * @return the entity certificate
 */
const X509 *SSLContext::getEntityCertificate() const {
    if (!ctx) throw std::invalid_argument("NULL");

    const auto car = static_cast<CertStatusExData *>(SSL_CTX_get_ex_data(ctx.get(), ossl_gbl->SSL_CTX_ex_idx));
    return car->cert.get();
}

bool SSLContext::hasExpired() const {
    if (!ctx) throw std::invalid_argument("NULL");
    const auto now = time(nullptr);
    const auto cert = getEntityCertificate();
    if (!cert) return false;
    const certs::CertDate expiry_date = X509_get_notAfter(cert);
    return expiry_date.t < now;
}

/**
 * @brief Get the peer credentials from the SSL context
 *
 * This function retrieves the peer credentials from the SSL context and fills the PeerCredentials structure.
 * It also attempts to use the root certificate authority name to qualify the authority.
 *
 * @param C the PeerCredentials to fill
 * @param ctx the SSL context to get the peer credentials from
 * @return true if the peer credentials were successfully retrieved, false otherwise
 */
bool SSLContext::getPeerCredentials(PeerCredentials &C, const SSL *ctx) {
    if (!ctx) throw std::invalid_argument("NULL");

    if (const auto cert = SSL_get0_peer_certificate(ctx)) {
        PeerCredentials temp(C);  // copy current as initial (don't overwrite isTLS)
        const auto subj = X509_get_subject_name(cert);
        char name[64];
        if (subj && X509_NAME_get_text_by_NID(subj, NID_commonName, name, sizeof(name) - 1)) {
            name[sizeof(name) - 1] = '\0';
            log_debug_printf(io, "Peer CN=%s\n", name);
            temp.method = "x509";
            temp.account = name;

            // Get serial number
            const ASN1_INTEGER* serial_asn1 = X509_get_serialNumber(cert);
            if (!serial_asn1) throw std::runtime_error("Failed to retrieve serial number from peer certificate");
            serial_number_t serial = 0;
            for (int i = 0; i < serial_asn1->length; ++i) serial = serial << 8 | serial_asn1->data[i];
            temp.serial = std::to_string(serial);

            // try to use certificate chain authority names to qualify
            if (const auto chain = SSL_get0_verified_chain(ctx)) {
                const auto N = sk_X509_num(chain);

                if (N > 0) {
                    std::string authority;
                    char common_name[256];

                    // Start from index 1 to skip the entity certificate (first in chain)
                    // But if there's only one certificate, we don't skip it
                    const int start_index = (N > 1) ? 1 : 0;

                    // Process certificates in the chain in reverse order, from root to issuer
                    for (int i = N - 1; i >= start_index; i--) {
                        const auto chain_cert = sk_X509_value(chain, i);
                        const X509_NAME *certName = X509_get_subject_name(chain_cert);

                        if (chain_cert && certName &&
                            X509_NAME_get_text_by_NID(certName, NID_commonName, common_name, sizeof(common_name) - 1)) {

                            // Add this name to the authority string
                            if (!authority.empty()) {
                                authority += '\n';
                            }
                            authority += common_name;

                            // If this is the issuer cert (first in the chain after entity), also set the issuer_id
                            if (i == start_index) {
                                temp.issuer_id = certs::CertStatus::getSkId(chain_cert);
                            }
                            if (i == N - 1 && !(X509_check_ca(chain_cert) || (X509_get_extension_flags(chain_cert) & EXFLAG_SS))) {
                                log_warn_printf(io, "Last cert in peer chain is not root Root certificate authority certificate? %s\n",
                                                std::string(SB() << ossl::ShowX509{chain_cert}).c_str());
                            }
                        }
                    }

                    // Only set the authority if we found at least one name
                    if (!authority.empty()) {
                        temp.authority = authority;
                    }
                }
            }
        }

        C = std::move(temp);
        return true;
    }
    return false;
}

/**
 * @brief Subscribe to the peer certificate status
 *
 * This function subscribes to the peer certificate status and calls the given function when the status changes.
 *
 * @param ssl the SSL context to get the peer certificate from
 * @param fn the function to call when the certificate status changes
 * @return true if the peer certificate status was successfully subscribed, false otherwise
 */
std::shared_ptr<SSLPeerStatusAndMonitor> SSLContext::subscribeToPeerCertStatus(const SSL *ssl, const std::function<void(certs::cert_status_class_t)> &fn) {
    if (!ssl) throw std::invalid_argument("NULL");

    if (const auto cert = SSL_get0_peer_certificate(ssl)) {
        // Subscribe to peer certificate status if necessary
        const auto ex_data = CertStatusExData::fromSSL(const_cast<SSL *>(ssl));
        if (ex_data) {
            return ex_data->subscribeToPeerCertStatus(cert, [=](const certs::cert_status_class_t status) { fn(status); });
        }
    }
    throw certs::CertStatusNoExtensionException("No Certificate");
}

SSLError::SSLError(const std::string &msg)
    : std::runtime_error([&msg]() -> std::string {
          std::ostringstream strm;
          const char *file = nullptr;
          int line = 0;
          const char *data = nullptr;
          int flags = 0;
          while (const auto err = ERR_get_error_all(&file, &line, nullptr, &data, &flags)) {
              strm << file << ':' << line << ':' << ERR_reason_error_string(err);
              if (data && (flags & ERR_TXT_STRING)) strm << ':' << data;
              strm << ", ";
          }
          strm << msg;
          return strm.str();
      }()) {}

SSLError::~SSLError() = default;

std::ostream &operator<<(std::ostream &strm, const ShowX509 &cert) {
    if (cert.cert) {
        const auto name = X509_get_subject_name(cert.cert);
        const auto issuer = X509_get_issuer_name(cert.cert);
        assert(name);
        const ossl_ptr<BIO> io(__FILE__, __LINE__, BIO_new(BIO_s_mem()));
        {
            try {
                const auto cert_id = certs::CertStatusManager::getCertIdFromCert(cert.cert);
                (void)BIO_printf(io.get(), "\nCertificate ID : ");
                (void)BIO_printf(io.get(), cert_id.c_str());
            } catch (...) {}
        }
        (void)BIO_printf(io.get(), "\nEntity Subject : ");
        (void)X509_NAME_print(io.get(), name, 1024);
        (void)BIO_printf(io.get(), "\nIssuer Subject : ");
        (void)X509_NAME_print(io.get(), issuer, 1024);
        if (const auto atm = X509_get0_notBefore(cert.cert)) {
            const certs::CertDate the_date(atm);
            (void)BIO_printf(io.get(), "\nValid From     : ");
            (void)BIO_printf(io.get(), the_date.s.c_str());
        }
        if (const auto atm = X509_get0_notAfter(cert.cert)) {
            const certs::CertDate the_date(atm);
            (void)BIO_printf(io.get(), "\nExpires On     : ");
            (void)BIO_printf(io.get(), the_date.s.c_str());
        }
        {
            char *str = nullptr;
            if (const auto len = BIO_get_mem_data(io.get(), &str)) {
                strm.write(str, len);
            }
        }
    } else {
        strm << "NULL";
    }
    return strm;
}

}  // namespace ossl
}  // namespace pvxs
