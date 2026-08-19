/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "auth.h"

#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>

#include "authregistry.h"
#include "ccrmanager.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "configcerts.h"
#include "p12filefactory.h"
#include "security.h"

DEFINE_LOGGER(config, "pvxs.auth.config");

namespace pvxs {
namespace certs {

// Shared authenticator logger, defined once here and declared extern in auth.h
// (loggers should not be defined in a header; DEFINE_LOGGER yields a static per
// translation unit).
::pvxs::logger auth{"pvxs.auth.common"};

/**
 * @brief Get a pointer to the singleton Auth object for the given type.
 *
 * This function returns a pointer to the singleton Auth object for the given type.
 *
 * @param type the type of the Auth object to get (e.g. "std", "ldap", "krb", "jwt")
 * @return a pointer to the singleton Auth object for the given type
 * @throws std::logic_error if the Auth object for the given type is not found
 */
Auth *Auth::getAuth(const std::string &type) {
    const auto auth = AuthRegistry::instance().getAuth(type);
    if (auth == nullptr) {
        throw std::logic_error("Auth::getAuth: no such auth type");
    }
    return auth;
}

/**
 * @brief Creates a signed certificate.
 *
 * Create a PVStructure that corresponds to the ccr parameter of a certificate
 * creation request. This request will be sent to the PVACMS through the default
 * channel (PVAccess) and will be used to create the certificate.
 *
 * @param credentials the credentials that describe the subject of the
 * certificate
 * @param key_pair the public/private key to be used in the certificate, only
 * public key is used
 * @param usage the desired certificate usage
 * @param config The configuration for the certificate
 * @return A managed shared CertCreationRequest object.
 */
std::shared_ptr<CertCreationRequest> Auth::createCertCreationRequest(const std::shared_ptr<AuthnCredentials> &credentials, const std::shared_ptr<KeyPair> &key_pair,
                                                                     const uint16_t &usage, const ConfigAuthN &config) const {
    // Create a new CertCreationRequest object.
    auto cert_creation_request = std::make_shared<CertCreationRequest>(type_, verifier_fields_);
    cert_creation_request->credentials = credentials;

    // Fill in the ccr from the base data we've gathered so far.
    if (key_pair) {
        cert_creation_request->ccr["type"] = type_; // Authenticator type
        cert_creation_request->ccr["usage"] = usage; // Desired Certificate usage
        cert_creation_request->ccr["pub_key"] = key_pair->public_key; // The public key to use (you keep the private key private)

        // Optional CCR components
        if (!credentials->name.empty()) cert_creation_request->ccr["name"] = credentials->name;
        if (!credentials->organization.empty()) cert_creation_request->ccr["organization"] = credentials->organization;
        if (!credentials->organization_unit.empty()) cert_creation_request->ccr["organization_unit"] = credentials->organization_unit;
        if (!credentials->country.empty()) cert_creation_request->ccr["country"] = credentials->country;
        if (credentials->not_before >0) cert_creation_request->ccr["not_before"] = credentials->not_before;
        if (credentials->not_after >0) cert_creation_request->ccr["not_after"] = credentials->not_after;

        // Don't include any status checking extension.  This will disable any certificate renewal functionality
        if (config.no_status) cert_creation_request->ccr["no_status"] = config.no_status;

        // Do we need to add a configuration uri to the certificate?
        if (!credentials->config_uri_base.empty()) cert_creation_request->ccr["config_uri_base"] = credentials->config_uri_base;
    }
    return cert_creation_request;
}

/**
 * @brief Signs a certificate.
 *
 * This function takes a certificate creation request and sends its ccr
 * PVStructure to PVACMS to be signed. It will wait for the signed signature or
 * any reported error.
 *
 * @param ccr A shared pointer to a CertCreationRequest object
 * containing the ccr PVStructure which contains the certificate, and its
 * validity as well as any verifier specific required fields.
 * @param timeout the timeout for the request
 * @param cert_pv_prefix the CMS pv prefix
 * @param issuer_id the issuer ID of the CMS
 * @return the certificate in PEM format with the certificate authority chain ordered from leaf to root
 * @throws std::runtime_error when exceptions arise
 *
 * @note It is the responsibility of the caller to ensure that the
 * CCR object is valid and contains the required information
 * before calling this function.
 */
std::tuple<time_t, std::string> Auth::processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr,
                                                                       const std::string &cert_pv_prefix,
                                                                       const std::string &issuer_id,
                                                                       const double timeout,
                                                                       const std::shared_ptr<KeyPair> &key_pair,
                                                                       const CertData &held_before_request) const {
    // Forward the ccr to the certificate management service. The key pair and what the
    // keychain held before the request are carried through so an authenticator can act
    // on a reply addressed to the key that made the request.
    return ccr_manager_.createCertificate(ccr, cert_pv_prefix, issuer_id, timeout, key_pair, held_before_request);
}

namespace {
/**
 * @brief RenewalManager is a class that manages the renewal of a certificate.
 *
 * This class is used to monitor the status of a certificate and renew it when indicated by the CMS.
 */
struct RenewalManager {
    CertData cert_data;
    std::function<CertData()> renew_fn;
    server::SharedPV config_pv;
    Value config_pv_value;
    client::Context client;
    std::shared_ptr<client::Subscription> sub;
    server::Server* config_server{nullptr}; // set by runAuthNDaemon; used to break run() on exit
    int exit_code{0};                        // result propagated out of runAuthNDaemon

    RenewalManager(CertData&& cert, const std::function<CertData()>&& fn)
        : cert_data(std::move(cert)), renew_fn(std::move(fn)), config_pv(server::SharedPV::buildMailbox()) {
        auto client_config = client::Config::fromEnv();
        client_config.tls_disabled = true;
        client = client_config.build();
    }

    /**
     * @brief Start the monitor for the certificate status.
     *
     * Subscribes to the certificate's status PV. Each update is handled by onStatusUpdate,
     * which evaluates the live status (including the very first/initial update) and acts on
     * it: revoked/expired certs are re-minted, a cert that can never be renewed in time stops
     * the daemon, and a renewal_due flag triggers renewal. Connect/disconnect events from the
     * PVACMS are handled here too: a disconnect is benign (the cert is reused until the CMS
     * comes back), so the daemon keeps running and the subscription reconnects on its own.
     */
    void startMonitor() {
        sub.reset();

        try {
            auto status_pv_name = CmsStatusManager::getStatusPvFromCert(cert_data.cert);

            std::cout << "Monitoring certificate status on " << status_pv_name << " for renewal" << std::endl;
            sub = client.monitor(status_pv_name)
                .maskConnected(false)
                .maskDisconnected(false)
                .event([this, status_pv_name](client::Subscription& s) {
                    this->onStatusUpdate(s, status_pv_name);
                })
                .exec();
        } catch (const CertStatusNoExtensionException& e) {
            // No online status available
        } catch (const std::exception& e) {
            log_err_printf(config, "Error starting certificate status monitor: %s\n", e.what());
        }
    }

    /**
     * @brief Stop the daemon with the given exit code.
     *
     * Records the exit code and breaks the blocking config_server_.run() in runAuthNDaemon so
     * the process returns that code (used to avoid a process-manager restart loop on a
     * permanently non-renewable certificate).
     *
     * @param code Exit code to return.
     */
    void stopDaemon(const int code) {
        exit_code = code;
        if (config_server) config_server->interrupt();
    }

    /**
     * @brief On status update callback.
     *
     * Called for each status update (and connect/disconnect event) from the CMS. On every
     * update it first evaluates the live status of the held certificate, then, if still
     * healthy, renews when the CMS flags renewal_due.
     */
    void onStatusUpdate(client::Subscription& s, const std::string& pv_name) {
        try {
            while(auto update = s.pop()) {
                if (handleStatus(update, pv_name)) return; // daemon stopping or monitor restarted

                auto renewal_due_value = update["renewal_due"];
                if (renewal_due_value && renewal_due_value.as<bool>()) {
                    std::cout << "Renewal due for cert on " << pv_name << ". Requesting new certificate." << std::endl;
                    try {
                        cert_data = renew_fn(); // Renew and update our copy of CertData
                        const CertDate renew_by = cert_data.renew_by;
                        if (renew_by.t) {
                            config_pv_value["renew_by"] = renew_by.s;
                            config_pv.post(config_pv_value);
                            std::cout << "Certificate renewed successfully until " << renew_by.s << std::endl;
                        } else
                            std::cout << "Certificate renewed successfully " << std::endl;
                    } catch (const std::exception& e) {
                        log_err_printf(config, "Certificate renewal failed: %s. Will retry after next status update (or manual intervention).\n", e.what());
                    }
                }
            }
        } catch (client::Connected& conn) {
            log_debug_printf(config, "Connected to certificate status PV %s\n", pv_name.c_str());
        } catch (client::Disconnect& disconn) {
            // Benign: keep reusing the current cert and let the subscription reconnect.
            std::cout << "Disconnected from certificate status PV " << pv_name
                      << "; reusing current certificate until PVACMS returns" << std::endl;
        } catch(std::exception& e) {
             log_err_printf(config, "Error in renewal subscription callback: %s\n", e.what());
        }
    }

    /**
     * @brief Evaluate a status update against the held certificate.
     *
     * Mirrors the (formerly startup-time) checks, now driven by the live monitor on the first
     * and every subsequent update: a REVOKED/EXPIRED cert is re-minted (and the monitor moved
     * to the new cert's status PV); a cert with no usable renew-by date (it can never be
     * renewed before it expires) stops the daemon with exit code 15 so process managers do not
     * restart-loop. Returns true if the caller should stop processing this batch (the daemon is
     * stopping, or the monitor was restarted onto a different PV).
     */
    bool handleStatus(const Value& update, const std::string& pv_name) {
        const auto status_index = update["value.index"];
        if (!status_index) return false; // not a status value (e.g. a bare connect notification)
        const auto status = static_cast<certstatus_t>(status_index.as<uint32_t>());

        // renew_by is published as a plain POSIX time_t, the same epoch the cert's
        // not_after uses, so no conversion is needed. A renew_by on or after not_after
        // is treated as not-renewable.
        const time_t cert_not_after = CertFactory::getNotAfterTimeFromCert(cert_data.cert);
        const auto renew_by_posix = static_cast<time_t>(update["renew_by"].as<uint64_t>());
        const bool has_usable_renew_by = usableRenewBy(renew_by_posix, cert_not_after);

        switch (certStatusAction(status, has_usable_renew_by)) {
            case CertStatusAction::MintNew:
                std::cout << "Certificate on " << pv_name
                          << " is revoked or expired. Requesting a new certificate." << std::endl;
                try {
                    cert_data = renew_fn(); // mint a fresh cert (new serial/status PV)
                    const CertDate renew_by = cert_data.renew_by;
                    if (renew_by.t) {
                        config_pv_value["renew_by"] = renew_by.s;
                        config_pv.post(config_pv_value);
                    }
                    startMonitor(); // re-point the subscription at the new cert's status PV
                } catch (const std::exception& e) {
                    log_err_printf(config, "Certificate re-mint failed: %s. Will retry on next status update.\n", e.what());
                }
                return true; // either restarted onto a new PV, or will retry next update
            case CertStatusAction::ExitNonRenewable:
                log_err_printf(config, "%s: certificate is not renewable (no usable renew-by); stopping daemon\n", pv_name.c_str());
                stopDaemon(15);
                return true;
            case CertStatusAction::None:
                return false;
        }
        return false;
    }
};
} // namespace

/**
 * @brief Run the authenticator daemon
 *
 * This Authenticator daemon will monitor the status of a certificate and renew it when indicated by the CMS.
 * It will also maintain a PV that will publish configuration information.
 *
 * @param authn_config The Authenticator's configuration
 * @param cert_data The certificate data (contains cert, cert_auth_chain, and key)
 * @param fn The function to call to get the next certificate
 */
int Auth::runAuthNDaemon(const ConfigAuthN &authn_config, bool, CertData &&cert_data, const std::function<CertData()> &&fn) {
    const auto issuer_id = CertStatus::getIssuerId(cert_data.cert_auth_chain);
    const std::string skid(CertStatus::getSkId(cert_data.cert));

    // The manager holds all state and logic for renewals and is kept alive by a shared_ptr.
    auto renewal_manager = std::make_shared<RenewalManager>(std::move(cert_data), std::move(fn));

    // Set up and run the config server
    auto config = server::Config::fromEnv();
    config.tls_disabled = true;

    renewal_manager->config_pv_value = getConfigurationPrototype();
    renewal_manager->config_pv.open(renewal_manager->config_pv_value);

    // Use a standard server, not ServerEv.
    config_server_ = server::Server(config);
    // Give the monitor a handle so it can break run() if the certificate becomes non-renewable.
    renewal_manager->config_server = &config_server_;

    // Start monitoring in the background on client worker threads.
    renewal_manager->startMonitor();

    renewal_manager->config_pv.onFirstConnect([&, renewal_manager](server::SharedPV &pv) {
        pv.post(renewal_manager->config_pv_value);
    });

    const std::string pv_name = getConfigURI(authn_config.getCertPvPrefix(), issuer_id, skid);
    config_server_.addPV(pv_name, renewal_manager->config_pv);
    std::cout << "Cert Config info available on: " << pv_name << std::endl;

    // This blocks until interrupt() is called (e.g. by the monitor when the certificate is
    // permanently non-renewable). The renewal logic runs in the background on client threads.
    config_server_.run();
    return renewal_manager->exit_code;
}

std::string Auth::formatTimeDuration(time_t total_seconds) {
    // Calculate days, hours, minutes, and seconds.
    constexpr time_t seconds_per_day = 86400;
    constexpr time_t seconds_per_hour = 3600;
    constexpr time_t seconds_per_minute = 60;

    const time_t days = total_seconds / seconds_per_day;
    total_seconds %= seconds_per_day;
    const time_t hours = total_seconds / seconds_per_hour;
    total_seconds %= seconds_per_hour;
    const time_t minutes = total_seconds / seconds_per_minute;
    const time_t secs = total_seconds % seconds_per_minute;

    // Build a vector of non-optional parts.
    // According to the format, the days, hrs, and mins parts are only included if nonzero.
    // Seconds are always displayed.
    std::vector<std::string> parts;
    if (days > 0) {
        parts.push_back(std::to_string(days) + " days");
    }
    if (hours > 0) {
        parts.push_back(std::to_string(hours) + " hrs");
    }
    if (minutes > 0) {
        parts.push_back(std::to_string(minutes) + " mins");
    }
    if (parts.empty() || secs > 0) {
        parts.push_back(std::to_string(secs) + " secs");
    }

    // Join the parts using the pattern:
    //  - If only one part exists, return it.
    //  - If two parts exist, join with " and ".
    //  - If three or more parts exist, join with commas, but use " and " before the last part.
    std::ostringstream oss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            if (i == parts.size() - 1) {
                oss << " and ";
            } else {
                oss << ", ";
            }
        }
        oss << parts[i];
    }
    return oss.str();
}


}  // namespace certs
}  // namespace pvxs
