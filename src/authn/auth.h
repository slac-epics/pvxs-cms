/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_AUTH_H
#define PVXS_AUTH_H

#include <functional>
#include <string>
#include <vector>

#include <CLI/App.hpp>

#include <pvxs/client.h>
#include <pvxs/data.h>
#include <pvxs/log.h>

#include "ccrmanager.h"
#include "certfactory.h"
#include "certstatusfactory.h"
#include "certstatusmanager.h"
#include "configstd.h"
#include "openssl.h"
#include "security.h"
#include "serverev.h"

namespace pvxs {
namespace certs {

// Shared authenticator logger; defined in auth.cpp (not here — loggers should
// not be defined in a header).
extern ::pvxs::logger auth;

/**
 * @brief What the certificate management service can hand an authenticator filling in a reply.
 *
 * Everything else an authenticator needs is already in the request or in the reply being built:
 * the state, the serial number and the certificate identifier are all set before the hook runs.
 * This carries only what is not, and only the service can construct one. The certificate
 * database is deliberately absent: deciding what to record is the service's, so an authenticator
 * built into a client tool never has to link it.
 */
struct CreateResponseContext {
    /**
     * The certificate request identifier recorded for this request, or empty when it has
     * none. The service decides whether a request gets one; the authenticator only carries
     * it back. Empty is the ordinary case: only a request awaiting approval has one.
     */
    std::string request_id;
    /** The certificate authority private key, for signing what is returned. */
    const ossl_ptr<EVP_PKEY> *cert_auth_pkey{nullptr};
};

/**
 * @class Auth
 * @brief Abstract class for authentication operations.
 *
 * The Auth class provides an interface for retrieving credentials and
 * creating and validating Certificate Creation Requests (CCRs).
 */
using namespace certs;
class Auth {
 public:
    std::string type_{};
    std::vector<Member> verifier_fields_{};

    // Constructor and Destructor
    Auth(const std::string &type, const std::vector<Member> &verifier_fields)
        : type_(type), verifier_fields_(verifier_fields) {}

    virtual ~Auth() = default;

    /**
     * @brief Get credentials for the given configuration and usage.
     *
     * This function returns a shared pointer to a Credentials object for the given configuration and usage.
     * Implementers should fill in the Credentials object with the appropriate values for the given configuration and
     * usage.
     *
     * @param config The configuration to use for the credentials
     * @param for_client Whether the credentials are for a client or server
     * @return A shared pointer to the Credentials object
     */
    virtual std::shared_ptr<AuthnCredentials> getCredentials(const client::Config &config, bool for_client = true) const = 0;

    /**
     * @brief Verify a Certificate Creation Request (CCR).
     *
     * This function verifies a Certificate Creation Request (CCR). It is called inside PVACMS to verify the CCR.
     * Automatically compiles into the PVACMS if the auth method is registered, PVACMS will
     * look at any CCR it receives and call the overridden function with the CCR as the argument.
     * Implementers should provide appropriate code to verify the authenticity of the CCR.
     *
     * @param ccr The CCR to verify
     * @param authorized_validity the amount of time authorized for this certificate after verifying the request
     * @return True if the CCR is valid, false otherwise
     */
    virtual bool verify(Value &ccr, time_t &authorized_validity) const = 0;

    /**
     * @brief Members this authenticator wants added to the reply to a creation request.
     *
     * Returned empty by default, which leaves the reply exactly as it was, so a client
     * that knows nothing of this sees no change. Mirrors the verifier substructure the
     * request already carries: each authenticator owns its own part and ignores the rest.
     *
     * @return the members to place under `authenticator` in the reply
     */
    virtual std::vector<Member> responseFields() const { return {}; }

    /**
     * @brief Fill in the members declared by responseFields() on a reply.
     *
     * Called on the certificate management service after the fixed reply fields are set
     * and before the reply is sent.
     *
     * @param ccr the certificate creation request being answered
     * @param reply the reply being built
     */
    virtual void fillCreateResponse(const Value &ccr, Value &reply, const CreateResponseContext &context) const {
        (void)ccr;
        (void)reply;
        (void)context;
    }

    /**
     * @brief Act on the authenticator part of a reply, on the requesting side.
     *
     * Called only when the reply carries an `authenticator` member, so an authenticator
     * that adds nothing is never entered. The requesting key pair is passed because the
     * part may be addressed to the key that made the request, and the keychain contents
     * as they were before the request are passed because anything already trusted has to
     * come from before the reply rather than out of it.
     *
     * @param reply the reply received
     * @param key_pair the key pair used to make the request
     * @param held_before_request what the keychain held before the request was sent
     * @param expected_issuer_id the issuer the caller committed to before sending the request,
     *        so an authenticator that has to fall back on an authority delivered in the reply can
     *        check it against that commitment first
     */
    virtual void handleCreateResponse(const Value &reply,
                                      const std::shared_ptr<KeyPair> &key_pair,
                                      const CertData &held_before_request,
                                      const std::string &expected_issuer_id) const {
        (void)reply;
        (void)key_pair;
        (void)held_before_request;
        (void)expected_issuer_id;
    }

    /**
     * @brief Get the authenticator configuration from the environment.
     *
     * This function gets the authenticator configuration from the environment.
     * Implementers should get any authenticator specific configuration options from the environment.
     *
     * @param config The configuration to fill in
     */
    virtual void fromEnv(std::unique_ptr<client::Config> &config) = 0;

    /**
     * @brief Create a Certificate Creation Request (CCR) for the given credentials and key pair.
     *
     * This function creates a Certificate Creation Request (CCR) for the given credentials and key pair.
     * Implementers should fill in the CCR with the appropriate values for the given credentials and key pair.
     *
     * @param credentials The credentials to use for the CCR
     * @param key_pair The key pair to use for the CCR
     * @param usage The usage of the CCR
     * @param config The configuration to use for the CCR
     * @return A shared pointer to the CCR
     */
    virtual std::shared_ptr<CertCreationRequest> createCertCreationRequest(
        const std::shared_ptr<AuthnCredentials> &credentials,
        const std::shared_ptr<KeyPair> &key_pair,
        const uint16_t &usage,
        const ConfigAuthN &config) const = 0;

    /**
     * @brief Get the placeholder text for the options help text.
     *
     * This function returns a string containing the placeholder text for the options help text.
     * This will be inserted into the usage documentation for PVACMS to indicate where this authenticator's options
     * should be placed. Implementers should return a string containing the placeholder text for the options help text.
     * e.g. "Enter the kerberos principal name: ".  This should be enclosed in square brackets for consistency to
     * indicate optional arguments.
     *
     * @return A string containing the placeholder text for the options help text
     */
    virtual std::string getOptionsPlaceholderText() {
        return {};
    }

    /**
     * @brief Get the options help text.
     *
     * This function returns a string containing the options help text.
     * Implementers should return a string containing the options help text.
     * The string will be multi-line and will be formatted to fit into the usage documentation for PVACMS.
     * It should start with a string heading that matches the name given in the getOptionsPlaceholderText() function.
     *
     * e.g. if getOptionsPlaceholderText() returns "[kerberos Options]", the heading should be "kerberos Options"
     * followed by multiple lines of help text for the kerberos options.
     *
     * @return A string containing the options help text
     */
    virtual std::string getOptionsHelpText() {
        return {};
    }

    /**
     * @brief Add the options to the CLI application.
     *
     * This function adds the options to the CLI application object so that they can be parsed from the command line.
     * Implementers should add all required options to the CLI application object.
     * They should expect to find a configuration object that matches the type of the authenticator in the map under the
     * key of the type name. They should use this entry to store the values retrieved from the command line for the
     * authenticator's options
     *
     * @param app The CLI application object
     * @param authn_config_map A map of the authenticator configuration
     */
    virtual void addOptions(CLI::App &app,
                            std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map) {}

    /**
     * This function transfers the configuration from the given config object to the authenticator.
     * Useful for when configuration is not available when using an authenticator. Only implement this
     * if required.
     * Implementers should transfer any configuration options that are required for situations where configuration
     * is not available when using an authenticator.
     *
     * @param config The configuration to transfer
     */
    virtual void configure(const client::Config &config) {}

    /**
     * @brief Process a Certificate Creation Request (CCR).
     *
     * This function processes a Certificate Creation Request (CCR).
     * It will return a string containing the PEM encoded certificate.
     *
     * @param ccr The CCR to process
     * @param timeout The timeout for the processing
     * @param cert_pv_prefix the CMS pv prefix
     * @param issuer_id the issuer ID of the CMS
     * @return The PEM encoded certificate
     */
    std::tuple<time_t, std::string> processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr,
                                                  const std::string &cert_pv_prefix,
                                                  const std::string &issuer_id,
                                                  double timeout,
                                                  const std::shared_ptr<KeyPair> &key_pair = {},
                                                  const CertData &held_before_request = {},
                                                  const std::string &expected_issuer_id = {}) const;

    /**
     * @brief Update the definitions with the authenticator-specific definitions.
     *
     * This function is called from PVACMS to update the definitions with the authenticator-specific definitions.
     * It updates the given definitions with the authenticator-specific definitions.
     *
     * @param defs the definitions to update with the authenticator-specific definitions
     */
    virtual void updateDefs(client::Config::defs_t &defs) const {}

    /**
     * @brief Registration of all supported auth methods.
     *
     * This static member is used to store all the supported authenticators.
     * The registration performed by each authenticator adds an entry to this map.
     * Registration is performed as follows:
     *
     * @code
     * #define PVXS_XXX_AUTH_TYPE "xxx"
     * struct AuthXxxRegistrar {
     *     AuthXxxRegistrar() {
     *         AuthRegistry::instance().registerAuth(PVXS_XXX_AUTH_TYPE, std::unique_ptr<Auth>(new AuthXxx()));
     *     }
     * } auth_n_xxx_registrar;
     * @endcode
     *
     * This will add an entry to the map for AuthXxx.
     */
    static std::map<const std::string, std::shared_ptr<Auth>> auths;

    /**
     * @brief Get the authenticator for the given type.
     *
     * This function returns a pointer to the authenticator for the given type.
     * Uses the authenticator map to find the authenticator for the given type.
     * If the type is not found, it will throw an exception.
     *
     * @param type The type of the authenticator
     * @return A pointer to the authenticator for the given type
     */
    static Auth *getAuth(const std::string &type);

    int runAuthNDaemon(const ConfigAuthN &authn_config,
                       bool for_client,
                       CertData &&cert_data,
                       const std::function<CertData()> &&fn);

 protected:
    // Called to have a standard presentation of the CCR for the
    // purposes of generating and verifying signatures
    static std::string ccrToString(const std::shared_ptr<CertCreationRequest> &ccr, const uint16_t &usage) {
        // Every organizational unit is covered, not just the innermost one, so that a value added
        // in flight cannot pass verification. A request carrying at most one unit produces the same
        // payload it did before units could repeat, so an older client still verifies here.
        return SB() << ccr->type                                                           // Type
                    << ccr->credentials->name                                              // Name
                    << ccr->credentials->country                                           // Country
                    << ccr->credentials->organization                                      // Organization
                    << joinOrganizationalUnits(ccr->credentials->organization_unit)        // Organizational Units
                    << ccr->credentials->not_before                                        // Not before
                    << ccr->credentials->not_after                                         // Not After
                    << ccr->credentials->config_uri_base                                   // Config URL Base
                    << usage;                                                              // Usage
    }

    // Called to have a standard presentation of the CCR for the
    // purposes of generating and verifying signatures
    static std::string ccrToString(const Value &ccr) {
        // Must produce byte for byte what the client-side overload above produced.
        return SB() << ccr["type"].as<std::string>()                              // Type
                    << ccr["name"].as<std::string>()                              // Name
                    << ccr["country"].as<std::string>()                           // Country
                    << ccr["organization"].as<std::string>()                      // Organization
                    << joinOrganizationalUnits(getOrganizationalUnits(ccr))       // Organizational Units
                    << ccr["not_before"].as<time_t>()                             // Not before
                    << ccr["not_after"].as<time_t>()                              // Not After
                    << ccr["config_uri_base"].as<std::string>()                   // Config URL Base
                    << ccr["usage"].as<uint16_t>();                               // Usage
    }

 private:
    server::Server config_server_{};
    class ConfigMonitorParams {
     public:
        const ConfigAuthN &config_;
        mutable ossl_ptr<X509> cert_{};
        const std::function<CertData()> fn_{};
        Value config_pv_value{getConfigurationPrototype()};

        ConfigMonitorParams(const ConfigAuthN &config, ossl_ptr<X509> &cert, const std::function<CertData()> &&fn)
            : config_(config), cert_(std::move(cert)), fn_(std::move(fn)) {}
    };

    static timeval configurationMonitor(std::shared_ptr<ConfigMonitorParams> config_monitor_params, server::SharedPV &pv);
    static std::string formatTimeDuration(time_t total_seconds);

    /**
     * @brief The prototype of the data returned for a certificate configuration PV
     *
     * A serial number, issuer ID, the keychain file and how long before it expires.
     * Each config change will update the serial number and expires_in value.
     * Keychain and issuer will stay the same
     *
     * @return The prototype of the data returned for a certificate configuration PV
     */
    static Value getConfigurationPrototype() {
        using namespace members;

        auto value = TypeDef(TypeCode::Struct,
                             {
                                 Member(TypeCode::UInt64, "serial"),
                                 Member(TypeCode::String, "issuer_id"),
                                 Member(TypeCode::String, "keychain"),
                                 Member(TypeCode::String, "renew_by"),
                             })
                         .create();
        return value;
    }

    /**
     * @brief Set a value in a Value object marking any changes to the field if the values changed and if not then
     * the field is unmarked.  Doesn't work for arrays or enums so you need to do that manually.
     *
     * @param target The Value object to set the value in
     * @param field The field to set the value in
     * @param new_value The new value to set
     */
    template <typename T>
    static void setValue(Value &target, const std::string &field, const T &new_value) {
        target[field] = new_value;
    }

    CCRManager ccr_manager_{};
};

/**
 * @brief Function to cast a pointer to a base class into a pointer to a
 * subclass
 *
 * This function checks if the given class S is a subclass of the given base
 * class C, then casts the given argument of type C into a pointer to S.
 *
 * @tparam S The derived class type
 * @tparam C The base class type
 * @param base_class A shared pointer to the base class object
 * @return A shared pointer to the derived class object if it is a subclass of
 * the base class, nullptr otherwise.
 *
 * @throws std::bad_cast If the cast from base class to derived class fails
 * @throws std::invalid_argument If S is not a subclass of C
 *
 * @note This function uses std::is_base_of to check for subclass relationship
 * and std::dynamic_pointer_cast for safe casting from base class to derived
 * class.
 *
 * @code
 *
 * // Example usage:
 *
 * class BaseClass {};
 * class DerivedClass : public BaseClass {};
 *
 * std::shared_ptr<BaseClass> base = std::make_shared<DerivedClass>();
 *
 * std::shared_ptr<DerivedClass> derived = castAs<DerivedClass>(base);
 *
 * if (derived != nullptr) {
 *  // Successfully casted to derived class
 * } else {
 *  // Not a subclass of derived class
 * }
 *
 * @endcode
 */
template <typename S, typename C>
std::shared_ptr<S> castAs(const std::shared_ptr<C> &base_class) {
    static_assert(std::is_base_of<C, S>::value, "not a subclass");
    return std::dynamic_pointer_cast<S>(base_class);
}

template <typename ConfigT, typename AuthT>
CertData getCertificate(bool &retrieved_credentials,
                        ConfigT config,
                        uint16_t cert_usage,
                        const AuthT &authenticator,
                        const std::string &tls_keychain_file,
                        const std::string &tls_keychain_pwd,
                        bool daemon_mode);

template <typename ConfigT, typename AuthT>
int runAuthenticator(int argc, char *argv[], std::function<void(ConfigT &, AuthT &)> pre_configure_hook = nullptr);

/**
 * @brief Issuer ID (SKID of the issuing certificate authority) carried by parsed cert data.
 *
 * Handles both keychain shapes:
 *  - an identity keychain: the leaf certificate plus its CA chain — the issuer is in the chain;
 *  - a trust-anchor-only keychain: the CA certificate is the sole/main certificate with no chain
 *    (as returned by `authnstd --trust-anchor`) — the issuer is that certificate itself.
 *
 * @throws std::runtime_error if no certificate authority can be identified.
 */
inline std::string certAuthorityIssuerId(const CertData &cert_data) {
    if (cert_data.cert_auth_chain && sk_X509_num(cert_data.cert_auth_chain.get()) > 0) {
        return CertStatus::getIssuerId(cert_data.cert_auth_chain);
    }
    if (cert_data.cert) {
        // Trust-anchor keychain: the authority is the certificate itself.
        return CertStatus::getSkId(cert_data.cert);
    }
    throw std::runtime_error("No certificate authority found to identify the issuer.");
}

/**
 * @brief The identifier of the certificate authority in cert data, computed from its public key.
 *
 * Deciding whether an authority is the expected one must never rest on the subject key identifier
 * extension: that is written by whoever produced the certificate, so an attacker substituting its
 * own authority simply writes the expected value into it and passes. Computing the identifier from
 * the public key removes that, because the attacker would have to find a key that hashes to the
 * expected value rather than just assert it.
 *
 * Returns the whole identifier, not a prefix. How much of it is compared is decided by the caller,
 * from how much they committed to in advance.
 *
 * @throws std::runtime_error if no certificate authority can be identified.
 */
inline std::string certAuthorityFullIssuerId(const CertData &cert_data) {
    if (cert_data.cert_auth_chain && sk_X509_num(cert_data.cert_auth_chain.get()) > 0) {
        return CertStatus::getFullSkId(CertStatus::getIssuerCa(cert_data.cert_auth_chain));
    }
    if (cert_data.cert) {
        // Trust-anchor keychain: the authority is the certificate itself.
        return CertStatus::getFullSkId(cert_data.cert.get());
    }
    throw std::runtime_error("No certificate authority found to identify the issuer.");
}

/**
 * @brief Whether an authority's identifier is the one committed to.
 *
 * The comparison runs over as much of the identifier as was committed to in advance. Someone who
 * pinned a certificate authority in a keychain has the whole thing and gets the whole thing
 * compared. Someone who typed the published short form gets that many digits compared, which is
 * all the form they used can carry; supplying more of it makes the check stronger.
 *
 * Compared without regard to case, since the identifier is written as hexadecimal either way.
 */
inline bool issuerIdIsExpected(const std::string &expected, const std::string &actual_full) {
    if (expected.empty() || expected.size() > actual_full.size()) return false;
    for (size_t i = 0; i < expected.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(expected[i]))
            != std::tolower(static_cast<unsigned char>(actual_full[i]))) return false;
    }
    return true;
}

/**
 * @brief Read the issuer ID of the certificate authority already trusted in a keychain file.
 *
 * If @p keychain_file exists and contains a certificate authority (a trust anchor downloaded by a
 * previous `--trust-anchor` run, or an existing identity keychain's CA chain), returns the issuer
 * ID pinned by that file. Returns an empty string if the file does not exist or carries no
 * authority. Never throws for a missing/unreadable file.
 *
 * @param keychain_file the keychain (p12) file to inspect
 * @param keychain_pwd the keychain password (may be empty)
 * @return the pinned issuer ID, or empty string if none
 */
inline std::string getTrustedIssuerId(const std::string &keychain_file, const std::string &keychain_pwd) {
    try {
        return certAuthorityFullIssuerId(IdFileFactory::create(keychain_file, keychain_pwd)->getCertDataFromFile());
    } catch (...) {
        // No existing keychain / no trusted authority — nothing pinned.
        return {};
    }
}

/**
 * @brief Refuse an issuer identifier that is too short to decide what to trust.
 *
 * @throws std::runtime_error naming the value and what is needed.
 */
inline void requireCompleteIssuerId(const std::string &issuer_id) {
    if (issuerIdIsComplete(issuer_id)) return;
    throw std::runtime_error(
        SB() << "The issuer '" << issuer_id << "' is only " << issuer_id.size()
             << " of the " << kIssuerIdFullLength
             << " digits of a subject key identifier, which is not enough to decide which certificate "
                "authority to trust. Nothing is trusted yet, so this identifier is the only thing "
                "deciding it. Give the whole subject key identifier, as the certificate manager prints "
                "it at startup, or pre-provision a keychain holding the authority to trust.");
}

/**
 * @brief Resolve the issuer ID that the caller has committed to trust, for this request.
 *
 * Trust must be asserted out-of-band before a certificate is accepted, otherwise the initial
 * exchange silently trusts whatever certificate authority answers — a man-in-the-middle could
 * substitute its own authority and compromise all later operations (issue slac-epics/pvxs-cms#18).
 *
 * The expected issuer is resolved in priority order:
 *  1. If the keychain file already pins a certificate authority (its issuer ID is available),
 *     that pinned issuer is used — and, if `--issuer` was also given, the two must agree.
 *  2. Otherwise the explicitly-supplied `config.issuer_id` (`--issuer` / `EPICS_PVA_AUTH_ISSUER`).
 *
 * @throws std::runtime_error if neither a pinned trust anchor nor an explicit issuer is available.
 * @return the issuer ID to require of the delivered certificate authority
 */
inline std::string resolveExpectedIssuerId(const std::string &configured_issuer_id,
                                           const std::string &keychain_file,
                                           const std::string &keychain_pwd) {
    const std::string pinned_issuer_id = getTrustedIssuerId(keychain_file, keychain_pwd);

    if (!pinned_issuer_id.empty()) {
        if (!configured_issuer_id.empty() && !issuerIdIsExpected(configured_issuer_id, pinned_issuer_id)) {
            throw std::runtime_error(SB() << "Specified issuer '" << configured_issuer_id
                                          << "' does not match the certificate authority already trusted in the keychain ('"
                                          << pinned_issuer_id << "'). Refusing to change the trusted authority.");
        }
        return pinned_issuer_id;
    }

    if (configured_issuer_id.empty()) {
        throw std::runtime_error(
            "No trusted issuer available: specify the expected issuer with --issuer (or EPICS_PVA_AUTH_ISSUER), "
            "or pre-provision a keychain containing the certificate authority to trust (authnstd --trust-anchor --issuer <id>). "
            "This prevents silently trusting an authority delivered over an untrusted channel.");
    }

    // Nothing is pinned, so this identifier is the only thing deciding which authority is
    // trusted, and it has to be the whole one. The short form names an authority in a channel
    // name and constrains 32 bits, which is few enough that an authority whose identifier
    // begins with any wanted 32 bits can be generated in hours; trusting on that basis would
    // accept one so generated. Once an authority is pinned the short form is enough, because
    // the pinned value is what is compared.
    requireCompleteIssuerId(configured_issuer_id);
    return configured_issuer_id;
}

/**
 * @brief Verify that the certificate authority in delivered cert data matches the expected issuer.
 *
 * Works for both an identity keychain (CA in the chain) and a trust-anchor keychain (CA is the
 * certificate itself).
 *
 * @throws std::runtime_error if the delivered authority's issuer ID differs from @p expected_issuer_id.
 */
inline void verifyDeliveredIssuerId(const CertData &delivered, const std::string &expected_issuer_id) {
    const std::string delivered_issuer_id = certAuthorityFullIssuerId(delivered);
    if (!issuerIdIsExpected(expected_issuer_id, delivered_issuer_id)) {
        throw std::runtime_error(SB() << "Delivered certificate authority issuer '" << delivered_issuer_id
                                      << "' does not match the expected issuer '" << expected_issuer_id
                                      << "'. Rejecting — the authority may have been substituted in transit.");
    }
}

/**
 * @brief Get a certificate for the given authenticator
 *
 * This function gets a certificate for the given authenticator.
 *
 * @param retrieved_credentials the retrieved credentials flag - true if credentials were retrieved
 * @param config the configuration to use for the certificate
 * @param cert_usage the certificate usage client, server, or ioc
 * @param authenticator the authenticator to use for the certificate
 * @param tls_keychain_file the TLS keychain file to use for the certificate
 * @param tls_keychain_pwd the TLS keychain password to use for the certificate, none if empty
 * @param daemon_mode
 * @return The certificate data
 */
template <typename ConfigT, typename AuthT>
CertData getCertificate(bool & /*retrieved_credentials*/,
                        ConfigT config,
                        uint16_t cert_usage,
                        const AuthT &authenticator,
                        const std::string &tls_keychain_file,
                        const std::string &tls_keychain_pwd,
                        bool daemon_mode) {
    CertData cert_data;

    if (auto credentials = authenticator.getCredentials(config, IS_USED_FOR_(cert_usage, pvxs::ssl::kForClient))) {
        // If daemon mode, then add base uri to credentials
        if (daemon_mode) credentials->config_uri_base = config.getCertPvPrefix();

        std::shared_ptr<KeyPair> key_pair;
        log_debug_printf(auth, "Credentials retrieved for: %s authenticator\n", authenticator.type_.c_str());

        // What the keychain held before the request was sent. Anything an authenticator
        // has to trust while reading the reply must come from here rather than from the
        // reply itself.
        CertData held_before_request;
        try {
            held_before_request = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
        } catch (...) {
            // Nothing held yet. Expected on a first run.
        }

        // Get or create the key pair.  Store it in the keychain file if not already present
        try {
            // Check if the key pair exists
            key_pair = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getKeyFromFile();
        } catch (std::exception &e) {
            // Make a new key pair file
            try {
                log_debug_printf(auth, "%s\n", e.what());
                key_pair = IdFileFactory::createKeyPair();
            } catch (std::exception &new_e) {
                throw std::runtime_error(SB() << "Error creating client key: " << new_e.what());
            }
        }

        // Create a Certificate Creation Request (CCR) using the credentials and key pair
        auto cert_creation_request = authenticator.createCertCreationRequest(credentials, key_pair, cert_usage, config);

        log_debug_printf(auth, "CCR created for: %s Authenticator\n", authenticator.type_.c_str());

        // Attempt to create a certificate with the Certificate Creation Request (CCR)
        time_t renew_by;
        std::string p12_pem_string;
        std::tie(renew_by, p12_pem_string) = authenticator.processCertificateCreationRequest(cert_creation_request,
                                                                              config.getCertPvPrefix(),
                                                                              config.issuer_id,
                                                                              config.getRequestTimeout(),
                                                                              key_pair,
                                                                              held_before_request,
                                                                              expected_issuer_id);

        // If the certificate was created successfully, write it to the keychain file
        if (!p12_pem_string.empty()) {
            log_debug_printf(auth, "Cert generated by PVACMS and successfully received: %s\n", p12_pem_string.c_str());

            // Attempt to write the certificate and private key to a cert file protected by the configured password
            auto file_factory =
                IdFileFactory::create(tls_keychain_file, tls_keychain_pwd, key_pair, nullptr, nullptr, p12_pem_string);
            file_factory->writeIdentityFile();
            std::cout << "Keychain file created   : " << tls_keychain_file << std::endl;

            // Read the certificate and private key back from the keychain file for info and verification
            cert_data = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
            const auto serial_number = CertStatusFactory::getSerialNumber(cert_data.cert);
            const auto issuer_id = CertStatus::getIssuerId(cert_data.cert_auth_chain);

            // Get the start and end dates of the certificate
            const std::string from = CertDate(credentials->not_before).s;
            const auto expiration_t = CmsStatusManager::getExpirationDateFromCert(cert_data.cert);
            const std::string expiration_s = CertDate(expiration_t).s;

            // Log the certificate info
            log_info_printf(auth, "   CERT ID: %s\n", getCertId(issuer_id, serial_number).c_str());
            log_info_printf(auth, "AUTHN TYPE: %s\n", authenticator.type_.c_str());
            log_info_printf(auth, " OUTPUT TO: %s\n", tls_keychain_file.c_str());
            log_info_printf(auth, "SUBJECT CN: %s\n", credentials->name.c_str());
            if (!credentials->organization.empty()) log_info_printf(auth, "SUBJECT  O: %s\n", credentials->organization.c_str());
            // One line per unit, innermost first, so the whole containment path is visible
            for (const auto &organization_unit : credentials->organization_unit)
                log_info_printf(auth, "SUBJECT OU: %s\n", organization_unit.c_str());
            if (!credentials->country.empty()) log_info_printf(auth, "SUBJECT  C:%s\n", credentials->country.c_str());
            log_info_printf(auth, "VALID FROM: %s\n", from.c_str());
            if (renew_by) {
                const std::string renew_by_date = CertDate(renew_by).s;
                log_info_printf(auth, "RENEWAL BY: %s\n", renew_by_date.c_str());
            }
            log_info_printf(auth, "EXPIRES ON: %s\n", expiration_s.c_str());
            std::cout << "Certificate identifier  : " << issuer_id << ":" << serial_number << std::endl;
            log_info_printf(auth, "--------------------------------------%s", "\n");
        }
    }
    return cert_data;
}

/** What the daemon's status monitor should do with the certificate it is monitoring,
 *  given a status update from the CMS. */
enum class CertStatusAction { None, MintNew, ExitNonRenewable };

/** Is the certificate's renew_by usable, i.e. renewable?
 *  Renewable means: renewable = non-zero renew_by strictly before the cert's not_after.
 *  Both arguments must be Unix time_t in the same epoch. A renew_by on or after not_after
 *  is NOT usable, because the cert cannot be renewed once it has expired.
 *  Pure (no I/O) so it can be unit-tested without a certificate. */
inline bool usableRenewBy(const time_t renew_by_unix, const time_t not_after) {
    return (renew_by_unix != 0) && (renew_by_unix < not_after);
}

/** Decide what the daemon's status monitor should do for a received status update.
 *  Pure (no I/O) so it can be unit-tested.
 *
 *  This evaluates the certificate the daemon already holds against the live status the CMS
 *  reports, on both the first (initial) update and every subsequent one:
 *   - REVOKED/EXPIRED  => MintNew (the held cert is bad; request a fresh one),
 *   - no usable renew_by => ExitNonRenewable (the cert can never be renewed in time, so stop
 *     the daemon with a distinct exit code rather than restart-loop),
 *   - otherwise          => None (keep monitoring; renewal_due drives the actual renewal).
 *
 *  has_usable_renew_by means "has a USABLE renew_by": renewable = non-zero renew_by strictly
 *  before the cert's not_after (see usableRenewBy). */
inline CertStatusAction certStatusAction(const certstatus_t status, const bool has_usable_renew_by) {
    if (status == REVOKED || status == EXPIRED) return CertStatusAction::MintNew;
    if (!has_usable_renew_by) return CertStatusAction::ExitNonRenewable;
    return CertStatusAction::None; // VALID/PENDING*; renewal_due drives the renewal itself
}

/**
 * @brief Run the authenticator
 *
 * This function runs the authenticator to get a certificate.  It may run in daemon mode
 * if the daemon flag is set.
 *
 * It assumes that readParameters exists with the correct signature for the templated ConfigT
 * and returns a non-zero exit status if it fails.
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @param pre_configure_hook the pre configure hook to call before the authenticator is configured
 * @return The exit status 0 if successful, non-zero if an error occurs and we should exit
 */
template <typename ConfigT, typename AuthT>
int runAuthenticator(int argc, char *argv[], std::function<void(ConfigT &, AuthT &)> pre_configure_hook) {
    AuthT authenticator{};
    logger_config_env();
    bool retrieved_credentials{false};

    try {
        auto config = ConfigT::fromEnv();

        bool verbose{false}, debug{false}, daemon_mode{false}, force{false};
        uint16_t cert_usage{pvxs::ssl::kForClient};

        const auto parse_result = readParameters(argc, argv, config, verbose, debug, cert_usage, daemon_mode, force);
        if (parse_result)
            return parse_result == -1 ? 0 : parse_result;

        if (verbose) {
            logger_level_set(std::string("pvxs.auth." + authenticator.type_ + "*").c_str(), pvxs::Level::Info);
            logger_level_set(std::string("pvxs.auth.ccr").c_str(), pvxs::Level::Info);
        }
        if (debug)
            logger_level_set(std::string("pvxs.auth." + authenticator.type_ + "*").c_str(), pvxs::Level::Debug);

        // Execute a special case hook if provided
        if (pre_configure_hook) pre_configure_hook(config, authenticator);

        authenticator.configure(config);

        if (verbose) std::cout << "Effective config\n" << config << std::endl;

        const std::string tls_keychain_file =
            IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_file : config.tls_keychain_file;
        const std::string tls_keychain_pwd =
            IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_pwd : config.getKeychainPassword();

        CertData cert_data;
        try {
            auto new_cert_data = IdFileFactory::create(tls_keychain_file, tls_keychain_pwd)->getCertDataFromFile();
            const auto now = timeNow();
            const auto not_after_time =
                (!new_cert_data.cert) ? 0 : CertFactory::getNotAfterTimeFromCert(new_cert_data.cert);
            if (not_after_time > now) {
                cert_data = std::move(new_cert_data);
            }
        } catch (std::exception &) {}

        if (daemon_mode && cert_data.cert && !force) {
            // Decide here only what can be known locally, without any network I/O: does the
            // existing certificate carry an online status PV extension? If it does NOT (or there
            // is no cert file at all, handled above), behave as normal and mint a fresh cert.
            // If it does, adopt the existing cert and start the daemon: the status monitor then
            // fetches the initial status and handles renew-by / revoked / expired (and PVACMS
            // connect/disconnect) itself, rather than doing a separate blocking status request
            // here. See RenewalManager in auth.cpp.
            bool has_status_ext = true;
            try {
                (void)CmsStatusManager::getStatusPvFromCert(cert_data.cert);
            } catch (const CertStatusNoExtensionException&) {
                has_status_ext = false;
            }
            if (!has_status_ext) {
                cert_data = CertData{}; // no online status => mint as normal (one-shot mint path)
            }
        }

        if (!cert_data.cert || force) {
            cert_data = getCertificate(retrieved_credentials,
                                       config,
                                       cert_usage,
                                       authenticator,
                                       tls_keychain_file,
                                       tls_keychain_pwd, daemon_mode);
        } else if (!daemon_mode) {
            log_warn_printf(auth,
                            "%s: Valid certificate found: Use `--force` flag to overwrite\n",
                            tls_keychain_file.c_str());
        }

        if (cert_data.cert && daemon_mode) {
            return authenticator.runAuthNDaemon(config,
                                         IS_USED_FOR_(cert_usage, pvxs::ssl::kForClient),
                                         std::move(cert_data),
                                         [&retrieved_credentials,
                                          config,
                                          cert_usage,
                                          authenticator,
                                          tls_keychain_file,
                                          tls_keychain_pwd, &daemon_mode] {
                                             return getCertificate(retrieved_credentials,
                                                                   config,
                                                                   cert_usage,
                                                                   authenticator,
                                                                   tls_keychain_file,
                                                                   tls_keychain_pwd, daemon_mode);
                                         });
        }
        return 0;
    } catch (std::exception &e) {
        // Any exception reaching here is a hard failure of the certificate
        // request (e.g. PVACMS rejected the CCR, RPC/keychain failure). It must
        // surface as an error, not a warning.
        log_err_printf(auth, "%s\n", e.what());
        return -1;
    }
}

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_H
