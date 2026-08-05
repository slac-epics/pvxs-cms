/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnstd.h"

#include <pvxs/log.h>

#include "authregistry.h"
#include "certfactory.h"
#include "certfilefactory.h"
#include "certrequestid.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "configstd.h"
#include "openssl.h"
#include "p12filefactory.h"

#include <CLI/CLI.hpp>

DEFINE_LOGGER(auth, "pvxs.auth.std");

namespace pvxs {
namespace certs {

/**
 * @brief Registrar for the standard authenticator
 *
 * This will register the Standard authenticator with the AuthRegistry.
 * This allows it to be found by PVACMS to authenticate Standard certificate
 * creation requests (CCRs).
 *
 * The Standard authenticator uses the commandline, environment, or user/hostname
 * information to create the credentials for the certificate.
 */
struct AuthNStdRegistrar {
    AuthNStdRegistrar() {  // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_DEFAULT_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNStd()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_std_registrar;

/**
 * @brief Extract the country code from the given locale string
 *
 * This will extract the country code from a locale string.  It works by finding
 * the country part of the locale string, which is always after an underscore.
 * It then converts the country code to uppercase and returns it.
 *
 * @param locale_str the locale string to extract the country code from
 * @return the country code extracted from the locale string
 */
static std::string extractCountryCode(const std::string &locale_str) {
    // Look for underscore
    const auto pos = locale_str.find('_');
    if (pos == std::string::npos || pos + 3 > locale_str.size()) {
        return "";
    }

    std::string country_code = locale_str.substr(pos + 1, 2);
    std::transform(country_code.begin(), country_code.end(), country_code.begin(), toupper);
    return country_code;
}

/**
 * @brief Get the current country code of where the process is running.
 *
 * This returns the two-letter country code.  It is always upper case.
 * For example for the United States it returns `US`, and for France, `FR`.
 *
 * The fact that a locale string is not always available and that the country part is optional
 * means that it rarely works.  It tries the following:
 *
 * 1. Try from std::locale("")
 * 2. Try from the LANG environment variable
 * 3. Default to "US" if both attempts failed
 *
 * @return the current country code of where the process is running
 */
static std::string getCountryCode() {
    // 1. Try from std::locale("")
    {
        const std::locale loc("");
        const std::string name = loc.name();
        if (name != "C" && name != "POSIX") {
            std::string cc = extractCountryCode(name);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 2. If we failed, try the LANG environment variable
    {
        const char *lang = std::getenv("LANG");
        if (lang && *lang) {
            const std::string locale_str(lang);
            std::string cc = extractCountryCode(locale_str);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 3. Default to "US" if both attempts failed
    return "US";
}

/**
 * @brief Creates credentials for use in creating a certificate.
 *
 * This function retrieves the credentials required for the creation of an X.509
 * certificate.  It uses supplied parameters, environment variables, current logged-on username/hostname,
 * or the current country code of where the process is running to obtain the common name,
 * organization, organizational unit, and country needed for the subject of the certificate.
 *
 * - If username is not specified in either the commandline or environment then use the logged-in username
 * - If organization is not specified in either the commandline or environment then use the hostname of the machine
 * - If organizational unit is not specified in either the commandline or environment then leave blank
 * - If country is not specified in either the commandline or environment then use the current
 *   country code of where the process is running or default to "US"
 *
 * @param config The ConfigStd object containing the environment variables optionally overridden by commandline
 * parameters and pre-filled with default values.
 * @param for_client true if getting credentials for a client
 * @return A structure containing the credentials required for the creation of a certificate.
 */
std::shared_ptr<AuthnCredentials> AuthNStd::getCredentials(const client::Config &config, const bool for_client) const {
    const auto &std_config = dynamic_cast<const ConfigStd &>(config);

    log_debug_printf(auth,
                     "\n******************************************\nDefault, "
                     "Standard Authenticator: %s\n",
                     "Begin acquisition");

    auto std_credentials = std::make_shared<DefaultCredentials>();

    // Set the expiration time of the certificate
    const time_t now = timeNow();
    std_credentials->not_before = now;
    if (std_config.cert_validity_mins <= 0)
        std_credentials->not_after = 0;
    else
        std_credentials->not_after = now + std_config.cert_validity_mins * 60;

    if (std_config.trust_anchor_only) {
        std_credentials->name = "";
        std_credentials->organization = "";
        std_credentials->organization_unit = {};
        std_credentials->country = "";
        log_debug_printf(auth, "Trust Anchor%s\n", "");
        return std_credentials;
    }
    if (for_client) {
        if (!std_config.name.empty())
            std_credentials->name = std_config.name;
        if (!std_config.organization.empty())
            std_credentials->organization = std_config.organization;
        if (!std_config.organizational_unit.empty())
            std_credentials->organization_unit = std_config.organizational_unit;
        if (!std_config.country.empty())
            std_credentials->country = std_config.country;
        else
            std_credentials->country = getCountryCode();
    } else {
        if (!std_config.server_name.empty())
            std_credentials->name = std_config.server_name;
        if (!std_config.server_organization.empty())
            std_credentials->organization = std_config.server_organization;
        if (!std_config.server_organizational_unit.empty())
            std_credentials->organization_unit = std_config.server_organizational_unit;
        if (!std_config.server_country.empty())
            std_credentials->country = std_config.server_country;
        else
            std_credentials->country = getCountryCode();
    }

    log_debug_printf(auth,
                     "Standard Credentials retrieved for: %s@%s\n",
                     std_credentials->name.c_str(),
                     std_credentials->organization.c_str());

    return std_credentials;
}

/**
 * @brief Create a PVStructure that corresponds to the ccr parameter of a Certificate Creation Request (CCR).
 *
 * This request will be sent to the PVACMS through the default channel (PV Access) and will be used to create the
 * certificate.
 *
 * @param credentials the credentials that describe the subject of the certificate
 * @param key_pair the public/private key to be used in the certificate, only public key is used
 * @param usage certificate usage
 * @param config the configuration for the certificate creation request
 * @return A managed shared CertCreationRequest object.
 */
std::shared_ptr<CertCreationRequest> AuthNStd::createCertCreationRequest(
    const std::shared_ptr<AuthnCredentials> &credentials,
    const std::shared_ptr<KeyPair> &key_pair,
    const uint16_t &usage,
    const ConfigAuthN &config) const {
    auto cert_creation_request = Auth::createCertCreationRequest(credentials, key_pair, usage, config);

    return cert_creation_request;
}

/**
 * @brief Verify the Certificate Creation Request (CCR)
 *
 * This implementation simply returns true, since the credentials presented in the CCR are trusted.
 * The assumption is that the CCR is either coming from a trustworthy source, or it will
 * require a manual approval step, which would likely involve an administrator making a
 * PUT request to the status PV included as an extension in the certificate to approve the certificate.
 *
 * @param ccr the Certificate Creation Request (CCR)
 * @param authenticated_expiration_date
 * @return true if the Certificate Creation Request (CCR) is valid
 */
bool AuthNStd::verify(Value &ccr, time_t &authenticated_expiration_date) const {
    // For standard auth, the authorized expiration is simply what was requested
    // Since this authenticator doesn't provide any additional constraints
    authenticated_expiration_date = ccr["not_after"].as<uint32_t>();
    return true;
}

/**
 * @brief The members this authenticator adds to a certificate creation reply.
 *
 * Two byte arrays: the encrypted request identifier and the signature over it. Byte arrays
 * rather than text, because PVAccess carries them natively and base64 here would only add an
 * encoding step and a decoding failure mode.
 *
 * Declaring them does not mean every reply carries them. A reply for a request that is not
 * awaiting approval leaves both empty, and the requesting side treats that as nothing to do.
 */
std::vector<Member> AuthNStd::responseFields() const {
    return {
        members::UInt8A("request_id"),
        members::UInt8A("signature"),
    };
}

/**
 * @brief Return the request identifier, encrypted to the key that asked for the certificate.
 *
 * Encrypted to the requester's public key, so only the holder of the matching private key can
 * read it, and signed by the certificate authority over bytes that bind it to this certificate
 * and this key. Someone who substituted their own key in the request cannot read it, so the
 * real requester never gets an identifier to email and no approval happens.
 *
 * Nothing is written when the service recorded no identifier for this request, which is every
 * request that is not awaiting approval.
 */
void AuthNStd::fillCreateResponse(const Value &ccr, Value &reply, const CreateResponseContext &context) const {
    if (context.request_id.empty()) return;

    if (!context.cert_auth_pkey || !*context.cert_auth_pkey) {
        throw std::runtime_error("No certificate authority key to sign the certificate request identifier with");
    }

    const auto pub_key = ccr["pub_key"].as<std::string>();
    const auto cert_id = reply["cert_id"].as<std::string>();
    const auto pub_key_digest = publicKeyDigest(pub_key);

    const auto payload = buildRequestIdPayload(context.request_id, cert_id, pub_key_digest, timeNow());
    const auto ciphertext = encryptToRequester(pub_key, payload);
    const auto signature = CertFactory::sign(*context.cert_auth_pkey,
                                             requestIdSignedBytes(cert_id, pub_key_digest, ciphertext));

    reply["authenticator.request_id"] = shared_array<const uint8_t>(ciphertext.begin(), ciphertext.end());
    reply["authenticator.signature"] = shared_array<const uint8_t>(signature.begin(), signature.end());
}

/**
 * @brief Read the request identifier out of a reply and tell the requester to email it.
 *
 * The order here decides what a failure means, so it is fixed: rebuild what the signature
 * covers from what we already hold, verify the signature, only then decrypt, then check the
 * identifier really was issued for this certificate and this key, and only then print.
 *
 * Verifying before decrypting means a corrupted or substituted package is refused on the
 * signature rather than reported as a decryption failure, which would read as though our own
 * key were wrong.
 *
 * Every failure is loud and prints no identifier. A failure to decrypt is the visible form of
 * a public key substituted in transit, which is the whole point of this, so it must never be
 * mistaken for nothing to report.
 */
void AuthNStd::handleCreateResponse(const Value &reply,
                                    const std::shared_ptr<KeyPair> &key_pair,
                                    const CertData &held_before_request,
                                    const std::string &expected_issuer_id) const {
    const auto ciphertext_value = reply["authenticator.request_id"];
    const auto signature_value = reply["authenticator.signature"];
    if (!ciphertext_value || !signature_value) return;

    const auto ciphertext = ciphertext_value.as<shared_array<const uint8_t>>();
    const auto signature = signature_value.as<shared_array<const uint8_t>>();
    if (ciphertext.empty() || signature.empty()) return;  // nothing awaiting approval

    if (!key_pair || !key_pair->pkey) {
        throw std::runtime_error("No key pair to read the certificate request identifier with");
    }

    const auto cert_id = reply["cert_id"].as<std::string>();
    const auto pub_key_digest = publicKeyDigest(key_pair->pkey.get());

    // Which key verifies the signature depends on what was committed to before the request was
    // sent, and the two are not equally strong. A certificate authority already in the keychain
    // needs nothing from this reply. Otherwise the authority delivered in this reply is used,
    // and that is only sound because the reply's authority has already been matched against an
    // issuer the operator supplied out of band; a signature checked with a key taken from the
    // same reply proves nothing, so those two steps must not be separated.
    ossl_ptr<EVP_PKEY> authority_key;
    if (held_before_request.cert_auth_chain && sk_X509_num(held_before_request.cert_auth_chain.get()) > 0) {
        authority_key.reset(X509_get_pubkey(CertStatus::getIssuerCa(held_before_request.cert_auth_chain)));
    } else if (held_before_request.cert) {
        authority_key.reset(X509_get_pubkey(held_before_request.cert.get()));
    } else {
        const auto delivered = reply["cert"];
        if (!delivered) {
            throw std::runtime_error(
                "The reply carries a certificate request identifier but no certificate authority to check its "
                "signature against");
        }
        const auto cert_data = certDataFromPem(delivered.as<std::string>());

        // The commitment made before the request was sent is what makes this sound. Checking it
        // here, immediately before the key is used, rather than relying on a later check
        // elsewhere: a signature verified with a key taken from the same reply proves nothing,
        // so nothing may come between these two lines.
        verifyDeliveredIssuerId(cert_data, expected_issuer_id);

        if (cert_data.cert_auth_chain && sk_X509_num(cert_data.cert_auth_chain.get()) > 0) {
            authority_key.reset(X509_get_pubkey(CertStatus::getIssuerCa(cert_data.cert_auth_chain)));
        } else if (cert_data.cert) {
            authority_key.reset(X509_get_pubkey(cert_data.cert.get()));
        }
    }
    if (!authority_key) {
        throw std::runtime_error(
            "No certificate authority public key to check the certificate request identifier's signature against");
    }

    const std::vector<uint8_t> covered = requestIdSignedBytes(
        cert_id, pub_key_digest, std::vector<uint8_t>(ciphertext.begin(), ciphertext.end()));
    if (!CertFactory::verifySignature(authority_key, covered,
                                      std::vector<uint8_t>(signature.begin(), signature.end()))) {
        throw std::runtime_error(
            "The certificate request identifier is not signed by the certificate authority this request trusts. "
            "Refusing it: the reply may have been changed in transit");
    }

    const auto payload = decryptWithRequesterKey(
        key_pair, std::vector<uint8_t>(ciphertext.begin(), ciphertext.end()));
    const auto parsed = parseRequestIdPayload(payload, cert_id, pub_key_digest);

    std::cout << "email this Certificate Request ID: " << requestIdForDisplay(parsed.request_id)
              << ", to your SPVA administrator for approval" << std::endl;
}

}  // namespace certs
}  // namespace pvxs
