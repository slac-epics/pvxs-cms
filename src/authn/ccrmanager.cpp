/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "ccrmanager.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>

#include "auth.h"
#include "certfactory.h"
#include "certstatus.h"
#include "openssl.h"
#include "security.h"
#include "trustanchors.h"

DEFINE_LOGGER(auth_log, "pvxs.auth.ccr");

namespace pvxs {
namespace certs {

using namespace members;

void CCRManager::checkIssuedOrganizationalUnits(const std::vector<std::string> &requested, const std::string &pem_string) {
    const ossl_ptr<BIO> bio(BIO_new_mem_buf(pem_string.data(), static_cast<int>(pem_string.size())), false);
    if (!bio) throw std::runtime_error("Unable to read the certificate that was issued");
    const ossl_ptr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), false);
    if (!cert) throw std::runtime_error("Unable to read the certificate that was issued");

    const auto issued = getSubjectOrganizationalUnits(X509_get_subject_name(cert.get()));
    if (issued == requested) return;

    throw std::runtime_error(SB() << "The certificate that was issued does not carry the organizational units that "
                                     "were asked for: asked for "
                                  << joinOrganizationalUnits(requested) << ", was issued " << joinOrganizationalUnits(issued)
                                  << ". A certificate manager that predates nested organizational units drops all but "
                                     "the innermost one, which claims a different and broader identity, so the "
                                     "keychain file has not been written.");
}

/**
 * @brief Create a certificate
 *
 * This function creates a certificate from the given Certificate Creation Request (CCR).
 *
 * @param cert_creation_request Certificate Creation Request (CCR)
 * @param cert_pv_prefix the CMS pv prefix
 * @param issuer_id the issuer ID of the CMS
 * @param timeout Timeout for the request
 * @param timeout Timeout for the request
 * @return std::string PEM format Certificate.
 */
std::tuple<time_t, std::string> CCRManager::createCertificate(const std::shared_ptr<CertCreationRequest> &cert_creation_request,
                                                              const std::string &cert_pv_prefix,
                                                              const std::string &issuer_id,
                                                              const double timeout,
                                                              const std::shared_ptr<KeyPair> &key_pair,
                                                              const CertData &held_before_request,
                                                              const std::string &expected_issuer_id) {
    auto uri = nt::NTURI({}).build();
    uri += {Struct("query", CCR_PROTOTYPE(cert_creation_request->verifier_fields))};
    auto arg = uri.create();

    // Set values of request argument
    const auto create_pv = issuer_id.empty() ? getCertCreatePv(cert_pv_prefix) : getCertCreatePv(cert_pv_prefix, issuer_id);
    arg["path"] = create_pv;
    arg["query"].from(cert_creation_request->ccr);

    // Ask over TLS where the keychain already holds an authority to verify the answer against,
    // and fall back to plain TCP where it does not.
    //
    // This is the step that turns a trust anchor into an identity, and a server that accepts TLS
    // alone answers nothing else, so a holder on the far side of such a server can only ask this
    // way. The request presents no identity of its own - the point of it is that there is not one
    // yet - so the connection is anonymous whichever transport carries it, and the answer is
    // still verified against the authority the keychain already holds. Remote verification is
    // enabled so that a holder whose own certificate status cannot be established from where it stands is
    // not held back by it.
    //
    // Plain TCP is kept as the fallback rather than dropped. A holder with no anchor at all has
    // no other way to ask, and neither has one whose own certificate no longer stands, because a
    // server refuses a TLS connection from a holder it can see has been revoked. Asking again in
    // the clear is what lets such a holder be issued a replacement.
    // Asked of what the keychain actually holds, not of whether a keychain was named. Every
    // holder names one, including the ones that have never had a file there, so naming one says
    // nothing about whether there is an authority to verify an answer against.
    const auto holds_an_authority = !cms::cert::heldAnchorIds(held_before_request).empty();

    const auto base_config = client::Config::fromEnv();
    Value value;
    bool answered = false;
    if (holds_an_authority && base_config.isTlsConfigured()) {
        auto tls_config = base_config;
        // This request is made where the holder cannot reach the certificate manager to
        // establish its own certificate status, which is the whole reason it is asking.
        tls_config.disableOwnCertStatusCheck();
        try {
            auto tls_client = tls_config.build();
            value = tls_client.rpc(create_pv, arg).exec()->wait(timeout);
            answered = true;
        } catch (const std::exception &) {
            // No answer over TLS, or no usable keychain to offer one with. Ask in the clear.
        }
    }

    if (!answered) {
        auto config = base_config;
        config.tls_disabled = true;
        auto client = config.build();
        try {
            value = client.rpc(create_pv, arg).exec()->wait(timeout);
        } catch (const client::Timeout &) {
            // Nothing answered. The name carries the authority being asked, so say which one:
            // an authority that has been minted again has a different one, and a request naming
            // the previous one reaches a name nothing serves.
            throw std::runtime_error(SB() << "No certificate manager answered " << create_pv << " within "
                                          << timeout << " seconds. Nothing serves that name, so either no "
                                          << "certificate manager for this authority is running, or it cannot "
                                          << "be reached from here.");
        }
    }

    std::string pem_string;
    auto pem_val = value["cert"];
    if ( pem_val ) {
        pem_string = pem_val.as<std::string>();
        // Only when more than one unit was asked for: a single unit travels in the field every
        // certificate manager reads, so there is nothing that can be silently dropped.
        const auto &requested_units = cert_creation_request->credentials->organization_unit;
        if (requested_units.size() > 1) CCRManager::checkIssuedOrganizationalUnits(requested_units, pem_string);
        log_info_printf(auth_log, "X.509 certificate(%s)\n", value["state"].as<std::string>().c_str());
    } else {
        log_info_printf(auth_log, "X.509 certificate RENEWED (%s)\n", value["state"].as<std::string>().c_str());
    }
    log_debug_printf(auth_log, "%s\n", value["value.index"].as<std::string>().c_str());
    log_debug_printf(auth_log, "%llu\n", (unsigned long long)value["serial"].as<serial_number_t>());
    log_debug_printf(auth_log, "%s\n", value["issuer"].as<std::string>().c_str());
    log_debug_printf(auth_log, "%s\n", value["cert_id"].as<std::string>().c_str());
    log_debug_printf(auth_log, "%s\n", value["status_pv"].as<std::string>().c_str());
    // An authenticator only hears about a reply that carries a part for it, so one that
    // adds nothing is never entered and nothing about its path changes.
    if (const auto authenticator_part = value["authenticator"]) {
        (void)authenticator_part;
        Auth::getAuth(cert_creation_request->type)
            ->handleCreateResponse(value, key_pair, held_before_request, expected_issuer_id);
    }

    const auto renew_by_val = value["renew_by"];
    const CertDate expiration_date(value["expiration"].as<time_t>());
    log_debug_printf(auth_log, "Expires On: %s\n", expiration_date.s.c_str() );
    if (renew_by_val) {
        const auto renew_by_t = renew_by_val.as<time_t>();
        const CertDate renew_by(renew_by_t);
        log_debug_printf(auth_log, "Renew By: %s\n", renew_by.s.c_str() );
        return {renew_by.t, pem_string};
    }
    return {0, pem_string};
}
}  // namespace certs
}  // namespace pvxs
