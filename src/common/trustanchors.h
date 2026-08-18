/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_TRUSTANCHORS_H
#define PVXS_TRUSTANCHORS_H

#include <algorithm>
#include <iomanip>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "certfilefactory.h"
#include "certstatus.h"
#include "ownedptr.h"
#include "utilpvt.h"

namespace cms {
namespace cert {

//! The refusal when a trust anchor is asked for without naming the authority to trust.
//!
//! Retrieving a trust anchor is the moment trust is established, and there is nothing pinned to
//! establish it against, so the authority has to be identified out of band.
constexpr const char *kNoIssuerNamedForTrustAnchor =
    "Refusing to download a trust anchor without --issuer (or EPICS_PVA_AUTH_ISSUER): "
    "the expected certificate authority must be identified to avoid trusting a substituted authority.";

//! Width of the label column the tools already print in, as in `Keychain file created   : `.
constexpr int kLabelColumnWidth = 24;

/**
 * @brief Whether a certificate is a trust anchor, which is a self-signed root.
 *
 * The same test the library uses when it decides what to put in a connection's trust store, so
 * that what the tools write and what the library trusts cannot disagree.
 */
inline bool isTrustAnchor(X509 *certificate) {
    return certificate && (X509_get_extension_flags(certificate) & EXFLAG_SS) != 0;
}

//! The certificates in a chain, in file order, as plain borrowed pointers.
inline std::vector<X509 *> certsInChain(const pvxs::ossl_shared_ptr<STACK_OF(X509)> &chain) {
    std::vector<X509 *> certificates;
    if (!chain) return certificates;
    for (int i = 0; i < sk_X509_num(chain.get()); i++) certificates.push_back(sk_X509_value(chain.get(), i));
    return certificates;
}

/**
 * @brief The trust anchors a keychain's chain holds, in file order.
 *
 * @param chain the certificate authority chain read from a keychain
 * @return the self-signed certificates in it, in the order the file holds them
 */
inline std::vector<X509 *> anchorsInChain(const pvxs::ossl_shared_ptr<STACK_OF(X509)> &chain) {
    std::vector<X509 *> anchors;
    for (X509 *certificate : certsInChain(chain))
        if (isTrustAnchor(certificate)) anchors.push_back(certificate);
    return anchors;
}

//! The certificate in @p pool that issued @p subject, or null when none of them did.
inline X509 *issuerOf(X509 *subject, const std::vector<X509 *> &pool) {
    if (!subject) return nullptr;
    for (X509 *candidate : pool) {
        if (!candidate || X509_cmp(candidate, subject) == 0) continue;
        if (X509_check_issued(candidate, subject) == X509_V_OK) return candidate;
    }
    return nullptr;
}

/**
 * @brief Follow the issuer of each certificate in turn until a trust anchor is reached.
 *
 * @param start the certificate to walk up from, which may itself be the anchor
 * @param available the certificates the invocation has to hand
 * @param anchors the anchors the file is to hold, searched after @p available
 * @param path filled in with each certificate stepped through, the anchor last
 * @return the anchor reached, or null when the walk runs out of material before one
 */
inline X509 *walkToAnchor(X509 *start,
                          const std::vector<X509 *> &available,
                          const std::vector<X509 *> &anchors,
                          std::vector<X509 *> &path) {
    X509 *node = start;
    // A certificate cannot be stepped through twice, so the material to hand bounds the walk and
    // a certificate that issued itself in a loop cannot spin here.
    for (size_t steps = 0; node && steps <= available.size() + anchors.size(); steps++) {
        if (isTrustAnchor(node)) return node;
        X509 *next = issuerOf(node, available);
        if (!next) next = issuerOf(node, anchors);
        if (!next) return nullptr;
        path.push_back(next);
        node = next;
    }
    return nullptr;
}

/**
 * @brief The trust anchor the keychain's identity chains to.
 *
 * Found by walking from the identity to the root it is issued under, not read from a position
 * among the anchors: nothing in the file marks which anchor is the primary one. A self-signed
 * identity is its own issuer and its own root, so it is its own primary. A file holding no
 * identity takes its first anchor.
 *
 * @param cert_data the keychain contents
 * @return the primary anchor, borrowed from @p cert_data
 * @throws std::runtime_error if the identity reaches no anchor, or the file holds none
 */
inline X509 *primaryAnchor(const pvxs::certs::CertData &cert_data) {
    const auto chain = certsInChain(cert_data.cert_auth_chain);

    if (cert_data.cert) {
        X509 *const identity = cert_data.cert.get();
        if (isTrustAnchor(identity)) return identity;

        X509 *const issuer = issuerOf(identity, chain);
        if (!issuer)
            throw std::runtime_error("The keychain's identity is not issued by any certificate authority the keychain holds");

        std::vector<X509 *> path;
        const std::vector<X509 *> no_anchors;
        if (X509 *const anchor = walkToAnchor(issuer, chain, no_anchors, path)) return anchor;
        throw std::runtime_error("The keychain's identity chains to no trust anchor the keychain holds");
    }

    const auto anchors = anchorsInChain(cert_data.cert_auth_chain);
    if (anchors.empty()) throw std::runtime_error("The keychain holds no trust anchor");
    return anchors.front();
}

//! The whole subject key identifier of each anchor a keychain holds, primary first.
//!
//! Primary comes first because that is the order `planAnchors` reads the held list in when
//! nothing is named and the primary anchor is the one asked to mint.
inline std::vector<std::string> heldAnchorIds(const pvxs::certs::CertData &cert_data) {
    std::vector<std::string> ids;
    const auto anchors = anchorsInChain(cert_data.cert_auth_chain);
    if (anchors.empty()) return ids;

    const auto add = [&ids](X509 *anchor) {
        std::string id;
        try {
            id = pvxs::certs::CertStatus::getFullSkId(anchor);
        } catch (const std::exception &) {
            return;  // an authority with no subject key identifier cannot be named at all
        }
        if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
    };

    try {
        add(primaryAnchor(cert_data));
    } catch (const std::exception &) {
        // A keychain whose identity chains to nothing it holds is already wrong. Report the
        // anchors it does hold in file order rather than reporting none.
    }
    for (X509 *anchor : anchors) add(anchor);
    return ids;
}

//! The whole subject key identifier of the primary anchor, or an empty string when there is none.
inline std::string primaryAnchorId(const pvxs::certs::CertData &cert_data) {
    try {
        return pvxs::certs::CertStatus::getFullSkId(primaryAnchor(cert_data));
    } catch (const std::exception &) {
        return {};
    }
}

/**
 * @brief The trust anchor a named certificate authority chains to, out of what is to hand.
 *
 * An authority that is its own root answers itself, which is every single-level authority. One
 * that signs from an intermediate answers the root above it, because it is the root a keychain
 * has to hold for the certificates that authority mints to verify.
 *
 * @param issuer_id the identifier as it was named, which may be a short form
 * @param pool every certificate the invocation has to hand
 * @return the anchor, borrowed from @p pool, or null when nothing to hand names that authority
 */
inline X509 *anchorForIssuerId(const std::string &issuer_id, const std::vector<X509 *> &pool) {
    for (X509 *candidate : pool) {
        if (!candidate) continue;
        std::string full;
        try {
            full = pvxs::certs::CertStatus::getFullSkId(candidate);
        } catch (const std::exception &) {
            continue;
        }
        if (!pvxs::certs::issuerIdIsExpected(issuer_id, full)) continue;
        if (isTrustAnchor(candidate)) return candidate;
        std::vector<X509 *> path;
        const std::vector<X509 *> no_anchors;
        if (X509 *const anchor = walkToAnchor(candidate, pool, no_anchors, path)) return anchor;
    }
    return nullptr;
}

/**
 * @brief Lay the whole certificate authority chain out afresh around the identity.
 *
 * Nothing is added to the chain the file held before, so a certificate's position says nothing
 * about when it was first trusted. With an identity, element 0 is that identity's issuer, which
 * is the one position in the chain that carries any meaning because `CertStatus::getIssuerCa`
 * reads it; then the anchor that identity chains to, with any intermediate on the way in issuing
 * order; then the remaining anchors in the order they were named; then any intermediate
 * certificate authority still unplaced, for a reader's benefit. With no identity there is
 * nothing to lead with, so element 0 is the first anchor to hold and the rest follow in order.
 *
 * Sameness is `X509_cmp`, over the whole encoded certificate, so nothing is written twice and a
 * single-level authority appears once, at element 0.
 *
 * The returned stack borrows its certificates: they must outlive it, and it must outlive the
 * write it is handed to.
 *
 * @param identity the certificate the file will hold, or null for a trust anchor only file
 * @param available every other certificate to hand, the delivered chain before the held one
 * @param anchors_to_hold the anchors the file is to hold, in the order they were named
 * @return the chain to write
 * @throws std::runtime_error if the identity's issuer is not to hand, or it chains to no anchor
 */
inline pvxs::ossl_ptr<STACK_OF(X509)> layOutChain(X509 *identity,
                                                  const std::vector<X509 *> &available,
                                                  const std::vector<X509 *> &anchors_to_hold) {
    pvxs::ossl_ptr<STACK_OF(X509)> chain(sk_X509_new_null());
    std::vector<X509 *> placed;

    const auto place = [&chain, &placed](X509 *certificate) {
        if (!certificate) return;
        for (X509 *already : placed)
            if (X509_cmp(already, certificate) == 0) return;
        if (!sk_X509_push(chain.get(), certificate))
            throw std::runtime_error("Unable to add a certificate to the keychain's certificate authority chain");
        placed.push_back(certificate);
    };

    if (!identity) {
        if (anchors_to_hold.empty())
            throw std::runtime_error("A keychain holding no identity has to hold at least one trust anchor");
        for (X509 *anchor : anchors_to_hold) place(anchor);
        return chain;
    }

    X509 *issuer = isTrustAnchor(identity) ? identity : issuerOf(identity, available);
    if (!issuer) issuer = issuerOf(identity, anchors_to_hold);
    if (!issuer)
        throw std::runtime_error(
            "The certificate authority that issued the identity is not among the certificates to hand, so the "
            "keychain cannot be written with that identity's issuer first.");
    place(issuer);

    std::vector<X509 *> path;
    if (!walkToAnchor(issuer, available, anchors_to_hold, path))
        throw std::runtime_error(
            "The identity chains to no trust anchor, counting what the keychain already holds together with the "
            "anchors about to be written.");
    for (X509 *step : path) place(step);

    for (X509 *anchor : anchors_to_hold) place(anchor);

    // Then any intermediate certificate authority still unplaced. Roots are deliberately left
    // out: an anchor the file held and this invocation is not to hold has been dropped, and
    // carrying it over here would put it straight back.
    for (X509 *candidate : available)
        if (candidate && !isTrustAnchor(candidate) && X509_check_ca(candidate)) place(candidate);

    return chain;
}

/**
 * @brief The chain a reset of the anchor set writes, refusing to strand the identity kept.
 *
 * The identity and its key already in the keychain are left in place, so that identity must
 * still chain to one of the roots about to be written. Without that refusal a command meant to
 * adjust trust would leave a holder with a perfectly good certificate that nothing in its own
 * file can verify.
 *
 * The check is made against what the file already holds together with the roots about to be
 * written and reaches no further: a keychain whose identity chains to nothing it holds is
 * already in a state it should not be in, and the remedy is to put it right rather than for the
 * tool to fetch more material to complete the chain with.
 *
 * Throwing rather than writing is the whole of "writes nothing": the caller has nothing to write
 * until this returns.
 *
 * @param held the keychain contents as they are now
 * @param anchors_to_hold the roots retrieved for the issuers named, in the order they were named
 * @return the chain to write
 * @throws std::runtime_error if the identity would be stranded, naming the authority it chains to
 */
inline pvxs::ossl_ptr<STACK_OF(X509)> chainForAnchorReset(const pvxs::certs::CertData &held,
                                                          const std::vector<X509 *> &anchors_to_hold) {
    if (held.cert) {
        X509 *const chains_to = primaryAnchor(held);
        bool named = false;
        for (X509 *const anchor : anchors_to_hold)
            if (X509_cmp(anchor, chains_to) == 0) named = true;
        if (!named)
            throw std::runtime_error(pvxs::SB()
                                     << "The identity in this keychain chains to the certificate authority '"
                                     << pvxs::certs::CertStatus::getFullSkId(chains_to)
                                     << "', which is not among the issuers named, so replacing the trust anchors "
                                        "would leave that identity unverifiable. Nothing has been written. Name "
                                        "that authority too, or remove the identity first.");
    }
    return layOutChain(held.cert.get(), certsInChain(held.cert_auth_chain), anchors_to_hold);
}

/**
 * @brief What one invocation was told, and what the keychain already held.
 */
struct AnchorPlanInput {
    //! The authorities named on this invocation, in the order they were named.
    std::vector<std::string> named_issuers;
    //! The whole identifiers of the anchors the keychain holds, primary first.
    std::vector<std::string> held_anchor_ids;
    //! Whether `--trust-anchor` was given.
    bool trust_anchor_option{false};
};

/**
 * @brief What that invocation means for the minting authority and for the anchor set.
 */
struct AnchorPlan {
    //! The authority asked to mint. Empty means nothing is minted.
    std::string minting_issuer;
    //! The anchors the file is to hold, ordered. Membership, not chain position.
    std::vector<std::string> anchor_ids;
    //! Named, not used, and not already held, so worth a warning.
    std::vector<std::string> ignored_issuers;
    //! Whether this invocation establishes trust, which is when several may be named.
    bool establishing_trust{false};
    //! Empty, or the reason nothing is written.
    std::string refusal;
};

/**
 * @brief Decide the minting authority and the anchor set from one invocation.
 *
 * Naming an authority to mint one certificate is an everyday act and must not remove an anchor,
 * so `--issuer` adds and never removes, and adding an anchor beyond the one that minted is only
 * meaningful when trust is being established. `--trust-anchor` is the one thing that resets the
 * set to the list named.
 *
 * Pure, so every rule can be checked without a keychain, a network or a certificate manager.
 */
inline AnchorPlan planAnchors(const AnchorPlanInput &input) {
    AnchorPlan plan;
    plan.establishing_trust = input.trust_anchor_option || input.held_anchor_ids.empty();

    // The whole identifier a named authority resolves to when the keychain already holds it.
    // Comparing against the held value is what lets a short form name an authority already
    // trusted, while the whole identifier is still required for one that is not.
    const auto heldForm = [&input](const std::string &named) -> std::string {
        for (const auto &held : input.held_anchor_ids)
            if (pvxs::certs::issuerIdIsExpected(named, held)) return held;
        return std::string();
    };

    const auto addAnchor = [&plan](const std::string &id) {
        if (id.empty()) return;
        if (std::find(plan.anchor_ids.begin(), plan.anchor_ids.end(), id) == plan.anchor_ids.end())
            plan.anchor_ids.push_back(id);
    };

    if (input.trust_anchor_option) {
        if (input.named_issuers.empty()) {
            plan.refusal = kNoIssuerNamedForTrustAnchor;
            return plan;
        }
        // Nothing is minted, and the named list is the whole of the resulting membership.
        for (const auto &named : input.named_issuers) {
            const auto held = heldForm(named);
            addAnchor(held.empty() ? named : held);
        }
        return plan;
    }

    if (!input.named_issuers.empty()) {
        const auto held = heldForm(input.named_issuers.front());
        plan.minting_issuer = held.empty() ? input.named_issuers.front() : held;
    } else if (!input.held_anchor_ids.empty()) {
        // Nothing named anywhere, so the primary anchor mints, and it leads the held list.
        plan.minting_issuer = input.held_anchor_ids.front();
    }
    // The root of the authority that minted is forced by the certificate rather than chosen, so
    // it joins the set whether or not this invocation is establishing trust.
    addAnchor(plan.minting_issuer);

    for (size_t i = 1; i < input.named_issuers.size(); i++) {
        const auto &named = input.named_issuers[i];
        const auto held = heldForm(named);
        if (held.empty() && !plan.establishing_trust) {
            // An anchor is only added when trust is being established. One the keychain already
            // trusts is left out of the warning deliberately: a site is expected to leave
            // EPICS_PVA_AUTH_ISSUER set to its whole trusted list, and warning about those would
            // fire on correct configuration.
            plan.ignored_issuers.push_back(named);
            continue;
        }
        addAnchor(held.empty() ? named : held);
    }

    // Nothing already held is dropped because it went unmentioned.
    for (const auto &held : input.held_anchor_ids) addAnchor(held);

    return plan;
}

//! The subject of a certificate, rendered `CN=..., O=..., C=US` as `pvxcert -f` renders it.
inline std::string anchorSubject(X509 *certificate) {
    const pvxs::ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()), false);
    if (!bio || !certificate) return {};
    X509_NAME_print(bio.get(), X509_get_subject_name(certificate), 1024);
    BUF_MEM *buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);
    if (!buffer || !buffer->data) return {};
    return std::string(buffer->data, buffer->length);
}

/**
 * @brief List the anchors a keychain holds, primary first and labelled.
 *
 * Nothing in the file marks which anchor is the primary one, so these lines are where an
 * operator sees which it is, and can catch it being the wrong one before anything is built on
 * the file.
 *
 * @param cert_data the keychain contents as they were written
 * @param out where to print
 */
inline void printAnchorListing(const pvxs::certs::CertData &cert_data, std::ostream &out) {
    const auto anchors = anchorsInChain(cert_data.cert_auth_chain);
    if (anchors.empty()) return;

    X509 *primary = nullptr;
    try {
        primary = primaryAnchor(cert_data);
    } catch (const std::exception &) {
        // A keychain whose primary cannot be derived still has anchors worth listing.
    }

    const std::ios::fmtflags flags(out.flags());
    if (primary) out << std::left << std::setw(kLabelColumnWidth) << "Primary Root CA" << ": " << anchorSubject(primary) << std::endl;
    for (X509 *anchor : anchors) {
        if (primary && X509_cmp(anchor, primary) == 0) continue;
        out << std::left << std::setw(kLabelColumnWidth) << "Trusted Root CA" << ": " << anchorSubject(anchor) << std::endl;
    }
    out.flags(flags);
}

/**
 * @brief Whether the anchor set or the primary anchor ended up different from what they were.
 *
 * The anchor set is compared as a set, because the order it is written in means nothing. The
 * primary is compared as well, because a request minted from an authority already trusted can
 * move it without changing the set, and that is a change to the file worth seeing.
 */
inline bool trustChanged(const pvxs::certs::CertData &before, const pvxs::certs::CertData &after) {
    std::vector<std::string> was = heldAnchorIds(before);
    std::vector<std::string> now = heldAnchorIds(after);
    std::sort(was.begin(), was.end());
    std::sort(now.begin(), now.end());
    if (was != now) return true;
    return primaryAnchorId(before) != primaryAnchorId(after);
}

}  // namespace cert
}  // namespace cms

#endif  // PVXS_TRUSTANCHORS_H
