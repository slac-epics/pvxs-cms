/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERTREQUESTID_H_
#define PVXS_CERTREQUESTID_H_

#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "certfilefactory.h"
#include "security.h"

namespace pvxs {
namespace certs {

/**
 * A certificate request identifier, and the package that carries one back to whoever asked
 * for the certificate.
 *
 * A certificate creation request travels in clear text. Someone able to change traffic in
 * transit can replace the public key in it with one of their own: the request still names
 * the real person, an administrator still sees a plausible subject, and the certificate that
 * gets issued belongs to the attacker's private key. An administrator approving that has
 * nothing to check it against.
 *
 * The identifier is a second factor that travels by a route the request never touches. The
 * service mints one, returns it encrypted to the public key that arrived in the request, and
 * the requester emails it to an administrator, who compares it by eye before approving. Only
 * the holder of the matching private key can read it, so a substituted key produces no
 * identifier, no email and no approval. A silent substitution becomes a visible failure.
 *
 * What that does NOT claim: the rest of the exchange has neither confidentiality nor
 * integrity, the identifier is not a secret once emailed, and none of it stops an
 * administrator approving without looking. It gives them something to compare, and cannot
 * make them compare it.
 */

/*
 * The table the identifier is recorded in, and the statements that use it.
 *
 * Its own table, not another column on the certificate table: an identifier is not a property
 * of a certificate, it is a record of one request for one, and only a request awaiting approval
 * has one. Keyed on the serial number, which is how the rest of the schema names a certificate.
 *
 * The create statement must be run on every start rather than only when the certificate table is
 * absent, because the statement that builds the certificate table never reaches a database made
 * by an earlier version, and every running deployment would otherwise be left without this one.
 */
#define SQL_CREATE_REQUEST_ID_TABLE               \
    "CREATE TABLE IF NOT EXISTS cert_request_ids(" \
    "     serial INTEGER PRIMARY KEY,"            \
    "     request_id TEXT NOT NULL,"              \
    "     pub_key_digest TEXT NOT NULL,"          \
    "     created INTEGER NOT NULL"               \
    "); "                                         \
    "CREATE INDEX IF NOT EXISTS idx_cert_request_ids_request_id " \
    "     ON cert_request_ids(request_id);"

#define SQL_CREATE_REQUEST_ID         \
    "INSERT INTO cert_request_ids ( " \
    "     serial,"                    \
    "     request_id,"                \
    "     pub_key_digest,"            \
    "     created"                     \
    ") "                               \
    "VALUES ( "                        \
    "     :serial,"                    \
    "     :request_id,"                \
    "     :pub_key_digest,"            \
    "     :created"                    \
    ");"

#define SQL_REQUEST_ID_BY_SERIAL      \
    "SELECT request_id, pub_key_digest "  \
    "FROM cert_request_ids "          \
    "WHERE serial = :serial;"

/** First line of the encrypted payload. Checked exactly. */
constexpr const char *kRequestIdPayloadVersion = "SPVA-REQUEST-ID-1";

/** First field of the signed byte string. */
constexpr const char *kRequestIdSignatureVersion = "SPVA-REQUEST-ID-SIG-1";

/** Characters in a canonical identifier. */
constexpr size_t kRequestIdLength = 16;

/**
 * @brief Mint an identifier: 80 random bits in the Crockford base32 alphabet.
 *
 * It does not have to be unguessable. Guessing one gains nothing, because an attacker still
 * has to make an email arrive from an address the administrator trusts. It is random anyway,
 * because random costs nothing and removes any chance of two live requests sharing a value.
 *
 * @return 16 upper case characters
 * @throws std::runtime_error if the random source fails
 */
std::string generateRequestId();

/**
 * @brief Group an identifier for printing: four groups of four, hyphen separated.
 */
std::string requestIdForDisplay(const std::string &canonical);

/**
 * @brief The stored and compared form: upper case, hyphens removed.
 *
 * So a value that has been read aloud, retyped, or lower-cased by a mail client still
 * matches what was issued.
 *
 * @throws std::runtime_error if what is left is not 16 characters of the alphabet
 */
std::string requestIdCanonical(const std::string &as_written);

/**
 * @brief SHA-256 of the subject public key information, as 64 lower case hex characters.
 *
 * The same encoding that is hashed for a subject key identifier, so the two agree about what
 * identifies a key.
 */
std::string publicKeyDigest(EVP_PKEY *pub_key);
std::string publicKeyDigest(const std::string &pub_key_pem);

/** The five line payload that gets encrypted. */
std::string buildRequestIdPayload(const std::string &request_id,
                                  const std::string &cert_id,
                                  const std::string &pub_key_digest,
                                  time_t issued_at);

/** What a parsed payload held, once every binding in it has been checked. */
struct RequestIdPayload {
    std::string request_id;
    std::string cert_id;
    std::string pub_key_digest;
    time_t issued_at{0};
};

/**
 * @brief Read a decrypted payload, checking it belongs to this request.
 *
 * The version line is compared exactly, and the certificate identifier and public key digest
 * against what the caller already knows, so a package built for another request cannot be
 * presented for this one.
 *
 * @throws std::runtime_error on any mismatch
 */
RequestIdPayload parseRequestIdPayload(const std::string &payload,
                                       const std::string &expected_cert_id,
                                       const std::string &expected_pub_key_digest);

/**
 * @brief Encrypt to the key that arrived in the request.
 *
 * RSA with optimal asymmetric encryption padding, SHA-256 digest, mask generation function 1
 * with SHA-256, empty label.
 *
 * A key that is not RSA, or whose modulus is under 2048 bits, or a payload the modulus cannot
 * carry, throws rather than falling back to anything weaker or truncating. A later move to
 * elliptic curve keys therefore fails loudly and forces the key agreement step to be designed
 * rather than skipped.
 */
std::vector<uint8_t> encryptToRequester(const std::string &pub_key_pem, const std::string &payload);

/**
 * @brief Decrypt with the private key that made the request.
 *
 * @throws std::runtime_error if it cannot be decrypted, which is what a substituted public
 *         key looks like from here
 */
std::string decryptWithRequesterKey(const std::shared_ptr<KeyPair> &key_pair,
                                    const std::vector<uint8_t> &ciphertext);

/**
 * @brief Split a delivered certificate chain, in text form, into leaf and authorities.
 *
 * The reply carries the new certificate and the authorities above it as one block of text. This
 * reads it without writing anything to disk, so the authority in it can be checked against the
 * one committed to in advance before anything is trusted or stored.
 *
 * @throws std::runtime_error if the text holds no certificate
 */
CertData certDataFromPem(const std::string &pem);

/**
 * @brief The byte string the signature covers.
 *
 * Version, certificate identifier, public key digest and ciphertext, separated by a zero
 * byte. No covered field can contain a zero byte, so the separation is unambiguous.
 *
 * The certificate identifier and the digest are not sent as part of the package: the
 * requester already holds both, so it rebuilds these bytes rather than being told them, and
 * anyone altering either has to forge the signature to match.
 */
std::vector<uint8_t> requestIdSignedBytes(const std::string &cert_id,
                                          const std::string &pub_key_digest,
                                          const std::vector<uint8_t> &ciphertext);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTREQUESTID_H_
