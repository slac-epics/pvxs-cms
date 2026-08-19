/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certrequestid.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <pvxs/log.h>

#include "openssl.h"

namespace pvxs {
namespace certs {

namespace {

// Crockford base32: the digits and the letters, less I, L, O and U, which are the ones a
// reader confuses with 1, 1, 0 and V.
constexpr const char *kAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

constexpr size_t kRequestIdBits = 80;
constexpr size_t kRequestIdBytes = kRequestIdBits / 8;
constexpr size_t kDisplayGroup = 4;

/** Smallest modulus accepted for encrypting to a requester, in bits. */
constexpr int kMinimumRsaModulusBits = 2048;

std::string toHex(const unsigned char *data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    return oss.str();
}

/** The requester's key, parsed from the public key text the request carried. */
ossl_ptr<EVP_PKEY> publicKeyFromPem(const std::string &pub_key_pem) {
    const ossl_ptr<BIO> bio(BIO_new_mem_buf(pub_key_pem.data(), static_cast<int>(pub_key_pem.size())), false);
    if (!bio) throw std::runtime_error("Failed to read the requester's public key");
    ossl_ptr<EVP_PKEY> key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), false);
    if (!key) throw std::runtime_error("The requester's public key could not be parsed");
    return key;
}

/**
 * @brief The reason OpenSSL gives, so a failure says something more than that it failed.
 *
 * The queue is emptied before each operation by clearOpensslErrors, because otherwise an error
 * left behind by unrelated earlier work is reported instead, and on the failure that matters
 * most here that would name the wrong cause entirely.
 */
void clearOpensslErrors() { ERR_clear_error(); }

std::string opensslError() {
    const auto code = ERR_get_error();
    if (!code) return "no further detail";
    char buf[256] = {0};
    ERR_error_string_n(code, buf, sizeof(buf));
    return buf;
}

}  // namespace

std::string generateRequestId() {
    clearOpensslErrors();
    unsigned char raw[kRequestIdBytes] = {0};
    if (RAND_bytes(raw, static_cast<int>(sizeof(raw))) != 1) {
        throw std::runtime_error(SB() << "Failed to generate a certificate request identifier: " << opensslError());
    }

    // 80 bits is exactly 16 five-bit groups, so there is nothing left over and no padding.
    std::string out;
    out.reserve(kRequestIdLength);
    uint32_t buffer = 0;
    int bits = 0;
    for (const unsigned char byte : raw) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kAlphabet[(buffer >> bits) & 0x1F]);
        }
    }
    return out;
}

std::string requestIdForDisplay(const std::string &canonical) {
    std::string out;
    out.reserve(kRequestIdLength + kRequestIdLength / kDisplayGroup);
    for (size_t i = 0; i < canonical.size(); i++) {
        if (i && i % kDisplayGroup == 0) out.push_back('-');
        out.push_back(canonical[i]);
    }
    return out;
}

std::string requestIdCanonical(const std::string &as_written) {
    std::string out;
    for (const char c : as_written) {
        if (c == '-' || c == ' ') continue;
        const char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (!std::strchr(kAlphabet, upper) || upper == '\0') {
            throw std::runtime_error(SB() << "'" << as_written
                                          << "' is not a certificate request identifier: it holds the character '"
                                          << c << "', which is not one it can be written with");
        }
        out.push_back(upper);
    }
    if (out.size() != kRequestIdLength) {
        throw std::runtime_error(SB() << "'" << as_written << "' is not a certificate request identifier: it has "
                                      << out.size() << " characters where one has " << kRequestIdLength);
    }
    return out;
}

std::string publicKeyDigest(EVP_PKEY *pub_key) {
    if (!pub_key) throw std::runtime_error("No public key to identify");

    unsigned char *der = nullptr;
    const int der_len = i2d_PUBKEY(pub_key, &der);
    if (der_len <= 0) {
        OPENSSL_free(der);
        throw std::runtime_error("Failed to encode the public key to identify it");
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der, static_cast<size_t>(der_len), hash);
    OPENSSL_free(der);
    return toHex(hash, sizeof(hash));
}

std::string publicKeyDigest(const std::string &pub_key_pem) {
    const auto key = publicKeyFromPem(pub_key_pem);
    return publicKeyDigest(key.get());
}

std::string buildRequestIdPayload(const std::string &request_id,
                                  const std::string &cert_id,
                                  const std::string &pub_key_digest,
                                  const time_t issued_at) {
    // Every field is checked for a line feed, because a field carrying one would move the
    // line boundaries and let one field pose as another.
    for (const auto *field : {&request_id, &cert_id, &pub_key_digest}) {
        if (field->find('\n') != std::string::npos || field->find('\0') != std::string::npos) {
            throw std::runtime_error("A certificate request identifier field cannot contain a line feed or a zero byte");
        }
    }
    std::ostringstream oss;
    oss << kRequestIdPayloadVersion << '\n'
        << request_id << '\n'
        << cert_id << '\n'
        << pub_key_digest << '\n'
        << static_cast<int64_t>(issued_at) << '\n';
    return oss.str();
}

RequestIdPayload parseRequestIdPayload(const std::string &payload,
                                       const std::string &expected_cert_id,
                                       const std::string &expected_pub_key_digest) {
    std::istringstream iss(payload);
    std::string version, request_id, cert_id, digest, issued;
    if (!std::getline(iss, version) || !std::getline(iss, request_id) || !std::getline(iss, cert_id) ||
        !std::getline(iss, digest) || !std::getline(iss, issued)) {
        throw std::runtime_error("The certificate request identifier package is not the expected five lines");
    }

    if (version != kRequestIdPayloadVersion) {
        throw std::runtime_error(SB() << "The certificate request identifier package says it is '" << version
                                      << "' where this version reads '" << kRequestIdPayloadVersion << "'");
    }
    if (cert_id != expected_cert_id) {
        throw std::runtime_error(SB() << "The certificate request identifier was issued for certificate '" << cert_id
                                      << "' but arrived answering a request for '" << expected_cert_id
                                      << "'. Refusing it: it belongs to another request");
    }
    if (digest != expected_pub_key_digest) {
        throw std::runtime_error(SB() << "The certificate request identifier was issued against a different key than "
                                         "the one this request used. Refusing it: it belongs to another request");
    }

    RequestIdPayload out;
    out.request_id = requestIdCanonical(request_id);
    out.cert_id = cert_id;
    out.pub_key_digest = digest;
    try {
        out.issued_at = static_cast<time_t>(std::stoll(issued));
    } catch (const std::exception &) {
        throw std::runtime_error("The certificate request identifier package does not carry a readable time of issue");
    }
    return out;
}

std::vector<uint8_t> encryptToRequester(const std::string &pub_key_pem, const std::string &payload) {
    clearOpensslErrors();
    const auto key = publicKeyFromPem(pub_key_pem);

    if (EVP_PKEY_base_id(key.get()) != EVP_PKEY_RSA) {
        throw std::runtime_error(
            "The requester's key is not RSA, so the certificate request identifier cannot be encrypted to it. "
            "Encrypting to another key type needs a key agreement step, which has not been designed");
    }
    const int modulus_bits = EVP_PKEY_bits(key.get());
    if (modulus_bits < kMinimumRsaModulusBits) {
        throw std::runtime_error(SB() << "The requester's key has a " << modulus_bits
                                      << " bit modulus, under the " << kMinimumRsaModulusBits
                                      << " bit minimum for encrypting a certificate request identifier to it");
    }

    const ossl_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key.get(), nullptr), false);
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        throw std::runtime_error(SB() << "Failed to start encrypting to the requester's key: " << opensslError());
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error(SB() << "Failed to set the padding for encrypting to the requester's key: "
                                      << opensslError());
    }

    // What this key and padding can carry. Stated rather than discovered from a failure, so an
    // over-long payload says why rather than reporting an encryption error.
    const size_t modulus_bytes = static_cast<size_t>(EVP_PKEY_size(key.get()));
    const size_t oaep_overhead = 2 * SHA256_DIGEST_LENGTH + 2;
    if (modulus_bytes <= oaep_overhead || payload.size() > modulus_bytes - oaep_overhead) {
        throw std::runtime_error(SB() << "The certificate request identifier package is " << payload.size()
                                      << " bytes, more than the " << (modulus_bytes - oaep_overhead)
                                      << " the requester's key can carry. Refusing to shorten it");
    }

    size_t out_len = 0;
    const auto *in = reinterpret_cast<const unsigned char *>(payload.data());
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &out_len, in, payload.size()) <= 0) {
        throw std::runtime_error(SB() << "Failed to size the encrypted certificate request identifier: "
                                      << opensslError());
    }
    std::vector<uint8_t> out(out_len);
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &out_len, in, payload.size()) <= 0) {
        throw std::runtime_error(SB() << "Failed to encrypt the certificate request identifier: " << opensslError());
    }
    out.resize(out_len);
    return out;
}

std::string decryptWithRequesterKey(const std::shared_ptr<KeyPair> &key_pair,
                                    const std::vector<uint8_t> &ciphertext) {
    if (!key_pair || !key_pair->pkey) {
        throw std::runtime_error("No private key to read the certificate request identifier with");
    }
    clearOpensslErrors();

    const ossl_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key_pair->pkey.get(), nullptr), false);
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        throw std::runtime_error(SB() << "Failed to start reading the certificate request identifier: "
                                      << opensslError());
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error(SB() << "Failed to set the padding for reading the certificate request identifier: "
                                      << opensslError());
    }

    size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &out_len, ciphertext.data(), ciphertext.size()) <= 0) {
        throw std::runtime_error(SB() << "The certificate request identifier could not be read with the key this "
                                         "request used: " << opensslError());
    }
    std::vector<unsigned char> out(out_len);
    if (EVP_PKEY_decrypt(ctx.get(), out.data(), &out_len, ciphertext.data(), ciphertext.size()) <= 0) {
        throw std::runtime_error(SB() << "The certificate request identifier could not be read with the key this "
                                         "request used: " << opensslError());
    }
    return {reinterpret_cast<const char *>(out.data()), out_len};
}

CertData certDataFromPem(const std::string &pem) {
    const ossl_ptr<BIO> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), false);
    if (!bio) throw std::runtime_error("Failed to read the delivered certificate");

    ossl_ptr<X509> leaf;
    ossl_shared_ptr<STACK_OF(X509)> authorities(sk_X509_new_null());
    while (true) {
        ossl_ptr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), false);
        if (!cert) break;
        // The first is the new certificate; everything after it is an authority above it, the
        // nearest first, which is the order the rest of this module reads a chain in.
        if (!leaf) {
            leaf = std::move(cert);
        } else {
            sk_X509_push(authorities.get(), cert.release());
        }
    }
    if (!leaf) throw std::runtime_error("The delivered certificate could not be read");

    return CertData(leaf, authorities);
}

std::vector<uint8_t> requestIdSignedBytes(const std::string &cert_id,
                                          const std::string &pub_key_digest,
                                          const std::vector<uint8_t> &ciphertext) {
    std::vector<uint8_t> out;
    const auto append = [&out](const char *begin, const size_t len) {
        out.insert(out.end(), begin, begin + len);
        out.push_back(0x00);
    };
    append(kRequestIdSignatureVersion, std::strlen(kRequestIdSignatureVersion));
    append(cert_id.data(), cert_id.size());
    append(pub_key_digest.data(), pub_key_digest.size());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

}  // namespace certs
}  // namespace pvxs
