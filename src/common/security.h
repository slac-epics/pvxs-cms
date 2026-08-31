/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SEC_SECURITY_H
#define PVXS_SEC_SECURITY_H

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include <pvxs/nt.h>

#include "ownedptr.h"

namespace pvxs {
namespace certs {

//! Separator between organizational unit values wherever they must share one string:
//! the environment variables, and the signature payload. Matches the separator the
//! keychain settings already use, so there is one convention rather than two.
constexpr char kOrganizationalUnitSeparator = ';';

//! Remove leading and trailing whitespace, so `OU= beamline` and `OU=beamline` are one value.
inline std::string trimSurroundingWhitespace(const std::string &value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

/**
 * @brief Trim each organizational unit, drop empty ones, and refuse a value we cannot carry.
 *
 * A repeated value, and a value containing the separator, are refused at the point of request.
 *
 * Values are compared exactly and case is not folded, matching how the common name is treated.
 *
 * @param units the organizational units to normalize in place, innermost first
 * @throws std::runtime_error if a value is repeated or contains the separator
 */
inline void normalizeOrganizationalUnits(std::vector<std::string> &units) {
    std::vector<std::string> normalized;
    normalized.reserve(units.size());
    for (const auto &unit : units) {
        auto trimmed = trimSurroundingWhitespace(unit);
        if (trimmed.empty()) continue;
        if (trimmed.find(kOrganizationalUnitSeparator) != std::string::npos)
            throw std::runtime_error(SB() << "Organizational unit \"" << trimmed << "\" contains a '"
                                          << kOrganizationalUnitSeparator << "', which separates one unit from the next");
        if (std::find(normalized.begin(), normalized.end(), trimmed) != normalized.end())
            throw std::runtime_error(SB() << "Organizational unit \"" << trimmed
                                          << "\" is given more than once: a unit cannot contain itself");
        normalized.push_back(std::move(trimmed));
    }
    units = std::move(normalized);
}

/**
 * @brief Split a separator-delimited list of organizational units into its values.
 *
 * The values are read innermost first: the first value sits inside the second. Surrounding
 * whitespace is trimmed and empty values are dropped, so `" staff ; beamline"` and
 * `"staff;beamline"` both give `{"staff", "beamline"}`.
 *
 * @param value the joined list, as an environment variable carries it
 * @return the organizational units, innermost first
 * @throws std::runtime_error if a value is repeated
 */
inline std::vector<std::string> parseOrganizationalUnits(const std::string &value) {
    std::vector<std::string> units;
    for (std::string::size_type start = 0;;) {
        const auto separator = value.find(kOrganizationalUnitSeparator, start);
        if (separator == std::string::npos) {
            units.push_back(value.substr(start));
            break;
        }
        units.push_back(value.substr(start, separator - start));
        start = separator + 1;
    }
    normalizeOrganizationalUnits(units);
    return units;
}

/**
 * @brief Join organizational units into one string, innermost first.
 *
 * The inverse of parseOrganizationalUnits for any list that parse would produce. A single unit
 * joins to itself and no units join to the empty string, so a request carrying at most one unit
 * produces exactly the string it produced before units could repeat.
 *
 * @param units the organizational units, innermost first
 * @return the values joined by the separator
 */
inline std::string joinOrganizationalUnits(const std::vector<std::string> &units) {
    std::string joined;
    for (const auto &unit : units) {
        if (!joined.empty()) joined += kOrganizationalUnitSeparator;
        joined += unit;
    }
    return joined;
}

/**
 * @class AuthnCredentials
 * @brief Represents the credentials for an abstract Authenticator.
 *
 * This structure provides the principal name.
 */
struct AuthnCredentials {
    virtual ~AuthnCredentials() {};

    // Principal's name - e.g. username, or device name, or IP address.
    std::string name;
    std::string country;
    std::string organization;
    //! Organizational units, innermost first: the first sits inside the second, and so on.
    std::vector<std::string> organization_unit;

    // Validity
    time_t not_before;
    time_t not_after;

    // Config uri
    std::string config_uri_base;

    static std::string base64Encode(const char *data, const size_t len) {
        BUF_MEM *buffer_ptr;

        BIO *b64 = BIO_new(BIO_f_base64());          // Create a base64 filter
        BIO *bio = BIO_new(BIO_s_mem());             // Create a memory BIO
        BIO_push(b64, bio);                          // Chain them
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newline breaks
        BIO_write(b64, data, len);                   // Write the input string
        BIO_flush(b64);                              // Ensure all data is written
        BIO_get_mem_ptr(b64, &buffer_ptr);           // Get the output buffer

        std::string out(buffer_ptr->data, buffer_ptr->length);  // Create a string from the buffer

        BIO_free_all(b64);  // Free the BIOs

        return out;
    }

    static std::string base64Decode(const std::string &input) {
        int inputLength = input.size();
        // Create a BIO chain: base64 filter + memory buffer.
        BIO *b64 = BIO_new(BIO_f_base64());
        // Disable newline processing
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO *bio = BIO_new_mem_buf(input.data(), inputLength);
        bio = BIO_push(b64, bio);

        // Allocate enough memory to hold the decoded data.
        // Base64 encoding expands data by roughly 4/3.
        const int max_decoded_length = inputLength * 3 / 4;
        std::string decoded;
        decoded.resize(max_decoded_length);

        const int decodedLength = BIO_read(bio, &decoded[0], inputLength);
        if (decodedLength < 0) {
            BIO_free_all(bio);
            throw std::runtime_error("Base64 decoding failed");
        }
        decoded.resize(decodedLength);

        BIO_free_all(bio);
        return decoded;
    }

    static std::string base64Encode(const std::string &in) { return base64Encode(in.data(), in.size()); }
};

#define CCR_PROTOTYPE(VERIFIER)                \
    {                                          \
        members::String("type"),               \
        members::String("name"),               \
        members::String("country"),            \
        members::String("organization"),       \
        members::String("organization_unit"),  \
        members::StringA("organization_units"),\
        members::UInt16("usage"),              \
        members::UInt64("not_before"),         \
        members::UInt64("not_after"),          \
        members::String("pub_key"),            \
        members::String("config_uri_base"),    \
        members::Bool("no_status"),            \
        members::Struct("verifier", VERIFIER), \
    }

/**
 * @brief Express a single organizational unit as a list, with an empty value meaning no unit.
 *
 * For the places that still hold one unit in one string: a configured certificate authority unit,
 * a value read out of the existing single-value database column.
 *
 * @param unit the one unit, or an empty string for none
 * @return a list holding that unit, or an empty list
 */
inline std::vector<std::string> singleOrganizationalUnit(const std::string &unit) {
    if (unit.empty()) return {};
    return {unit};
}

/**
 * @brief The innermost organizational unit, or an empty string when there is none.
 *
 * The single value the existing `certs.OU` column holds. That column is derived and never
 * authoritative: it exists so the existing index, the existing queries and anything reading the
 * table directly keep working, and the innermost unit is the most specific single value to show.
 *
 * @param units the organizational units, innermost first
 * @return the innermost unit, or an empty string
 */
inline const std::string &innermostOrganizationalUnit(const std::vector<std::string> &units) {
    static const std::string none;
    return units.empty() ? none : units.front();
}

/**
 * @brief Read the organizational units out of a certificate creation request.
 *
 * A request from a client that predates repeated units carries no `organization_units` field at
 * all, because the request travels with its own type. Its single `organization_unit` value is
 * then read as a one-element list, so such a request is handled exactly as it was before.
 *
 * When a request carries both fields they must agree, and this is the only way to read the units,
 * so no caller can act on the list without the two having been compared. Were the server to build
 * the subject from the list while a verifier inspected only the single value, a caller could leave
 * an authorised value in the single field, put unauthorised values in the list, and have them all
 * issued. The check is here, so it holds for every call site.
 *
 * @param ccr the certificate creation request as it arrived
 * @return the organizational units, innermost first
 * @throws std::runtime_error if the request carries both fields and they disagree
 */
inline std::vector<std::string> getOrganizationalUnits(const Value &ccr) {
    const auto single_value = ccr["organization_unit"];
    const auto single = single_value ? single_value.as<std::string>() : std::string();

    if (const auto units_value = ccr["organization_units"]) {
        const auto values = units_value.as<shared_array<const std::string>>();
        if (values.empty()) {
            if (!single.empty())
                throw std::runtime_error(SB() << "Certificate creation request names organizational unit \"" << single
                                              << "\" but its list of units is empty");
            return {};
        }
        if (values[0] != single)
            throw std::runtime_error(SB() << "Certificate creation request names organizational unit \"" << single
                                          << "\" but the innermost unit in its list is \"" << values[0] << "\"");
        return {values.begin(), values.end()};
    }

    return singleOrganizationalUnit(single);
}

struct CertCreationRequest final {
    std::shared_ptr<AuthnCredentials> credentials;

    // Type of authenticator to use to verify this certificate creation request:
    // "std", "krb", etc
    std::string type;

    // PVStructure containing the Authenticator specific CCR to be
    // transmitted over the wire.  The type field is used to in the server side
    // switch to correctly decode and verify the ccr.
    //
    // The verification structure will be filled by the Authenticator subtypes
    // based on their verification needs. If your Authenticator can use
    // just a string token to pass verification information then use this
    // definition directly, otherwise replace the definition with a similar
    // structure definition except that the verifier substructure will be your
    // custom verification structure.  The server will recognise the type and
    // understand how to decode it.
    //
    // Note: Only the claims in the certificate are significant when it comes to
    // verification.  The other fields are included for information, fail fast
    // optimisations, and debugging.
    //
    Value ccr;
    std::vector<Member> verifier_fields;

    // Constructor
    CertCreationRequest(const std::string &auth_type, std::vector<Member> verifier_fields) : type(auth_type), verifier_fields(verifier_fields) {
        ccr = TypeDef(TypeCode::Struct, CCR_PROTOTYPE(verifier_fields)).create();
    }
};

struct KeyPair final {
    std::string public_key;
    ossl_ptr<EVP_PKEY> pkey;

    // Default constructor
    KeyPair() = default;

    explicit KeyPair(ossl_ptr<EVP_PKEY> new_pkey) : pkey(std::move(new_pkey)) {
        const ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()));

        if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
            throw std::runtime_error("Failed to write public key to BIO");
        }

        BUF_MEM *bptr;                      // to hold pointer to data in the BIO object.
        BIO_get_mem_ptr(bio.get(), &bptr);  // set to point into BIO object

        // Create a string from the BIO
        std::string result(bptr->data, bptr->length);
        public_key = result;
    }

    // Constructor that takes a std::string for public_key
    // @note private key is not set with this constructor
    explicit KeyPair(const std::string &public_key_string) : public_key(public_key_string) {
        BIO *bio = BIO_new_mem_buf((void *)public_key_string.c_str(), -1);
        pkey.reset(PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr));
        BIO_free(bio);

        if (!pkey) {
            throw std::runtime_error(SB() << "Failed to create public key from string: \n" << public_key_string);
        }
    }

    ossl_ptr<EVP_PKEY> getPublicKey() const {
        const ossl_ptr<BIO> bio(BIO_new_mem_buf(public_key.c_str(), public_key.size()));
        if (!bio) {
            throw std::runtime_error("Unable to create BIO");
        }

        ossl_ptr<EVP_PKEY> key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), false);
        if (!key) {
            throw std::runtime_error("Unable to read public key");
        }

        return key;
    }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_SEC_SECURITY_H
