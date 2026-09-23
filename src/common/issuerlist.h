/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_ISSUERLIST_H
#define PVXS_ISSUERLIST_H

#include <algorithm>
#include <string>
#include <vector>

#include "certstatus.h"
#include "security.h"

namespace cms {
namespace cert {

//! The characters that separate one issuer identifier from the next.
//!
//! Whitespace and the comma, and nothing else. The semicolon is left out because, unquoted in a
//! shell, `EPICS_PVA_AUTH_ISSUER=aaaa;bbbb` sets the variable to `aaaa` and then tries to run
//! `bbbb` as a command, leaving the variable holding a plausible wrong value. The colon is left
//! out because an identifier may be written with colons in it.
constexpr const char *kIssuerListSeparators = " \t\r\n,";

/**
 * @brief Split a list of certificate authority identifiers into its values.
 *
 * The order is the meaning: the first entry is the authority asked to mint, and the order the
 * rest are named in is the order they are written in. So `"aaaa bbbb"`, `"aaaa,bbbb"` and
 * `" aaaa , bbbb "` all give `{"aaaa", "bbbb"}`, in that order.
 *
 * Each surviving entry is read with `readIssuerId`, so every form a certificate prints its
 * authority in is accepted and a value that is not an identifier is refused with that value in
 * the message. A repeated entry keeps its first occurrence, because that is the occurrence whose
 * position decides the ordering.
 *
 * @param value the list, as an option value or an environment variable carries it
 * @return the identifiers, minting authority first
 * @throws std::runtime_error if an entry is not an issuer identifier
 */
inline std::vector<std::string> parseIssuerList(const std::string &value) {
    std::vector<std::string> issuers;
    for (std::string::size_type start = 0;;) {
        const auto separator = value.find_first_of(kIssuerListSeparators, start);
        const auto entry = pvxs::certs::trimSurroundingWhitespace(
            separator == std::string::npos ? value.substr(start) : value.substr(start, separator - start));
        if (!entry.empty()) {
            const auto digits = pvxs::certs::readIssuerId(entry);
            if (!digits.empty() && std::find(issuers.begin(), issuers.end(), digits) == issuers.end())
                issuers.push_back(digits);
        }
        if (separator == std::string::npos) break;
        start = separator + 1;
    }
    return issuers;
}

/**
 * @brief Join certificate authority identifiers into one string, minting authority first.
 *
 * The inverse of parseIssuerList for any list that parse would produce. One identifier joins to
 * itself, so a configuration naming a single authority reports exactly the string it reported
 * before a list could be named.
 *
 * @param issuers the identifiers, minting authority first
 * @return the identifiers separated by a single space
 */
inline std::string joinIssuerList(const std::vector<std::string> &issuers) {
    std::string joined;
    for (const auto &issuer : issuers) {
        if (!joined.empty()) joined += ' ';
        joined += issuer;
    }
    return joined;
}

}  // namespace cert
}  // namespace cms

#endif  // PVXS_ISSUERLIST_H
