/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERTFILTER_H_
#define PVXS_CERTFILTER_H_

#include <cstdint>
#include <ctime>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace pvxs {
namespace certs {

/**
 * @brief What is wrong with a filter, said so an operator can act on it.
 *
 * Carries the whole message: what is wrong, the expression with a caret under the place, and
 * what to do about it. Never parser vocabulary, never the text of another exception.
 */
class CertFilterError final : public std::runtime_error {
  public:
    CertFilterError(std::string message, const size_t position) : std::runtime_error(message), position_(position) {}
    /** Character offset into the expression the message points at. */
    size_t position() const { return position_; }

  private:
    size_t position_;
};

/** The fields a test can name. */
enum class FilterField {
    Id,        //!< the printed certificate identifier; matched in memory
    Serial,    //!< the serial on its own
    Issuer,    //!< the serving issuer; decided before any query runs
    Name,      //!< common name
    Org,       //!< organization
    Unit,      //!< organizational unit
    Country,   //!< country
    State,     //!< status, by name
    Issued,        IssuedBefore,   IssuedAfter,    //!< start of validity
    Expires,       ExpiresBefore,  ExpiresAfter,   //!< end of validity
    RenewBy,       RenewBefore,    RenewAfter,     //!< when renewal is due
    Changed,       ChangedBefore,  ChangedAfter,   //!< when the status last changed
    Type,      //!< what the certificate is for
};

/** How one value in a test is to be matched. */
enum class FilterValueKind {
    Text,       //!< plain text, `*` matching any run of characters
    Regex,      //!< wrapped in slashes
    Status,     //!< a status name, already resolved
    Number,     //!< a serial
    Instant,    //!< one moment
    DayRange,   //!< a whole day, for a bare date field
};

/** One alternative within a test. Several joined by `|` mean any of them. */
struct FilterValue {
    FilterValueKind kind{FilterValueKind::Text};
    std::string text;      //!< as written, for text and regular expressions
    int64_t number{0};     //!< a serial, a status index, or a moment in POSIX seconds
    int64_t number_end{0}; //!< end of a day range, exclusive
};

/** A node of the parsed expression. */
struct FilterNode {
    enum class Kind { Test, And, Or, Not } kind{Kind::Test};

    // Test
    FilterField field{FilterField::Name};
    std::string field_text;             //!< as the operator wrote it, for messages
    std::vector<FilterValue> values;    //!< any of these matches
    size_t position{0};                 //!< where the test starts, for messages

    // And, Or, Not
    std::vector<std::unique_ptr<FilterNode>> children;
};

/** One row's worth of what a filter can be asked about. */
struct FilterRow {
    std::string cert_id;   //!< the printed identifier, from the listing's own helper
    uint64_t serial{0};
    std::string common_name;
    std::string organization;
    std::vector<std::string> organizational_units;  //!< several: any one matching is a match
    std::string country;
    int status{0};
    time_t not_before{0};
    time_t not_after{0};
    time_t renew_by{0};
    time_t status_date{0};
};

/** A filter, ready to narrow a listing. */
class CertFilter {
  public:
    /**
     * @brief Read a filter expression.
     *
     * @param expression what the operator wrote
     * @param now        the moment a period is measured from, so a test can fix the clock
     * @throws CertFilterError with a message meant to be shown as it is
     */
    static CertFilter parse(const std::string &expression, time_t now);

    /**
     * @brief The condition to put in the query, and the values to bind to it.
     *
     * A superset: every test that is not a column, or is a regular expression, is replaced by
     * the constant true. That is only safe because the expression is first put into negation
     * normal form, where no negation sits above a test, so widening a test can only widen the
     * result. The condition is an optimisation; matches() is the correctness.
     *
     * Values are always bound, never pasted into the text.
     */
    const std::string &whereClause() const { return where_clause_; }
    const std::vector<FilterValue> &bindings() const { return bindings_; }

    /** Whether a row satisfies the whole expression as written. */
    bool matches(const FilterRow &row) const;

    /**
     * @brief Whether this filter can match anything at this certificate authority.
     *
     * An `issuer:` test naming another authority empties the result, and says so here rather
     * than by running a query that cannot return a row.
     */
    bool possibleFor(const std::string &issuer_id) const;

    /** The expression as written. */
    const std::string &text() const { return text_; }

  private:
    std::string text_;
    std::unique_ptr<FilterNode> root_;
    std::string where_clause_;
    std::vector<FilterValue> bindings_;
};

/** Longest expression accepted. The call is reachable by any client. */
constexpr size_t kFilterMaxLength = 4096;
/** Deepest bracket nesting accepted. */
constexpr size_t kFilterMaxDepth = 32;
/** Most regular expressions in one expression: each one can backtrack badly. */
constexpr size_t kFilterMaxRegexes = 8;
/** Most rows the in-memory pass will look at. */
constexpr size_t kFilterMaxRows = 100000;

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTFILTER_H_
