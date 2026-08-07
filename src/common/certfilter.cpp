/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certfilter.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <map>
#include <regex>
#include <sstream>

#include "certdate.h"
#include "certstatus.h"

namespace pvxs {
namespace certs {

namespace {

const char *const kFieldList =
    "Fields: id, serial, issuer, name, org, unit, country, state, issued, expires,\n"
    "renew_by, changed, and the before and after forms such as expires_before.";

/** Every field name an operator may write, and what it means. */
const std::map<std::string, FilterField> &fieldNames() {
    static const std::map<std::string, FilterField> names{
        {"id", FilterField::Id},
        {"serial", FilterField::Serial},
        {"issuer", FilterField::Issuer},
        {"name", FilterField::Name},
        {"org", FilterField::Org},
        {"unit", FilterField::Unit},
        {"country", FilterField::Country},
        {"state", FilterField::State},
        {"type", FilterField::Type},
        {"issued", FilterField::Issued},
        {"issued_before", FilterField::IssuedBefore},
        {"issued_after", FilterField::IssuedAfter},
        {"expires", FilterField::Expires},
        {"expires_before", FilterField::ExpiresBefore},
        {"expires_after", FilterField::ExpiresAfter},
        {"renew_by", FilterField::RenewBy},
        {"renew_before", FilterField::RenewBefore},
        {"renew_after", FilterField::RenewAfter},
        {"changed", FilterField::Changed},
        {"changed_before", FilterField::ChangedBefore},
        {"changed_after", FilterField::ChangedAfter},
    };
    return names;
}

std::string lowerCase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](const unsigned char c) { return std::tolower(c); });
    return s;
}

std::string upperCase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](const unsigned char c) { return std::toupper(c); });
    return s;
}

/** How many single-character edits separate two words. Used only to suggest a near miss. */
size_t editDistance(const std::string &a, const std::string &b) {
    std::vector<size_t> previous(b.size() + 1), current(b.size() + 1);
    for (size_t j = 0; j <= b.size(); ++j) previous[j] = j;
    for (size_t i = 1; i <= a.size(); ++i) {
        current[0] = i;
        for (size_t j = 1; j <= b.size(); ++j) {
            const size_t substitute = previous[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1);
            current[j] = std::min({previous[j] + 1, current[j - 1] + 1, substitute});
        }
        previous = current;
    }
    return previous[b.size()];
}

/** The closest of a set of known words, if one is close enough to be worth suggesting. */
std::string nearestWord(const std::string &written, const std::vector<std::string> &known) {
    std::string best;
    size_t best_distance = 0;
    for (const auto &candidate : known) {
        const auto distance = editDistance(lowerCase(written), lowerCase(candidate));
        if (best.empty() || distance < best_distance) {
            best = candidate;
            best_distance = distance;
        }
    }
    // Beyond a third of the word's length the suggestion is noise rather than help.
    const auto tolerance = std::max<size_t>(1, written.size() / 3 + 1);
    return best_distance <= tolerance ? best : std::string{};
}

/** Every status name, for resolving `state:` and for suggesting a near miss. */
std::vector<std::string> statusNames() {
    std::vector<std::string> names;
    for (int i = 0; i <= REVOKED; ++i) names.emplace_back(cert_state_name(i));
    return names;
}

/**
 * @brief Build the three-part message: what is wrong, where, and what to do.
 *
 * The caret line is what makes a position useful to someone who is not counting characters.
 */
CertFilterError filterError(const std::string &expression, const size_t position, const std::string &what_is_wrong,
                            const std::string &what_to_do) {
    std::ostringstream message;
    message << "I cannot understand the filter at position " << position << ":\n\n"
            << "  " << expression << "\n"
            << "  " << std::string(std::min(position, expression.size()), ' ') << "^\n\n"
            << what_is_wrong;
    if (!what_to_do.empty()) message << "\n" << what_to_do;
    return CertFilterError(message.str(), position);
}

/////////////////////////////////////////////////////////////////////////////
// Tokeniser
/////////////////////////////////////////////////////////////////////////////

struct Token {
    enum class Kind { End, OpenBracket, CloseBracket, Word, Test } kind{Kind::End};
    std::string field;               //!< for a test
    std::vector<std::string> values; //!< for a test: the alternatives, still as written
    std::vector<bool> is_regex;      //!< parallel to values
    std::string word;                //!< for and, or, not
    size_t position{0};
};

class Tokeniser {
  public:
    explicit Tokeniser(const std::string &expression) : text_(expression) {}

    std::vector<Token> run() {
        std::vector<Token> tokens;
        while (true) {
            skipSpaces();
            if (at_ >= text_.size()) break;

            const auto start = at_;
            const char c = text_[at_];

            if (c == '(') { ++at_; { Token t; t.kind = Token::Kind::OpenBracket; t.position = start; tokens.push_back(std::move(t)); } continue; }
            if (c == ')') { ++at_; { Token t; t.kind = Token::Kind::CloseBracket; t.position = start; tokens.push_back(std::move(t)); } continue; }

            // A word runs to whitespace or a bracket. Whether it is a joining word or the start
            // of a test is decided by whether it contains a colon: a test always does, which is
            // why `org:and` needs no special case.
            const auto word = readWord();
            const auto colon = word.find(':');
            if (colon == std::string::npos) {
                Token token;
                token.kind = Token::Kind::Word;
                token.word = lowerCase(word);
                token.position = start;
                tokens.push_back(std::move(token));
                continue;
            }

            Token token;
            token.kind = Token::Kind::Test;
            token.field = word.substr(0, colon);
            token.position = start;
            splitValues(word.substr(colon + 1), start + colon + 1, token);
            tokens.push_back(std::move(token));
        }
        { Token t; t.kind = Token::Kind::End; t.position = text_.size(); tokens.push_back(std::move(t)); }
        return tokens;
    }

  private:
    void skipSpaces() {
        while (at_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[at_]))) ++at_;
    }

    /** Reads to the next space or bracket, honouring quotes and slash-wrapped values. */
    std::string readWord() {
        std::string out;
        while (at_ < text_.size()) {
            const char c = text_[at_];
            if (std::isspace(static_cast<unsigned char>(c)) || c == '(' || c == ')') break;

            if (c == '\'' || c == '"') {
                out += readQuoted(c);
                continue;
            }
            if (c == '/') {
                out += readSlashed();
                continue;
            }
            out += c;
            ++at_;
        }
        return out;
    }

    /** A quoted value. The quotes stay, so the value parser knows it was quoted. */
    std::string readQuoted(const char quote) {
        const auto opened = at_;
        std::string out(1, quote);
        ++at_;
        while (at_ < text_.size()) {
            const char c = text_[at_];
            if (c == '\\' && at_ + 1 < text_.size()) {
                out += c;
                out += text_[at_ + 1];
                at_ += 2;
                continue;
            }
            ++at_;
            out += c;
            if (c == quote) return out;
        }
        throw filterError(text_, opened, "This quote is never closed.",
                          "Add the matching quote, or remove this one.");
    }

    std::string readSlashed() {
        const auto opened = at_;
        std::string out(1, '/');
        ++at_;
        while (at_ < text_.size()) {
            const char c = text_[at_];
            if (c == '\\' && at_ + 1 < text_.size()) {
                out += c;
                out += text_[at_ + 1];
                at_ += 2;
                continue;
            }
            ++at_;
            out += c;
            if (c == '/') return out;
        }
        throw filterError(text_, opened, "This pattern is never closed.",
                          "A pattern starts and ends with a slash, as in /beam.*line/.");
    }

    /** Splits `a|b|c` into alternatives, without breaking a quoted or slashed value. */
    void splitValues(const std::string &all, const size_t base, Token &token) const {
        std::string current;
        bool in_quote = false, in_slash = false;
        char quote = 0;
        bool current_is_regex = false;

        const auto flush = [&]() {
            token.values.push_back(current);
            token.is_regex.push_back(current_is_regex);
            current.clear();
            current_is_regex = false;
        };

        for (size_t i = 0; i < all.size(); ++i) {
            const char c = all[i];
            if (c == '\\' && i + 1 < all.size()) {
                current += c;
                current += all[i + 1];
                ++i;
                continue;
            }
            if (!in_slash && (c == '\'' || c == '"')) {
                if (!in_quote) { in_quote = true; quote = c; }
                else if (c == quote) { in_quote = false; }
                continue;  // the quotes themselves are not part of the value
            }
            if (!in_quote && c == '/') {
                in_slash = !in_slash;
                if (!in_slash) current_is_regex = true;
                else current_is_regex = true;
                continue;
            }
            if (c == '|' && !in_quote && !in_slash) { flush(); continue; }
            current += c;
        }
        flush();
        (void)base;
    }

    const std::string &text_;
    size_t at_{0};
};


/////////////////////////////////////////////////////////////////////////////
// Parser
/////////////////////////////////////////////////////////////////////////////

/** Turn a broken-down date into a moment, reading it as Coordinated Universal Time.
 *
 * The one function that does this is spelled differently on either platform, and neither
 * spelling exists on the other. mktime is not a substitute: it reads the same fields as local
 * time, so it would move every date in the filter by the offset of whatever zone the machine
 * happens to be in.
 */
inline int64_t momentFromUtc(std::tm &tm) {
#if defined(_WIN32) || defined(_MSC_VER)
    return static_cast<int64_t>(_mkgmtime(&tm));
#else
    return static_cast<int64_t>(timegm(&tm));
#endif
}

/** Reads a date written as YYYY-MM-DD, optionally with a time, as Coordinated Universal Time. */
bool parseAbsoluteDate(const std::string &text, int64_t &start, int64_t &end, bool &whole_day) {
    std::tm tm{};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    const int with_time = std::sscanf(text.c_str(), "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);
    if (with_time != 3 && with_time != 6) return false;
    if (month < 1 || month > 12 || day < 1 || day > 31) return false;

    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    const auto moment = momentFromUtc(tm);
    whole_day = with_time == 3;
    start = moment;
    end = whole_day ? moment + 24 * 60 * 60 : moment + 1;
    return true;
}

/** True where a value is a period: digits followed by a unit letter, possibly repeated. */
bool looksLikePeriod(const std::string &text) {
    if (text.empty()) return false;
    bool seen_digit = false, seen_unit = false;
    for (const char c : text) {
        if (std::isdigit(static_cast<unsigned char>(c))) { seen_digit = true; continue; }
        if (std::string("yMwdhms").find(c) != std::string::npos) { seen_unit = true; continue; }
        return false;
    }
    return seen_digit && seen_unit;
}

bool isAllDigits(const std::string &text) {
    if (text.empty()) return false;
    for (const char c : text) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

bool isDateField(const FilterField field) {
    switch (field) {
        case FilterField::Issued: case FilterField::IssuedBefore: case FilterField::IssuedAfter:
        case FilterField::Expires: case FilterField::ExpiresBefore: case FilterField::ExpiresAfter:
        case FilterField::RenewBy: case FilterField::RenewBefore: case FilterField::RenewAfter:
        case FilterField::Changed: case FilterField::ChangedBefore: case FilterField::ChangedAfter:
            return true;
        default:
            return false;
    }
}

bool isComparisonField(const FilterField field) {
    switch (field) {
        case FilterField::IssuedBefore: case FilterField::IssuedAfter:
        case FilterField::ExpiresBefore: case FilterField::ExpiresAfter:
        case FilterField::RenewBefore: case FilterField::RenewAfter:
        case FilterField::ChangedBefore: case FilterField::ChangedAfter:
            return true;
        default:
            return false;
    }
}

/** A `*_before` field looks forward from now; a `*_after` field looks back. */
bool comparisonLooksForward(const FilterField field) {
    switch (field) {
        case FilterField::IssuedBefore: case FilterField::ExpiresBefore:
        case FilterField::RenewBefore: case FilterField::ChangedBefore:
            return true;
        default:
            return false;
    }
}

class Parser {
  public:
    Parser(const std::string &expression, std::vector<Token> tokens, const time_t now)
        : text_(expression), tokens_(std::move(tokens)), now_(now) {}

    std::unique_ptr<FilterNode> run() {
        auto node = parseOr(0);
        if (peek().kind != Token::Kind::End) {
            const auto &token = peek();
            if (token.kind == Token::Kind::CloseBracket) {
                throw filterError(text_, token.position, "There is a closing bracket with nothing to close.",
                                  "Remove it, or add the opening bracket it belongs to.");
            }
            throw filterError(text_, token.position, "I expected the filter to end here.",
                              "Put the word and, or, or or between two tests.");
        }
        if (regex_count_ > kFilterMaxRegexes) {
            throw filterError(text_, 0, "This filter has too many patterns in it.",
                              "Use at most " + std::to_string(kFilterMaxRegexes) + " slash-wrapped patterns.");
        }
        return node;
    }

  private:
    const Token &peek() const { return tokens_[at_]; }
    const Token &take() { return tokens_[at_++]; }

    std::unique_ptr<FilterNode> parseOr(const size_t depth) {
        auto left = parseAnd(depth);
        while (peek().kind == Token::Kind::Word && peek().word == "or") {
            take();
            auto right = parseAnd(depth);
            auto node = std::unique_ptr<FilterNode>(new FilterNode);
            node->kind = FilterNode::Kind::Or;
            node->children.push_back(std::move(left));
            node->children.push_back(std::move(right));
            left = std::move(node);
        }
        return left;
    }

    std::unique_ptr<FilterNode> parseAnd(const size_t depth) {
        auto left = parseNot(depth);
        while (peek().kind == Token::Kind::Word && peek().word == "and") {
            take();
            auto right = parseNot(depth);
            auto node = std::unique_ptr<FilterNode>(new FilterNode);
            node->kind = FilterNode::Kind::And;
            node->children.push_back(std::move(left));
            node->children.push_back(std::move(right));
            left = std::move(node);
        }
        return left;
    }

    std::unique_ptr<FilterNode> parseNot(const size_t depth) {
        if (peek().kind == Token::Kind::Word && peek().word == "not") {
            take();
            auto node = std::unique_ptr<FilterNode>(new FilterNode);
            node->kind = FilterNode::Kind::Not;
            node->children.push_back(parseNot(depth));
            return node;
        }
        return parsePrimary(depth);
    }

    std::unique_ptr<FilterNode> parsePrimary(const size_t depth) {
        if (depth > kFilterMaxDepth) {
            throw filterError(text_, peek().position, "This filter has too many brackets inside brackets.",
                              "Use at most " + std::to_string(kFilterMaxDepth) + " levels.");
        }

        const auto &token = peek();
        if (token.kind == Token::Kind::OpenBracket) {
            const auto opened = token.position;
            take();
            auto inner = parseOr(depth + 1);
            if (peek().kind != Token::Kind::CloseBracket) {
                throw filterError(text_, opened, "This bracket is never closed.",
                                  "Add a closing bracket, or remove this one.");
            }
            take();
            return inner;
        }

        if (token.kind == Token::Kind::Test) return parseTest(take());

        if (token.kind == Token::Kind::Word) {
            take();
            if (token.word == "and" || token.word == "or") {
                throw filterError(text_, token.position, "There is nothing before the word \"" + token.word + "\".",
                                  "A joining word goes between two tests.");
            }
            throw filterError(text_, token.position, "\"" + token.word + "\" is not a test.",
                              "A test is written as field:value, for example state:VALID.\n" + std::string(kFieldList));
        }

        throw filterError(text_, token.position, "I expected a test here.",
                          "A test is written as field:value, for example state:VALID.");
    }

    std::unique_ptr<FilterNode> parseTest(const Token &token) {
        auto node = std::unique_ptr<FilterNode>(new FilterNode);
        node->kind = FilterNode::Kind::Test;
        node->field_text = token.field;
        node->position = token.position;

        const auto &names = fieldNames();
        const auto found = names.find(lowerCase(token.field));
        if (found == names.end()) {
            std::vector<std::string> known;
            for (const auto &pair : names) known.push_back(pair.first);
            const auto suggestion = nearestWord(token.field, known);
            std::string advice;
            if (!suggestion.empty()) advice = "Did you mean \"" + suggestion + "\"?\n";
            advice += kFieldList;
            throw filterError(text_, token.position, "There is no field called \"" + token.field + "\".", advice);
        }
        node->field = found->second;

        for (size_t i = 0; i < token.values.size(); ++i) {
            node->values.push_back(readValue(node->field, token.values[i], token.is_regex[i], token.position));
        }
        return node;
    }

    FilterValue readValue(const FilterField field, const std::string &written, const bool is_regex,
                          const size_t position) {
        FilterValue value;
        if (is_regex) {
            ++regex_count_;
            value.kind = FilterValueKind::Regex;
            value.text = written;
            try {
                std::regex probe(written, std::regex::ECMAScript | std::regex::icase);
                (void)probe;
            } catch (const std::regex_error &) {
                throw filterError(text_, position, "I cannot understand the pattern \"" + written + "\".",
                                  "A pattern is written between slashes, as in /beam.*line/.");
            }
            return value;
        }

        if (field == FilterField::State) {
            const auto wanted = upperCase(written);
            const auto names = statusNames();
            for (size_t i = 0; i < names.size(); ++i) {
                if (names[i] == wanted) {
                    value.kind = FilterValueKind::Status;
                    value.number = static_cast<int64_t>(i);
                    value.text = names[i];
                    return value;
                }
            }
            const auto suggestion = nearestWord(written, names);
            std::string advice;
            if (!suggestion.empty()) advice = "Did you mean \"" + suggestion + "\"?\n";
            advice += "Statuses: ";
            for (size_t i = 0; i < names.size(); ++i) advice += (i ? ", " : "") + names[i];
            advice += ".";
            throw filterError(text_, position, "There is no status called \"" + written + "\".", advice);
        }

        if (field == FilterField::Serial) {
            if (!isAllDigits(written)) {
                throw filterError(text_, position, "A serial is a whole number, and \"" + written + "\" is not.",
                                  "Write the serial as digits, or use id: to match the whole identifier.");
            }
            value.kind = FilterValueKind::Number;
            value.number = std::strtoll(written.c_str(), nullptr, 10);
            value.text = written;
            return value;
        }

        if (isDateField(field)) return readDateValue(field, written, position);

        value.kind = FilterValueKind::Text;
        value.text = written;
        return value;
    }

    FilterValue readDateValue(const FilterField field, const std::string &written, const size_t position) {
        FilterValue value;

        int64_t start = 0, end = 0;
        bool whole_day = false;
        if (parseAbsoluteDate(written, start, end, whole_day)) {
            if (isComparisonField(field)) {
                value.kind = FilterValueKind::Instant;
                value.number = start;
            } else {
                value.kind = whole_day ? FilterValueKind::DayRange : FilterValueKind::Instant;
                value.number = start;
                value.number_end = end;
            }
            value.text = written;
            return value;
        }

        if (looksLikePeriod(written)) {
            if (!isComparisonField(field)) {
                throw filterError(text_, position, "A period does not say which side of it you want.",
                                  "Use expires_before: or expires_after: with a period, and a date "
                                  "such as 2026-07-31 with expires:.");
            }
            time_t seconds = 0;
            try {
                seconds = static_cast<time_t>(CertDate::parseDuration(written));
            } catch (const std::exception &) {
                throw filterError(text_, position, "I cannot understand the period \"" + written + "\".",
                                  "A period is a number and a unit letter, as in 30d. The letters are "
                                  "y years, M months, w weeks, d days, h hours, m minutes and s seconds; "
                                  "note that M is months and m is minutes.");
            }
            value.kind = FilterValueKind::Instant;
            // A "before" field looks forward from now, an "after" field looks back, so that
            // "expires before thirty days from now" and "issued after seven days ago" both read
            // the way they are said.
            value.number = comparisonLooksForward(field) ? static_cast<int64_t>(now_) + seconds
                                                         : static_cast<int64_t>(now_) - seconds;
            value.text = written;
            return value;
        }

        if (isAllDigits(written)) {
            throw filterError(text_, position, "\"" + written + "\" has no unit, so I cannot tell what it means.",
                              "Add a unit letter, as in " + written +
                                  "d for days. The letters are y years, M months, w weeks, d days, "
                                  "h hours, m minutes and s seconds.");
        }

        throw filterError(text_, position, "I cannot understand the date \"" + written + "\".",
                          "Write a date as 2026-07-31, a date and time as '2026-07-31 10:31:21', "
                          "or a period such as 30d.");
    }

    const std::string &text_;
    std::vector<Token> tokens_;
    size_t at_{0};
    size_t regex_count_{0};
    time_t now_;
};


/////////////////////////////////////////////////////////////////////////////
// Negation normal form, the query condition, and matching
/////////////////////////////////////////////////////////////////////////////

std::unique_ptr<FilterNode> clone(const FilterNode &node);

/**
 * @brief Push every negation down onto the tests.
 *
 * This is what makes replacing a test with "always true" safe when building the query
 * condition: with no negation above a test, widening a test can only widen the result, so the
 * condition returns a superset and never hides a row the operator should have seen.
 */
std::unique_ptr<FilterNode> toNegationNormalForm(const FilterNode &node, const bool negated) {
    auto out = std::unique_ptr<FilterNode>(new FilterNode);

    switch (node.kind) {
        case FilterNode::Kind::Test:
            *out = FilterNode{};
            out->kind = FilterNode::Kind::Test;
            out->field = node.field;
            out->field_text = node.field_text;
            out->values = node.values;
            out->position = node.position;
            if (!negated) return out;
            {
                auto wrapper = std::unique_ptr<FilterNode>(new FilterNode);
                wrapper->kind = FilterNode::Kind::Not;
                wrapper->children.push_back(std::move(out));
                return wrapper;
            }

        case FilterNode::Kind::Not:
            // Two negations cancel.
            return toNegationNormalForm(*node.children.front(), !negated);

        case FilterNode::Kind::And:
        case FilterNode::Kind::Or: {
            const bool is_and = node.kind == FilterNode::Kind::And;
            // Negating an "and" gives an "or" of the negations, and the other way round.
            out->kind = (is_and != negated) ? FilterNode::Kind::And : FilterNode::Kind::Or;
            for (const auto &child : node.children) {
                out->children.push_back(toNegationNormalForm(*child, negated));
            }
            return out;
        }
    }
    return out;
}

std::unique_ptr<FilterNode> clone(const FilterNode &node) {
    auto out = std::unique_ptr<FilterNode>(new FilterNode);
    out->kind = node.kind;
    out->field = node.field;
    out->field_text = node.field_text;
    out->values = node.values;
    out->position = node.position;
    for (const auto &child : node.children) out->children.push_back(clone(*child));
    return out;
}

/** The column a field reads, or nothing where the field is not a column. */
const char *columnOf(const FilterField field) {
    switch (field) {
        case FilterField::Serial: return "serial";
        case FilterField::Name: return "CN";
        case FilterField::Org: return "O";
        // A certificate may carry several units, one row each, so the test runs inside a
        // subquery over the child table rather than against a column on certs. See
        // conditionFor, which wraps whatever is built here.
        case FilterField::Unit: return "u.value";
        case FilterField::Country: return "C";
        case FilterField::State: return "status";
        case FilterField::Issued: case FilterField::IssuedBefore: case FilterField::IssuedAfter: return "not_before";
        case FilterField::Expires: case FilterField::ExpiresBefore: case FilterField::ExpiresAfter: return "not_after";
        case FilterField::RenewBy: case FilterField::RenewBefore: case FilterField::RenewAfter: return "renew_by";
        case FilterField::Changed: case FilterField::ChangedBefore: case FilterField::ChangedAfter:
            return "status_date";
        default: return nullptr;  // id and issuer are not columns
    }
}

/** Escapes the characters LIKE treats specially, then turns `*` into the wildcard LIKE uses. */
std::string toLikePattern(const std::string &text, bool &has_wildcard) {
    std::string out;
    has_wildcard = false;
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '\\' && i + 1 < text.size() && text[i + 1] == '*') {
            out += "*";  // an escaped asterisk is a literal one
            ++i;
            continue;
        }
        if (c == '*') { out += '%'; has_wildcard = true; continue; }
        // Escaped so a value containing one of these matches only itself.
        if (c == '%' || c == '_' || c == '\\') { out += '\\'; }
        out += c;
    }
    return out;
}

/** Whether a test can be turned into a condition at all. */
bool isPushable(const FilterNode &test) {
    if (columnOf(test.field) == nullptr) return false;
    for (const auto &value : test.values) {
        if (value.kind == FilterValueKind::Regex) return false;
    }
    return !test.values.empty();
}

/** Builds one test's condition, appending anything it needs bound. */
std::string conditionFor(const FilterNode &test, const bool negated, std::vector<FilterValue> &bindings) {
    const auto *column = columnOf(test.field);
    std::string joined;

    for (const auto &value : test.values) {
        std::string one;
        switch (value.kind) {
            case FilterValueKind::Status:
            case FilterValueKind::Number:
                one = std::string(column) + " = ?";
                bindings.push_back(value);
                break;

            case FilterValueKind::Instant:
                if (isComparisonField(test.field)) {
                    one = std::string(column) + (comparisonLooksForward(test.field) ? " <= ?" : " >= ?");
                    bindings.push_back(value);
                } else {
                    one = std::string(column) + " >= ? AND " + column + " < ?";
                    FilterValue from = value, to = value;
                    to.number = value.number_end ? value.number_end : value.number + 1;
                    bindings.push_back(from);
                    bindings.push_back(to);
                }
                break;

            case FilterValueKind::DayRange: {
                one = std::string(column) + " >= ? AND " + column + " < ?";
                FilterValue from = value, to = value;
                to.number = value.number_end;
                bindings.push_back(from);
                bindings.push_back(to);
                break;
            }

            case FilterValueKind::Text: {
                bool has_wildcard = false;
                FilterValue bound = value;
                bound.text = toLikePattern(value.text, has_wildcard);
                if (has_wildcard) {
                    one = std::string(column) + " LIKE ? ESCAPE '\\'";
                } else {
                    // Text matching is case-insensitive everywhere, so an exact test says so.
                    one = std::string(column) + " = ? COLLATE NOCASE";
                }
                bindings.push_back(bound);
                break;
            }

            case FilterValueKind::Regex:
                return "1";  // never reached: a regular expression is not pushable
        }
        // The units live one row per value in a child table, so the test asks whether any of a
        // certificate's rows satisfies it. That makes `unit:beamline` find a certificate whose
        // units are staff inside beamline, which naming an outer unit is meant to do.
        if (test.field == FilterField::Unit)
            one = "EXISTS (SELECT 1 FROM cert_subject_units u WHERE u.serial = c.serial AND (" + one + "))";
        joined += (joined.empty() ? "(" : " OR ") + one;
    }
    joined += ")";
    return negated ? "NOT " + joined : joined;
}

/** Walks the negation normal form, building the condition. */
std::string buildCondition(const FilterNode &node, std::vector<FilterValue> &bindings) {
    switch (node.kind) {
        case FilterNode::Kind::Test:
            // Not a column, or a pattern the database cannot run: let everything through here
            // and leave it to the pass over the rows.
            return isPushable(node) ? conditionFor(node, false, bindings) : "1";

        case FilterNode::Kind::Not: {
            const auto &test = *node.children.front();
            if (test.kind != FilterNode::Kind::Test || !isPushable(test)) return "1";
            return conditionFor(test, true, bindings);
        }

        case FilterNode::Kind::And:
        case FilterNode::Kind::Or: {
            const char *joiner = node.kind == FilterNode::Kind::And ? " AND " : " OR ";
            std::string out;
            for (const auto &child : node.children) {
                out += (out.empty() ? "(" : joiner) + buildCondition(*child, bindings);
            }
            out += ")";
            return out;
        }
    }
    return "1";
}

/////////////////////////////////////////////////////////////////////////////
// Matching a row
/////////////////////////////////////////////////////////////////////////////

bool textMatches(const std::string &pattern, const std::string &subject) {
    // The same wildcard rule the condition uses, applied here so the two agree.
    std::string regex_text;
    for (size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if (c == '\\' && i + 1 < pattern.size() && pattern[i + 1] == '*') {
            regex_text += "\\*";
            ++i;
            continue;
        }
        if (c == '*') { regex_text += ".*"; continue; }
        if (std::string("^$.|?+()[]{}\\").find(c) != std::string::npos) regex_text += '\\';
        regex_text += c;
    }
    try {
        const std::regex expression("^" + regex_text + "$", std::regex::ECMAScript | std::regex::icase);
        return std::regex_match(subject, expression);
    } catch (const std::regex_error &) {
        return false;
    }
}

bool regexMatches(const std::string &pattern, const std::string &subject) {
    try {
        const std::regex expression(pattern, std::regex::ECMAScript | std::regex::icase);
        return std::regex_search(subject, expression);
    } catch (const std::regex_error &) {
        return false;
    }
}

/**
 * @brief Whether any one of a certificate's organizational unit values matches.
 *
 * The one place organizational unit matching is decided. A certificate may carry several
 * values - an institution nests them - and a test matches when any one of them does, so
 * `not unit:beamline` means none of them does. Keeping it here means the change that stores
 * several values has one place to edit.
 */
bool unitMatches(const FilterValue &value, const std::vector<std::string> &units) {
    for (const auto &unit : units) {
        if (value.kind == FilterValueKind::Regex ? regexMatches(value.text, unit)
                                                 : textMatches(value.text, unit)) {
            return true;
        }
    }
    return false;
}

bool valueMatchesRow(const FilterNode &test, const FilterValue &value, const FilterRow &row) {
    const auto text_of = [&row](const FilterField field) -> const std::string & {
        static const std::string empty;
        switch (field) {
            case FilterField::Id: return row.cert_id;
            case FilterField::Name: return row.common_name;
            case FilterField::Org: return row.organization;
            case FilterField::Country: return row.country;
            // The word the listing prints in its Type column, so what an operator reads is
            // what they can write. It is derived from the stored key usage rather than held
            // in a column, so it is only ever matched here, never pushed into the query.
            case FilterField::Type: return row.type;
            default: return empty;
        }
    };

    switch (test.field) {
        case FilterField::Unit:
            return unitMatches(value, row.organizational_units);

        case FilterField::Serial:
            return value.kind == FilterValueKind::Number && static_cast<uint64_t>(value.number) == row.serial;

        case FilterField::State:
            return value.kind == FilterValueKind::Status && static_cast<int>(value.number) == row.status;

        case FilterField::Issuer:
            // Decided before the query; every row of this authority matches.
            return true;

        default:
            break;
    }

    if (isDateField(test.field)) {
        time_t when = 0;
        switch (test.field) {
            case FilterField::Issued: case FilterField::IssuedBefore: case FilterField::IssuedAfter:
                when = row.not_before; break;
            case FilterField::Expires: case FilterField::ExpiresBefore: case FilterField::ExpiresAfter:
                when = row.not_after; break;
            case FilterField::RenewBy: case FilterField::RenewBefore: case FilterField::RenewAfter:
                when = row.renew_by; break;
            default:
                when = row.status_date; break;
        }
        if (isComparisonField(test.field)) {
            return comparisonLooksForward(test.field) ? when <= value.number : when >= value.number;
        }
        const auto end = value.number_end ? value.number_end : value.number + 1;
        return when >= value.number && when < end;
    }

    const auto &subject = text_of(test.field);
    return value.kind == FilterValueKind::Regex ? regexMatches(value.text, subject)
                                                : textMatches(value.text, subject);
}

bool nodeMatches(const FilterNode &node, const FilterRow &row) {
    switch (node.kind) {
        case FilterNode::Kind::Test:
            for (const auto &value : node.values) {
                if (valueMatchesRow(node, value, row)) return true;
            }
            return false;
        case FilterNode::Kind::Not:
            return !nodeMatches(*node.children.front(), row);
        case FilterNode::Kind::And:
            for (const auto &child : node.children) {
                if (!nodeMatches(*child, row)) return false;
            }
            return true;
        case FilterNode::Kind::Or:
            for (const auto &child : node.children) {
                if (nodeMatches(*child, row)) return true;
            }
            return false;
    }
    return false;
}

/** Collects every `issuer:` test, so a filter naming another authority can be answered at once. */
void collectIssuerTests(const FilterNode &node, std::vector<const FilterNode *> &out) {
    if (node.kind == FilterNode::Kind::Test) {
        if (node.field == FilterField::Issuer) out.push_back(&node);
        return;
    }
    for (const auto &child : node.children) collectIssuerTests(*child, out);
}

}  // namespace


CertFilter CertFilter::parse(const std::string &expression, const time_t now) {
    if (expression.size() > kFilterMaxLength) {
        throw CertFilterError("That filter is too long. Use at most " + std::to_string(kFilterMaxLength) +
                                  " characters.",
                              0);
    }

    CertFilter filter;
    filter.text_ = expression;

    Tokeniser tokeniser(filter.text_);
    Parser parser(filter.text_, tokeniser.run(), now);
    const auto parsed = parser.run();

    filter.root_ = toNegationNormalForm(*parsed, false);
    filter.where_clause_ = buildCondition(*filter.root_, filter.bindings_);
    return filter;
}

bool CertFilter::matches(const FilterRow &row) const { return root_ ? nodeMatches(*root_, row) : true; }

bool CertFilter::possibleFor(const std::string &issuer_id) const {
    if (!root_) return true;
    std::vector<const FilterNode *> issuer_tests;
    collectIssuerTests(*root_, issuer_tests);
    for (const auto *test : issuer_tests) {
        bool any_matches = false;
        for (const auto &value : test->values) {
            // An authority names itself in full on its own certificate and by the first eight
            // digits of that in a channel name, and both get written down. Compare only as far
            // as the shorter of the two runs, so either names the same authority. A pattern or
            // a regular expression is left alone: what it was written to match is the caller's
            // business, not something to shorten on their behalf.
            if (value.kind == FilterValueKind::Text && value.text.find('*') == std::string::npos &&
                value.text.size() > issuer_id.size()) {
                if (textMatches(value.text.substr(0, issuer_id.size()), issuer_id)) {
                    any_matches = true;
                    continue;
                }
            }
            if (value.kind == FilterValueKind::Regex ? regexMatches(value.text, issuer_id)
                                                     : textMatches(value.text, issuer_id)) {
                any_matches = true;
            }
        }
        // A plain issuer test naming somewhere else can never match a row here. Nested under an
        // "or" it could still be satisfied by the other side, so only a filter that is nothing
        // but issuer tests is answered this way.
        if (!any_matches && issuer_tests.size() == 1 && root_->kind == FilterNode::Kind::Test) return false;
    }
    return true;
}

}  // namespace certs
}  // namespace pvxs
