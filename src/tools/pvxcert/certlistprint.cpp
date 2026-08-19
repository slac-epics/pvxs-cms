/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certlistprint.h"

#include <algorithm>
#include <vector>

namespace pvxs {
namespace certs {

namespace {

/** The column field names, in the order the server declared them. */
std::vector<std::string> columnNames(const Value &table) {
    std::vector<std::string> names;
    const auto columns = table["value"];
    for (const auto &column : columns.ichildren()) {
        names.emplace_back(columns.nameOf(column));
    }
    return names;
}

/** Each column's values. Absent entries read as empty so a short column cannot misalign a row. */
std::vector<std::string> columnValues(const Value &table, const std::string &name) {
    const auto column = table["value"][name];
    if (!column) return {};
    const auto values = column.as<shared_array<const std::string>>();
    return {values.begin(), values.end()};
}

/** Quote for comma separated output, doubling any quotation mark, as the format requires. */
std::string csvField(const std::string &value) {
    const bool needs_quoting = value.find_first_of(",\"\n\r") != std::string::npos;
    if (!needs_quoting) return value;
    std::string quoted{"\""};
    for (const char c : value) {
        if (c == '"') quoted += '"';
        quoted += c;
    }
    quoted += '"';
    return quoted;
}

/** Escape for a JavaScript Object Notation string. */
std::string jsonField(const std::string &value) {
    std::string escaped;
    for (const char c : value) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped += c;
        }
    }
    return escaped;
}

}  // namespace

bool parseCertListFormat(const std::string &name, CertListFormat &out) {
    if (name == "columns" || name.empty()) {
        out = CertListFormat::Columns;
        return true;
    }
    if (name == "csv") {
        out = CertListFormat::Csv;
        return true;
    }
    if (name == "json") {
        out = CertListFormat::Json;
        return true;
    }
    return false;
}

void printCertList(std::ostream &out, const Value &table, const CertListFormat format) {
    const auto names = columnNames(table);
    if (names.empty()) return;

    // Headings from the server's own labels, so a column added on the server appears here
    // without a change to this program. Falls back to the field name if a label is missing.
    const auto labels_array = table["labels"].as<shared_array<const std::string>>();
    std::vector<std::string> labels{labels_array.begin(), labels_array.end()};
    labels.resize(names.size());
    for (size_t i = 0; i < names.size(); ++i) {
        if (labels[i].empty()) labels[i] = names[i];
    }

    std::vector<std::vector<std::string>> columns;
    columns.reserve(names.size());
    size_t row_count = 0;
    for (const auto &name : names) {
        columns.push_back(columnValues(table, name));
        row_count = std::max(row_count, columns.back().size());
    }
    const auto cell = [&columns](const size_t column, const size_t row) -> const std::string & {
        static const std::string empty;
        return row < columns[column].size() ? columns[column][row] : empty;
    };

    switch (format) {
        case CertListFormat::Csv: {
            for (size_t c = 0; c < names.size(); ++c) out << (c ? "," : "") << csvField(labels[c]);
            out << "\n";
            for (size_t r = 0; r < row_count; ++r) {
                for (size_t c = 0; c < names.size(); ++c) out << (c ? "," : "") << csvField(cell(c, r));
                out << "\n";
            }
            break;
        }

        case CertListFormat::Json: {
            // Field names are the server's, not the labels, so a program reads the same names
            // the served operation uses.
            out << "[";
            for (size_t r = 0; r < row_count; ++r) {
                out << (r ? ",\n " : "\n ") << "{";
                for (size_t c = 0; c < names.size(); ++c) {
                    out << (c ? ", " : "") << "\"" << jsonField(names[c]) << "\": \"" << jsonField(cell(c, r)) << "\"";
                }
                out << "}";
            }
            out << (row_count ? "\n]" : "]") << "\n";
            break;
        }

        case CertListFormat::Columns:
        default: {
            std::vector<size_t> widths(names.size());
            for (size_t c = 0; c < names.size(); ++c) {
                widths[c] = labels[c].size();
                for (size_t r = 0; r < row_count; ++r) widths[c] = std::max(widths[c], cell(c, r).size());
            }

            const auto write_row = [&](const std::vector<std::string> &values) {
                for (size_t c = 0; c < names.size(); ++c) {
                    if (c) out << "  ";
                    // The last column is not padded, so a line carries no trailing spaces.
                    if (c + 1 == names.size()) {
                        out << values[c];
                    } else {
                        out << values[c] << std::string(widths[c] - values[c].size(), ' ');
                    }
                }
                out << "\n";
            };

            write_row(labels);
            for (size_t r = 0; r < row_count; ++r) {
                std::vector<std::string> row;
                row.reserve(names.size());
                for (size_t c = 0; c < names.size(); ++c) row.push_back(cell(c, r));
                write_row(row);
            }
            break;
        }
    }
}

}  // namespace certs
}  // namespace pvxs
