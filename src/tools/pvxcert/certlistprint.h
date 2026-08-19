/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CERTLISTPRINT_H_
#define PVXS_CERTLISTPRINT_H_

#include <ostream>
#include <string>

#include <pvxs/data.h>

namespace pvxs {
namespace certs {

/** How `--list` writes the table it was served. */
enum class CertListFormat {
    Columns,  //!< aligned columns for a person to read
    Csv,      //!< comma separated, for a spreadsheet or a script
    Json,     //!< one object per certificate, for a program
};

/**
 * @brief Read a format name from the command line.
 *
 * @param name the value given to the option
 * @param out  set when the name is recognised
 * @return false for an unrecognised name, so the caller can say what is accepted
 */
bool parseCertListFormat(const std::string &name, CertListFormat &out);

/**
 * @brief Write a served certificate listing.
 *
 * The headings come from the table's own labels and the rows are written in the order the
 * server sent them, never re-sorted: the server picks an order that is stable under an
 * update, and a client that re-sorted would undo that.
 *
 * @param out    where the table goes - standard output, so it can be piped
 * @param table  the served `epics:nt/NTTable:1.0` value
 * @param format how to write it
 */
void printCertList(std::ostream &out, const Value &table, CertListFormat format);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CERTLISTPRINT_H_
