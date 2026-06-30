/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef CMS_VERSION_H
#define CMS_VERSION_H

#include <ostream>

namespace cms {

/** Stream the pvxs-cms version banner.
 *
 * Prints the pvxs-cms module revision (Git describe) followed by the
 * pvxs/EPICS/libevent/OpenSSL lines from pvxs::version_information, so every
 * CMS executable's -V output identifies both the module and the libraries it
 * was built against. Use as a stream manipulator: `std::cout << cms::version_information;`.
 */
std::ostream& version_information(std::ostream& strm);

}  // namespace cms

#endif  // CMS_VERSION_H
