/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "cmsversion.h"

#include <ostream>

#include <pvxs/util.h>

#include "pvxscmsVCS.h"

namespace cms {

std::ostream& version_information(std::ostream& strm) {
#ifdef PVXS_CMS_VCS_VERSION
    strm << "PVXS-CMS (" PVXS_CMS_VCS_VERSION ")\n";
#else
    strm << "PVXS-CMS (unknown revision)\n";
#endif
    return pvxs::version_information(strm);
}

}  // namespace cms
