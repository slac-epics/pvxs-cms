/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "openssl.h"

#include <fstream>
#include <stdexcept>

#include <epicsExit.h>

#include <openssl/err.h>

#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusmanager.h"
#include "evhelper.h"
#include "ownedptr.h"

#ifndef TLS1_3_VERSION
#error TLS 1.3 support required.  Upgrade to openssl >= 1.1.0
#endif

namespace pvxs {
namespace ossl {


}  // namespace ossl
}  // namespace pvxs
