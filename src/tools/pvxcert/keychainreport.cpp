/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "keychainreport.h"

#include <ostream>
#include <stdexcept>
#include <string>

#include "certstatusmanager.h"
#include "openssl.h"
#include "trustanchors.h"

namespace cms {
namespace cert {

std::string printKeychainReport(const pvxs::certs::CertData &cert_data, std::ostream &out, std::ostream &err) {
    if (!cert_data.cert) {
        if (anchorsInChain(cert_data.cert_auth_chain).empty()) {
            throw std::runtime_error("Failed to read certificate from file");
        }
        err << "No identity certificate; trust anchors only:" << std::endl;
        printAnchorListing(cert_data, out);
        return {};
    }

    // Not every certificate names a config PV, so a failed lookup just leaves the line out.
    std::string config_id{};
    try {
        config_id = pvxs::certs::CmsStatusManager::getConfigPvFromCert(cert_data.cert);
    } catch (...) {
    }

    err << "Certificate Details: " << std::endl << "============================================" << std::endl;
    out << pvxs::ossl::ShowX509{cert_data.cert.get()} << std::endl
        << (config_id.empty() ? "" : "Config URI     : " + config_id + "\n");
    err << "--------------------------------------------\n" << std::endl;
    printAnchorListing(cert_data, out);
    return pvxs::certs::CmsStatusManager::getStatusPvFromCert(cert_data.cert);
}

}  // namespace cert
}  // namespace cms
