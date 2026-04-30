/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "pvacms.h"

#include <iostream>
#include <stdexcept>
#include <string>

#include <dbStaticLib.h>
#include <asLib.h>
#include <sqlite3.h>

#include <pvxs/client.h>
#include <cms/cms.h>
#include <pvxs/log.h>

#include "certstatus.h"
#include "certstatusfactory.h"
#include "certfilefactory.h"
#include "configcms.h"
#include "ownedptr.h"

DEFINE_LOGGER(pvacms, "cms.certs.cms");

int main(int argc, char *argv[]) {
    using cms::ConfigCms;
    using cms::StartupAbort;
    using cms::cert::CertStatus;
    using cms::cert::CertStatusFactory;
    using cms::cert::IdFileFactory;

    try {
        auto config = ConfigCms::forCms();
        auto authn_config_map = cms::getAuthNConfigMap();

        auto program_name = argv[0];
        bool verbose = false;
        std::string admin_name, admin_name_ensure;

        if (auto rc = cms::readParameters(argc, argv, program_name, config, authn_config_map,
                                          verbose, admin_name, admin_name_ensure))
            return rc;

        if (verbose)
            pvxs::logger_level_set("cms.*", pvxs::Level::Info);
        pvxs::logger_config_env();
        if (config.quiet) {
            pvxs::logger_level_set("cms.*", pvxs::Level::Warn);
            pvxs::logger_level_set("pvxs.*", pvxs::Level::Warn);
        }

        if (!config.backup_path.empty()) {
            std::string backup_dest = config.backup_path;
            if (backup_dest.size() < 3 || backup_dest.substr(backup_dest.size() - 3) != ".db")
                backup_dest += ".db";
            pvxs::sql_ptr certs_db;
            if (sqlite3_open_v2(config.certs_db_filename.c_str(), certs_db.acquire(),
                                SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
                std::cerr << "Cannot open database for backup: " << config.certs_db_filename << std::endl;
                return 1;
            }
            const bool ok = cms::performBackup(certs_db.get(), backup_dest);
            if (ok) std::cout << "Database backup written: " << backup_dest << std::endl;
            return ok ? 0 : 1;
        }

        if (!admin_name.empty() || !admin_name_ensure.empty()) {
            pvxs::sql_ptr certs_db;
            cms::initCertsDatabase(certs_db, config.certs_db_filename, config.quiet);

            pvxs::ossl_ptr<EVP_PKEY> cert_auth_pkey;
            pvxs::ossl_ptr<X509> cert_auth_cert;
            pvxs::ossl_ptr<X509> cert_auth_root_cert;
            pvxs::ossl_shared_ptr<STACK_OF(X509)> cert_auth_chain;
            auto is_initialising = false;
            cms::getOrCreateCertAuthCertificate(config, certs_db,
                                                cert_auth_cert, cert_auth_pkey,
                                                cert_auth_chain, cert_auth_root_cert,
                                                is_initialising);

            if (!admin_name.empty()) {
                try {
                    cms::createAdminClientCert(config, certs_db, cert_auth_pkey, cert_auth_cert,
                                               cert_auth_chain, admin_name);
                    cms::addUserToAdminACF(config, admin_name);
                    log_warn_printf(pvacms,
                                    "Admin user \"%s\" has been added to list of administrators of this PVACMS.  Restart the PVACMS for it to take effect\n",
                                    admin_name.c_str());
                } catch (const std::runtime_error &e) {
                    if (!is_initialising)
                        throw std::runtime_error(std::string("Error creating admin user certificate: ") + e.what());
                }
                return 0;
            }

            if (!admin_name_ensure.empty()) {
                try {
                    cms::createAdminClientCert(config, certs_db, cert_auth_pkey, cert_auth_cert,
                                               cert_auth_chain, admin_name_ensure);
                    log_warn_printf(pvacms,
                                    "Make sure user \"%s\" appears in %s to ensure it is in the list of administrators of this PVACMS\n",
                                    admin_name_ensure.c_str(), config.pvacms_acf_filename.c_str());
                } catch (const std::runtime_error &e) {
                    const std::string msg = e.what();
                    if (msg.find("Duplicate Certificate Subject") != std::string::npos) {
                        log_warn_printf(pvacms,
                                        "Admin user \"%s\" certificate not created: a certificate with this subject is already registered. Continuing startup.\n",
                                        admin_name_ensure.c_str());
                        cms::addUserToAdminACF(config, admin_name_ensure);
                    } else {
                        throw std::runtime_error(std::string("Error ensuring admin user certificate: ") + e.what());
                    }
                }
            }
        }

        auto state = cms::prepareCmsState(config);

        if (!config.pvacms_acf_filename.empty()) {
            log_debug_printf(pvacms, "Setting server access security from ACF: %s\n", config.pvacms_acf_filename.c_str());
            if (auto err = asInitFile(config.pvacms_acf_filename.c_str(), ""))
                throw std::runtime_error(pvxs::SB() << "Failed to load "
                                                    << config.pvacms_acf_filename
                                                    << " : " << err);
        } else {
            log_err_printf(pvacms, "****EXITING****: PVACMS Access Security Policy File Required%s", "\n");
            return 1;
        }

        auto handle = cms::detail::prepareServerFromState(config, std::move(state));

        if (verbose) {
            std::cout << "Effective config\n" << config << std::endl;
        }

        cms::startCluster(handle);
        cms::stopServer(handle);
        return 0;
    } catch (const cms::StartupAbort &) {
        return 1;
    } catch (const std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error: %s\n", e.what());
        return 1;
    }
}
