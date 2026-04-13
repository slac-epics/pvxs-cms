/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "configcms.h"

#include <envDefs.h>
#include <osiFileName.h>

#include <pvxs/log.h>

#include "authregistry.h"
#include "configcerts.h"

DEFINE_LOGGER(cert_cfg, "pvxs.certs.cfg");

namespace pvxs {
namespace certs {

/**
 * @brief Create a Config object with default values suitable for use with a Mock CMS
 * This is isolated and has all CMS configuration
 *
 * @return ConfigCms for CMS
 */
ConfigCms ConfigCms::mockCms(int family) {
    auto ret = ConfigCms{};
    ret.applyCertsEnv();
    ret.applyCmsEnv({});

    ret.udp_port = 0u; // Select a random port
    ret.tcp_port = 0u;
    ret.tls_port = 0u;
    ret.auto_beacon = false;

    switch (family) {
        case AF_INET:
            ret.interfaces.emplace_back("127.0.0.1");
            ret.beaconDestinations.emplace_back("127.0.0.1");
            break;
        case AF_INET6:
            ret.interfaces.emplace_back("::1");
            ret.beaconDestinations.emplace_back("::1");
            break;
    default:
        throw std::logic_error(SB() << "Unsupported address family " << family);
    }

    ret.disableStatusCheck();
    ret.disableStapling();
    return ret;
}

/**
 * @brief Create a Config object with default values suitable for a PVACMS service
 *
 * @return ConfigCms for PVACMS
 */
ConfigCms ConfigCms::forCms() {
    auto ret = ConfigCms{};
    ret.applyCertsEnv();
    ret.applyCmsEnv({});
    ret.disableStatusCheck();
    ret.disableStapling();
    return ret;
}

void ConfigCms::applyCmsEnv(const std::map<std::string, std::string> &defs) {
    PickOne pickone{defs, true};
    PickOne pick_another_one{defs, true};

    // EPICS_PVACMS_TLS_KEYCHAIN (default the private key to use the same file and password)
    if (pickone({"EPICS_PVACMS_TLS_KEYCHAIN", "EPICS_PVAS_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(tls_keychain_file = pickone.val);

        // EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE
        std::string password_filename;
        if (pickone.name == "EPICS_PVACMS_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_PVACMS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pick_another_one.val;
        } else if (pickone.name == "EPICS_PVAS_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE"});
            password_filename = pick_another_one.val;
        }
        ensureDirectoryExists(password_filename);
        try {
            setKeychainPassword(getFileContents(password_filename));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "error reading password file: %s. %s", password_filename.c_str(), e.what());
        }
    } else {
        std::string filename = SB() << getXdgPvaConfigHome() << OSI_PATH_SEPARATOR << "pvacms.p12";
        ensureDirectoryExists(tls_keychain_file = filename);
    }

    // EPICS_PVACMS_ACF
    if (pickone({"EPICS_PVACMS_ACF"})) {
        ensureDirectoryExists(pvacms_acf_filename = pickone.val);
    } else {
        std::string filename = SB() << getXdgPvaConfigHome() << OSI_PATH_SEPARATOR << "pvacms.acf";
        ensureDirectoryExists(pvacms_acf_filename = filename);
    }

    // EPICS_PVACMS_DB
    if (pickone({"EPICS_PVACMS_DB"})) {
        ensureDirectoryExists(certs_db_filename = pickone.val);
    } else {
        std::string filename = SB() << getXdgPvaDataHome() << OSI_PATH_SEPARATOR << "certs.db";
        ensureDirectoryExists(filename);
        certs_db_filename = filename;
    }

    // EPICS_CERT_AUTH_TLS_KEYCHAIN

    if (pickone({"EPICS_CERT_AUTH_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(cert_auth_keychain_file = pickone.val);

        // EPICS_CERT_AUTH_TLS_KEYCHAIN_PWD_FILE
        if (pickone.name == "EPICS_CERT_AUTH_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_CERT_AUTH_TLS_KEYCHAIN_PWD_FILE"});
            std::string password_filename = pick_another_one.val;
            ensureDirectoryExists(password_filename);
            try {
                cert_auth_keychain_pwd = getFileContents(password_filename);
            } catch (std::exception &e) {
                log_err_printf(cert_cfg, "error reading password file: %s. %s", password_filename.c_str(), e.what());
            }
        }
    } else {
        std::string filename = SB() << getXdgPvaConfigHome() << OSI_PATH_SEPARATOR << "cert_auth.p12";
        ensureDirectoryExists(cert_auth_keychain_file = filename);
    }
    // EPICS_ADMIN_TLS_KEYCHAIN
    if (pickone({"EPICS_ADMIN_TLS_KEYCHAIN"})) {
        ensureDirectoryExists(admin_keychain_file = pickone.val);

        // EPICS_ADMIN_TLS_KEYCHAIN_PWD_FILE
        if (pickone.name == "EPICS_ADMIN_TLS_KEYCHAIN") {
            pick_another_one({"EPICS_ADMIN_TLS_KEYCHAIN_PWD_FILE"});
            std::string password_filename = pick_another_one.val;
            ensureDirectoryExists(password_filename);
            try {
                admin_keychain_pwd = getFileContents(password_filename);
            } catch (std::exception &e) {
                log_err_printf(cert_cfg, "error reading password file: %s. %s", password_filename.c_str(), e.what());
            }
        }
    } else {
        std::string filename = SB() << getXdgPvaConfigHome() << OSI_PATH_SEPARATOR << "admin.p12";
        ensureDirectoryExists(admin_keychain_file = filename);
    }

    // EPICS_CERT_AUTH_NAME
    if (pickone({"EPICS_CERT_AUTH_NAME"})) {
        cert_auth_name = pickone.val;
    }

    // EPICS_CERT_AUTH_ORGANIZATION
    if (pickone({"EPICS_CERT_AUTH_ORGANIZATION", "EPICS_PVAS_AUTH_ORGANIZATION", "EPICS_PVA_AUTH_ORGANIZATION"})) {
        cert_auth_organization = pickone.val;
    }

    // EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT
    if (pickone({"EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT", "EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT", "EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"})) {
        cert_auth_organizational_unit = pickone.val;
    }

    // EPICS_CERT_AUTH_COUNTRY
    if (pickone({"EPICS_CERT_AUTH_COUNTRY", "EPICS_PVAS_AUTH_COUNTRY", "EPICS_PVA_AUTH_COUNTRY"})) {
        cert_auth_country = pickone.val;
    }

    // EPICS_PVACMS_CERT STATUS VALIDITY MINS
    if (pickone({"EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS"})) {
        try {
            cert_status_validity_mins = CertDate::parseDurationMins(pickone.val);
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid validity duration : %s", pickone.name.c_str(), e.what());
        }
    }

    // EPICS_PVACMS_REQUIRE_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_APPROVAL"})) {
        cert_client_require_approval = cert_server_require_approval = cert_ioc_require_approval = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"})) {
        cert_client_require_approval = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_REQUIRE_SERVER_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_SERVER_APPROVAL"})) {
        cert_server_require_approval = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_REQUIRE_IOC_APPROVAL
    if (pickone({"EPICS_PVACMS_REQUIRE_IOC_APPROVAL", "EPICS_PVACMS_REQUIRE_SERVER_APPROVAL", "EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"})) {
        cert_ioc_require_approval = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_DISALLOW_CUSTOM_DURATION
    if (pickone({"EPICS_PVACMS_DISALLOW_CUSTOM_DURATION"})) {
        cert_disallow_client_custom_duration = cert_disallow_server_custom_duration = cert_disallow_ioc_custom_duration = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_DISALLOW_CLIENT_CUSTOM_DURATION
    if (pickone({"EPICS_PVACMS_DISALLOW_CLIENT_CUSTOM_DURATION"})) {
        cert_disallow_client_custom_duration = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_DISALLOW_SERVER_CUSTOM_DURATION
    if (pickone({"EPICS_PVACMS_DISALLOW_SERVER_CUSTOM_DURATION"})) {
        cert_disallow_server_custom_duration = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_DISALLOW_IOC_CUSTOM_DURATION
    if (pickone({"EPICS_PVACMS_DISALLOW_IOC_CUSTOM_DURATION", "EPICS_PVACMS_DISALLOW_SERVER_CUSTOM_DURATION", "EPICS_PVACMS_DISALLOW_CLIENT_CUSTOM_DURATION"})) {
        cert_disallow_ioc_custom_duration = parseTo<bool>(pickone.val);
    }

    // EPICS_PVACMS_CERT_VALIDITY
    if (pickone({"EPICS_PVACMS_CERT_VALIDITY"})) {
        default_client_cert_validity = default_server_cert_validity = default_ioc_cert_validity = pickone.val;
    }

    // EPICS_PVACMS_CERT_VALIDITY_CLIENT
    if (pickone({"EPICS_PVACMS_CERT_VALIDITY_CLIENT"})) {
        default_client_cert_validity = pickone.val;
    }

    // EPICS_PVACMS_CERT_VALIDITY_SERVER
    if (pickone({"EPICS_PVACMS_CERT_VALIDITY_SERVER"})) {
        default_server_cert_validity = pickone.val;
    }

    // EPICS_PVACMS_CERT_VALIDITY_IOC
    if (pickone({"EPICS_PVACMS_CERT_VALIDITY_IOC", "EPICS_PVACMS_CERT_VALIDITY_SERVER", "EPICS_PVACMS_CERT_VALIDITY_CLIENT"})) {
        default_ioc_cert_validity = pickone.val;
    }

    // EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION
    if (pickone({"EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION"})) {
        cert_status_subscription = static_cast<CertStatusSubscription>(parseTo<int8_t>(pickone.val));
    }

    // EPICS_PVACMS_CLUSTER_PV_PREFIX
    if (pickone({"EPICS_PVACMS_CLUSTER_PV_PREFIX"})) {
        cluster_pv_prefix = pickone.val;
    }

    // EPICS_PVACMS_CLUSTER_DISCOVERY_TIMEOUT
    if (pickone({"EPICS_PVACMS_CLUSTER_DISCOVERY_TIMEOUT"})) {
        try {
            cluster_discovery_timeout_secs = static_cast<uint32_t>(parseTo<uint64_t>(pickone.val));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid timeout: %s\n", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVACMS_CLUSTER_BIDI_TIMEOUT"})) {
        try {
            cluster_bidi_timeout_secs = static_cast<uint32_t>(parseTo<uint64_t>(pickone.val));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid timeout: %s\n", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVACMS_INTEGRITY_CHECK_INTERVAL"})) {
        try {
            integrity_check_interval_secs = static_cast<uint32_t>(parseTo<uint64_t>(pickone.val));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid interval: %s\n", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVACMS_AUDIT_RETENTION_DAYS"})) {
        try {
            audit_retention_days = static_cast<uint32_t>(parseTo<uint64_t>(pickone.val));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid retention days: %s\n", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVACMS_RATE_LIMIT"})) {
        try {
            rate_limit = static_cast<uint32_t>(parseTo<uint64_t>(pickone.val));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid rate limit: %s\n", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVACMS_RATE_LIMIT_BURST"})) {
        try {
            rate_limit_burst = static_cast<uint32_t>(parseTo<uint64_t>(pickone.val));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid rate limit burst: %s\n", pickone.name.c_str(), e.what());
        }
    }

    if (pickone({"EPICS_PVACMS_MAX_CONCURRENT_CCR"})) {
        try {
            max_concurrent_ccr = static_cast<uint32_t>(parseTo<uint64_t>(pickone.val));
        } catch (std::exception &e) {
            log_err_printf(cert_cfg, "%s invalid concurrent CCR limit: %s\n", pickone.name.c_str(), e.what());
        }
    }

}

/**
 * Update the definitions with the PVACMS specific definitions.
 *
 * This function is called from PVACMS to update the definitions with the PVACMS specific definitions.
 * It updates the definitions with the TLS stop if no cert, the ACF file, the certs database file, the certificate authority keychain file,
 * the admin keychain file, the certificate authority name, the certificate authority organization, the certificate authority organizational unit,
 * the certificate authority country, the certificate validity minutes, the client require approval, the server require approval,
 * the ioc require approval, and the certificate status subscription.
 *
 * It also adds any defs for any registered authn methods
 *
 * @param defs the definitions to update with the PVACMS specific definitions
 */
void ConfigCms::updateDefs(defs_t &defs) const {
    Config::updateDefs(defs);
    defs["EPICS_PVACMS_ACF"] = pvacms_acf_filename;
    defs["EPICS_PVACMS_DB"] = certs_db_filename;
    defs["EPICS_CERT_AUTH_TLS_KEYCHAIN"] = cert_auth_keychain_file;
    defs["EPICS_ADMIN_TLS_KEYCHAIN"] = admin_keychain_file;
    defs["EPICS_CERT_AUTH_NAME"] = cert_auth_name;
    defs["EPICS_CERT_AUTH_ORGANIZATION"] = defs["EPICS_PVAS_AUTH_ORGANIZATION"] = defs["EPICS_PVA_AUTH_ORGANIZATION"] = cert_auth_organization;
    defs["EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT"] = defs["EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT"] = defs["EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT"] =
        cert_auth_organizational_unit;
    defs["EPICS_CERT_AUTH_COUNTRY"] = defs["EPICS_PVAS_AUTH_COUNTRY"] = defs["EPICS_PVAS_AUTH_COUNTRY"] = cert_auth_country;
    defs["EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS"] = CertDate::formatDurationMins(cert_status_validity_mins);
    if ( cert_client_require_approval == cert_server_require_approval && cert_server_require_approval == cert_ioc_require_approval) {
        defs["EPICS_PVACMS_REQUIRE_APPROVAL"] = cert_client_require_approval ? "YES" : "NO";
    } else {
        defs["EPICS_PVACMS_REQUIRE_CLIENT_APPROVAL"] = cert_client_require_approval ? "YES" : "NO";
        defs["EPICS_PVACMS_REQUIRE_SERVER_APPROVAL"] = cert_server_require_approval ? "YES" : "NO";
        defs["EPICS_PVACMS_REQUIRE_IOC_APPROVAL"] = cert_ioc_require_approval ? "YES" : "NO";
    }
    if ( cert_disallow_client_custom_duration == cert_disallow_server_custom_duration && cert_disallow_server_custom_duration == cert_disallow_ioc_custom_duration) {
        defs["EPICS_PVACMS_DISALLOW_CUSTOM_DURATION"] = cert_disallow_client_custom_duration ? "YES" : "NO";
    } else {
        defs["EPICS_PVACMS_DISALLOW_CLIENT_CUSTOM_DURATION"] = cert_disallow_client_custom_duration ? "YES" : "NO";
        defs["EPICS_PVACMS_DISALLOW_SERVER_CUSTOM_DURATION"] = cert_disallow_server_custom_duration ? "YES" : "NO";
        defs["EPICS_PVACMS_DISALLOW_IOC_CUSTOM_DURATION"] = cert_disallow_ioc_custom_duration ? "YES" : "NO";
    }
    if (default_client_cert_validity == default_server_cert_validity && default_server_cert_validity == default_ioc_cert_validity) {
        defs["EPICS_PVACMS_CERT_VALIDITY"] = default_client_cert_validity;
    } else {
        defs["EPICS_PVACMS_CLIENT_CERT_VALIDITY"] = default_client_cert_validity ;
        defs["EPICS_PVACMS_SERVER_CERT_VALIDITY"] = default_server_cert_validity;
        defs["EPICS_PVACMS_IOC_CERT_VALIDITY"] = default_ioc_cert_validity;
    }
    defs["EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION"] = (cert_status_subscription == DEFAULT) ? "DEFAULT" : (cert_status_subscription == YES) ? "YES" : "NO";
    defs["EPICS_PVACMS_CLUSTER_PV_PREFIX"] = cluster_pv_prefix;
    defs["EPICS_PVACMS_CLUSTER_DISCOVERY_TIMEOUT"] = std::to_string(cluster_discovery_timeout_secs);
    defs["EPICS_PVACMS_CLUSTER_BIDI_TIMEOUT"] = std::to_string(cluster_bidi_timeout_secs);
    defs["EPICS_PVACMS_INTEGRITY_CHECK_INTERVAL"] = std::to_string(integrity_check_interval_secs);
    defs["EPICS_PVACMS_AUDIT_RETENTION_DAYS"] = std::to_string(audit_retention_days);
    defs["EPICS_PVACMS_RATE_LIMIT"] = std::to_string(rate_limit);
    defs["EPICS_PVACMS_RATE_LIMIT_BURST"] = std::to_string(rate_limit_burst);
    defs["EPICS_PVACMS_MAX_CONCURRENT_CCR"] = std::to_string(max_concurrent_ccr);

    // Add any defs for any registered authn methods
    for (auto &authn_entry : AuthRegistry::getRegistry()) authn_entry.second->updateDefs(defs);
}

}  // namespace certs
}  // namespace pvxs
