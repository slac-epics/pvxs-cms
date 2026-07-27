/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <list>
#include <string>

#include <epicsGetopt.h>
#include <epicsThread.h>
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <termios.h>
#endif
#include <pvxs/client.h>
#include <pvxs/log.h>

#include <CLI/CLI.hpp>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatusmanager.h"
#include "cmsversion.h"
#include "openssl.h"

using namespace pvxs;

namespace {

DEFINE_LOGGER(certslog, "pvxs.certs.tool");

#if !defined(_WIN32) && !defined(_MSC_VER)
void setEcho(const bool enable) {
    termios tty{};
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}
#endif
}  // namespace

enum CertAction { STATUS, APPROVE, DENY, REVOKE };
const char* actionToString(const CertAction &action) {
    return action == STATUS ? "Get Status"
         : action == APPROVE ? "Approve"
         : action == REVOKE ? "Revoke"
         : "Deny";
}

struct cliparams {
    const int argc;
    const char* const* argv;
    std::string cert_file;
    std::string cert_status_pv;
    std::string cert_pv_prefix{"CERT:STATUS:"};
    bool approve = false;
    bool revoke = false;
    bool deny = false;
    bool password_flag = false;
    bool debug = false;
    bool only_status_pv = false;
    bool verbose = false;

    cliparams(int argc, char *argv[])
        :argc(argc)
        ,argv(argv)
    {}
};

int readParameters(cliparams& params, client::Config &conf) {
    if(params.argc<=0)
        return 42;
    auto program_name = params.argv[0];
    bool show_version{false}, help{false};

    // Argument configuration
    CLI::App app{"Certificate Management Utility for PVXS"};
    app.set_help_flag("", "");  // deactivate built-in help TODO: done't!

    // Add a positional argument
    app.add_option("cert_id_or_pv", params.cert_status_pv)->required(false);

    // Define flags
    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", params.verbose);
    app.add_flag("--status-pv", params.only_status_pv);
    app.add_flag("-d,--debug", params.debug);
    app.add_flag("-p,--password", params.password_flag);
    app.add_flag("-V,--version", show_version);

    // Define options
    double timeout = conf.getRequestTimeout();
    app.add_option("-w,--timeout", timeout);
    app.add_option("-f,--file", params.cert_file, "The keychain file to read if no Certificate ID specified");
    app.add_option("--cert-pv-prefix", params.cert_pv_prefix,
                   "Status PV name prefix for the <issuer>:<serial> form (default CERT:STATUS:). "
                   "Ignored when -f/--file is given (the full status PV is read from the certificate).");

    // Action flags in a mutually exclusive group
    app.add_flag("-A,--approve", params.approve);
    app.add_flag("-R,--revoke", params.revoke);
    app.add_flag("-D,--deny", params.deny);

    CLI11_PARSE(app, params.argc, params.argv);

    conf.setRequestTimeout(timeout);

    if (help) {
        std::cout << "Certificate management utility for PVXS\n"
                  << std::endl
                  << "Gets the STATUS of a certificate, REVOKES a certificate, or APPROVES or DENIES a pending certificate approval.\n"
                  << std::endl
                  << "  A certificate is identified one of two ways:\n"
                  << "    <issuer>:<serial>  one colon,  e.g. 27975e6b:7246297371190731775\n"
                  << "                       status PV = <prefix> + <issuer>:<serial>  (see --cert-pv-prefix)\n"
                  << "    <status_pv>        two+ colons, e.g. MYCMS:27975e6b:7246297371190731775\n"
                  << "                       used exactly as given\n"
                  << std::endl
                  << "  Get certificate status from keychain file: The keychain file must be a PKCS#12 file.\n"
                  << std::endl
                  << "  APPROVAL and DENIAL of pending certificate approval requests: Can only be made by administrators.\n"
                  << std::endl
                  << "  REVOCATION of a certificate: Can only be made by an administrator.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options] <cert_id_or_pv>  Get certificate status\n"
                  << "  " << program_name << " [file_options] [options] (-f | --file) <cert_file>\n"
                  << "                                             Get certificate information from the specified cert file\n"
                  << "  " << program_name << " [options] (-A | --approve) <cert_id_or_pv>\n"
                  << "                                             APPROVE pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-D | --deny) <cert_id_or_pv>  DENY pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-R | --revoke) <cert_id_or_pv>\n"
                  << "                                             REVOKE certificate (ADMIN ONLY)\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "file_options:\n"
                  << "  (-p | --password)                          Prompt for password\n"
                  << "\n"
                  << "options:\n"
                  << "  (-w | --timeout) <timout_secs>             Operation timeout in seconds.  Default 5.0s\n"
                  << "  (--cert-pv-prefix) <prefix>                Status PV prefix for the <issuer>:<serial> form.  Default CERT:STATUS:\n"
                  << "  (-d | --debug)                             Debug mode: Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\"\n"
                  << "  (-v | --verbose)                           Verbose mode\n"
                  << "  (--status-pv)                              Print only certificate status PV name.  Use with -f\n"
                  << std::endl;
        exit(0);
    }

    if (show_version) {
        if (params.argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            exit(10);
        }
        std::cout << ::cms::version_information;
        exit(0);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    try {
        logger_config_env();
        auto conf = client::Config::fromEnv();

        // Variables to store options
        CertAction action{STATUS};
        std::string password;

        cliparams params(argc, argv);
        if (auto err = readParameters(params, conf))
            return err;

        if (params.password_flag && params.cert_file.empty()) {
            log_err_printf(certslog, "Error: -p must only be used with -f.%s", "\n");
            return 1;
        }

        if (!params.cert_file.empty() && (params.approve || params.revoke || params.deny)) {
            log_err_printf(certslog, "Error: -I, -A, -R, or -D cannot be used with -f.%s", "\n");
            return 2;
        }

        // Handle the flags after parsing
        if (params.debug) logger_level_set("pvxs.*", Level::Debug);
        if (params.password_flag) {
            std::cerr << "Enter password: ";
#if !defined(_WIN32) && !defined(_MSC_VER)
            setEcho(false);
#endif
            std::getline(std::cin, password);
#if !defined(_WIN32) && !defined(_MSC_VER)
            setEcho(true);
#endif
            std::cerr << std::endl;
        }

        if (params.approve) {
            action = APPROVE;
        } else if (params.revoke)
            action = REVOKE;
        else if (params.deny) {
            action = DENY;
        } else {
            conf.tls_disabled = true;
        }

        auto client = conf.build();

        if (params.verbose) std::cerr << "Effective config\n" << conf;

        std::list<std::shared_ptr<client::Operation>> ops;

        epicsEvent done;

        std::string cert_id;

        if (!params.cert_file.empty()) {
            try {
                auto cert_data = certs::IdFileFactory::create(params.cert_file, password)->getCertDataFromFile();
                if (cert_data.cert == nullptr) {
                    throw std::runtime_error("Failed to read certificate from file");
                }
                std::string config_id{};
                try {
                    config_id = certs::CmsStatusManager::getConfigPvFromCert(cert_data.cert);
                } catch (...) {
                }

                if(!params.only_status_pv)
                    std::cout << "Certificate Details: " << std::endl
                              << "============================================" << std::endl
                              << ossl::ShowX509{cert_data.cert.get()} << std::endl
                              << (config_id.empty() ? "" : "Config URI     : " + config_id + "\n") << "--------------------------------------------\n"
                              << std::endl;
                cert_id = certs::CmsStatusManager::getStatusPvFromCert(cert_data.cert);
            } catch (std::exception &e) {
                std::cerr << "Online Certificate Status: " << std::endl
                          << "============================================" << std::endl
                          << "Not configured: " << e.what() << std::endl;
                if(params.only_status_pv)
                    return 1;
                return 0;
            }
        } else {
            // one colon: <issuer>:<serial>, expanded with the prefix.  More: full status PV, used verbatim.
            const auto ncolons = std::count(params.cert_status_pv.begin(), params.cert_status_pv.end(), ':');
            cert_id = ncolons >= 2 ? params.cert_status_pv
                                   : params.cert_pv_prefix + params.cert_status_pv;
        }

        if(params.only_status_pv) {
            if(cert_id.empty())
                return 1;
            else
                std::cout<<cert_id<<std::endl;
            return 0;
        }

        try {
            if (action != STATUS) {
                std::cout << actionToString(action) << " ==> " << cert_id;
            }
            Value result;
            switch (action) {
                case STATUS:
                    result = client.get(cert_id).exec()->wait(conf.getRequestTimeout());
                    break;
                case APPROVE:
                    result = client.put(cert_id).set("state", "APPROVED").exec()->wait(conf.getRequestTimeout());
                    break;
                case DENY:
                    result = client.put(cert_id).set("state", "DENIED").exec()->wait(conf.getRequestTimeout());
                    break;
                case REVOKE:
                    result = client.put(cert_id).set("state", "REVOKED").exec()->wait(conf.getRequestTimeout());
                    break;
            }
            Indented I(std::cout);
            if (result) {
                std::cout << "Certificate Status: " << std::endl
                          << "============================================" << std::endl
                          << "Certificate ID: " << cert_id.substr(cert_id.rfind(':') - 8) << std::endl
                          << "Status        : " << result["state"].as<std::string>() << std::endl
                          << "Status Issued : " << result["ocsp_status_date"].as<std::string>() << std::endl
                          << "Status Expires: " << result["ocsp_certified_until"].as<std::string>() << std::endl;
                if (result["value.index"].as<uint32_t>() == certs::REVOKED) {
                    std::cout << "Revocation Date: " << result["ocsp_revocation_date"].as<std::string>() << std::endl;
                }
                std::cout << "--------------------------------------------\n" << std::endl;
            } else if (action != STATUS)
                std::cout << " ==> Completed Successfully\n";
        } catch (std::exception &e) {
            std::cout << std::endl;
            log_err_printf(certslog, "%s\n", e.what());
            return 4;
        }

    } catch (std::exception &e) {
        log_err_printf(certslog, "Error: %s%s", e.what(), "\n");
        return 5;
    }
}
