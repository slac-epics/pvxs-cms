/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <CLI/CLI.hpp>

#include "authnstd.h"
#include "authregistry.h"
#include "cmsversion.h"
#include "configstd.h"
#include "issuerlist.h"
#include "openssl.h"
#include "p12filefactory.h"
#include "trustanchors.h"

namespace pvxs {
namespace certs {

/**
 * @brief Define the options for the authnstd tool
 *
 * This function defines the options for the authnstd tool.
 *
 * @param app the CLI::App object to add the options to
 * @param config the configuration to override with command line parameters
 * @param verbose the verbose flag to set the logger level
 * @param debug the debug flag to set the logger level
 * @param daemon_mode the daemon mode flag to set daemon mode
 * @param show_version the show version flag to show version and exit
 * @param help the help flag to show this help message and exit
 * @param add_config_uri the add config uri flag to add a config uri to the generated certificate
 * @param usage the certificate usage client, server, or ioc
 * @param name the name
 * @param organization the organization
 * @param organizational_unit the organizational units, innermost first
 * @param country the country
 * @param cert_validity_mins the requested certificate validity in minutes
 * @param cert_pv_prefix the certificate status PV prefix
 */
 void defineOptions(CLI::App &app, ConfigStd &config, bool &verbose, bool &debug, bool &daemon_mode, bool &force, bool &show_version, bool &help, bool &add_config_uri,
                    std::string &usage, std::string &name, std::string &organization, std::vector<std::string> &organizational_unit, std::string &country, std::string &cert_validity_mins, std::string &cert_pv_prefix,
                    std::vector<std::string> &issuer_option) {
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-d,--debug", debug, "Debug mode");
    app.add_flag("-V,--version", show_version, "Print version and exit.");
    app.add_flag("--force", force, "Force overwrite if certificate exists.");
    app.add_flag("-a,--trust-anchor", config.trust_anchor_only, "Download Trust Anchor into keychain file");
    app.add_flag("-s,--no-status", config.no_status, "Request that status checking not be required for this certificate. PVACMS may ignore this request if it is configured to require all certificates to have status checking");

    app.add_flag("-D,--daemon", daemon_mode, "Daemon mode");
    app.add_flag("--add-config-uri", add_config_uri, "Add a config uri to the generated certificate");
    app.add_option("--cert-pv-prefix", cert_pv_prefix, "Specifies the pv prefix to use to contact PVACMS.  Default `CERT`");
    // One option carrying a list, in the same shape as EPICS_PVA_AUTH_ISSUER, so there is one
    // syntax to learn. An unquoted list is an error. Giving the option twice is an error.
    app.add_option("-i,--issuer", issuer_option, "The issuer IDs of the PVACMS services to contact, whitespace or comma separated.  If not specified (default) broadcast to any that are listening")
        ->allow_extra_args(false);

    app.add_option("-u,--cert-usage", usage, "Certificate usage.  `server`, `client`, `ioc`");

    app.add_option("-t,--time", cert_validity_mins, "Duration of the certificate in minutes.  Default 30 days");

    app.add_option("-n,--name", name, "Specify Certificate's name");
    app.add_option("-o,--organization", organization, "Specify the Certificate's Organisation");
    // Repeatable, one value each: a unit name may contain spaces, so a second bare word after
    // --ou is far more likely to be a mistake than a second unit
    app.add_option("--ou", organizational_unit, "Specify the Certificate's Organizational Unit.  May be given more than once, innermost first")
        ->allow_extra_args(false);
    app.add_option("-c,--country", country, "Specify the Certificate's Country");
}

/**
 * @brief Show the help message for the authnstd tool
 *
 * This function shows the help message for the authnstd tool.
 *
 * @param program_name the program name
 */
void showHelp(const char *program_name) {
    std::cout << "authnstd - Secure PVAccess Standard Authenticator\n"
              << std::endl
              << "Generates client, server, or ioc certificates based on the Standard Authenticator. \n"
              << "Uses specified parameters to create certificates that require administrator APPROVAL before becoming VALID.\n"
              << std::endl
              << "usage:\n"
              << "  " << program_name << " [options]                          Create certificate in PENDING_APPROVAL state\n"
              << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
              << "  " << program_name << " (-V | --version)                   Print version and exit\n"
              << std::endl
              << "options:\n"
              << "  (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|ioc.  Default `client`\n"
              << "  (-n | --name) <name>                       Specify common name of the certificate. Default <logged-in-username>\n"
              << "  (-o | --organization) <organization>       Specify organisation name for the certificate. Default <hostname>\n"
              << "        --ou <org-unit>                      Specify organisational unit for the certificate. Default <blank>\n"
              << "                                             May be given more than once to name a nested unit.  Give the innermost\n"
              << "                                             unit first: `--ou staff --ou beamline` means staff is inside beamline\n"
              << "  (-c | --country) <country>                 Specify country for the certificate. Default locale setting if detectable otherwise `US`\n"
              << "  (-t | --time) <minutes>                    Duration of the certificate in minutes.  e.g. 30 or 1d or 1y3M2d4m\n"
              << "  (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`\n"
              << "        --cert-pv-prefix <cert_pv_prefix>    Specifies the pv prefix to use to contact PVACMS.  Default `CERT`\n"
              << "        --add-config-uri                     Add a config uri to the generated certificate\n"
              << "        --force                              Force overwrite if certificate exists\n"
              << "  (-a | --trust-anchor)                      Download Trust Anchors into keychain file.  Do not create a certificate\n"
              << "                                             Replaces the trust anchors the keychain holds with the issuers named\n"
              << "  (-s | --no-status)                         Request that status checking not be required for this certificate\n"
              << "  (-i | --issuer) <issuer_ids>               The issuer IDs of the PVACMS services to contact, given once as one list\n"
              << "                                             separated by whitespace or by a comma.  All four of these name the same two:\n"
              << "                                               --issuer \"aaaa bbbb\"      --issuer aaaa,bbbb\n"
              << "                                               EPICS_PVA_AUTH_ISSUER=\"aaaa bbbb\"    EPICS_PVA_AUTH_ISSUER=aaaa,bbbb\n"
              << "                                             The first issuer named is asked to mint.  --issuer adds an authority to the\n"
              << "                                             keychain's trust anchors and never removes one; --trust-anchor replaces the\n"
              << "                                             whole set with the list named.  Naming more than one issuer only means\n"
              << "                                             something when trust is being established, which is --trust-anchor or a\n"
              << "                                             keychain that holds no trust anchor yet\n"
              << "                                             If not specified (default) broadcast to any that are listening\n"
              << "  (-v | --verbose)                           Verbose mode\n"
              << "  (-d | --debug)                             Debug mode\n"
              << std::endl;
}

/*
 * @brief Read the command line parameters
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @param config the configuration to override with command line parameters
 * @param verbose the verbose flag to set the logger level
 * @param debug the debug flag to set the logger level
 * @param cert_usage the certificate usage client, server, or ioc
 * @return exit status 0 if successful, non-zero if an error occurs and we should exit
 */
int readParameters(int argc, char *argv[], ConfigStd &config, bool &verbose, bool &debug, uint16_t &cert_usage, bool &daemon_mode, bool &force) {
    auto program_name = argv[0];
    bool show_version{false}, help{false}, add_config_uri{false};
    std::string usage{"client"}, name, organization, country, cert_validity_mins, cert_pv_prefix;
    std::vector<std::string> organizational_unit, issuer_option;

    CLI::App app{"authnstd - Secure PVAccess Standard Authenticator"};

    defineOptions(app, config, verbose, debug, daemon_mode, force, show_version, help, add_config_uri, usage, name, organization, organizational_unit, country, cert_validity_mins, cert_pv_prefix, issuer_option);

    CLI11_PARSE(app, argc, argv);

    if (issuer_option.size() > 1) {
        std::cerr << "--issuer is given once, with a list: --issuer \"aaaa bbbb\" or --issuer aaaa,bbbb. "
                     "It was given " << issuer_option.size() << " times." << std::endl;
        return 16;
    }

    // An option given at all replaces EPICS_PVA_AUTH_ISSUER entirely, for membership and for ordering.
    if (!issuer_option.empty()) {
        try {
            config.issuer_ids = cms::cert::parseIssuerList(issuer_option.front());
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            return 16;
        }
    }

    // The built-in help from CLI11 is pretty lame, so we'll do our own
    // Make sure we update this help text when options change
    if (help) {
        showHelp(program_name);
        exit(0);
    }

    // Show the version and exit
    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            return 10;
        }
        std::cout << ::cms::version_information;
        exit(0);
    }

    // Set the certificate usage based on the command line parameters
    if (usage == "server") {
        cert_usage = ssl::kForServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create server certificates" << std::endl;
            return 10;
        }
    } else if (usage == "client") {
        cert_usage = ssl::kForClient;
        if (config.tls_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVA_TLS_KEYCHAIN environment variable to create client certificates" << std::endl;
            return 11;
        }
    } else if (usage == "ioc") {
        cert_usage = ssl::kForClientAndServer;
        if (config.tls_srv_keychain_file.empty()) {
            std::cerr << "You must set EPICS_PVAS_TLS_KEYCHAIN environment variable to create ioc certificates" << std::endl;
            return 12;
        }
    } else {
        std::cerr << "Usage must be one of `client`, `server`, or `ioc`: " << usage << std::endl;
        return 13;
    }

    // Pull out command line args to override config values
    if ( !name.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.name = name; break;
            case ssl::kForServer: config.server_name = name; break;
            default: config.name = config.server_name = name; break;
        }
    }
    if ( !organization.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.organization = organization; break;
            case ssl::kForServer: config.server_organization = organization; break;
            default: config.organization = config.server_organization = organization; break;
        }
    }
    try {
        // Trims each value and refuses a repeated one, so a unit cannot be asked to contain itself
        normalizeOrganizationalUnits(organizational_unit);
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        return 15;
    }
    if ( !organizational_unit.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.organizational_unit = organizational_unit; break;
            case ssl::kForServer: config.server_organizational_unit = organizational_unit; break;
            default: config.organizational_unit = config.server_organizational_unit = organizational_unit; break;
        }
    }
    if ( !country.empty()) {
        switch (cert_usage) {
            case ssl::kForClient: config.country = country; break;
            case ssl::kForServer: config.server_country = country; break;
            default: config.country = config.server_country = country; break;
        }
    }
    if (!cert_validity_mins.empty()) {
        config.cert_validity_mins = CertDate::parseDurationMins(cert_validity_mins);
    }

    if (!cert_pv_prefix.empty()) {
        config.setCertPvPrefix(cert_pv_prefix);
    }

    if ( config.trust_anchor_only) {
        const std::string tls_keychain_file = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_file : config.tls_keychain_file;
        const std::string tls_keychain_pwd = IS_FOR_A_SERVER_(cert_usage) ? config.tls_srv_keychain_pwd : config.getKeychainPassword();

        // What the keychain holds now. The reset replaces the anchors and keeps everything else,
        // so this has to be read before anything is retrieved.
        const auto held = certs::readKeychainOrNothing(tls_keychain_file, tls_keychain_pwd);

        cms::cert::AnchorPlanInput plan_input;
        plan_input.named_issuers = config.issuer_ids;
        plan_input.held_anchor_ids = cms::cert::heldAnchorIds(held);
        plan_input.trust_anchor_option = true;
        const auto plan = cms::cert::planAnchors(plan_input);

        // Downloading trust anchors bootstraps trust, so the operator must identify the expected
        // authorities out of band. Require --issuer (or EPICS_PVA_AUTH_ISSUER) and verify each
        // delivered authority matches before storing, so a substituted one is never trusted (#18).
        if (!plan.refusal.empty()) {
            std::cerr << plan.refusal << std::endl;
            return 14;
        }

        AuthNStd authenticator{};
        std::vector<CertData> retrieved;
        try {
            for (const auto &issuer_id : config.issuer_ids) {
                // Retrieving a trust anchor is the moment trust is decided. An authority the
                // keychain already holds is decided against the held value, so a short form
                // names it; one it does not hold is decided by the name alone.
                certs::requireCompleteUnlessHeld(issuer_id, plan_input.held_anchor_ids);
                // Nothing is written until every named authority has answered, so a keychain is
                // never left holding whichever subset did.
                retrieved.push_back(certs::retrieveTrustAnchor(authenticator, config, cert_usage, issuer_id));
            }
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            return 14;
        }

        try {
            // The root each named authority chains to, not the certificate it signs with. Two
            // authorities under one root each answer that root, and it is written once.
            std::vector<X509 *> anchors_to_hold;
            anchors_to_hold.reserve(retrieved.size());
            for (const auto &delivered : retrieved) anchors_to_hold.push_back(anchorFromReply(delivered));

            // The identity already in the file is kept, so the chain is laid out around it and
            // the reset is refused outright when it would leave that identity unverifiable.
            const auto chain = cms::cert::chainForAnchorReset(held, anchors_to_hold);

            IdFileFactory::create(tls_keychain_file, tls_keychain_pwd, held.key_pair, held.cert.get(), chain.get(), "")
                ->writeIdentityFile();
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            return 14;
        }

        std::cout << "Trust Anchor retrieved"<< std::endl;

        // The anchors are listed whenever the set or the primary ends up different from what it
        // was, because nothing in the file marks which anchor is primary.
        const auto written = certs::readKeychainOrNothing(tls_keychain_file, tls_keychain_pwd);
        if (cms::cert::trustChanged(held, written)) cms::cert::printAnchorListing(written, std::cout);
        return -1;
    }

    return 0;
}

}  // namespace certs
}  // namespace pvxs

using namespace pvxs::certs;

/**
 * @brief Main function for the authnstd tool
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @return the exit status
 */
int main(const int argc, char *argv[]) { return runAuthenticator<ConfigStd, AuthNStd>(argc, argv); }
