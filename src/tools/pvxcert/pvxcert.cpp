/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdlib>
#include <iostream>
#include <list>
#include <string>

#include <epicsGetopt.h>
#include <epicsThread.h>

// Asking whether there is a terminal to review at, and turning echo off while a password is
// typed, are the same two jobs on either platform but come from different headers. Neither set
// exists on the other, so both have to be reached for conditionally.
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <termios.h>
#include <unistd.h>
#else
#include <io.h>
#include <stdio.h>
#endif

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>

#include <CLI/CLI.hpp>

#include "certfilter.h"
#include "certlistprint.h"
#include "certreview.h"
#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatusmanager.h"
#include "cmsversion.h"
#include "keychainreport.h"
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
std::string actionToString(const CertAction &action) {
    return action == STATUS ? "Get Status" : action == APPROVE ? "Approve" : action == REVOKE ? "Revoke" : "Deny";
}
int readParameters(const int argc, char *argv[], const char *program_name, client::Config &conf, bool &approve, bool &revoke, bool &deny, bool &debug,
                   bool &password_flag, bool &verbose, std::string &cert_file, std::string &issuer_serial_string, std::string &cert_pv_prefix,
                   bool &list, std::string &format_name, std::string &cert_list_pv_prefix, std::string &where,
                   bool &pending, std::string &expiring, bool &review_pending, bool &review_issued,
                   std::string &all, bool &assume_yes) {
    bool show_version{false}, help{false};

    // Argument configuration
    CLI::App app{"Certificate Management Utility for PVXS"};
    app.set_help_flag("", "");  // deactivate built-in help

    // Add a positional argument
    app.add_option("cert_id", issuer_serial_string)->required(false);

    // Define flags
    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose);
    app.add_flag("-d,--debug", debug);
    app.add_flag("-p,--password", password_flag);
    app.add_flag("-V,--version", show_version);

    // Define options
    double timeout = conf.getRequestTimeout();
    app.add_option("-w,--timeout", timeout);
    app.add_option("-f,--file", cert_file, "The keychain file to read if no Certificate ID specified");
    app.add_option("--cert-pv-prefix", cert_pv_prefix,
                   "Status PV name prefix for the <issuer>:<serial> form (default CERT:STATUS:). "
                   "Ignored when -f/--file is given (the full status PV is read from the certificate).");

    app.add_flag("-l,--list", list);
    app.add_option("--where", where, "Narrow the listing, for example \"state:VALID and org:SLAC\"");
    app.add_flag("--pending", pending);
    app.add_option("--expiring", expiring, "List certificates expiring within a period, for example 30d");
    app.add_option("--format", format_name, "How --list writes its table: columns (default), csv or json");
    app.add_option("--cert-list-pv-prefix", cert_list_pv_prefix,
                   "Prefix the listing operation is served under (default CERT)");

    app.add_flag("--review-pending", review_pending,
                 "Review every certificate awaiting a decision, one at a time");
    app.add_flag("--review-issued", review_issued,
                 "Review issued certificates for revocation, one at a time");
    app.add_option("--all", all,
                   "Decide every listed certificate without asking: approve or deny when "
                   "reviewing pending requests, no value when reviewing issued certificates")
        ->expected(0, 1);
    app.add_flag("--yes", assume_yes, "Answer the one final confirmation");

    // Action flags in a mutually exclusive group
    app.add_flag("-A,--approve", approve);
    app.add_flag("-R,--revoke", revoke);
    app.add_flag("-D,--deny", deny);

    // Do not let the argument parsing library choose the exit code: it returns its own,
    // which is how an unrecognised option used to exit 109. Keep its message, use ours.
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e) == 0 ? 0 : 3;
    }

    conf.setRequestTimeout(timeout);

    if (help) {
        std::cout << "Certificate management utility for PVXS\n"
                  << std::endl
                  << "Gets the STATUS of a certificate, REVOKES a certificate, or APPROVES or DENIES a pending certificate approval.\n"
                  << std::endl
                  << "  Get certificate status from serial number: The certificate ID is specified as <issuer>:<serial>, \n"
                  << "  where <issuer> is the first 8 hex digits of the subject key identifier of the issuer and <serial>\n"
                  << "  is the serial number of the certificate. e.g. 27975e6b:07246297371190731775.\n"
                  << std::endl
                  << "  Get certificate status from keychain file: The keychain file must be a PKCS#12 file.\n"
                  << std::endl
                  << "  APPROVAL and DENIAL of pending certificate approval requests: Can only be made by administrators.\n"
                  << std::endl
                  << "  REVOCATION of a certificate: Can only be made by an administrator.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options] <cert_id> Get certificate status\n"
                  << "  " << program_name << " [file_options] [options] (-f | --file) <cert_file>\n"
                  << "                                             Get certificate information from the specified cert file\n"
                  << "  " << program_name << " [options] (-A | --approve) <cert_id>\n"
                  << "                                             APPROVE pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-D | --deny) <cert_id>  DENY pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-R | --revoke) <cert_id>\n"
                  << "                                             REVOKE certificate (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-l | --list)     List certificates\n"
                  << "  " << program_name << " [options] --review-pending    Review certificates awaiting a decision\n"
                  << "  " << program_name << " [options] --review-issued     Review issued certificates for revocation\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "file_options:\n"
                  << "  (-p | --password)                          Prompt for password\n"
                  << "\n"
                  << "options:\n"
                  << "  (-w | --timeout) <timout_secs>             Operation timeout in seconds.  Default 5.0s\n"
                  << "  (--cert-pv-prefix) <prefix>                Status PV prefix for the <cert_id> form.  Default CERT:STATUS:\n"
                  << "  (--cert-list-pv-prefix) <prefix>           Prefix the listing is served under.  Default CERT\n"
                  << "  (--format) <columns|csv|json>              How --list writes its table.  Default columns\n"
                  << "  (--where) <expression>                     Narrow the listing.  See below\n"
                  << "  (--pending)                                Short for --where \"state:PENDING_APPROVAL\"\n"
                  << "  (--expiring) <period>                      Short for --where \"expires_before:<period> and state:VALID\"\n"
                  << "  (--review-pending)                         Ask about each certificate awaiting a decision in turn.\n"
                  << "                                             Answer approve, deny, skip, stop or cancel.  Nothing is\n"
                  << "                                             written until you confirm once at the end\n"
                  << "  (--review-issued)                          Ask about each issued certificate in turn, narrowed by\n"
                  << "                                             --where.  Answer revoke, skip, stop or cancel\n"
                  << "  (--all) [approve|deny]                     Decide every listed certificate without being asked.\n"
                  << "                                             Takes approve or deny with --review-pending, no value\n"
                  << "                                             with --review-issued\n"
                  << "  (--yes)                                    Answer the final confirmation.  With --all this approves\n"
                  << "                                             or revokes without checking any request identifier\n"
                  << "  (-d | --debug)                             Debug mode: Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\"\n"
                  << "  (-v | --verbose)                           Verbose mode\n"
                  << std::endl
                  << "filter expression:\n"
                  << "  A test is written field:value, and tests join with and, or and not, grouped\n"
                  << "  with brackets.  Several values for one field are separated by | and mean any\n"
                  << "  of them.  Fields: id, serial, issuer, name, org, unit, country, state, issued,\n"
                  << "  expires, renew_by, changed, and the before and after forms such as\n"
                  << "  expires_before.  A date is 2026-07-31 or '2026-07-31 10:31:21' in Coordinated\n"
                  << "  Universal Time; a period is a number and a unit letter such as 30d.\n"
                  << "\n"
                  << "  " << program_name << " --list --where \"(org:SLAC or org:LBNL) and expires_before:30d\"\n"
                  << std::endl
                  << "Results are written to standard output and everything else to standard error,\n"
                  << "so the output can be piped into another program.\n"
                  << std::endl
                  << "exit codes:\n"
                  << "  0   Did what was asked.  A query that matched nothing is also 0.\n"
                  << "  1   Failed.\n"
                  << "  2   Interrupted before it finished.\n"
                  << "  3   The command line was wrong.\n"
                  << "  4   Timed out.\n"
                  << "  5   Some operations in a batch failed while others succeeded.\n"
                  << std::endl;
        exit(0);
    }

    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            exit(3);
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
        auto program_name = argv[0];

        // Variables to store options
        CertAction action{STATUS};
        bool approve{false}, revoke{false}, deny{false}, debug{false}, password_flag{false}, verbose{false}, list{false};
        std::string cert_file, password, issuer_serial_string, format_name, where, expiring;
        bool pending{false}, review_pending{false}, review_issued{false}, assume_yes{false};
        std::string all;
        std::string cert_pv_prefix{"CERT:STATUS:"};
        std::string cert_list_pv_prefix{"CERT"};

        auto parse_result = readParameters(argc, argv, program_name, conf, approve, revoke, deny, debug, password_flag, verbose, cert_file,
                                           issuer_serial_string, cert_pv_prefix, list, format_name, cert_list_pv_prefix,
                                           where, pending, expiring, review_pending, review_issued, all, assume_yes);
        if (parse_result) exit(parse_result);

        certs::CertListFormat list_format{certs::CertListFormat::Columns};
        if (!format_name.empty()) {
            if (!list) {
                log_err_printf(certslog, "Error: --format only applies to --list.%s", "\n");
                return 3;
            }
            if (!certs::parseCertListFormat(format_name, list_format)) {
                log_err_printf(certslog, "Error: unrecognised --format '%s'. Accepted: columns, csv, json.\n", format_name.c_str());
                return 3;
            }
        }

        // The two shorthands stand for expressions. Combining either with --where would leave
        // it unclear which one applies, so it is refused rather than guessed at.
        if ((pending || !expiring.empty()) && !where.empty()) {
            log_err_printf(certslog, "Error: --pending and --expiring cannot be combined with --where.%s", "\n");
            return 3;
        }
        if (pending && !expiring.empty()) {
            log_err_printf(certslog, "Error: --pending and --expiring cannot be used together.%s", "\n");
            return 3;
        }
        if (pending) where = "state:PENDING_APPROVAL";
        if (!expiring.empty()) where = "expires_before:" + expiring + " and state:VALID";

        const bool reviewing = review_pending || review_issued;

        if (review_pending && review_issued) {
            log_err_printf(certslog, "Error: --review-pending and --review-issued cannot be used together.%s", "\n");
            return 3;
        }
        if (reviewing && (approve || revoke || deny || !cert_file.empty() || !issuer_serial_string.empty() || list)) {
            log_err_printf(certslog,
                           "Error: --review-pending and --review-issued cannot be used with -l, -f, -A, -D, -R or a certificate ID.%s",
                           "\n");
            return 3;
        }
        if (!reviewing && (!all.empty() || assume_yes)) {
            log_err_printf(certslog, "Error: --all and --yes only apply to --review-pending or --review-issued.%s", "\n");
            return 3;
        }
        if (!where.empty() && !list && !review_issued) {
            log_err_printf(certslog, "Error: --where, --pending and --expiring only apply to --list and --review-issued.%s", "\n");
            return 3;
        }
        if (review_pending && !where.empty()) {
            log_err_printf(certslog, "Error: --review-pending selects the pending certificates itself, so --where does not apply.%s", "\n");
            return 3;
        }

        // Read the expression before building a client, so a typing mistake costs no round trip
        // and is reported even when the certificate manager cannot be reached.
        if (!where.empty()) {
            try {
                certs::CertFilter::parse(where, certs::timeNow());
            } catch (const certs::CertFilterError &e) {
                std::cerr << e.what() << std::endl;
                return 3;
            }
        }

        if (reviewing) {
            certs::ReviewOptions options;
            options.mode = review_pending ? certs::ReviewMode::Approval : certs::ReviewMode::Revocation;
            options.now = certs::CertDate(certs::timeNow()).s;
#if !defined(_WIN32) && !defined(_MSC_VER)
            options.interactive = isatty(STDIN_FILENO) != 0;
#else
            options.interactive = _isatty(_fileno(stdin)) != 0;
#endif
            options.assume_yes = assume_yes;

            // --all takes a decision when reviewing pending requests, because there are two of
            // them, and no value when reviewing issued certificates, because there is only one.
            const auto all_given = std::find(argv, argv + argc, std::string("--all")) != argv + argc;
            if (all_given) {
                if (review_pending) {
                    if (all == "approve") {
                        options.all = certs::ReviewDecision::Approve;
                    } else if (all == "deny") {
                        options.all = certs::ReviewDecision::Deny;
                    } else {
                        log_err_printf(certslog, "Error: --all needs a value with --review-pending: approve or deny.%s", "\n");
                        return 3;
                    }
                } else {
                    if (!all.empty()) {
                        log_err_printf(certslog, "Error: --all takes no value with --review-issued.%s", "\n");
                        return 3;
                    }
                    options.all = certs::ReviewDecision::Revoke;
                }
            }
            if (assume_yes && options.interactive == false && options.all == certs::ReviewDecision::Undecided) {
                log_err_printf(certslog, "Error: --yes needs either a terminal to review at or --all.%s", "\n");
                return 3;
            }

            auto review_client = conf.build();
            const auto list_pv = certs::getCertListPv(cert_list_pv_prefix);
            const auto selection = review_pending ? std::string("state:PENDING_APPROVAL") : where;

            std::vector<certs::ReviewRow> rows;
            try {
                Value arguments = nt::NTURI({members::String("where")}).create();
                arguments["query.where"] = selection;
                const auto table = review_client.rpc(list_pv, arguments).exec()->wait(conf.getRequestTimeout());
                rows = certs::reviewRowsFromTable(table);
            } catch (const client::Timeout &) {
                log_err_printf(certslog, "Timed out listing certificates from %s\n", list_pv.c_str());
                return 4;
            } catch (const std::exception &e) {
                log_err_printf(certslog, "Failed to list certificates: %s\n", e.what());
                return 1;
            }

            // A certificate is only offered when it can actually be acted on, and the reason it
            // cannot is shown rather than the certificate being quietly dropped.
            if (review_issued) {
                // Only the status decides here. Whose certificate it is decides nothing,
                // because an ordinary user may revoke their own and that is the point of the
                // operation for them: a key has leaked and they want it stopped without
                // finding an administrator first. Only an administrator is refused their own,
                // so that a certificate manager cannot be talked out of the identity it needs
                // in order to keep answering.
                //
                // The tool cannot tell which of the two it is holding. The served listing
                // looks the same either way: the certificate manager builds the request
                // identifier column for every caller and simply leaves the values empty for
                // one who may not see them, so there is nothing in the reply to read it off.
                // Withholding on a guess would take the operation away from the users who are
                // entitled to it, so the administrator's own certificate is offered like any
                // other and the manager's refusal is reported against it, the same way as any
                // other write that the manager declines.
                for (auto &row : rows) {
                    if (!certs::isRevocable(row.status)) {
                        row.ineligible_reason = "status " + row.status + " cannot be revoked";
                    }
                }
            }

            certs::ReviewCallbacks callbacks;
            callbacks.currentStatus = [&](const std::string &cert_id) -> std::string {
                try {
                    const auto value = review_client.get(cert_pv_prefix + cert_id).exec()->wait(conf.getRequestTimeout());
                    return value["state"].as<std::string>();
                } catch (const std::exception &) {
                    return {};  // unreadable, so treated as unchanged and left to the write
                }
            };
            callbacks.apply = [&](const std::string &cert_id, const certs::ReviewDecision decision) -> std::string {
                const char *state = decision == certs::ReviewDecision::Approve   ? "APPROVED"
                                    : decision == certs::ReviewDecision::Deny    ? "DENIED"
                                                                                 : "REVOKED";
                try {
                    review_client.put(cert_pv_prefix + cert_id).set("state", state).exec()->wait(conf.getRequestTimeout());
                    return {};
                } catch (const std::exception &e) {
                    return e.what();  // the certificate manager's own words, verbatim
                }
            };

            return certs::runReview(rows, options, callbacks, std::cin, std::cout, std::cerr);
        }

        if (list) {
            // --list asks a different question from the others, and answers it for the whole
            // database rather than one certificate, so combining it with them is meaningless
            // rather than merely unsupported.
            if (approve || revoke || deny || !cert_file.empty() || !issuer_serial_string.empty()) {
                log_err_printf(certslog, "Error: --list cannot be used with -f, -A, -D, -R or a certificate ID.%s", "\n");
                return 3;
            }

            // Transport security stays on, unlike the status path which turns it off: the
            // caller has to be identified for an administrator to receive the request
            // identifier column.
            auto list_client = conf.build();
            const auto list_pv = certs::getCertListPv(cert_list_pv_prefix);
            if (verbose) std::cerr << "Listing certificates from " << list_pv << std::endl;

            try {
                // The expression travels as an argument on the call, so the certificate
                // manager reads it for itself rather than trusting the check made above.
                Value arguments = nt::NTURI({members::String("where")}).create();
                arguments["query.where"] = where;
                const auto table =
                    list_client.rpc(list_pv, arguments).exec()->wait(conf.getRequestTimeout());
                certs::printCertList(std::cout, table, list_format);
                return 0;
            } catch (const client::Timeout &) {
                log_err_printf(certslog, "Timed out listing certificates from %s\n", list_pv.c_str());
                return 4;
            } catch (const std::exception &e) {
                log_err_printf(certslog, "Failed to list certificates: %s\n", e.what());
                return 1;
            }
        }

        if (password_flag && cert_file.empty()) {
            log_err_printf(certslog, "Error: -p must only be used with -f.%s", "\n");
            return 3;
        }

        if (!cert_file.empty() && (approve || revoke || deny)) {
            log_err_printf(certslog, "Error: -I, -A, -R, or -D cannot be used with -f.%s", "\n");
            return 3;
        }

        // Handle the flags after parsing
        if (debug) logger_level_set("pvxs.*", Level::Debug);
        if (password_flag) {
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

        if (approve) {
            action = APPROVE;
        } else if (revoke)
            action = REVOKE;
        else if (deny) {
            action = DENY;
        } else {
            conf.tls_disabled = true;
        }

        auto client = conf.build();

        if (verbose) std::cerr << "Effective config\n" << conf;

        std::list<std::shared_ptr<client::Operation>> ops;

        epicsEvent done;

        std::string cert_id;

        if (!cert_file.empty()) {
            try {
                auto cert_data = certs::IdFileFactory::create(cert_file, password)->getCertDataFromFile();
                cert_id = cms::cert::printKeychainReport(cert_data, std::cout, std::cerr);
                // An anchors-only keychain has no certificate to ask the status of.
                if (cert_id.empty()) return 0;
            } catch (std::exception &e) {
                std::cerr << "Online Certificate Status: " << std::endl
                          << "============================================" << std::endl
                          << "Not configured: " << e.what() << std::endl;
                return 0;
            }
        } else {
            cert_id = cert_pv_prefix + issuer_serial_string;
        }

        try {
            if (action != STATUS) {
                std::cerr << actionToString(action) << " ==> " << cert_id;
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
                std::cerr << "Certificate Status: " << std::endl << "============================================" << std::endl;
                std::cout << "Certificate ID: " << cert_id.substr(cert_id.rfind(':') - 8) << std::endl
                          << "Status        : " << result["state"].as<std::string>() << std::endl
                          << "Status Issued : " << result["ocsp_status_date"].as<std::string>() << std::endl
                          << "Status Expires: " << result["ocsp_certified_until"].as<std::string>() << std::endl;
                if (result["value.index"].as<uint32_t>() == certs::REVOKED) {
                    std::cout << "Revocation Date: " << result["ocsp_revocation_date"].as<std::string>() << std::endl;
                }
                std::cerr << "--------------------------------------------\n" << std::endl;
            } else if (action != STATUS)
                std::cerr << " ==> Completed Successfully\n";
        } catch (const client::Timeout &e) {
            // Distinguished from an unspecified failure so a caller can tell the server
            // did not answer in time from the server refusing what was asked.
            std::cerr << std::endl;
            log_err_printf(certslog, "%s\n", e.what());
            return 4;
        } catch (const client::Interrupted &e) {
            // Same meaning pvxget gives this code.
            std::cerr << std::endl;
            log_err_printf(certslog, "%s\n", e.what());
            return 2;
        } catch (std::exception &e) {
            std::cerr << std::endl;
            log_err_printf(certslog, "%s\n", e.what());
            return 1;
        }

    } catch (std::exception &e) {
        log_err_printf(certslog, "Error: %s%s", e.what(), "\n");
        return 1;
    }
}
