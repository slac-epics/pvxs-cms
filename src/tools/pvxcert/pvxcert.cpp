/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <list>
#include <string>

#include <epicsGetopt.h>
#include <epicsThread.h>
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <termios.h>
#endif
#include <openssl/x509v3.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>

#include <CLI/CLI.hpp>

#include "security.h"

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatusmanager.h"
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

enum CertAction { STATUS, APPROVE, DENY, REVOKE, SCHEDULE };
std::string actionToString(const CertAction &action, const std::vector<std::string> &schedule_values = {}) {
    if (action == SCHEDULE) {
        if (schedule_values.size() == 1 && schedule_values[0] == "show") return "Show Schedule";
        if (schedule_values.size() == 1 && schedule_values[0] == "none") return "Clear Schedule";
        return "Set Schedule";
    }
    return action == STATUS ? "Get Status" : action == APPROVE ? "Approve" : action == REVOKE ? "Revoke" : "Deny";
}
int readParameters(const int argc, char *argv[], const char *program_name, client::Config &conf, bool &approve, bool &revoke, bool &deny, bool &debug,
                   bool &password_flag, bool &verbose, std::string &cert_file, std::string &issuer_serial_string,
                   std::vector<std::string> &schedule_values) {
    bool show_version{false}, help{false};

    CLI::App app{"Certificate Management Utility for PVXS"};
    app.set_help_flag("", "");

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

    // Action flags in a mutually exclusive group
    app.add_flag("-A,--approve", approve);
    app.add_flag("-R,--revoke", revoke);
    app.add_flag("-D,--deny", deny);
    app.add_option("-S,--schedule", schedule_values,
                   "Manage validity schedule windows (Admin only): show | none | day,HH:MM,HH:MM (repeatable).")
        ->expected(1, 1)
        ->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)
        ->allow_extra_args(false);

    CLI11_PARSE(app, argc, argv);

    conf.setRequestTimeout(timeout);

    if (help) {
        std::cout << "Certificate management utility for PVXS\n"
                  << std::endl
                  << "Gets the STATUS of a certificate, REVOKES a certificate, or APPROVES or DENIES a pending certificate approval.\n"
                  << std::endl
                  << "  Get certificate status from serial number: The certificate ID is specified as <issuer>:<serial>, \n"
                  << "  where <issuer> is the first 8 hex digits of the subject key identifier of the issuer and <serial>\n"
                  << "  is the serial number of the certificate. e.g. 27975e6b:7246297371190731775.\n"
                  << std::endl
                  << "  Get certificate status from keychain file: The keychain file must be a PKCS#12 file.\n"
                  << std::endl
                  << "  APPROVAL and DENIAL of pending certificate approval requests: Can only be made by administrators.\n"
                  << std::endl
                  << "  REVOCATION of a certificate: Can only be made by an administrator.\n"
                  << std::endl
                  << "  SET/SHOW SCHEDULE manages the validity schedule windows for a certificate.\n"
                  << "  Schedules require status monitoring to be enabled on the certificate. Admin only.\n"
                  << std::endl
                  << "usage:\n"
                  << "  " << program_name << " [options] <cert_id>                Get certificate status\n"
                  << "  " << program_name << " [file_options] [options] (-f | --file) <cert_file>\n"
                  << "                                             Get certificate information from the specified cert file\n"
                  << "  " << program_name << " [options] (-A | --approve) <cert_id>\n"
                  << "                                             APPROVE pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-D | --deny) <cert_id>  DENY pending certificate approval request (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-R | --revoke) <cert_id>\n"
                  << "                                             REVOKE certificate (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-S | --schedule) show <cert_id>\n"
                  << "                                             SHOW current schedule windows (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-S | --schedule) none <cert_id>\n"
                  << "                                             REMOVE all schedule windows (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-S | --schedule) <day,HH:MM,HH:MM> [-S <day,HH:MM,HH:MM> ...] <cert_id>\n"
                  << "                                             SET validity schedule windows, replacing any existing (ADMIN ONLY)\n"
                  << "                                             day: 0=Sun 1=Mon 2=Tue 3=Wed 4=Thu 5=Fri 6=Sat or * for every day\n"
                  << "                                             times are UTC, e.g. -S '1,08:00,17:00' for Mon 08:00-17:00\n"
                  << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
                  << "  " << program_name << " (-V | --version)                   Print version and exit\n"
                  << std::endl
                  << "file_options:\n"
                  << "  (-p | --password)                          Prompt for password\n"
                  << "\n"
                  << "options:\n"
                  << "  (-w | --timeout) <timout_secs>             Operation timeout in seconds.  Default 5.0s\n"
                  << "  (-d | --debug)                             Debug mode: Shorthand for $PVXS_LOG=\"pvxs.*=DEBUG\"\n"
                  << "  (-v | --verbose)                           Verbose mode\n"
                  << std::endl;
        exit(0);
    }

    if (show_version) {
        if (argc > 2) {
            std::cerr << "Error: -V option cannot be used with any other options.\n";
            exit(10);
        }
        std::cout << version_information;
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
        bool approve{false}, revoke{false}, deny{false}, debug{false}, password_flag{false}, verbose{false};
        std::string cert_file, password, issuer_serial_string;
        std::vector<std::string> schedule_values;

        auto parse_result =
            readParameters(argc, argv, program_name, conf, approve, revoke, deny, debug, password_flag, verbose, cert_file, issuer_serial_string, schedule_values);
        if (parse_result) exit(parse_result);

        if (password_flag && cert_file.empty()) {
            log_err_printf(certslog, "Error: -p must only be used with -f.%s", "\n");
            return 1;
        }

        if (!cert_file.empty() && (approve || revoke || deny)) {
            log_err_printf(certslog, "Error: -I, -A, -R, or -D cannot be used with -f.%s", "\n");
            return 2;
        }

        // Handle the flags after parsing
        if (debug) logger_level_set("pvxs.*", Level::Debug);
        if (password_flag) {
            std::cout << "Enter password: ";
#if !defined(_WIN32) && !defined(_MSC_VER)
            setEcho(false);
#endif
            std::getline(std::cin, password);
#if !defined(_WIN32) && !defined(_MSC_VER)
            setEcho(true);
#endif
            std::cout << std::endl;
        }

        if (approve) {
            action = APPROVE;
        } else if (revoke)
            action = REVOKE;
        else if (deny) {
            action = DENY;
        } else if (!schedule_values.empty()) {
            action = SCHEDULE;
        } else {
            conf.tls_disabled = true;
        }

        auto client = conf.build();

        if (verbose) std::cout << "Effective config\n" << conf;

        std::list<std::shared_ptr<client::Operation>> ops;

        epicsEvent done;

        std::string cert_id;

        if (!cert_file.empty()) {
            try {
                auto cert_data = certs::IdFileFactory::create(cert_file, password)->getCertDataFromFile();
                if (cert_data.cert == nullptr) {
                    throw std::runtime_error("Failed to read certificate from file");
                }
                std::string config_id{};
                try {
                    config_id = certs::CmsStatusManager::getConfigPvFromCert(cert_data.cert);
                } catch (...) {
                }

                std::string san_display;
                {
                    const int san_idx = X509_get_ext_by_NID(cert_data.cert.get(), NID_subject_alt_name, -1);
                    if (san_idx >= 0) {
                        X509_EXTENSION *ext = X509_get_ext(cert_data.cert.get(), san_idx);
                        const ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ext);
                        const unsigned char *p = data->data;
                        GENERAL_NAMES *gens = d2i_GENERAL_NAMES(nullptr, &p, static_cast<long>(data->length));
                        if (gens) {
                            for (int i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
                                const GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
                                std::string entry;
                                if (gen->type == GEN_DNS) {
                                    const auto *dns = reinterpret_cast<const ASN1_IA5STRING *>(gen->d.dNSName);
                                    entry = "dns=" + std::string(reinterpret_cast<const char *>(dns->data),
                                                                 static_cast<size_t>(dns->length));
                                } else if (gen->type == GEN_IPADD) {
                                    const auto *ip = gen->d.iPAddress;
                                    if (ip->length == 4) {
                                        char buf[32];
                                        snprintf(buf, sizeof(buf), "ip=%d.%d.%d.%d",
                                                 ip->data[0], ip->data[1], ip->data[2], ip->data[3]);
                                        entry = buf;
                                    }
                                } else if (gen->type == GEN_URI) {
                                    const auto *uri = reinterpret_cast<const ASN1_IA5STRING *>(gen->d.uniformResourceIdentifier);
                                    entry = "uri=" + std::string(reinterpret_cast<const char *>(uri->data),
                                                                 static_cast<size_t>(uri->length));
                                }
                                if (!entry.empty()) {
                                    if (!san_display.empty()) san_display += ", ";
                                    san_display += entry;
                                }
                            }
                            GENERAL_NAMES_free(gens);
                        }
                    }
                }
                std::cout << "Certificate Details: " << std::endl
                          << "============================================" << std::endl
                          << ossl::ShowX509{cert_data.cert.get()} << std::endl
                          << (san_display.empty() ? "" : "SAN            : " + san_display + "\n")
                          << (config_id.empty() ? "" : "Config URI     : " + config_id + "\n") << "--------------------------------------------\n"
                          << std::endl;
                cert_id = certs::CmsStatusManager::getStatusPvFromCert(cert_data.cert);
            } catch (std::exception &e) {
                std::cout << "Online Certificate Status: " << std::endl
                          << "============================================" << std::endl
                          << "Not configured: " << e.what() << std::endl;
                return 0;
            }
        } else {
            auto colon = issuer_serial_string.rfind(':');
            if (colon != std::string::npos) {
                const std::string issuer = issuer_serial_string.substr(0, colon);
                const uint64_t serial = std::stoull(issuer_serial_string.substr(colon + 1));
                issuer_serial_string = certs::getCertId(issuer, serial);
            }
            cert_id = "CERT:STATUS:" + issuer_serial_string;
        }

        try {
            if (action != STATUS) {
                const auto display_id = issuer_serial_string.empty()
                    ? cert_id.substr(cert_id.find("STATUS:") + 7)
                    : issuer_serial_string;
                std::cout << actionToString(action, schedule_values) << " ==> " << display_id << std::endl;
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
                case SCHEDULE: {
                    auto colon = issuer_serial_string.rfind(':');
                    if (colon == std::string::npos) {
                        log_err_printf(certslog, "Error: cert_id must be <issuer>:<serial> for --schedule\n%s", "");
                        return 3;
                    }
                    uint64_t serial = std::stoull(issuer_serial_string.substr(colon + 1));

                    bool show_only = (schedule_values.size() == 1 && schedule_values[0] == "show");
                    bool clear_all = (schedule_values.size() == 1 && schedule_values[0] == "none");

                    std::vector<certs::ScheduleWindow> windows;
                    if (!show_only && !clear_all) {
                        for (const auto &sv : schedule_values) {
                            auto c1 = sv.find(',');
                            auto c2 = (c1 != std::string::npos) ? sv.find(',', c1 + 1) : std::string::npos;
                            if (c1 == std::string::npos || c2 == std::string::npos || c2 >= sv.size() - 1) {
                                log_err_printf(certslog, "Invalid --schedule format '%s': expected day,HH:MM,HH:MM (or 'show'/'none')\n", sv.c_str());
                                return 3;
                            }
                            certs::ScheduleWindow sw;
                            sw.day_of_week = sv.substr(0, c1);
                            sw.start_time  = sv.substr(c1 + 1, c2 - c1 - 1);
                            sw.end_time    = sv.substr(c2 + 1);
                            windows.push_back(std::move(sw));
                        }
                    }

                    using namespace pvxs::members;
                    auto req_type = TypeDef(TypeCode::Struct, {
                        Struct("query", {
                            UInt64("serial"),
                            Bool("read_only"),
                            StructA("schedule", {
                                String("day_of_week"),
                                String("start_time"),
                                String("end_time"),
                            }),
                        }),
                    }).create();
                    req_type["query.serial"]    = serial;
                    req_type["query.read_only"] = show_only;
                    if (!windows.empty()) {
                        shared_array<Value> sched_arr(windows.size());
                        for (size_t i = 0; i < windows.size(); i++) {
                            sched_arr[i] = req_type["query.schedule"].allocMember();
                            sched_arr[i]["day_of_week"] = windows[i].day_of_week;
                            sched_arr[i]["start_time"]  = windows[i].start_time;
                            sched_arr[i]["end_time"]    = windows[i].end_time;
                        }
                        req_type["query.schedule"] = sched_arr.freeze();
                    }

                    auto schedule_pv = conf.getCertPvPrefix().empty()
                                           ? std::string("CERT:SCHEDULE")
                                           : conf.getCertPvPrefix() + ":SCHEDULE";
                    result = client.rpc(schedule_pv, req_type).exec()->wait(conf.getRequestTimeout());

                    if (result) {
                        auto sched = result["schedule"];
                        auto sched_arr = sched ? sched.as<shared_array<const Value>>() : shared_array<const Value>{};
                        static const char *day_names[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
                        std::cout << "Schedule:" << std::endl
                                  << "============================================" << std::endl;
                        if (sched_arr.empty()) {
                            std::cout << "  (no schedule windows)" << std::endl;
                        } else {
                            for (const auto &win : sched_arr) {
                                auto dow   = win["day_of_week"].as<std::string>();
                                auto start = win["start_time"].as<std::string>();
                                auto end   = win["end_time"].as<std::string>();
                                std::string day_str = (dow == "*") ? "Every day" : day_names[dow[0] - '0'];
                                std::cout << "  " << std::left << std::setw(10) << day_str
                                          << start << " - " << end << " UTC" << std::endl;
                            }
                        }
                        std::cout << "--------------------------------------------\n" << std::endl;
                    }
                    result = Value{};
                    break;
                }
            }
            Indented I(std::cout);
            if (result) {
                std::cout << "Certificate Status: " << std::endl
                          << "============================================" << std::endl
                          << "Certificate ID: " << cert_id.substr(cert_id.rfind(':') - 8) << std::endl
                          << "Status        : " << result["state"].as<std::string>() << std::endl
                          << "Status Issued : " << result["ocsp_status_date"].as<std::string>() << std::endl
                          << "Status Expires: " << result["ocsp_certified_until"].as<std::string>() << std::endl;
                auto schedule = result["schedule"];
                if (schedule) {
                    auto sched_arr = schedule.as<shared_array<const Value>>();
                    if (sched_arr.size() > 0) {
                        std::cout << "Schedule:" << std::endl;
                        static const char *day_names[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
                        for (const auto &win : sched_arr) {
                            auto dow   = win["day_of_week"].as<std::string>();
                            auto start = win["start_time"].as<std::string>();
                            auto end   = win["end_time"].as<std::string>();
                            std::string day_str = (dow == "*") ? "Every day" : day_names[dow[0] - '0'];
                            std::cout << "  " << std::left << std::setw(10) << day_str
                                      << start << " - " << end << " UTC" << std::endl;
                        }
                    }
                }

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
