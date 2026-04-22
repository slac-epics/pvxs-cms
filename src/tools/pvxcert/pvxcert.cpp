/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <list>
#include <string>

#include <epicsGetopt.h>
#include <epicsThread.h>
#include <epicsTime.h>
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <termios.h>
#endif
#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/netcommon.h>
#include <pvxs/nt.h>

#include <CLI/CLI.hpp>

#include "security.h"

#include "certdate.h"
#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusmanager.h"
#include "openssl.h"
#include "ownedptr.h"

using namespace pvxs;

namespace {

DEFINE_LOGGER(certslog, "pvxs.certs.tool");

// Strict uint64 parse: rejects empty/sign/whitespace/trailing-junk that std::stoull would silently accept,
// and rewrites std::stoull's opaque "stoull" / "out_of_range" into a message naming the bad input.
uint64_t parseSerial(const std::string &s) {
    if (s.empty()) {
        throw std::runtime_error("malformed certificate serial: empty value (expected <issuer>:<serial>)");
    }
    if (!std::isdigit(static_cast<unsigned char>(s.front()))) {
        throw std::runtime_error("malformed certificate serial '" + s +
                                 "': must be an unsigned decimal integer");
    }
    try {
        std::size_t pos = 0;
        const uint64_t value = std::stoull(s, &pos);
        if (pos != s.size()) {
            throw std::runtime_error("malformed certificate serial '" + s +
                                     "': unexpected trailing characters");
        }
        return value;
    } catch (const std::out_of_range &) {
        throw std::runtime_error("malformed certificate serial '" + s +
                                 "': value exceeds 64-bit unsigned range");
    } catch (const std::invalid_argument &) {
        throw std::runtime_error("malformed certificate serial '" + s +
                                 "': must be an unsigned decimal integer");
    }
}

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
constexpr int kColonCol = 32;

static void writeLabel(std::ostream& strm, const char* label, int indent = 2) {
    std::string s(indent, ' ');
    s += label;
    if (static_cast<int>(s.size()) < kColonCol) s.append(kColonCol - s.size(), ' ');
    strm << s << " : ";
}

static void writeSubHeader(std::ostream& strm, const char* header) {
    strm << "  " << header << "\n";
}

static std::string epochToUtc(const uint64_t epics_secs) {
    if (epics_secs == 0) return "(none)";
    const time_t posix = static_cast<time_t>(epics_secs) + POSIX_TIME_AT_EPICS_EPOCH;
    char buf[64];
    if (std::strftime(buf, sizeof(buf), CERT_TIME_FORMAT, std::gmtime(&posix))) return buf;
    return "(date error)";
}

static std::string timePointToUtc(const std::chrono::system_clock::time_point& tp) {
    const time_t t = std::chrono::system_clock::to_time_t(tp);
    char buf[64];
    if (std::strftime(buf, sizeof(buf), CERT_TIME_FORMAT, std::gmtime(&t))) return buf;
    return "(date error)";
}

static void dumpStatusSection(const Value& result, const std::string& cert_id) {
    using cms::cert::CmsStatusManager;
    using cms::cert::cert_state_name;
    using cms::cert::CertDate;
    using cms::cert::getCertId;
    using cms::cert::IdFileFactory;
    using cms::cert::ocsp_cert_state_name;
    using cms::cert::REVOKED;
    using cms::cert::ScheduleWindow;
    static const char* const kDayNames[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

    std::cout << "\nCertificate Status\n"
              << "============================================\n";

    const auto cert_idx = result["value.index"].as<uint32_t>();
    const auto ocsp_idx = result["ocsp_status.value.index"].as<uint32_t>();

    {
        std::string short_id = cert_id;
        const auto pos = short_id.find("STATUS:");
        if (pos != std::string::npos) short_id = short_id.substr(pos + 7);
        writeLabel(std::cout, "Certificate ID");
        std::cout << short_id << "\n";
    }
    writeLabel(std::cout, "Serial");
    std::cout << result["serial"].as<uint64_t>() << "\n";
    writeLabel(std::cout, "Status");
    std::cout << CERT_STATE(static_cast<int>(cert_idx)) << "\n";
    writeLabel(std::cout, "OCSP Status");
    std::cout << OCSP_CERT_STATE(static_cast<int>(ocsp_idx)) << "\n";
    writeLabel(std::cout, "Renewal Due");
    std::cout << (result["renewal_due"].as<bool>() ? "Yes" : "No") << "\n";
    writeLabel(std::cout, "Renew By");
    std::cout << epochToUtc(result["renew_by"].as<uint64_t>()) << "\n";
    {
        const auto revdate = result["ocsp_revocation_date"].as<std::string>();
        writeLabel(std::cout, "Revocation Date");
        std::cout << (revdate.empty() ? "(not revoked)" : revdate) << "\n";
    }

    {
        const auto san_arr = result["san"].as<shared_array<const Value>>();
        if (san_arr.empty()) {
            writeLabel(std::cout, "SANs");
            std::cout << "(none)\n";
        } else {
            writeSubHeader(std::cout, "SANs");
            for (const auto& e : san_arr) {
                writeLabel(std::cout, e["type"].as<std::string>().c_str(), 4);
                std::cout << e["value"].as<std::string>() << "\n";
            }
        }
    }

    {
        const auto sched = result["schedule"].as<shared_array<const Value>>();
        if (!sched.empty()) {
            writeSubHeader(std::cout, "Schedule");
            for (const auto& win : sched) {
                const auto dow   = win["day_of_week"].as<std::string>();
                const auto start = win["start_time"].as<std::string>();
                const auto end   = win["end_time"].as<std::string>();
                const std::string day_str = (dow == "*") ? "Every day" : kDayNames[dow[0] - '0'];
                writeLabel(std::cout, day_str.c_str(), 4);
                std::cout << start << " - " << end << " UTC\n";
            }
        }
    }
}

static void dumpMetadataSection(const std::chrono::system_clock::time_point& req_t,
                                const std::chrono::system_clock::time_point& resp_t,
                                const std::string& peer_addr,
                                const std::string& iface,
                                const Value& result) {
    static const char* const kEpicsSeverity[] = {"NO_ALARM", "MINOR", "MAJOR", "INVALID"};
    static const char* const kEpicsStatus[]   = {
        "NO_STATUS", "READ", "WRITE", "HIHI", "HIGH", "LOLO", "LOW", "STATE",
        "COS", "COMM", "TIMEOUT", "HWLIMIT", "CALC", "SCAN", "LINK", "SOFT",
        "BAD_SUB", "UDF", "DISABLE", "SIMM", "READ_ACCESS", "WRITE_ACCESS"
    };

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(resp_t - req_t).count();
    const auto ocsp_bytes = result["ocsp_response"].as<shared_array<const uint8_t>>();
    const auto ts_secs = result["timeStamp.secondsPastEpoch"].as<uint64_t>();
    const auto ts_ns   = result["timeStamp.nanoseconds"].as<uint32_t>();

    std::ostringstream ts_str;
    ts_str << epochToUtc(ts_secs) << "." << std::setfill('0') << std::setw(9) << ts_ns;

    std::cout << "\nStatus Request\n"
              << "============================================\n";
    writeLabel(std::cout, "Date Requested");     std::cout << timePointToUtc(req_t) << "\n";
    writeLabel(std::cout, "Date Received");      std::cout << timePointToUtc(resp_t) << "\n";
    writeLabel(std::cout, "Response Time");      std::cout << ms << " ms\n";
    writeLabel(std::cout, "PVACMS Node Address"); std::cout << peer_addr << "\n";
    {
        const auto nid = result["pvacms_node_id"].as<std::string>();
        writeLabel(std::cout, "PVACMS Node ID");
        std::cout << (nid.empty() ? "(unknown)" : nid) << "\n";
    }
    writeLabel(std::cout, "Local Interface");    std::cout << iface << "\n";
    writeLabel(std::cout, "Response Size");      std::cout << ocsp_bytes.size() << " bytes\n";
    writeLabel(std::cout, "PV Timestamp");       std::cout << ts_str.str() << "\n";

    {
        const auto sev_idx = result["alarm.severity"].as<int>();
        const auto sta_idx = result["alarm.status"].as<int>();
        const auto msg     = result["alarm.message"].as<std::string>();
        writeLabel(std::cout, "Alarm Severity");
        std::cout << (sev_idx >= 0 && sev_idx < 4 ? kEpicsSeverity[sev_idx] : "unknown") << "\n";
        writeLabel(std::cout, "Alarm Status");
        std::cout << (sta_idx >= 0 && sta_idx < 22 ? kEpicsStatus[sta_idx] : "unknown") << "\n";
        writeLabel(std::cout, "Alarm Message");
        std::cout << (msg.empty() ? "(none)" : msg) << "\n";
    }
}

static void dumpOcspSection(const Value& result) {
    const auto ocsp_bytes = result["ocsp_response"].as<shared_array<const uint8_t>>();

    std::cout << "\nOCSP Response\n"
              << "============================================\n";

    writeLabel(std::cout, "Status Date");
    std::cout << result["ocsp_status_date"].as<std::string>() << "\n";
    {
        const auto until = result["ocsp_certified_until"].as<std::string>();
        writeLabel(std::cout, "Certified Until");
        std::cout << (until.empty() ? "(permanent)" : until) << "\n";
    }

    if (ocsp_bytes.empty()) {
        writeLabel(std::cout, "Payload");
        std::cout << "(not available — empty)\n";
        return;
    }

    try {
        const uint8_t* raw = ocsp_bytes.data();
        const long raw_len = static_cast<long>(ocsp_bytes.size());
        ossl_ptr<OCSP_RESPONSE> ocsp_resp(d2i_OCSP_RESPONSE(nullptr, &raw, raw_len), false);
        if (!ocsp_resp) {
            writeLabel(std::cout, "Payload");
            std::cout << "(not available — parse failed)\n";
            return;
        }

        static const char* const kRespStatus[] = {
            "successful", "malformedRequest", "internalError",
            "tryLater", "(reserved)", "sigRequired", "unauthorized"
        };
        const int resp_status = OCSP_response_status(ocsp_resp.get());
        const char* resp_label = (resp_status >= 0 && resp_status <= 6) ? kRespStatus[resp_status] : "unknown";
        writeLabel(std::cout, "Response Status");
        std::cout << resp_label << "\n";

        if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) return;

        ossl_ptr<OCSP_BASICRESP> basic(OCSP_response_get1_basic(ocsp_resp.get()), false);
        if (!basic) {
            writeLabel(std::cout, "Payload");
            std::cout << "(basic response unavailable)\n";
            return;
        }

        {
            const ASN1_OCTET_STRING* by_key = nullptr;
            const X509_NAME* by_name = nullptr;
            OCSP_resp_get0_id(basic.get(), &by_key, &by_name);
            if (by_name) {
                ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()));
                X509_NAME_print_ex(bio.get(), by_name, 0, XN_FLAG_RFC2253);
                char* s = nullptr;
                const long len = BIO_get_mem_data(bio.get(), &s);
                writeLabel(std::cout, "Responder ID (DN)");
                std::cout << std::string(s, static_cast<size_t>(len)) << "\n";
            } else if (by_key) {
                writeLabel(std::cout, "Responder ID (Key)");
                for (int i = 0; i < by_key->length; ++i) {
                    if (i) std::cout << ':';
                    char buf[3]; snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(by_key->data[i]));
                    std::cout << buf;
                }
                std::cout << "\n";
            }
        }

        {
            const ASN1_GENERALIZEDTIME* produced = OCSP_resp_get0_produced_at(basic.get());
            if (produced) {
                writeLabel(std::cout, "Produced At");
                std::cout << cms::cert::CertDate(produced).s << "\n";
            }
        }

        {
            const X509_ALGOR* sig_alg = OCSP_resp_get0_tbs_sigalg(basic.get());
            if (sig_alg) {
                const int nid = OBJ_obj2nid(sig_alg->algorithm);
                const char* ln = OBJ_nid2ln(nid);
                writeLabel(std::cout, "Signature Algorithm");
                std::cout << (ln ? ln : "unknown") << "\n";
            }
        }

        const int n_resp = OCSP_resp_count(basic.get());
        writeLabel(std::cout, "Single Responses");
        std::cout << n_resp << "\n";

        static const char* const kCrlReasons[] = {
            "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
            "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL",
            "privilegeWithdrawn", "aACompromise"
        };

        for (int i = 0; i < n_resp; ++i) {
            const OCSP_SINGLERESP* sr = OCSP_resp_get0(basic.get(), i);
            if (!sr) continue;

            ASN1_GENERALIZEDTIME *this_upd = nullptr, *next_upd = nullptr, *rev_time = nullptr;
            int reason = 0;
            const int cert_status = OCSP_single_get0_status(const_cast<OCSP_SINGLERESP*>(sr),
                                                             &reason, &rev_time, &this_upd, &next_upd);

            const OCSP_CERTID* cid = OCSP_SINGLERESP_get0_id(sr);
            ASN1_INTEGER* serial_asn1 = nullptr;
            OCSP_id_get0_info(nullptr, nullptr, nullptr, &serial_asn1, const_cast<OCSP_CERTID*>(cid));

            std::string header = "Response [" + std::to_string(i+1) + "]";
            writeSubHeader(std::cout, header.c_str());

            if (serial_asn1) {
                const ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial_asn1, nullptr), false);
                if (bn) {
                    char* dec = BN_bn2dec(bn.get());
                    if (dec) {
                        writeLabel(std::cout, "Serial", 4);
                        std::cout << dec << "\n";
                        OPENSSL_free(dec);
                    }
                }
            }
            const char* status_label = (cert_status == V_OCSP_CERTSTATUS_GOOD)    ? "Good"
                                     : (cert_status == V_OCSP_CERTSTATUS_REVOKED) ? "Revoked"
                                                                                   : "Unknown";
            writeLabel(std::cout, "Certificate Status", 4);
            std::cout << status_label << "\n";
            writeLabel(std::cout, "This Update", 4);
            std::cout << (this_upd ? cms::cert::CertDate(this_upd).s : "(none)") << "\n";
            writeLabel(std::cout, "Next Update", 4);
            std::cout << (next_upd ? cms::cert::CertDate(next_upd).s : "(none)") << "\n";
            if (cert_status == V_OCSP_CERTSTATUS_REVOKED) {
                writeLabel(std::cout, "Revocation Time", 4);
                std::cout << (rev_time ? cms::cert::CertDate(rev_time).s : "(none)") << "\n";
                const char* reason_label = (reason >= 0 && reason <= 9) ? kCrlReasons[reason] : "unknown";
                writeLabel(std::cout, "Revocation Reason", 4);
                std::cout << reason_label << "\n";
            }
        }
    } catch (const std::exception& e) {
        writeLabel(std::cout, "Payload");
        std::cout << "(not available — " << e.what() << ")\n";
    }
}

 std::string formatBytes(uint64_t bytes) {
    std::ostringstream os;
    if (bytes < 1024ull) {
        os << bytes << " B";
    } else if (bytes < 1024ull * 1024ull) {
        os << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / 1024.0) << " KiB";
    } else if (bytes < 1024ull * 1024ull * 1024ull) {
        os << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / (1024.0 * 1024.0)) << " MiB";
    } else {
        os << std::fixed << std::setprecision(2) << (static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0)) << " GiB";
    }
    os << " (" << bytes << ")";
    return os.str();
}

 std::string iso8601ToCertUtc(const std::string& iso) {
    if (iso.empty()) return "(never)";
    struct tm tm_buf{};
    if (!strptime(iso.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm_buf)) return iso;
    char buf[64];
    if (std::strftime(buf, sizeof(buf), CERT_TIME_FORMAT, &tm_buf)) return buf;
    return iso;
}

 std::string formatUptime(uint64_t secs) {
    const uint64_t d = secs / 86400;
    const uint64_t h = (secs % 86400) / 3600;
    const uint64_t m = (secs % 3600) / 60;
    const uint64_t s = secs % 60;
    std::ostringstream os;
    if (d) os << d << "d ";
    os << std::setfill('0') << std::setw(2) << h << ":"
       << std::setfill('0') << std::setw(2) << m << ":"
       << std::setfill('0') << std::setw(2) << s
       << " (" << secs << "s)";
    return os.str();
}

void dumpHealthSection(const Value& result) {
    std::cout << "\nPVACMS Health\n"
              << "============================================\n";

    const bool ok = result["ok"].as<bool>();
    const bool db_ok = result["db_ok"].as<bool>();
    const bool ca_valid = result["ca_valid"].as<bool>();

    writeLabel(std::cout, "Status");
    std::cout << (ok ? "OK" : "DEGRADED") << "\n";
    writeLabel(std::cout, "Database Integrity");
    std::cout << (db_ok ? "OK" : "FAIL") << "\n";
    writeLabel(std::cout, "CA Certificate");
    std::cout << (ca_valid ? "Valid" : "Expired / Missing") << "\n";
    writeLabel(std::cout, "Uptime");
    std::cout << formatUptime(result["uptime_secs"].as<uint64_t>()) << "\n";
    writeLabel(std::cout, "Certificate Count");
    std::cout << result["cert_count"].as<uint64_t>() << "\n";
    writeLabel(std::cout, "Cluster Members");
    std::cout << result["cluster_members"].as<uint32_t>() << "\n";
    writeLabel(std::cout, "Last Check");
    std::cout << iso8601ToCertUtc(result["last_check"].as<std::string>()) << "\n";
    std::cout << "--------------------------------------------\n" << std::endl;
}

void dumpMetricsSection(const Value& result) {
    std::cout << "\nPVACMS Metrics\n"
              << "============================================\n";

    writeSubHeader(std::cout, "Counters (since startup)");
    writeLabel(std::cout, "Certificates Created", 4);
    std::cout << result["certs_created"].as<uint64_t>() << "\n";
    writeLabel(std::cout, "Certificates Revoked", 4);
    std::cout << result["certs_revoked"].as<uint64_t>() << "\n";
    writeLabel(std::cout, "Uptime", 4);
    std::cout << formatUptime(result["uptime_secs"].as<uint64_t>()) << "\n";

    writeSubHeader(std::cout, "Gauges (current state)");
    writeLabel(std::cout, "Certificates Active", 4);
    std::cout << result["certs_active"].as<uint64_t>() << "\n";
    {
        std::ostringstream os;
        os << std::fixed << std::setprecision(3) << result["avg_ccr_time_ms"].as<double>() << " ms";
        writeLabel(std::cout, "Avg CCR Time", 4);
        std::cout << os.str() << "\n";
    }
    writeLabel(std::cout, "Database Size", 4);
    std::cout << formatBytes(result["db_size_bytes"].as<uint64_t>()) << "\n";
    std::cout << "--------------------------------------------\n" << std::endl;
}

}  // namespace

enum CertAction { NONE, STATUS, APPROVE, DENY, REVOKE, SCHEDULE, HEALTH, METRICS };
std::string actionToString(const CertAction &action, const std::vector<std::string> &schedule_values = {}) {
    if (action == SCHEDULE) {
        if (schedule_values.size() == 1 && schedule_values[0] == "show") return "Show Schedule";
        if (schedule_values.size() == 1 && schedule_values[0] == "none") return "Clear Schedule";
        return "Set Schedule";
    }
    switch (action) {
        case STATUS:  return "Get Status";
        case APPROVE: return "Approve";
        case REVOKE:  return "Revoke";
        case DENY:    return "Deny";
        case HEALTH:  return "Get Health";
        case METRICS: return "Get Metrics";
        default:      return "Unknown";
    }
}
int readParameters(const int argc, char *argv[], const char *program_name, client::Config &conf, bool &approve, bool &revoke, bool &deny, bool &debug,
                   bool &password_flag, bool &verbose, bool &dump, bool &health, bool &metrics, std::string &cert_file, std::string &issuer_serial_string,
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
    app.add_flag("-X,--dump", dump, "Dump all available certificate and status details");
    app.add_flag("-A,--approve", approve);
    app.add_flag("-R,--revoke", revoke);
    app.add_flag("-D,--deny", deny);
    app.add_flag("-H,--health", health, "Show formatted PVACMS CERT:HEALTH output");
    app.add_flag("-M,--metrics", metrics, "Show formatted PVACMS CERT:METRICS output");
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
                  << "  REVOCATION of a certificate: Can only be made by an administrator or the certificate owner.\n"
                  << "  When no cert_id is given, the certificate is read from -f <file> or $EPICS_PVA_TLS_KEYCHAIN.\n"
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
                  << "  " << program_name << " [options] (-R | --revoke) [<cert_id>]\n"
                  << "                                             REVOKE certificate; if cert_id omitted, reads from\n"
                  << "                                             -f <file> or $EPICS_PVA_TLS_KEYCHAIN\n"
                  << "  " << program_name << " [options] (-S | --schedule) show <cert_id>\n"
                  << "                                             SHOW current schedule windows (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-S | --schedule) none <cert_id>\n"
                  << "                                             REMOVE all schedule windows (ADMIN ONLY)\n"
                  << "  " << program_name << " [options] (-S | --schedule) <day,HH:MM,HH:MM> [-S <day,HH:MM,HH:MM> ...] <cert_id>\n"
                  << "                                             SET validity schedule windows, replacing any existing (ADMIN ONLY)\n"
                  << "                                             day: 0=Sun 1=Mon 2=Tue 3=Wed 4=Thu 5=Fri 6=Sat or * for every day\n"
                  << "                                             times are UTC, e.g. -S '1,08:00,17:00' for Mon 08:00-17:00\n"
                  << "  " << program_name << " [options] (-H | --health)          Show formatted PVACMS CERT:HEALTH output\n"
                  << "  " << program_name << " [options] (-M | --metrics)         Show formatted PVACMS CERT:METRICS output\n"
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
                  << "  (-X | --dump)                              Dump all available certificate and status details\n"
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
        bool approve{false}, revoke{false}, deny{false}, debug{false}, password_flag{false}, verbose{false}, dump{false};
        bool health{false}, metrics{false};
        std::string cert_file, password, issuer_serial_string;
        std::vector<std::string> schedule_values;

        auto parse_result =
            readParameters(argc, argv, program_name, conf, approve, revoke, deny, debug, password_flag, verbose, dump, health, metrics, cert_file, issuer_serial_string, schedule_values);
        if (parse_result) exit(parse_result);

        // --health and --metrics are standalone actions: no cert_id, no other action flags,
        // no file input, no password prompt, no --dump. Reject any combination.
        if (health || metrics) {
            if (health && metrics) {
                log_err_printf(certslog, "Error: --health and --metrics are mutually exclusive.%s", "\n");
                return 1;
            }
            if (!issuer_serial_string.empty() || !cert_file.empty() || approve || revoke || deny ||
                !schedule_values.empty() || dump || password_flag) {
                log_err_printf(certslog,
                               "Error: %s must be used alone (no cert_id, -f, -A, -R, -D, -S, -X, or -p).%s",
                               health ? "--health" : "--metrics", "\n");
                return 1;
            }
        }

        if (revoke && issuer_serial_string.empty()) {
            if (cert_file.empty() && !conf.tls_keychain_file.empty()) {
                cert_file = conf.tls_keychain_file;
            }
        }

        if (cert_file.empty() && issuer_serial_string.empty() && !approve && !revoke && !deny && schedule_values.empty()) {
            if (!conf.tls_keychain_file.empty()) {
                cert_file = conf.tls_keychain_file;
            }
        }

        if (password_flag && cert_file.empty()) {
            log_err_printf(certslog, "Error: -p must only be used with -f.%s", "\n");
            return 1;
        }

        if (!cert_file.empty() && (approve || deny)) {
            log_err_printf(certslog, "Error: -A or -D cannot be used with -f.%s", "\n");
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
        } else if (health) {
            action = HEALTH;
            conf.tls_disabled = true;
        } else if (metrics) {
            action = METRICS;
            conf.tls_disabled = true;
        } else {
            conf.tls_disabled = true;
        }

        if (action != STATUS) {
            conf.disableStatusCheck();
        }

        auto client = conf.build();

        if (verbose) std::cout << "Effective config\n" << conf;

        std::list<std::shared_ptr<client::Operation>> ops;

        epicsEvent done;

        std::string cert_id;

        if (action == HEALTH) {
            cert_id = "CERT:HEALTH";
        } else if (action == METRICS) {
            cert_id = "CERT:METRICS";
        } else if (!cert_file.empty()) {
            try {
                auto cert_data = cms::cert::IdFileFactory::create(cert_file, password)->getCertDataFromFile();
                if (cert_data.cert == nullptr) {
                    throw std::runtime_error("Failed to read certificate from file");
                }

                if (action == REVOKE) {
                    try {
                        cert_id = cms::cert::CmsStatusManager::getStatusPvFromCert(cert_data.cert);
                    } catch (...) {
                        cert_id = "CERT:STATUS:" + cms::cert::CmsStatusManager::getCertIdFromCert(cert_data.cert.get());
                    }
                } else {
                    std::string config_id{};
                    try {
                        config_id = cms::cert::CmsStatusManager::getConfigPvFromCert(cert_data.cert);
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
                    if (dump) {
                        std::cout << "Certificate Details: " << std::endl
                                  << "============================================" << std::endl
                                  << ossl::ShowX509Chain{cert_data.cert.get(), cert_data.cert_auth_chain.get()}
                                  << "\n--------------------------------------------\n" << std::endl;
                    } else {
                        std::cout << "Certificate Details: " << std::endl
                                  << "============================================" << std::endl
                                  << ossl::ShowX509{cert_data.cert.get()} << std::endl
                                  << (san_display.empty() ? "" : "SAN            : " + san_display + "\n")
                                  << (config_id.empty() ? "" : "Config URI     : " + config_id + "\n") << "--------------------------------------------\n"
                                  << std::endl;
                    }
                    try {
                        cert_id = cms::cert::CmsStatusManager::getStatusPvFromCert(cert_data.cert);
                    } catch (std::exception &e) {
                        std::cout << "Online Certificate Status: " << std::endl
                                  << "============================================" << std::endl
                                  << "Not configured: " << e.what() << std::endl;
                        return 0;
                    }
                }
            } catch (std::exception &e) {
                log_err_printf(certslog, "Error reading certificate from file: %s\n", e.what());
                return 2;
            }
        } else {
            auto colon = issuer_serial_string.rfind(':');
            if (colon == std::string::npos || colon == 0 || colon == issuer_serial_string.size() - 1) {
                log_err_printf(certslog,
                               "Error: malformed cert_id '%s': expected <issuer>:<serial> (e.g. 27975e6b:7246297371190731775)\n",
                               issuer_serial_string.c_str());
                return 3;
            }
            const std::string issuer = issuer_serial_string.substr(0, colon);
            // issuer_id = first 8 hex digits of the hex SKID (see CmsStatusManager::getIssuerIdFromCert)
            const bool issuer_ok = (issuer.size() == 8) &&
                                   std::all_of(issuer.begin(), issuer.end(),
                                               [](unsigned char c) { return std::isxdigit(c) != 0; });
            if (!issuer_ok) {
                log_err_printf(certslog,
                               "Error: malformed issuer '%s' in cert_id '%s': expected 8 hex digits (e.g. 27975e6b)\n",
                               issuer.c_str(), issuer_serial_string.c_str());
                return 3;
            }
            const uint64_t serial = parseSerial(issuer_serial_string.substr(colon + 1));
            issuer_serial_string = cms::cert::getCertId(issuer, serial);
            cert_id = "CERT:STATUS:" + issuer_serial_string;
        }

        try {
            if (action != STATUS && action != HEALTH && action != METRICS) {
                const auto display_id = issuer_serial_string.empty()
                    ? cert_id.substr(cert_id.find("STATUS:") + 7)
                    : issuer_serial_string;
                std::cout << actionToString(action, schedule_values) << " ==> " << display_id << std::flush;
            }
            Value result;
            std::string dump_peer{"(unknown)"};
            std::string dump_iface{"(unknown)"};
            std::chrono::system_clock::time_point dump_req_t, dump_resp_t;

            switch (action) {
                case NONE:
                    break;
                case STATUS:
                    if (dump) {
                        epicsEvent dump_done;
                        std::shared_ptr<client::Connect> watcher = client.connect(cert_id)
                            .onConnect([&dump_iface](const client::Connected& c) {
                                if (c.cred && !c.cred->iface.empty()) dump_iface = c.cred->iface;
                            })
                            .exec();
                        dump_req_t = std::chrono::system_clock::now();
                        auto op = client.get(cert_id)
                            .result([&](client::Result&& r) {
                                const std::string peer = r.peerName();
                                if (!peer.empty()) dump_peer = peer;
                                try { result = r(); } catch (...) {}
                                dump_resp_t = std::chrono::system_clock::now();
                                dump_done.signal();
                            })
                            .exec();
                        if (!dump_done.wait(conf.getRequestTimeout())) throw client::Timeout();
                        watcher.reset();
                    } else {
                        result = client.get(cert_id).exec()->wait(conf.getRequestTimeout());
                    }
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
                    uint64_t serial = parseSerial(issuer_serial_string.substr(colon + 1));

                    bool show_only = (schedule_values.size() == 1 && schedule_values[0] == "show");
                    bool clear_all = (schedule_values.size() == 1 && schedule_values[0] == "none");

                    std::vector<cms::cert::ScheduleWindow> windows;
                    if (!show_only && !clear_all) {
                        for (const auto &sv : schedule_values) {
                            auto c1 = sv.find(',');
                            auto c2 = (c1 != std::string::npos) ? sv.find(',', c1 + 1) : std::string::npos;
                            if (c1 == std::string::npos || c2 == std::string::npos || c2 >= sv.size() - 1) {
                                log_err_printf(certslog, "Invalid --schedule format '%s': expected day,HH:MM,HH:MM (or 'show'/'none')\n", sv.c_str());
                                return 3;
                            }
                            cms::cert::ScheduleWindow sw;
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
                case HEALTH:
                case METRICS:
                    result = client.get(cert_id).exec()->wait(conf.getRequestTimeout());
                    break;
            }
            Indented I(std::cout);
            if (result) {
                if (action == HEALTH) {
                    dumpHealthSection(result);
                } else if (action == METRICS) {
                    dumpMetricsSection(result);
                } else if (dump && action == STATUS) {
                    dumpStatusSection(result, cert_id);
                    dumpMetadataSection(dump_req_t, dump_resp_t, dump_peer, dump_iface, result);
                    dumpOcspSection(result);
                    std::cout << "--------------------------------------------\n" << std::endl;
                } else {
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

                    if (result["value.index"].as<uint32_t>() == cms::cert::REVOKED) {
                        std::cout << "Revocation Date: " << result["ocsp_revocation_date"].as<std::string>() << std::endl;
                    }
                    std::cout << "--------------------------------------------\n" << std::endl;
                }
            } else if (action != STATUS && action != HEALTH && action != METRICS)
                std::cout << " ==> Completed Successfully" << std::endl;
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
