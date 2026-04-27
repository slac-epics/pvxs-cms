/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The PVAccess Certificate Management Service.
 *
 *   pvacms
 *
 */

#include "pvacms.h"

#include <pvxs/cms/pvacms.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <dirent.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <exception>
#include <fstream>
#include <future>
#include <iostream>
#include <list>
#include <limits>
#include <locale>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <tuple>
#include <vector>

#include <epicsGetopt.h>
#include <epicsTime.h>
#include <epicsVersion.h>
#include <dbBase.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/client.h>
#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <wildcardpv.h>
#include <pvxs/credentials.h>

#include "auth.h"
#include "authregistry.h"
#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusfactory.h"
#include "clusterctrl.h"
#include "clusterdiscovery.h"
#include "clustersync.h"
#include "configcms.h"
#include "pvacmsVersion.h"
#include "openssl.h"
#include "ownedptr.h"
#include "pvacmsRuntime.h"
#include "security.h"
#include "serverev.h"
#include "sqlite3.h"
#include "tokenbucket.h"
#include "utilpvt.h"

#include <CLI/CLI.hpp>

DEFINE_LOGGER(pvacms, "cms.certs.cms");
DEFINE_LOGGER(pvacmsmonitor, "cms");

namespace cms {
using pvxs::Value;
using pvxs::shared_array;
using pvxs::version_information;
using pvxs::NoConvert;
using pvxs::impl::ConfigCommon;
namespace server = pvxs::server;
namespace client = pvxs::client;
namespace nt = pvxs::nt;
namespace members = pvxs::members;
using pvxs::parseTo;
using cms::detail::SB;
using cms::detail::ensureDirectoryExists;
using cms::detail::getFileContents;
using cms::auth::Auth;
using cms::auth::AuthRegistry;
using cms::cert::DbCert;
using cms::cert::IdFileFactory;
using cms::cert::KeyPair;
    using cms::cert::SanEntry;
    using cms::cert::ScheduleWindow;
    using cms::cert::CertFactory;
    using cms::cert::CertStatus;
    using cms::cert::CmsStatusManager;
    using cms::cert::CertStatusFactory;
    using cms::cert::CertData;
    using cms::cert::CertDate;
    using cms::cert::PVACertificateStatus;
    using cms::cert::getCertId;
    using cms::cert::getCertCreatePv;
    using cms::cert::getCertStatusPvBase;
    using cms::cert::getCertStatusPv;
    using cms::cert::getCertIssuerPv;
    using cms::cert::getCertAuthRootPv;
    using cms::cert::getCertStatusURI;
    using cms::cert::certstatus_t;
    using cms::cert::CertStatusSubscription;
    using cms::cert::DEFAULT;
    using cms::cert::YES;
    using cms::cert::NO;
    using cms::cert::VALID;
    using cms::cert::PENDING;
    using cms::cert::PENDING_APPROVAL;
    using cms::cert::PENDING_RENEWAL;
    using cms::cert::SCHEDULED_OFFLINE;
    using cms::cert::EXPIRED;
    using cms::cert::REVOKED;
    using cms::cert::UNKNOWN;
    using cms::cluster::ClusterController;
    using cms::cluster::ClusterDiscovery;
    using cms::cluster::ClusterSyncPublisher;
    using cms::cluster::TokenBucket;

// fwd decl (declared with external linkage in pvacms.h so serverHandle.cpp can call it)
void insertLoadedCertIfMissing(const ConfigCms &config,
                               sql_ptr &certs_db,
                               const ossl_ptr<X509> &cert,
                               const ossl_shared_ptr<STACK_OF(X509)> &chain,
                               const std::string &expected_issuer_id,
                               bool is_ca);

bool postUpdateToNextCertToExpire(const CertStatusFactory &cert_status_factory,
                                  server::WildcardPV &status_pv,
                                  const sql_ptr &certs_db,
                                  const std::string &cert_pv_prefix,
                                  const std::string &issuer_id,
                                  const std::string &full_skid = {});

DbCert getOriginalCert(CertFactory &cert_factory, const sql_ptr &certs_db, const std::string &issuer_id);

bool postUpdateToNextCertNearingRenewal(const CertStatusFactory &cert_status_creator,
                                  server::WildcardPV &status_pv,
                                  const sql_ptr &certs_db,
                                  const std::string &cert_pv_prefix,
                                  const std::string &issuer_id);

bool postUpdateToNextCertToNeedRenewal(const CertStatusFactory &cert_status_creator,
                                  server::WildcardPV &status_pv,
                                  const sql_ptr &certs_db,
                                  const std::string &cert_pv_prefix,
                                  const std::string &issuer_id);

PvacmsRuntime &defaultRuntime()
{
    static PvacmsRuntime runtime;
    return runtime;
}

epicsMutex &getStatusPvLock()       { return defaultRuntime().status_pv_lock; }
epicsMutex &getStatusUpdateLock()   { return defaultRuntime().status_update_lock; }

TokenBucket &getCreateCertificateRateLimiter()
{
    return defaultRuntime().create_certificate_rate_limiter;
}

std::atomic<uint32_t> &getCreateCertificateInflightCount()
{
    return defaultRuntime().create_certificate_inflight_count;
}

std::atomic<uint64_t> &getCertsCreatedCounter()
{
    return defaultRuntime().certs_created_counter;
}

std::atomic<uint64_t> &getCertsRevokedCounter()
{
    return defaultRuntime().certs_revoked_counter;
}

void pruneOldBackups(const std::string &dir, uint32_t max_count)
{
    if (max_count == 0) return;

    std::vector<std::string> backups;
    DIR *d = opendir(dir.c_str());
    if (!d) return;

    while (auto *entry = readdir(d)) {
        std::string name = entry->d_name;
        if (name.find("certs_backup_") == 0u && name.size() > 3u &&
            name.substr(name.size() - 3u) == ".db") {
            backups.push_back(dir + "/" + name);
        }
    }
    closedir(d);

    std::sort(backups.begin(), backups.end());

    while (backups.size() > max_count) {
        if (std::remove(backups.front().c_str()) == 0) {
            log_info_printf(pvacms, "Pruned old backup: %s\n", backups.front().c_str());
        }
        backups.erase(backups.begin());
    }
}

bool performBackup(sqlite3 *src_db, const std::string &dest_path)
{
    log_info_printf(pvacms, "Starting database backup to %s\n", dest_path.c_str());

    sqlite3 *dest_db = nullptr;
    if (sqlite3_open(dest_path.c_str(), &dest_db) != SQLITE_OK) {
        log_err_printf(pvacms, "Database backup open failed for %s: %s\n",
                       dest_path.c_str(), dest_db ? sqlite3_errmsg(dest_db) : "sqlite3_open failed");
        if (dest_db) sqlite3_close(dest_db);
        return false;
    }

    sqlite3_backup *backup = sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (!backup) {
        log_err_printf(pvacms, "Database backup init failed for %s: %s\n",
                       dest_path.c_str(), sqlite3_errmsg(dest_db));
        sqlite3_close(dest_db);
        return false;
    }

    const int step_status = sqlite3_backup_step(backup, -1);
    const int finish_status = sqlite3_backup_finish(backup);
    const bool ok = step_status == SQLITE_DONE && finish_status == SQLITE_OK;

    if (!ok) {
        log_err_printf(pvacms, "Database backup failed for %s: %s\n",
                       dest_path.c_str(), sqlite3_errmsg(dest_db));
        sqlite3_close(dest_db);
        return false;
    }

    if (sqlite3_close(dest_db) != SQLITE_OK) {
        log_err_printf(pvacms, "Database backup close failed for %s: %s\n",
                       dest_path.c_str(), sqlite3_errmsg(dest_db));
        return false;
    }

    struct stat st;
    if (stat(dest_path.c_str(), &st) == 0) {
        log_info_printf(pvacms, "Completed database backup to %s (%lld bytes)\n",
                        dest_path.c_str(), static_cast<long long>(st.st_size));
    } else {
        log_info_printf(pvacms, "Completed database backup to %s\n", dest_path.c_str());
    }

    return true;
}

CcrTimingTracker &getCcrTimingTracker()
{
    return defaultRuntime().ccr_timing_tracker;
}

namespace {

std::string escapeJsonString(const std::string &input)
{
    std::string output;
    output.reserve(input.size());
    for (const auto ch : input) {
        switch (ch) {
        case '\\':
            output += "\\\\";
            break;
        case '"':
            output += "\\\"";
            break;
        case '\n':
            output += "\\n";
            break;
        case '\r':
            output += "\\r";
            break;
        case '\t':
            output += "\\t";
            break;
        default:
            output += ch;
            break;
        }
    }
    return output;
}

std::string unescapeJsonString(const std::string &input)
{
    std::string output;
    output.reserve(input.size());
    for (size_t i = 0; i < input.size(); i++) {
        if (input[i] == '\\' && i + 1 < input.size()) {
            switch (input[i + 1]) {
            case '\\':
                output += '\\';
                break;
            case '"':
                output += '"';
                break;
            case 'n':
                output += '\n';
                break;
            case 'r':
                output += '\r';
                break;
            case 't':
                output += '\t';
                break;
            default:
                output += input[i + 1];
                break;
            }
            i++;
        } else {
            output += input[i];
        }
    }
    return output;
}

}  // namespace

std::string sanToJson(const std::vector<SanEntry> &entries)
{
    if (entries.empty())
        return std::string();

    auto json = SB();
    json << '[';
    for (size_t i = 0; i < entries.size(); i++) {
        if (i)
            json << ',';
        json << "{\"type\":\"" << escapeJsonString(entries[i].type)
             << "\",\"value\":\"" << escapeJsonString(entries[i].value)
             << "\"}";
    }
    json << ']';
    return json.str();
}

std::vector<SanEntry> sanFromJson(const std::string &json)
{
    std::vector<SanEntry> entries;
    if (json.empty())
        return entries;

    static const std::string kTypePattern("{\"type\":\"");
    static const std::string kValuePattern("\",\"value\":\"");
    static const std::string kEndPattern("\"}");

    size_t pos = 0u;
    while ((pos = json.find(kTypePattern, pos)) != std::string::npos) {
        pos += kTypePattern.size();
        const auto value_pos = json.find(kValuePattern, pos);
        if (value_pos == std::string::npos)
            break;
        const auto end_pos = json.find(kEndPattern, value_pos + kValuePattern.size());
        if (end_pos == std::string::npos)
            break;

        SanEntry entry;
        entry.type = unescapeJsonString(json.substr(pos, value_pos - pos));
        entry.value = unescapeJsonString(json.substr(value_pos + kValuePattern.size(),
                                                    end_pos - (value_pos + kValuePattern.size())));
        entries.push_back(std::move(entry));
        pos = end_pos + kEndPattern.size();
    }

    return entries;
}

struct InflightCcrGuard {
    explicit InflightCcrGuard(std::atomic<uint32_t> &counter)
        : counter_(counter)
    {}

    ~InflightCcrGuard()
    {
        counter_.fetch_sub(1u);
    }

    std::atomic<uint32_t> &counter_;
};

struct ASMember {
    std::string name{};
    ASMEMBERPVT mem{};
    ASMember() : ASMember("DEFAULT") {}
    explicit ASMember(const std::string &n) : name(n) {
        if (auto err = asAddMember(&mem, name.c_str()))
            throw std::runtime_error(SB() << "Unable to create ASMember " << n<<" : "<<err);
        // mem references name.c_str()
    }
    ~ASMember() {
        // all clients must be disconnected...
        if (asRemoveMember(&mem))
            log_err_printf(pvacms, "Unable to cleanup ASMember %s\n", name.c_str());
    }
};

static const std::string kCertRoot("CERT:ROOT");

// Forward decls

// Subject part extractor
std::string extractSubjectPart(const std::string &subject, const std::string &key) {
    std::size_t start = subject.find("/" + key + "=");
    if (start == std::string::npos) {
        return {};
    }
    start += key.size() + 2;                     // Skip over "/key="
    std::size_t end = subject.find("/", start);  // Find the end of the current value
    if (end == std::string::npos) {
        end = subject.size();
    }
    return subject.substr(start, end - start);
};

static bool isValidScheduleTime(const std::string &t) {
    if (t.size() != 5 || t[2] != ':')
        return false;
    if (!std::isdigit(static_cast<unsigned char>(t[0])) ||
        !std::isdigit(static_cast<unsigned char>(t[1])) ||
        !std::isdigit(static_cast<unsigned char>(t[3])) ||
        !std::isdigit(static_cast<unsigned char>(t[4])))
        return false;
    const int h = std::stoi(t.substr(0, 2));
    const int m = std::stoi(t.substr(3, 2));
    return h >= 0 && h <= 23 && m >= 0 && m <= 59;
}

static void validateSanEntries(const std::vector<SanEntry> &entries) {
    const auto isValidDnsLabel = [](const std::string &label) {
        if (label.empty() || label.size() > 63u)
            return false;
        if (label.front() == '-' || label.back() == '-')
            return false;
        for (const auto ch : label) {
            if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '-')
                return false;
        }
        return true;
    };

    for (const auto &entry : entries) {
        if (entry.type == "ip") {
            unsigned char buf4[4];
            unsigned char buf6[16];
            if (inet_pton(AF_INET, entry.value.c_str(), buf4) != 1 &&
                inet_pton(AF_INET6, entry.value.c_str(), buf6) != 1) {
                throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);
            }
        } else if (entry.type == "dns") {
            if (entry.value.empty() || entry.value.size() > 253u)
                throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);

            size_t pos = 0u;
            while (pos < entry.value.size()) {
                const auto end = entry.value.find('.', pos);
                const auto label = entry.value.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
                if (!isValidDnsLabel(label))
                    throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);
                if (end == std::string::npos)
                    break;
                pos = end + 1u;
            }
        } else if (entry.type == "hostname") {
            if (!isValidDnsLabel(entry.value) || entry.value.find('.') != std::string::npos) {
                throw std::runtime_error("Invalid SAN value for type '" + entry.type + "': " + entry.value);
            }
        } else {
            throw std::runtime_error("Unknown SAN type: " + entry.type);
        }
    }
}

static std::vector<ScheduleWindow> loadScheduleWindows(sqlite3 *db, uint64_t serial) {
    std::vector<ScheduleWindow> windows;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_SELECT_SCHEDULES_BY_SERIAL, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), static_cast<sqlite3_int64>(serial));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ScheduleWindow sw;
            auto col = [&](int c) -> std::string {
                auto t = sqlite3_column_text(stmt, c);
                return t ? reinterpret_cast<const char *>(t) : "";
            };
            sw.day_of_week = col(0);
            sw.start_time = col(1);
            sw.end_time = col(2);
            windows.push_back(std::move(sw));
        }
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return windows;
}

static std::string loadSanFromDb(sqlite3 *db, uint64_t serial) {
    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *stmt = nullptr;
    std::string result;
    if (sqlite3_prepare_v2(db, "SELECT san FROM certs WHERE serial = :serial", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), db_serial);
        if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            result = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        }
    }
    if (stmt)
        sqlite3_finalize(stmt);
    return result;
}

static void assignSchedule(Value &value, const std::vector<ScheduleWindow> &schedule_windows) {
    if (schedule_windows.empty())
        return;

    shared_array<Value> sched_arr(schedule_windows.size());
    for (size_t i = 0; i < schedule_windows.size(); i++) {
        sched_arr[i] = value["schedule"].allocMember();
        sched_arr[i]["day_of_week"] = schedule_windows[i].day_of_week;
        sched_arr[i]["start_time"] = schedule_windows[i].start_time;
        sched_arr[i]["end_time"] = schedule_windows[i].end_time;
    }
    value["schedule"] = sched_arr.freeze();
}

static void assignSan(Value &value, const std::vector<SanEntry> &entries) {
    if (entries.empty())
        return;

    shared_array<Value> san_arr(entries.size());
    for (size_t i = 0; i < entries.size(); i++) {
        san_arr[i] = value["san"].allocMember();
        san_arr[i]["type"] = entries[i].type;
        san_arr[i]["value"] = entries[i].value;
    }
    value["san"] = san_arr.freeze();
}

/**
 * @brief  The prototype of the returned data from a create certificate operation
 * @return  the prototype to use for create certificate operations
 */
Value getCreatePrototype() {
    using namespace members;
    auto value = TypeDef(TypeCode::Struct, "epics:nt/NTEnum:1.0", {
                    Struct("value", "enum_t", {
                        Int32("index"),
                        StringA("choices"),
                    }),
                    nt::Alarm{}.build().as("alarm"),
                    nt::TimeStamp{}.build().as("timeStamp"),
                    Struct("display", {
                        String("description"),
                    }),
                    Member(TypeCode::String, "issuer"),
                    Member(TypeCode::UInt64, "serial"),
                    Member(TypeCode::String, "state"),
                    Member(TypeCode::String, "cert_id"),
                    Member(TypeCode::String, "status_pv"),
                    Member(TypeCode::UInt64, "renew_by"),
                    Member(TypeCode::UInt64, "expiration"),
                     Member(TypeCode::String, "cert"),
                     StructA("schedule", {
                         String("day_of_week"),
                         String("start_time"),
                         String("end_time"),
                     }),
                     StructA("san", {
                         String("type"),
                         String("value"),
                     }),
         }).create();
    shared_array<const std::string> choices(CERT_STATES);
    value["value.choices"] = choices.freeze();
    return value;
}

/**
 * @brief  Create the certificate `Value` for the given certificate and certificate chain
 *
 * Uses the given certificate to extract the subject parts and
 * create the value to return, including the certificate chain if specified
 *
 * @param issuer_id The issuer ID - the ID of the issuer of the given certificate
 * @param cert The certificate to extract the subject parts from
 * @param cert_chain_ptr The certificate chain of the certificate or null if not specified
 * @return  The certificate `Value` for the given certificate
 */
static Value createCertificateValue(const std::string &issuer_id,
                                    const ossl_ptr<X509> &cert,
                                    const STACK_OF(X509) * cert_chain_ptr) {
    using namespace members;
    auto value = TypeDef(TypeCode::Struct,
                         {
                             Member(TypeCode::String, "issuer"),
                             Member(TypeCode::UInt64, "serial"),
                             Member(TypeCode::String, "name"),
                             Member(TypeCode::String, "org"),
                             Member(TypeCode::String, "org_unit"),
                             Member(TypeCode::String, "cert"),
                             nt::Alarm{}.build().as("alarm"),
                         })
                     .create();
    // Get subject
    const auto subject_name(X509_get_subject_name(cert.get()));
    const auto subject_ptr(X509_NAME_oneline(subject_name, nullptr, 0));
    if (!subject_ptr) {
        throw std::runtime_error("Unable to get the subject of the given certificate");
    }
    const std::string subject(subject_ptr);
    free(subject_ptr);

    std::string val;
    value["issuer"] = issuer_id;
    value["serial"] = CertStatusFactory::getSerialNumber(cert);
    if (!(val = extractSubjectPart(subject, "CN")).empty())
        value["name"] = val;
    if (!(val = extractSubjectPart(subject, "O")).empty())
        value["org"] = val;
    if (!(val = extractSubjectPart(subject, "OU")).empty())
        value["org_unit"] = val;
    value["cert"] = CertFactory::certAndCasToPemString(cert, cert_chain_ptr);

    return value;
}

/**
 * @brief  The value for a GET ISSUER certificate operation
 *
 * @param issuer_id The issuer ID
 * @param issuer_cert The issuer certificate
 * @param cert_auth_cert_chain The certificate authority chain back to the root certificate
 * @return  The value for a GET ISSUER certificate operation
 */
Value getIssuerValue(const std::string &issuer_id,
                     const ossl_ptr<X509> &issuer_cert,
                     const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain) {
    return createCertificateValue(issuer_id, issuer_cert, cert_auth_cert_chain.get());
}

/**
 * @brief  The value for a GET ROOT certificate operation
 *
 * @param issuer_id The issuer ID
 * @param root_cert The root certificate
 * @return  The value for a GET ROOT certificate operation
 */
Value getRootValue(const std::string &issuer_id, const ossl_ptr<X509> &root_cert) {
    return createCertificateValue(issuer_id, root_cert, nullptr);
}

/**
 * @brief Build the prototype Value for the CERT:HEALTH PV.
 *
 * Published as Normative Type ``epics:nt/NTEnum:1.0`` so generic PVA clients
 * (Phoebus, archiver, alarm server, ...) get standard ``value`` (enum_t with
 * choices "Not OK"/"OK"), ``alarm`` (severity/status/message) and
 * ``timeStamp`` substructures.  The ancillary health fields previously
 * exposed as a flat struct (``db_ok``, ``ca_valid``, ``uptime_secs``,
 * ``cert_count``, ``cluster_members``, ``last_check``) are appended as
 * sibling fields so they remain individually subscribable.
 *
 * @return  Prototype Value with NTEnum + ancillary fields, choices populated.
 */
Value makeHealthValue() {
    using namespace pvxs::members;

    auto def = nt::NTEnum{}.build();
    def += {
        Bool("db_ok"),
        Bool("ca_valid"),
        UInt64("uptime_secs"),
        UInt64("cert_count"),
        UInt32("cluster_members"),
        String("last_check"),
    };
    auto value = def.create();
    shared_array<const std::string> choices({"Not OK", "OK"});
    value["value.choices"] = choices.freeze();
    return value;
}

/**
 * @brief Build the prototype Value for the CERT:METRICS PV.
 *
 * Published as Normative Type ``epics:nt/NTScalar:1.0`` whose top-level
 * ``value`` (``uint64_t``) carries the operationally most-meaningful metric:
 * the number of currently active (VALID) certificates.  The remaining
 * counters/timings are appended as sibling fields so each can still be
 * subscribed individually.  Standard ``alarm``, ``timeStamp`` and
 * ``display`` substructures are provided by the NTScalar builder.
 *
 * @return  Prototype Value with NTScalar + ancillary fields, display populated.
 */
Value makeMetricsValue() {
    using namespace pvxs::members;

    auto def = nt::NTScalar{TypeCode::UInt64, /*display*/ true}.build();
    def += {
        UInt64("certs_created"),
        UInt64("certs_revoked"),
        Member(TypeCode::Float64, "avg_ccr_time_ms"),
        UInt64("db_size_bytes"),
        UInt64("uptime_secs"),
    };
    auto value = def.create();
    value["display.description"] = "Number of active (VALID) certificates";
    value["display.units"] = "certs";
    return value;
}

/**
 * @brief Initializes the certificate database by opening the specified
 * database file.
 *
 * @param certs_db A shared pointer to the SQLite database object.
 * @param db_file The path to the SQLite database file.
 *
 * @throws std::runtime_error if the database can't be opened or initialised
 */
void initCertsDatabase(sql_ptr &certs_db, const std::string &db_file) {
    log_debug_printf(pvacms, "Attempting to open certificate database file: %s\n", db_file.c_str());
    if (sqlite3_open(db_file.c_str(), certs_db.acquire()) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Can't open certs db file for writing: " << sqlite3_errmsg(certs_db.get()));
    }
    log_debug_printf(pvacms, "Opened certificate database file: %s\n", db_file.c_str());

    // SQLite hardening PRAGMAs — applied immediately after open
    if (sqlite3_exec(certs_db.get(), "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr) != SQLITE_OK) {
        log_err_printf(pvacms, "Failed to set WAL journal mode: %s\n", sqlite3_errmsg(certs_db.get()));
    }
    if (sqlite3_exec(certs_db.get(), "PRAGMA busy_timeout=5000", nullptr, nullptr, nullptr) != SQLITE_OK) {
        log_err_printf(pvacms, "Failed to set busy timeout: %s\n", sqlite3_errmsg(certs_db.get()));
    }
    if (sqlite3_exec(certs_db.get(), "PRAGMA foreign_keys=ON", nullptr, nullptr, nullptr) != SQLITE_OK) {
        log_err_printf(pvacms, "Failed to enable foreign keys: %s\n", sqlite3_errmsg(certs_db.get()));
    }
    log_debug_printf(pvacms, "Applied SQLite hardening PRAGMAs (WAL, busy_timeout, foreign_keys)%s\n", "");

    log_debug_printf(pvacms, "Checking for existence of certs database:\n%s\n", SQL_CHECK_EXISTS_DB_FILE);
    sqlite3_stmt *statement;
    if (sqlite3_prepare_v2(certs_db.get(), SQL_CHECK_EXISTS_DB_FILE, -1, &statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Failed to check if certs db exists: " << sqlite3_errmsg(certs_db.get()));
    }

    const bool table_exists = sqlite3_step(statement) == SQLITE_ROW;  // table exists if a row was returned
    sqlite3_finalize(statement);

    if (!table_exists) {
        log_debug_printf(pvacms, "Creating certs database:\n%s\n", SQL_CREATE_DB_FILE);
        const auto sql_status = sqlite3_exec(certs_db.get(), SQL_CREATE_DB_FILE, nullptr, nullptr, nullptr);
        if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE) {
            throw std::runtime_error(SB() << "Can't initialize certs db file: " << sqlite3_errmsg(certs_db.get()));
        }
        std::cout << "Certificate DB created  : " << db_file << std::endl;
    }
    log_debug_printf(pvacms, "Certs database exists: %s\n", "certs");

    // Schema version tracking — create table if missing, check/apply migrations
    if (sqlite3_exec(certs_db.get(), SQL_CREATE_SCHEMA_VERSION, nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Failed to create schema_version table: " << sqlite3_errmsg(certs_db.get()));
    }

    {
        sqlite3_stmt *ver_stmt = nullptr;
        if (sqlite3_prepare_v2(certs_db.get(), SQL_GET_SCHEMA_VERSION, -1, &ver_stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(SB() << "Failed to query schema version: " << sqlite3_errmsg(certs_db.get()));
        }

        if (sqlite3_step(ver_stmt) == SQLITE_ROW) {
            const int db_version = sqlite3_column_int(ver_stmt, 0);
            sqlite3_finalize(ver_stmt);

            if (db_version < PVACMS_SCHEMA_VERSION) {
                log_warn_printf(pvacms, "Database schema version %d is older than current version %d — applying migrations\n",
                                db_version, PVACMS_SCHEMA_VERSION);
                if (db_version < 2) {
                    if (sqlite3_exec(certs_db.get(), SQL_CREATE_AUDIT_TABLE, nullptr, nullptr, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to create audit table: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_stmt *mig_stmt = nullptr;
                    if (sqlite3_prepare_v2(certs_db.get(), SQL_INSERT_SCHEMA_VERSION, -1, &mig_stmt, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to prepare migration version insert: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_bind_int(mig_stmt, 1, 2);
                    sqlite3_bind_int64(mig_stmt, 2, static_cast<sqlite3_int64>(time(nullptr)));
                    if (sqlite3_step(mig_stmt) != SQLITE_DONE) {
                        sqlite3_finalize(mig_stmt);
                        throw std::runtime_error(SB() << "Failed to record migration to v2: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_finalize(mig_stmt);
                    log_info_printf(pvacms, "Applied migration to schema version 2 (audit table)%s\n", "");
                }
                if (db_version < 3) {
                    if (sqlite3_exec(certs_db.get(), SQL_CREATE_CERT_SCHEDULES_TABLE, nullptr, nullptr, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to create cert_schedules table: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_stmt *mig_stmt = nullptr;
                    if (sqlite3_prepare_v2(certs_db.get(), SQL_INSERT_SCHEMA_VERSION, -1, &mig_stmt, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to prepare migration version insert: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_bind_int(mig_stmt, 1, 3);
                    sqlite3_bind_int64(mig_stmt, 2, static_cast<sqlite3_int64>(time(nullptr)));
                    if (sqlite3_step(mig_stmt) != SQLITE_DONE) {
                        sqlite3_finalize(mig_stmt);
                        throw std::runtime_error(SB() << "Failed to record migration to v3: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_finalize(mig_stmt);
                    log_info_printf(pvacms, "Applied migration to schema version 3 (cert_schedules table)%s\n", "");
                }
                if (db_version < 4) {
                    sqlite3_stmt *info_stmt = nullptr;
                    if (sqlite3_prepare_v2(certs_db.get(), "PRAGMA table_info(certs)", -1, &info_stmt, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to inspect certs table for san column: " << sqlite3_errmsg(certs_db.get()));
                    }
                    bool san_exists = false;
                    while (sqlite3_step(info_stmt) == SQLITE_ROW) {
                        const auto *column_name = reinterpret_cast<const char *>(sqlite3_column_text(info_stmt, 1));
                        if (column_name && std::string(column_name) == "san") {
                            san_exists = true;
                            break;
                        }
                    }
                    sqlite3_finalize(info_stmt);
                    if (!san_exists) {
                        if (sqlite3_exec(certs_db.get(), "ALTER TABLE certs ADD COLUMN san TEXT DEFAULT NULL", nullptr, nullptr, nullptr) != SQLITE_OK) {
                            throw std::runtime_error(SB() << "Failed to add san column to certs table: " << sqlite3_errmsg(certs_db.get()));
                        }
                    }
                    sqlite3_stmt *mig_stmt = nullptr;
                    if (sqlite3_prepare_v2(certs_db.get(), SQL_INSERT_SCHEMA_VERSION, -1, &mig_stmt, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to prepare migration version insert: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_bind_int(mig_stmt, 1, 4);
                    sqlite3_bind_int64(mig_stmt, 2, static_cast<sqlite3_int64>(time(nullptr)));
                    if (sqlite3_step(mig_stmt) != SQLITE_DONE) {
                        sqlite3_finalize(mig_stmt);
                        throw std::runtime_error(SB() << "Failed to record migration to v4: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_finalize(mig_stmt);
                    log_info_printf(pvacms, "Applied migration to schema version 4 (san column)%s\n", "");
                }
                if (db_version < 5) {
                    static const char *remap_sql =
                        "UPDATE certs SET status = 99 WHERE status = 7;"
                        "UPDATE certs SET status = 7  WHERE status = 6;"
                        "UPDATE certs SET status = 6  WHERE status = 5;"
                        "UPDATE certs SET status = 5  WHERE status = 99;";
                    if (sqlite3_exec(certs_db.get(), remap_sql, nullptr, nullptr, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to remap status values for v5: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_stmt *mig_stmt = nullptr;
                    if (sqlite3_prepare_v2(certs_db.get(), SQL_INSERT_SCHEMA_VERSION, -1, &mig_stmt, nullptr) != SQLITE_OK) {
                        throw std::runtime_error(SB() << "Failed to prepare migration version insert: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_bind_int(mig_stmt, 1, 5);
                    sqlite3_bind_int64(mig_stmt, 2, static_cast<sqlite3_int64>(time(nullptr)));
                    if (sqlite3_step(mig_stmt) != SQLITE_DONE) {
                        sqlite3_finalize(mig_stmt);
                        throw std::runtime_error(SB() << "Failed to record migration to v5: " << sqlite3_errmsg(certs_db.get()));
                    }
                    sqlite3_finalize(mig_stmt);
                    log_info_printf(pvacms, "Applied migration to schema version 5 (SCHEDULED_OFFLINE enum reorder)%s\n", "");
                }
            } else if (db_version > PVACMS_SCHEMA_VERSION) {
                log_warn_printf(pvacms, "Database schema version %d is newer than current code version %d — possible downgrade\n",
                                db_version, PVACMS_SCHEMA_VERSION);
            }
        } else {
            sqlite3_finalize(ver_stmt);

            // No version row — first creation or pre-versioned database; record initial version
            sqlite3_stmt *ins_stmt = nullptr;
            if (sqlite3_prepare_v2(certs_db.get(), SQL_INSERT_SCHEMA_VERSION, -1, &ins_stmt, nullptr) != SQLITE_OK) {
                throw std::runtime_error(SB() << "Failed to prepare schema version insert: " << sqlite3_errmsg(certs_db.get()));
            }
            sqlite3_bind_int(ins_stmt, 1, PVACMS_SCHEMA_VERSION);
            sqlite3_bind_int64(ins_stmt, 2, static_cast<sqlite3_int64>(time(nullptr)));
            if (sqlite3_step(ins_stmt) != SQLITE_DONE) {
                sqlite3_finalize(ins_stmt);
                throw std::runtime_error(SB() << "Failed to insert initial schema version: " << sqlite3_errmsg(certs_db.get()));
            }
            sqlite3_finalize(ins_stmt);
            log_debug_printf(pvacms, "Recorded initial schema version %d\n", PVACMS_SCHEMA_VERSION);
        }
    }

    if (sqlite3_exec(certs_db.get(), SQL_CREATE_AUDIT_TABLE, nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Failed to create audit table: " << sqlite3_errmsg(certs_db.get()));
    }

    if (sqlite3_exec(certs_db.get(), SQL_CREATE_CERT_SCHEDULES_TABLE, nullptr, nullptr, nullptr) != SQLITE_OK) {
        throw std::runtime_error(SB() << "Failed to create cert_schedules table: " << sqlite3_errmsg(certs_db.get()));
    }
}

/**
 * @brief Get the worst certificate status from the database for the given serial number
 *
 * This is used to compare the retrieved status with the worst so far so
 * that we can iteratively determine the worst status for a set of certificates.
 * The set we are interested in is the set of Certificate Authority certificates.
 *
 * When we return the status of a Certificate we also check the status of the
 * Certificate Authority certificates and send the worst status to the client.
 *
 * @param certs_db The database to get the certificate status from
 * @param serial The serial number of the certificate
 * @param worst_status_so_far The worst certificate status so far
 * @param worst_status_time_so_far The time of the worst certificate status so far
 * @return The worst certificate status for the given serial number
 */
void getWorstCertificateStatus(const sql_ptr &certs_db,
                               const serial_number_t serial,
                               certstatus_t &worst_status_so_far,
                               time_t &worst_status_time_so_far) {
    certstatus_t status;
    time_t status_date;
    std::tie(status, status_date) = getCertificateStatus(certs_db, serial);
    // if worse
    if (status != UNKNOWN && certStatusSeverity(status) > certStatusSeverity(worst_status_so_far)) {
        worst_status_so_far = status;
        worst_status_time_so_far = status_date;
    }
}

/**
 * @brief Retrieves the status of a certificate from the database.
 *
 * This function retrieves the status of a certificate with the given serial
 * number from the specified database.
 *
 * @param certs_db A reference to the SQLite database connection.
 * @param serial The serial number of the certificate.
 *
 * @return The status of the certificate.
 *
 * @throw std::runtime_error If there is an error preparing the SQL statement or
 * retrieving the certificate status.
 */
std::tuple<certstatus_t, time_t> getCertificateStatus(const sql_ptr &certs_db, serial_number_t serial) {
    int cert_status = UNKNOWN;
    time_t status_date = std::time(nullptr);

    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement = nullptr;
    if (sqlite3_prepare_v2(certs_db.get(), SQL_CERT_STATUS, -1, &sql_statement, nullptr) != SQLITE_OK) {
        // On prepare failure SQLite leaves sql_statement undefined - do NOT finalize.
        throw std::logic_error(SB() << "failed to prepare sqlite statement: " << sqlite3_errmsg(certs_db.get()));
    }

    sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);

    if (sqlite3_step(sql_statement) == SQLITE_ROW) {
        cert_status = sqlite3_column_int(sql_statement, 0);
        status_date = sqlite3_column_int64(sql_statement, 1);
    }

    // Pair every successful prepare_v2 with finalize: in WAL mode an unfinalized
    // SELECT holds an open read transaction, blocking checkpoints and serialising
    // writers behind busy_timeout. Critical in cluster-mode (5 call sites including
    // hot status-monitor and cluster-bring-up paths). Same anti-pattern as the
    // getCertificateValidity bug fixed in 66a0982.
    sqlite3_finalize(sql_statement);

    return std::make_tuple(static_cast<certstatus_t>(cert_status), status_date);
}

std::string getCertificateSkid(const sql_ptr &certs_db, serial_number_t serial) {
    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *stmt;
    std::string skid;
    if (sqlite3_prepare_v2(certs_db.get(), SQL_CERT_SKID_BY_SERIAL, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), db_serial);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const auto *text = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            if (text)
                skid = text;
        }
    }
    sqlite3_finalize(stmt);
    return skid;
}

bool isNodeCertRevoked(const sql_ptr &certs_db, const std::string &node_id) {
    sqlite3_stmt *stmt;
    bool revoked = false;
    if (sqlite3_prepare_v2(certs_db.get(), SQL_CERT_IS_NODE_REVOKED, -1, &stmt, nullptr) == SQLITE_OK) {
        auto prefix = node_id + "%";
        sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":skid_prefix"), prefix.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, sqlite3_bind_parameter_index(stmt, ":revoked"), static_cast<int>(REVOKED));
        revoked = (sqlite3_step(stmt) == SQLITE_ROW);
    }
    sqlite3_finalize(stmt);
    return revoked;
}

/**
 * @brief Get the validity of a certificate from the database
 *
 * @param certs_db The database to get the certificate validity from
 * @param serial The serial number of the certificate
 * @return certificate info
 */
DbCert getCertificateValidity(const sql_ptr &certs_db, serial_number_t serial) {
    DbCert certificate;

    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement = nullptr;
    if (sqlite3_prepare_v2(certs_db.get(), SQL_CERT_VALIDITY, -1, &sql_statement, nullptr) != SQLITE_OK) {
        // On prepare failure SQLite leaves sql_statement undefined - do NOT finalize.
        throw std::logic_error(SB() << "failed to prepare sqlite statement: " << sqlite3_errmsg(certs_db.get()));
    }

    sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);

    if (sqlite3_step(sql_statement) == SQLITE_ROW) {
        certificate.not_before = sqlite3_column_int64(sql_statement, 0);
        certificate.not_after = sqlite3_column_int64(sql_statement, 1);
        certificate.renew_by = sqlite3_column_int64(sql_statement, 2);
    }

    // Pair every successful prepare_v2 with finalize: in WAL mode an unfinalized
    // SELECT holds an open read transaction, blocking checkpoints and serialising
    // writers behind busy_timeout. Critical in cluster-mode (10 call sites).
    sqlite3_finalize(sql_statement);

    return {certificate};
}

/**
 * @brief Generates a SQL clause for filtering valid certificate statuses.
 *
 * This function takes a vector of CertStatus values and generates a SQL clause that can be used to filter
 * records with matching statuses. Each status value in the vector is converted into a parameterized condition in the
 * clause. The generated clause starts with "AND (" and ends with " )" and contains multiple "OR" conditions for each
 * status value.
 *
 * @param valid_status The vector of CertStatus values to be filtered.
 * @return A string representing the SQL clause for filtering valid certificate statuses. If the vector is empty, an
 * empty string is returned.
 */
std::string getValidStatusesClause(const std::vector<certstatus_t> &valid_status) {
    const auto n_valid_status = valid_status.size();
    if (n_valid_status > 0) {
        auto valid_status_clauses = SB();
        valid_status_clauses << " AND status IN (";
        for (size_t i = 0; i < n_valid_status; i++) {
            if (i != 0)
                valid_status_clauses << ", ";
            valid_status_clauses << ":status" << i;
        }
        valid_status_clauses << ")";
        return valid_status_clauses.str();
    }
    return "";
}

/**
 * @brief Generates a SQL clause for filtering valid certificate serials
 *
 * It will generate an IN clause for the supplied serials
 *
 * @param serials The vector of serial numbers to filter
 * @return The SQL clause for filtering valid certificate serials
 */
std::string getSelectedSerials(const std::vector<serial_number_t> &serials) {
    const auto n_serials = serials.size();
    if (n_serials > 0) {
        bool first = true;
        auto serials_clauses = SB();
        serials_clauses << " serial IN (";
        for (auto serial : serials) {
            int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
            if (!first)
                serials_clauses << ", ";
            else
                first = false;
            serials_clauses << db_serial;
        }
        serials_clauses << ")";
        return serials_clauses.str();
    }
    return "";
}

/**
 * Binds the valid certificate status clauses to the given SQLite statement.
 *
 * @param sql_statement The SQLite statement to bind the clauses to.
 * @param valid_status A vector containing the valid certificate status values.
 */
void bindValidStatusClauses(sqlite3_stmt *sql_statement, const std::vector<certstatus_t> &valid_status) {
    const auto n_valid_status = valid_status.size();
    sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":now"), std::time(nullptr));
    for (size_t i = 0; i < n_valid_status; i++) {
        sqlite3_bind_int(sql_statement,
                         sqlite3_bind_parameter_index(sql_statement, (SB() << ":status" << i).str().c_str()),
                         valid_status[i]);
    }
}

/**
 * @brief Updates the status of a certificate in the certificates database.
 *
 * This function updates the status of a certificate in the certificates database.
 * The status is specified by the CertStatus enum. The function compares
 * the specified certificate's status with the valid_status vector to ensure that
 * only certificates that are already in one of those states are allowed to move
 * to the new status. If the existing status is valid, it updates the status of the
 * certificate associated with the specified serial number to the new status.
 *
 * @param certs_db A reference to the certificates database, represented as a sql_ptr object.
 * @param serial The serial number of the certificate to update.
 * @param cert_status The new status to set for the certificate.
 * @param approval_status the status to apply after approval
 * @param valid_status A vector containing the valid status values that are allowed to transition a certificate from.
 *
 * @return None
 */
void updateCertificateStatus(const sql_ptr &certs_db,
                             serial_number_t serial,
                             const certstatus_t cert_status,
                             const int approval_status,
                             const std::vector<certstatus_t> &valid_status) {
    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    int sql_status;
    std::string sql(approval_status == -1 ? SQL_CERT_SET_STATUS : SQL_CERT_SET_STATUS_W_APPROVAL);
    sql += getValidStatusesClause(valid_status);
    const auto current_time = std::time(nullptr);
    if ((sql_status = sqlite3_prepare_v2(certs_db.get(), sql.c_str(), -1, &sql_statement, nullptr)) == SQLITE_OK) {
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status"), cert_status);
        if (approval_status >= 0)
            sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":approved"), approval_status);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status_date"), current_time);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        bindValidStatusClauses(sql_statement, valid_status);
        sql_status = sqlite3_step(sql_statement);
    }
    sqlite3_finalize(sql_statement);

    // Check the number of rows affected
    if (sql_status == SQLITE_DONE) {
        const int rows_affected = sqlite3_changes(certs_db.get());
        if (rows_affected == 0) {
            throw std::runtime_error("Invalid state transition or invalid serial number");
        }
    } else {
        throw std::runtime_error(SB() << "Failed to set cert status: " << sqlite3_errmsg(certs_db.get()));
    }
}

void insertAuditRecord(sqlite3 *db, const std::string &action,
                       const std::string &operator_id, uint64_t serial,
                       const std::string &detail) {
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_AUDIT, -1, &stmt, nullptr) != SQLITE_OK) {
        log_err_printf(pvacms, "Failed to prepare audit insert: %s\n", sqlite3_errmsg(db));
        return;
    }
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":timestamp"),
                       static_cast<sqlite3_int64>(time(nullptr)));
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":action"),
                      action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":operator"),
                      operator_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"),
                       static_cast<sqlite3_int64>(serial));
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":detail"),
                      detail.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        log_err_printf(pvacms, "Failed to insert audit record: %s\n", sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
}

void updateCertificateRenewalStatus(const sql_ptr &certs_db, serial_number_t serial, const certstatus_t cert_status, const time_t renew_by) {
    Guard G(getStatusUpdateLock());
    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    int sql_status;
    const auto flag_only = renew_by == 0;
    const std::string sql(flag_only ? SQL_FLAG_RENEW_CERTS : SQL_RENEW_CERTS );
    const auto current_time = std::time(nullptr);
    if ((sql_status = sqlite3_prepare_v2(certs_db.get(), sql.c_str(), -1, &sql_statement, nullptr)) == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status_date"), current_time);
        if (!flag_only) {
            sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status"), cert_status);
            sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":renew_by"), renew_by);
        }
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        sql_status = sqlite3_step(sql_statement);
    }
    sqlite3_finalize(sql_statement);

    // Check the number of rows affected
    if (sql_status == SQLITE_DONE) {
        const int rows_affected = sqlite3_changes(certs_db.get());
        if (rows_affected == 0) {
            throw std::runtime_error("Invalid serial number");
        }
    } else {
        throw std::runtime_error(SB() << "Failed to set cert status: " << sqlite3_errmsg(certs_db.get()));
    }
}


void touchCertificateStatus(const sql_ptr &certs_db, serial_number_t serial) {
    Guard G(getStatusUpdateLock());
    const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
    sqlite3_stmt *sql_statement;
    int sql_status;
    const std::string sql = SQL_TOUCH_CERT_STATUS;
    const auto current_time = std::time(nullptr);
    if ((sql_status = sqlite3_prepare_v2(certs_db.get(), sql.c_str(), -1, &sql_statement, nullptr)) == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status_date"), current_time);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        sql_status = sqlite3_step(sql_statement);
    }
    sqlite3_finalize(sql_statement);

    // Check the number of rows affected
    if (sql_status == SQLITE_DONE) {
        const int rows_affected = sqlite3_changes(certs_db.get());
        if (rows_affected == 0) {
            throw std::runtime_error("Invalid serial number");
        }
    } else {
        throw std::runtime_error(SB() << "Failed to set cert status: " << sqlite3_errmsg(certs_db.get()));
    }
}


/**
 * @brief Generates a random serial number.
 *
 * This function generates a random serial number using the Mersenne Twister
 * algorithm. The generated serial number is a 64-bit unsigned integer.
 *
 * @return The generated serial number.
 *
 * @note The random number generator is seeded with a random value from
 * hardware. It is important to note that the quality of the randomness may vary
 *       depending on the hardware and operating system.
 */
serial_number_t generateSerial() {
    std::random_device random_from_device;                        // Obtain a random number from hardware
    auto seed = std::mt19937_64(random_from_device());            // Seed the generator
    std::uniform_int_distribution<serial_number_t> distribution;  // Define the range

    const serial_number_t random_serial_number = distribution(seed);  // Generate a random number
    return random_serial_number;
}

/**
 * @brief Store the certificate in the database
 *
 * This function stores the certificate details in the database provided
 *
 * @param[in] certs_db The SQL database connection
 * @param[in] cert_factory The certificate factory used to build the certificate
 * @return effective certificate status stored
 *
 * @throws std::runtime_error If failed to create the certificate in the
 * database
 */
certstatus_t storeCertificate(const sql_ptr &certs_db, CertFactory &cert_factory) {
    const auto db_serial =
        *reinterpret_cast<int64_t *>(&cert_factory.serial_);  // db stores as signed int so convert to and from
    const auto current_time = std::time(nullptr);
    const auto effective_status = cert_factory.initial_status_ != VALID     ? cert_factory.initial_status_
                                  : current_time < cert_factory.not_before_ ? PENDING
                                  : current_time >= cert_factory.not_after_ ? EXPIRED
                                                                            : cert_factory.initial_status_;

    checkForDuplicates(certs_db, cert_factory);

    sqlite3_stmt *sql_statement;
    auto sql_status = sqlite3_prepare_v2(certs_db.get(), SQL_CREATE_CERT, -1, &sql_statement, nullptr);
    if (sql_status == SQLITE_OK) {
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":serial"), db_serial);
        sqlite3_bind_text(sql_statement,
                          sqlite3_bind_parameter_index(sql_statement, ":skid"),
                          cert_factory.skid_.c_str(),
                          -1,
                          SQLITE_STATIC);
        sqlite3_bind_text(sql_statement,
                          sqlite3_bind_parameter_index(sql_statement, ":CN"),
                          cert_factory.name_.c_str(),
                          -1,
                          SQLITE_STATIC);
        sqlite3_bind_text(sql_statement,
                          sqlite3_bind_parameter_index(sql_statement, ":O"),
                          cert_factory.org_.c_str(),
                          -1,
                          SQLITE_STATIC);
        sqlite3_bind_text(sql_statement,
                          sqlite3_bind_parameter_index(sql_statement, ":OU"),
                          cert_factory.org_unit_.c_str(),
                          -1,
                          SQLITE_STATIC);
        sqlite3_bind_text(sql_statement,
                          sqlite3_bind_parameter_index(sql_statement, ":C"),
                          cert_factory.country_.c_str(),
                          -1,
                          SQLITE_STATIC);
        if (!cert_factory.san_entries_.empty()) {
            auto san_json = sanToJson(cert_factory.san_entries_);
            sqlite3_bind_text(sql_statement,
                              sqlite3_bind_parameter_index(sql_statement, ":san"),
                              san_json.c_str(), -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":san"));
        }
        sqlite3_bind_int(sql_statement,
                         sqlite3_bind_parameter_index(sql_statement, ":not_before"),
                         static_cast<int>(cert_factory.not_before_));
        sqlite3_bind_int(sql_statement,
                         sqlite3_bind_parameter_index(sql_statement, ":not_after"),
                         static_cast<int>(cert_factory.not_after_));
        sqlite3_bind_int(sql_statement,
                         sqlite3_bind_parameter_index(sql_statement, ":renew_by"),
                         (cert_factory.renew_by_ > 0) ? static_cast<int>(cert_factory.renew_by_) : static_cast<int>(cert_factory.not_after_));
        sqlite3_bind_int(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status"), effective_status);
        sqlite3_bind_int(sql_statement,
                         sqlite3_bind_parameter_index(sql_statement, ":approved"),
                         cert_factory.initial_status_ == VALID ? 1 : 0);
        sqlite3_bind_int64(sql_statement, sqlite3_bind_parameter_index(sql_statement, ":status_date"), current_time);

        sql_status = sqlite3_step(sql_statement);
    }

    sqlite3_finalize(sql_statement);

    if (sql_status != SQLITE_OK && sql_status != SQLITE_DONE) {
        throw std::runtime_error(SB() << "Failed to create certificate: " << sqlite3_errmsg(certs_db.get()));
    }
    return effective_status;
}

/**
 * @brief Checks for duplicates between certificates in the given database and the certificate that will be generated by
 * the given certificate factory.
 *
 * This function takes a reference to a `sql_ptr` object representing a database
 * and a reference to a `CertFactory` object. It checks for duplicates in the
 * database by comparing the subject of the certificate that would be generated by the
 * certificate factory with the ones in the database and by comparing the subject key identifier
 * that would be produced by the certificate factory with any that are already present in the
 * database. If any duplicates are found, they are handled according
 * to the specified business logic.
 *
 * Certificates that are pending and pending approval are also included.  So a new certificate
 * that matches any certificates that are not yet valid (pending) or are awaiting
 * administrator approval (pending approval) will be rejected.
 *
 * @param certs_db A reference to a `sql_ptr` object representing the database to check for duplicates.
 * @param cert_factory A reference to a `CertFactory` object containing the certificate configuration to compare against
 * the database.
 *
 * @return void
 *
 * @remark This function assumes that the database and certificate factory objects are properly initialized and
 * accessible. It does not handle any exceptions or errors that might occur during the duplicate checking process. Users
 * of this function should ensure that any required error handling and exception handling is implemented accordingly.
 */
void checkForDuplicates(const sql_ptr &certs_db, const CertFactory &cert_factory) {
    if (cert_factory.allow_duplicates_)
        return;

    // Prepare SQL statements
    sqlite3_stmt *sql_statement;

    const std::vector<certstatus_t> valid_status{VALID, PENDING_APPROVAL, PENDING_RENEWAL, PENDING};

    // Check for a duplicate subject
    std::string subject_sql(SQL_DUPS_SUBJECT);
    subject_sql += getValidStatusesClause(valid_status);
    if (sqlite3_prepare_v2(certs_db.get(), subject_sql.c_str(), -1, &sql_statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement");
    }
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":CN"),
                      cert_factory.name_.c_str(),
                      -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":O"),
                      cert_factory.org_.c_str(),
                      -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":OU"),
                      cert_factory.org_unit_.c_str(),
                      -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":C"),
                      cert_factory.country_.c_str(),
                      -1,
                      SQLITE_STATIC);
    bindValidStatusClauses(sql_statement, valid_status);
    const auto subject_dup_status =
        sqlite3_step(sql_statement) == SQLITE_ROW && sqlite3_column_int(sql_statement, 0) > 0;
    sqlite3_finalize(sql_statement);
    if (subject_dup_status) {
        throw std::runtime_error(SB() << "Duplicate Certificate Subject: cn=" << cert_factory.name_
                                      << ", o=" << cert_factory.org_ << ", ou=" << cert_factory.org_unit_
                                      << ", c=" << cert_factory.country_);
    }
}

/**
 * @brief The function that does the actual certificate creation in PVACMS
 *
 * Don't forget to cleanup `chain_ptr` after use with sk_X509_free()
 *
 * @param certs_db the database to write the certificate to
 * @param cert_factory the certificate factory to use to build the certificate
 *
 * @return the PEM string that contains the Cert, its chain, and the root cert
 */
ossl_ptr<X509> createCertificate(sql_ptr &certs_db, CertFactory &cert_factory) {
    // Check validity falls within an acceptable range
    if (cert_factory.issuer_certificate_ptr_)
        ensureValidityCompatible(cert_factory);

    auto certificate = cert_factory.create();

    // Store certificate in the database
    auto effective_status = storeCertificate(certs_db, cert_factory);

    // Print info about certificate creation
    std::string from = std::ctime(&cert_factory.not_before_);
    std::string to = std::ctime(&cert_factory.not_after_);
    std::string renew_by_s;

    auto const issuer_id = CertStatus::getSkId(cert_factory.issuer_certificate_ptr_);
    auto cert_id = getCertId(issuer_id, cert_factory.serial_);

    log_debug_printf(pvacms, "--------------------------------------%s", "\n");
    auto cert_description = (SB() << "X.509 "
                                  << (IS_USED_FOR_(cert_factory.usage_, cms::ssl::kForIntermediateCertAuth)
                                          ? "INTERMEDIATE CERTIFICATE AUTHORITY"
                                      : IS_USED_FOR_(cert_factory.usage_, cms::ssl::kForClientAndServer) ? "IOC"
                                      : IS_USED_FOR_(cert_factory.usage_, cms::ssl::kForClient)          ? "CLIENT"
                                      : IS_USED_FOR_(cert_factory.usage_, cms::ssl::kForServer)          ? "SERVER"
                                      : IS_USED_FOR_(cert_factory.usage_, cms::ssl::kForCMS)             ? "PVACMS"
                                                                                                    : "CERTIFICATE"))
                                .str();
    log_debug_printf(pvacms, "%s\n", cert_description.c_str());
    log_debug_printf(pvacms, "   CERT ID: %s\n", cert_id.c_str());
    log_debug_printf(pvacms, " ISSUER ID: %s\n", issuer_id.c_str());
    log_debug_printf(pvacms, "SERIAL NUM: %s\n", (SB() << std::setw(20) << std::setfill('0') << cert_factory.serial_).str().c_str());
    log_debug_printf(pvacms, "SUBJECT CN: %s\n", cert_factory.name_.c_str());
    if (!cert_factory.org_.empty()) log_debug_printf(pvacms, "SUBJECT  O: %s\n", cert_factory.org_.c_str());
    if (!cert_factory.org_unit_.empty()) log_debug_printf(pvacms, "SUBJECT OU: %s\n", cert_factory.org_unit_.c_str());
    if (!cert_factory.country_.empty()) log_debug_printf(pvacms, "SUBJECT  C: %s\n", cert_factory.country_.c_str());
    log_debug_printf(pvacms, "    STATUS: %s\n", CERT_STATE(effective_status));
    log_debug_printf(pvacms, "VALID FROM: %s\n", from.substr(0, from.size() - 1).c_str());
    if (!renew_by_s.empty()) log_debug_printf(pvacms, "RENEWAL BY: %s\n", renew_by_s.substr(0, renew_by_s.size() - 1).c_str());
    log_debug_printf(pvacms, "EXPIRES ON: %s\n", to.substr(0, to.size() - 1).c_str());
    log_debug_printf(pvacms, "--------------------------------------%s", "\n");

    return certificate;
}

/**
 * @brief Creates a PEM string representation of a certificate.
 *
 * This function creates a PEM string representation of a certificate by creating the certificate using the provided
 * certificate database and certificate factory, and then converting the certificate and certificate authority
 * certificate chain to PEM format.
 *
 * @param certs_db The certificate database.
 * @param cert_factory The certificate factory.
 * @return A PEM string representation of the certificate.
 */
std::string createCertificatePemString(sql_ptr &certs_db, CertFactory &cert_factory) {
    // Create the actual certificate
    const auto cert = createCertificate(certs_db, cert_factory);

    // Write out as PEM string for return to client
    return CertFactory::certAndCasToPemString(cert, cert_factory.certificate_chain_.get());
}

/**
 * This function is used to retrieve the value of a specified field from a given structure.
 *
 * @param src The structure from which to retrieve the field value.
 * @param field The name of the field whose value should be retrieved.
 * @return The value of the specified field in the given structure.
 *
 * @note This function assumes that the specified field exists in the structure and can be accessed using the dot
 * notation.
 * @warning If the specified field does not exist or cannot be accessed, the function will throw a field not found
 * exception.
 * @attention This function does not modify the given structure or its fields.
 * @see setStructureValue()
 */
template <typename T>
T getStructureValue(const Value &src, const std::string &field) {
    const auto value = src[field];
    if (!value) {
        throw std::runtime_error(SB() << field << " field not provided");
    }
    return value.as<T>();
}

/**
 * @brief Get the prior approval status of a certificate
 *
 * Determines if the certificate has been previously approved by checking the database for one that
 * matches the name, country, organization, and organization unit
 *
 * @param certs_db The database to get the certificate status from
 * @param name The name of the certificate
 * @param country The country of the certificate
 * @param organization The organization of the certificate
 * @param organization_unit The organizational unit of the certificate
 * @return True if the certificate has been previously approved, false otherwise
 */
bool getPriorApprovalStatus(const sql_ptr &certs_db,
                            const std::string &name,
                            const std::string &country,
                            const std::string &organization,
                            const std::string &organization_unit) {
    // Check for duplicate subject
    sqlite3_stmt *sql_statement;
    bool previously_approved{false};

    const std::string approved_sql(SQL_PRIOR_APPROVAL_STATUS);
    if (sqlite3_prepare_v2(certs_db.get(), approved_sql.c_str(), -1, &sql_statement, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare statement");
    }
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":CN"),
                      name.c_str(),
                      -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":O"),
                      organization.c_str(),
                      -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":OU"),
                      organization_unit.c_str(),
                      -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(sql_statement,
                      sqlite3_bind_parameter_index(sql_statement, ":C"),
                      country.c_str(),
                      -1,
                      SQLITE_STATIC);

    if (sqlite3_step(sql_statement) == SQLITE_ROW) {
        previously_approved = sqlite3_column_int(sql_statement, 0) == 1;
    }

    return previously_approved;
}

/**
 * @brief CERT:CREATE Handles the creation of a certificate.
 *
 * This function handles the creation of a certificate based on the provided
 * certificate creation parameters. It creates a reply containing the certificate data, and sends it
 * back to the client.
 *
 * @param config the config to use to create the certificate creation factory
 * @param certs_db the DB to write the certificate registration information
 * @param shared_status_pv
 * @param op The unique pointer to the execution operation.
 * @param args the RPC arguments
 * @param cert_auth_pkey the public/private key of the certificate authority certificate
 * @param cert_auth_cert the certificate authority certificate
 * @param cert_auth_cert_chain the certificate authority certificate chain
 * @param issuer_id the issuer ID to be encoded in the certificate
 */
int64_t onCreateCertificate(ConfigCms &config,
                         sql_ptr &certs_db,
                         server::WildcardPV &shared_status_pv,
                         std::unique_ptr<server::ExecOp> &&op,
                         Value &&args,
                         const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                          const ossl_ptr<X509> &cert_auth_cert,
                          const ossl_shared_ptr<stack_st_X509> &cert_auth_cert_chain,
                          std::string issuer_id) {
    auto ccr_start = std::chrono::steady_clock::now();
    auto ccr = args["query"];

    auto pub_key = ccr["pub_key"].as<std::string>();

    if (pub_key.empty()) {
        // We only want to get the trust-anchor if the pub key is empty
        // Create the certificate using the certificate factory, store it in the database and return the PEM string
        auto pem_string = CertFactory::certAndCasToPemString(cert_auth_cert, nullptr);

        // Construct and return the reply
        auto serial = CertStatusFactory::getSerialNumber(cert_auth_cert);
        auto cert_id = getCertId(issuer_id, serial);
        auto status_pv = getCertStatusURI(config.getCertPvPrefix(), cert_id);
        auto reply(getCreatePrototype());
        auto now(time(nullptr));
        setValue<uint32_t>(reply, "value.index", VALID);
        setValue<uint64_t>(reply, "timeStamp.secondsPastEpoch", now - POSIX_TIME_AT_EPICS_EPOCH);
        setValue<std::string>(reply, "state", CERT_STATE(VALID));
        setValue<uint64_t>(reply, "serial", serial);
        setValue<std::string>(reply, "issuer", issuer_id);
        setValue<std::string>(reply, "cert_id", cert_id);
        setValue<std::string>(reply, "status_pv", status_pv);
        setValue<uint64_t>(reply, "renew_by", 0);
        setValue<uint64_t>(reply, "expiration", 0);
        setValue<std::string>(reply, "cert", pem_string);
        op->reply(reply);
        return 0;
    }

    auto &inflight_ccr = getCreateCertificateInflightCount();
    const auto max_concurrent_ccr = config.max_concurrent_ccr;
    uint32_t current_inflight = inflight_ccr.load();
    while (true) {
        if (current_inflight >= max_concurrent_ccr) {
            log_warn_printf(pvacms,
                            "Overload: rejected CCR, %u/%u in-flight, rate=%u/s burst=%u\n",
                            current_inflight,
                            max_concurrent_ccr,
                            config.rate_limit,
                            config.rate_limit_burst);
            op->error("Too many concurrent requests. retry_after_secs: 1");
            return 0;
        }
        if (inflight_ccr.compare_exchange_weak(current_inflight, current_inflight + 1u)) {
            break;
        }
    }
    InflightCcrGuard inflight_guard(inflight_ccr);

    auto &rate_limiter = getCreateCertificateRateLimiter();
    if (!rate_limiter.tryConsume()) {
        const double retry_after_secs = rate_limiter.secsUntilReady();
        log_warn_printf(pvacms,
                        "Rate limit: rejected CCR, in-flight=%u/%u, rate=%u/s burst=%u, retry_after=%.1f\n",
                        inflight_ccr.load(),
                        max_concurrent_ccr,
                        config.rate_limit,
                        config.rate_limit_burst,
                        retry_after_secs);
        op->error(SB() << "Rate limit exceeded. retry_after_secs: " << retry_after_secs);
        return 0;
    }

    // OK, it looks like we need to generate a certificate then ...

    // First, make sure that we've updated any expired cert first
    auto const full_skid = CertStatus::getFullSkId(pub_key);
    auto cert_status_factory(
        CertStatusFactory(cert_auth_cert, cert_auth_pkey, cert_auth_cert_chain, config.cert_status_validity_mins));
    postUpdateToNextCertToExpire(cert_status_factory,
                                 shared_status_pv,
                                 certs_db,
                                 config.getCertPvPrefix(),
                                 issuer_id,
                                 full_skid);

    // Get some initial fields from the request as we start the creation process
    const auto now = time(nullptr);
    auto type = getStructureValue<const std::string>(ccr, "type");
    auto name = getStructureValue<const std::string>(ccr, "name");
    auto organization = getStructureValue<const std::string>(ccr, "organization");
    auto usage = getStructureValue<uint16_t>(ccr, "usage");

    try {
        time_t expiration, renew_by;
        auto no_status = ccr["no_status"].as<bool>();
        std::vector<ScheduleWindow> schedule_windows;
        auto schedule_arr = ccr["schedule"];
        if (schedule_arr) {
            auto sched = schedule_arr.as<shared_array<const Value>>();
            for (const auto &win : sched) {
                ScheduleWindow sw;
                sw.day_of_week = win["day_of_week"].as<std::string>();
                sw.start_time = win["start_time"].as<std::string>();
                sw.end_time = win["end_time"].as<std::string>();
                if (sw.day_of_week != "*" &&
                    (sw.day_of_week.size() != 1 || sw.day_of_week[0] < '0' || sw.day_of_week[0] > '6'))
                    throw std::runtime_error("Invalid day_of_week in schedule: must be 0-6 or *");
                if (!isValidScheduleTime(sw.start_time) || !isValidScheduleTime(sw.end_time))
                    throw std::runtime_error("Invalid time format in schedule: must be HH:MM");
                schedule_windows.push_back(std::move(sw));
            }
        }
            std::vector<SanEntry> san_entries;
        auto san_arr = ccr["san"];
        if (san_arr) {
            auto san = san_arr.as<shared_array<const Value>>();
            for (const auto &entry : san) {
                    SanEntry se;
                se.type = entry["type"].as<std::string>();
                se.value = entry["value"].as<std::string>();
                san_entries.push_back(std::move(se));
            }
        }
        if (!san_entries.empty()) {
            validateSanEntries(san_entries);
        }
        switch (config.cert_status_subscription) {
            case YES:
                if (no_status)
                    log_warn_printf(pvacms, "Ignoring Client no-status flag as PVACMS is configured for status monitoring%s\n", "");
                no_status = false;
                break;
            case NO:
                no_status = true;
                break;
            case DEFAULT:
                ;
        }
        if (no_status && !schedule_windows.empty()) {
            throw std::runtime_error("Scheduled certificates require status monitoring (no_status must be false)");
        }
        expiration = renew_by = getStructureValue<time_t>(ccr, "not_after");
        certstatus_t state = UNKNOWN;

        // Call the authenticator-specific verifier if not the default type
        if (type != PVXS_DEFAULT_AUTH_TYPE) {
            const auto authenticator = Auth::getAuth(type);
            // Calling authenticator may set the renew-by date to the maximum authenticated date
            if (!authenticator->verify(ccr, renew_by))
                throw std::runtime_error("CCR claims are invalid");
            state = VALID;
        } else {
            state = PENDING_APPROVAL;
            if ((IS_USED_FOR_(usage, cms::ssl::kForClientAndServer) && !config.cert_ioc_require_approval) ||
                (IS_USED_FOR_(usage, cms::ssl::kForClient) && !config.cert_client_require_approval) ||
                (IS_USED_FOR_(usage, cms::ssl::kForServer) && !config.cert_server_require_approval)) {
                state = VALID;
            }
        }

        if (expiration > 0)
            renew_by = std::min(renew_by, expiration);

        // Set the Expiration date
        // Use a default expiration date if none specified by the client, or we have disabled custom durations
        if ((config.cert_disallow_ioc_custom_duration || expiration <= 0) &&
            IS_USED_FOR_(usage, cms::ssl::kForClientAndServer)) {
            expiration = now + CertDate::parseDuration(config.default_ioc_cert_validity);
            if (expiration > 0)
                log_info_printf(pvacms, "Overriding requested expiration with default: %s\n", config.default_ioc_cert_validity.c_str());
        }
        else if ((config.cert_disallow_server_custom_duration || expiration <= 0) &&
                 IS_USED_FOR_(usage, cms::ssl::kForServer)) {
            expiration = now + CertDate::parseDuration(config.default_server_cert_validity);
            if (expiration > 0)
                log_info_printf(pvacms, "Overriding requested expiration with default: %s\n", config.default_server_cert_validity.c_str());
        }
        else if ((config.cert_disallow_client_custom_duration || expiration <= 0) &&
                 IS_USED_FOR_(usage, cms::ssl::kForClient)) {
            expiration = now + CertDate::parseDuration(config.default_client_cert_validity);
            if (expiration > 0)
                log_info_printf(pvacms, "Overriding requested expiration with default: %s\n", config.default_client_cert_validity.c_str());
        }

        auto has_renew_by = renew_by > 0 && renew_by != expiration;

        // If there's no status, then we can't support renew_by dates
        if (no_status) {
            if (has_renew_by) log_warn_printf(pvacms, "Renew-By date ignored because status monitoring is disabled%s\n", "");
            renew_by = 0;
        }
        if (renew_by == expiration) renew_by = 0;

        ///////////////////
        // Make Certificate
        ///////////////////

        // Get Public Key to use
        const auto key_pair = std::make_shared<KeyPair>(pub_key);

        // Generate a new serial number
        auto serial = generateSerial();

        // Get other certificate parameters from the request
        auto country = getStructureValue<const std::string>(ccr, "country");
        auto organization_unit = getStructureValue<const std::string>(ccr, "organization_unit");

        // If pending approval, then check if it has already been approved
        if (state == PENDING_APPROVAL) {
            if (getPriorApprovalStatus(certs_db, name, country, organization, organization_unit)) {
                state = VALID;
            }
        }

        // If config uri base provided then use it
        auto config_uri_base = ccr["config_uri_base"].as<std::string>();

        // Create a certificate factory
        const auto not_before = getStructureValue<time_t>(ccr, "not_before");
        auto certificate_factory = CertFactory(serial, key_pair, name, country, organization, organization_unit,
                                               not_before, expiration, renew_by, usage,
                                               config.getCertPvPrefix(), config_uri_base,
                                               config.cert_status_subscription, no_status,
                                               type != PVXS_DEFAULT_AUTH_TYPE,
                                               cert_auth_cert.get(),
                                               cert_auth_pkey.get(),
                                               cert_auth_cert_chain.get(),
                                               state);
        certificate_factory.san_entries_ = san_entries;

        auto reply(getCreatePrototype());
        std::string pem_string;

        ///////////////////////////////////////////////
        // Check if this certificate is renewing a prior one
        // We check by looking for certificates that have the same subject as this one
        // are not expired or revoked, and that have a valid renew_by date

        // Get the original Certificate to be renewed if one exists
        const auto original_certificate = getOriginalCert(certificate_factory, certs_db, issuer_id);
        // If we got an original certificate ok, then renew it
        if (original_certificate.status != UNKNOWN) {
            // The new renewal date is the renewal date from this ccr unless it's less than the expiration date of the original cert
            const auto new_renewal_date = std::min(original_certificate.not_after, renew_by);

            const auto status_date = std::time(nullptr); // Status date
            const std::string pv_name(getCertStatusURI(config.getCertPvPrefix(), issuer_id, original_certificate.serial));

            // If the original certificate has already expired (PENDING_RENEWAL) ...
            if ( original_certificate.status == PENDING_RENEWAL) {
                // Update the status to VALID and post an update to listeners

                // Create a cert status to post
                const auto cert_status = cert_status_factory.createPVACertificateStatus(original_certificate.serial, VALID, status_date, {}, new_renewal_date, 0);
                const auto new_status = static_cast<certstatus_t>(cert_status.status.i);

                updateCertificateRenewalStatus(certs_db, original_certificate.serial, new_status, new_renewal_date);
                postCertificateStatus(shared_status_pv, pv_name, original_certificate.serial, cert_status, &certs_db);
                log_info_printf(pvacmsmonitor, "%s ==> %s\n", getCertId(issuer_id, original_certificate.serial).c_str(), cert_status.status.s.c_str());
            } else { // VALID, PENDING_APPROVAL, PENDING
                // Update the renew_by date if it's less than the new one but don't change status and post an update to listeners
                if (original_certificate.renew_by < new_renewal_date) {
                    const auto cert_status = cert_status_factory.createPVACertificateStatus(original_certificate.serial, original_certificate.status, status_date, {}, new_renewal_date, 0);

                    updateCertificateRenewalStatus(certs_db, original_certificate.serial, original_certificate.status, new_renewal_date);
                    postCertificateStatus(shared_status_pv, pv_name, original_certificate.serial, cert_status, &certs_db);
                    log_info_printf(pvacmsmonitor, "%s <=> %s\n", getCertId(issuer_id, original_certificate.serial).c_str(), CERT_STATE(original_certificate.status));
                }
            }
            serial = original_certificate.serial;
            state = original_certificate.status;
            expiration = original_certificate.not_after;
            renew_by = new_renewal_date;
            has_renew_by = renew_by > 0 && renew_by != expiration;
        } else {
            // Otherwise just create a certificate as normal
            pem_string = createCertificatePemString(certs_db, certificate_factory);
        }
        sqlite3_stmt *delete_sched_stmt = nullptr;
        if (sqlite3_prepare_v2(certs_db.get(), SQL_DELETE_SCHEDULES_BY_SERIAL, -1, &delete_sched_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(delete_sched_stmt, sqlite3_bind_parameter_index(delete_sched_stmt, ":serial"), serial);
            sqlite3_step(delete_sched_stmt);
            sqlite3_finalize(delete_sched_stmt);
        }
        for (const auto &sw : schedule_windows) {
            sqlite3_stmt *sched_stmt = nullptr;
            if (sqlite3_prepare_v2(certs_db.get(), SQL_INSERT_SCHEDULE, -1, &sched_stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int64(sched_stmt, sqlite3_bind_parameter_index(sched_stmt, ":serial"), serial);
                sqlite3_bind_text(sched_stmt, sqlite3_bind_parameter_index(sched_stmt, ":day_of_week"), sw.day_of_week.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(sched_stmt, sqlite3_bind_parameter_index(sched_stmt, ":start_time"), sw.start_time.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(sched_stmt, sqlite3_bind_parameter_index(sched_stmt, ":end_time"), sw.end_time.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(sched_stmt);
                sqlite3_finalize(sched_stmt);
            }
        }
        auto cert_id = getCertId(issuer_id, serial);
        auto status_pv = getCertStatusURI(config.getCertPvPrefix(), issuer_id, serial);
        // Create the certificate using the certificate factory, store it in the database and return the PEM string

        ///////////////////////////////////////////////
        // Construct and return the reply
        reply["value.index"] = state;
        reply["timeStamp.secondsPastEpoch"] = now - POSIX_TIME_AT_EPICS_EPOCH;
        reply["state"] = CERT_STATE(state);
        reply["serial"] = serial;
        reply["issuer"] = issuer_id;
        reply["cert_id"] = cert_id;
        reply["status_pv"] = status_pv;
        reply["expiration"] = expiration;
        if (has_renew_by) reply["renew_by"] = renew_by - POSIX_TIME_AT_EPICS_EPOCH;
        if (!pem_string.empty()) reply["cert"] = pem_string;
        assignSchedule(reply, schedule_windows);
        assignSan(reply, san_entries);
        // Log the certificate info
        const auto org_val = ccr["organization"];
        const auto org_unit_val = ccr["organizational_unit"];
        const auto org = org_val ? org_val.as<std::string>() : "";
        const auto org_unit = org_unit_val ? org_unit_val.as<std::string>() : "";
        const std::string from = std::ctime(&now);
        const std::string expiration_s = std::ctime(&expiration);

        log_info_printf(pvacms, "%s *=> %s\n", cert_id.c_str(), CERT_STATE(state));
        log_info_printf(pvacms, "AUTHN TYPE: %s\n", type.c_str());
        log_info_printf(pvacms, "SUBJECT CN: %s\n", name.c_str());
        if (org_val) log_info_printf(pvacms, "SUBJECT  O: %s\n", org.c_str());
        if (org_unit_val) log_info_printf(pvacms, "SUBJECT OU: %s\n", org_unit.c_str());
        if (!country.empty()) log_info_printf(pvacms, "SUBJECT  C: %s\n", country.c_str());
        if (!san_entries.empty()) {
            std::string san_str;
            for (const auto &se : san_entries) {
                if (!san_str.empty()) san_str += ", ";
                san_str += se.type + "=" + se.value;
            }
            log_debug_printf(pvacms, "SUBJECT SAN: %s\n", san_str.c_str());
            log_info_printf(pvacms, "SUBJECT SAN: %s\n", san_str.c_str());
        }
        log_info_printf(pvacms, "VALID FROM: %s\n", from.substr(0, from.size()-1).c_str());
        if (has_renew_by) {
            const std::string renew_by_s = std::ctime(&renew_by);
            log_info_printf(pvacms, "RENEWAL BY: %s\n", renew_by_s.substr(0, renew_by_s.size()-1).c_str());
        }
        log_info_printf(pvacms, "EXPIRES ON: %s\n", expiration_s.substr(0, expiration_s.size()-1).c_str());
        op->reply(reply);
        insertAuditRecord(certs_db.get(), AUDIT_ACTION_CREATE,
                          SB() << type << ":" << name,
                          serial, SB() << "state=" << CERT_STATE(state));
        getCertsCreatedCounter().fetch_add(1u);
        auto ccr_end = std::chrono::steady_clock::now();
        double ccr_ms = std::chrono::duration<double, std::milli>(ccr_end - ccr_start).count();
        getCcrTimingTracker().record(ccr_ms);
        return static_cast<int64_t>(serial);
    } catch (std::exception &e) {
        // For any type of error return an error to the caller
        auto cert_name = NAME_STRING(name, organization);
        log_err_printf(pvacms, "Failed to create certificate for %s: %s\n", cert_name.c_str(), e.what());
        op->error(SB() << "Failed to create certificate for " << cert_name << ": " << e.what());
        return 0;
    }
}

/**
 * @brief Evaluate whether the given UTC time falls within any of the schedule windows.
 * @param now_utc Current UTC time
 * @param windows Vector of schedule windows to evaluate
 * @return true if now_utc is within at least one window
 */
static bool isWithinSchedule(time_t now_utc, const std::vector<ScheduleWindow> &windows) {
    if (windows.empty()) return true;

    struct tm tm_buf;
    gmtime_r(&now_utc, &tm_buf);
    int current_day = tm_buf.tm_wday;
    int current_mins = tm_buf.tm_hour * 60 + tm_buf.tm_min;

    for (const auto &w : windows) {
        if (w.day_of_week != "*") {
            int day = w.day_of_week[0] - '0';
            if (day != current_day) continue;
        }
        int start_h = std::stoi(w.start_time.substr(0, 2));
        int start_m = std::stoi(w.start_time.substr(3, 2));
        int end_h = std::stoi(w.end_time.substr(0, 2));
        int end_m = std::stoi(w.end_time.substr(3, 2));
        int start_mins = start_h * 60 + start_m;
        int end_mins = end_h * 60 + end_m;

        if (end_mins > start_mins) {
            if (current_mins >= start_mins && current_mins < end_mins) return true;
        } else {
            if (current_mins >= start_mins || current_mins < end_mins) return true;
        }
    }
    return false;
}

/**
 * Retrieves the status of the certificate identified by the pv_name.
 * This will verify the certificate chain back to the root certificate for all certificates that are managed by this
 * PVACMS so the status returned will certify that the entity cert (and its whole chain) is valid
 *
 * @param config
 * @param certs_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The WildcardPV object to store the retrieved status.
 * @param pv_name The status pv requested.
 * @param serial serial number string broken out from the pv_name
 * @param issuer_id issuer id string broken out from the pv_name
 * @param cert_auth_pkey The certificate authority's private key.
 * @param cert_auth_cert The certificate authority certificate.
 * @param cert_auth_chain The certificate authority's certificate chain.
 * @param our_node_id the PVACMS node ID
 *
 * @return void
 */
void onGetStatus(const ConfigCms &config,
                 const sql_ptr &certs_db,
                 const std::string &our_issuer_id,
                 server::WildcardPV &status_pv,
                 const std::string &pv_name,
                 const serial_number_t serial,
                 const std::string &issuer_id,
                 const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                 const ossl_ptr<X509> &cert_auth_cert,
                 const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
                 const std::string &our_node_id) {
    const auto cert_status_creator(
        CertStatusFactory(cert_auth_cert, cert_auth_pkey, cert_auth_chain, config.cert_status_validity_mins));
    try {
        std::vector<serial_number_t> cert_auth_serial_numbers;
        log_debug_printf(pvacms, "GET STATUS: Certificate %s\n", getCertId(our_issuer_id, serial).c_str());

        if (our_issuer_id != issuer_id) {
            throw std::runtime_error(SB() << "Issuer ID of certificate status requested: " << issuer_id
                                          << ", is not our issuer ID: " << our_issuer_id);
        }

        // get status value
        certstatus_t status;
        time_t status_date;
        std::tie(status, status_date) = getCertificateStatus(certs_db, serial);
        if (status == UNKNOWN) {
            throw std::runtime_error("Unable to determine certificate status");
        }

        // Get all other serial numbers to check (certificate authority and certificate authority chain)
        cert_auth_serial_numbers.push_back(CertStatusFactory::getSerialNumber(cert_auth_cert));
        const auto N = sk_X509_num(cert_auth_chain.get());
        for (int i = 0; i < N; ++i) {
            cert_auth_serial_numbers.push_back(
                CertStatusFactory::getSerialNumber(sk_X509_value(cert_auth_chain.get(), i)));
        }

        for (const auto cert_auth_serial_number : cert_auth_serial_numbers) {
            getWorstCertificateStatus(certs_db, cert_auth_serial_number, status, status_date);
        }

        const auto now = std::time(nullptr);
        const auto db_cert = getCertificateValidity(certs_db, serial);
        const auto cert_status = cert_status_creator.createPVACertificateStatus(
            serial, status, now, status_date, CertDate(db_cert.renew_by), false);
        const auto pvacms_node_id = our_node_id.empty() ? std::string{} : (our_issuer_id + ":" + our_node_id);
        postCertificateStatus(status_pv, pv_name, serial, cert_status, &certs_db, pvacms_node_id);
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS: %s\n", e.what());
        const auto pvacms_node_id = our_node_id.empty() ? std::string{} : (our_issuer_id + ":" + our_node_id);
        postCertificateStatus(status_pv, pv_name, serial, {}, nullptr, pvacms_node_id);
    }
}

/**
 * Revokes the certificate identified by the pv_name
 *
 * @param config
 * @param certs_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The WildcardPV object to update the status in.
 * @param op
 * @param pv_name The status PV to be updated to REVOKED.
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param cert_auth_pkey The Certificate Authority's private key.
 * @param cert_auth_cert The Certificate Authority's certificate.
 * @param cert_auth_chain The Certificate Authority's certificate chain.
 *
 * @return void
 */
void onRevoke(const ConfigCms &config,
              const sql_ptr &certs_db,
              const std::string &our_issuer_id,
              server::WildcardPV &status_pv,
              std::unique_ptr<server::ExecOp> &&op,
              const std::string &pv_name,
              const std::list<std::string> &parameters,
              const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
              const ossl_ptr<X509> &cert_auth_cert,
              const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
              const std::string &operator_id) {
    const auto cert_status_creator(
        CertStatusFactory(cert_auth_cert, cert_auth_pkey, cert_auth_chain, config.cert_status_validity_mins));
    try {
        Guard G(getStatusUpdateLock());
        serial_number_t serial = getParameters(parameters);
        log_debug_printf(pvacms, "REVOKE: Certificate %s\n", getCertId(our_issuer_id, serial).c_str());

        // set status value
        updateCertificateStatus(certs_db, serial, REVOKED, 0);
        insertAuditRecord(certs_db.get(), AUDIT_ACTION_REVOKE, operator_id,
                          serial, "");
        getCertsRevokedCounter().fetch_add(1u);

        const auto revocation_date = std::time(nullptr);
        const auto ocsp_status = cert_status_creator.createPVACertificateStatus(
            serial, REVOKED, revocation_date, revocation_date, CertDate{}, false);
        postCertificateStatus(status_pv, pv_name, serial, ocsp_status, &certs_db);
        log_info_printf(pvacms, "%s ==> REVOKED\n", getCertId(our_issuer_id, serial).c_str());
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error revoking certificate: %s\n", e.what());
        op->error(SB() << "Error revoking certificate: " << e.what());
    }
}

/**
 * Approves the certificate identified by the pv_name
 *
 * @param config
 * @param certs_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The WildcardPV object to update the status in.
 * @param op
 * @param pv_name The status PV to be updated to APPROVED.
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param cert_auth_pkey The Certificate Authority's private key.
 * @param cert_auth_cert The Certificate Authority's certificate.
 * @param cert_auth_chain The Certificate Authority's certificate chain.
 *
 * @return void
 */
void onApprove(const ConfigCms &config,
               const sql_ptr &certs_db,
               const std::string &our_issuer_id,
               server::WildcardPV &status_pv,
               std::unique_ptr<server::ExecOp> &&op,
               const std::string &pv_name,
               const std::list<std::string> &parameters,
               const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
               const ossl_ptr<X509> &cert_auth_cert,
               const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
               const std::string &operator_id) {
    const auto cert_status_creator(
        CertStatusFactory(cert_auth_cert, cert_auth_pkey, cert_auth_chain, config.cert_status_validity_mins));
    try {
        Guard G(getStatusUpdateLock());
        std::string issuer_id;
        serial_number_t serial = getParameters(parameters);
        log_debug_printf(pvacms, "APPROVE: Certificate %s\n", getCertId(our_issuer_id, serial).c_str());

        // set status value
        const auto status_date(time(nullptr));
        const DbCert db_cert(getCertificateValidity(certs_db, serial));
        const certstatus_t new_state = status_date < db_cert.not_before ? PENDING : status_date >= db_cert.not_after ? EXPIRED : status_date >= db_cert.renew_by ? PENDING_RENEWAL : VALID;
        updateCertificateStatus(certs_db, serial, new_state, 1, {PENDING_APPROVAL});
        insertAuditRecord(certs_db.get(), AUDIT_ACTION_APPROVE, operator_id,
                          serial, SB() << "new_state=" << CERT_STATE(new_state));

        const auto cert_status = cert_status_creator.createPVACertificateStatus(
            serial, new_state, status_date, CertDate(std::time(nullptr)),
            CertDate(db_cert.renew_by), false);
        postCertificateStatus(status_pv, pv_name, serial, cert_status, &certs_db);
        switch (new_state) {
            case VALID:
            case EXPIRED:
            case PENDING:
            case PENDING_RENEWAL:
                log_info_printf(pvacms, "%s ==> %s\n", getCertId(our_issuer_id, serial).c_str(), CERT_STATE(new_state));
                break;
            default:
                break;
        }
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error approving certificate: %s\n", e.what());
        op->error(SB() << "Error approving certificate: " << e.what());
    }
}

/**
 * Denies the pending the certificate identified by the pv_name
 *
 * @param config
 * @param certs_db A pointer to the SQL database object.
 * @param our_issuer_id The issuer ID of the server.  Must match the one provided in pv_name
 * @param status_pv The WildcardPV object to update the status in.
 * @param op
 * @param pv_name The status PV to be updated to DENIED.
 * @param parameters The issuer id and serial number strings broken out from the pv_name.
 * @param cert_auth_pkey The Certificate Authority's private key.
 * @param cert_auth_cert The Certificate Authority's certificate.
 * @param cert_auth_chain The Certificate Authority's certificate chain.
 *
 * @return void
 */
void onDeny(const ConfigCms &config,
            const sql_ptr &certs_db,
            const std::string &our_issuer_id,
            server::WildcardPV &status_pv,
            std::unique_ptr<server::ExecOp> &&op,
            const std::string &pv_name,
            const std::list<std::string> &parameters,
            const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
            const ossl_ptr<X509> &cert_auth_cert,
            const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
            const std::string &operator_id) {
    const auto cert_status_creator(
        CertStatusFactory(cert_auth_cert, cert_auth_pkey, cert_auth_chain, config.cert_status_validity_mins));
    try {
        Guard G(getStatusUpdateLock());
        std::string issuer_id;
        serial_number_t serial = getParameters(parameters);
        log_debug_printf(pvacms, "DENY: Certificate %s\n", getCertId(our_issuer_id, serial).c_str());

        // set status value
        updateCertificateStatus(certs_db, serial, REVOKED, 0, {PENDING_APPROVAL});
        insertAuditRecord(certs_db.get(), AUDIT_ACTION_DENY, operator_id,
                          serial, "");

        const auto revocation_date = std::time(nullptr);
        const auto cert_status = cert_status_creator.createPVACertificateStatus(
            serial, REVOKED, revocation_date, revocation_date, CertDate{}, false);
        postCertificateStatus(status_pv, pv_name, serial, cert_status, &certs_db);
        log_info_printf(pvacms, "%s ==> REVOKED (Approval Request Denied)\n", getCertId(our_issuer_id, serial).c_str());
        op->reply();
    } catch (std::exception &e) {
        log_err_printf(pvacms, "PVACMS Error denying certificate request: %s\n", e.what());
        op->error(SB() << "Error denying certificate request: " << e.what());
    }
}

/**
 * @brief Get the serial number from the parameters
 *
 * @param parameters The list of parameters from the WildcardPV
 * @return serial number
 */
uint64_t getParameters(const std::list<std::string> &parameters) {
    // get serial from URI parameters
    auto it = parameters.begin();
    const std::string &serial_string = *it;
    uint64_t serial;
    try {
        serial = std::stoull(serial_string);
    } catch (std::invalid_argument &) {
        throw std::runtime_error(SB() << "Conversion error: Invalid argument. Serial in PV name is not a number: "
                                      << serial_string);
    } catch (std::out_of_range &) {
        throw std::runtime_error(SB() << "Conversion error: Out of range. Serial is too large: " << serial_string);
    }

    return serial;
}

/**
 * @brief Get or create a certificate authority certificate.
 *
 * Check to see if a certificate authority key and certificate are located where the configuration
 * references them and check if they are valid.
 *
 * If not then create a new key and/or certificate and store them at the configured locations.
 *
 * If the certificate is invalid then make a backup, notify the user, then
 * create a new one.  A PVACMS only creates certificates with validity that
 * is within the lifetime of the certificate authority certificate so if the certificate authority certificate has
 * expired, all certificates it has signed will also have expired, and will need to be replaced.
 *
 * @param config the config to use to get certificate authority creation parameters if needed
 * @param certs_db the certificate database to write the certificate authority to if needed
 * @param cert_auth_cert the reference to the returned certificate (the issuer)
 * @param cert_auth_pkey the reference to the private key of the returned certificate
 * @param cert_auth_chain reference to the certificate chain of the returned cert
 * @param cert_auth_root_cert reference to the returned root of the certificate authority chain
 * @param is_initialising true if we are in the initializing state when called
 */
bool runSelfTests(const sql_ptr &certs_db,
                  const ossl_ptr<X509> &cert_auth_cert,
                  const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                  const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain) {
    bool all_ok = true;

    {
        auto now = time(nullptr);
        if (X509_cmp_time(X509_get0_notAfter(cert_auth_cert.get()), &now) <= 0) {
            log_err_printf(pvacms, "Self-test FAILED: CA certificate has expired%s\n", "");
            all_ok = false;
        }
        if (X509_cmp_time(X509_get0_notBefore(cert_auth_cert.get()), &now) > 0) {
            log_err_printf(pvacms, "Self-test FAILED: CA certificate is not yet valid%s\n", "");
            all_ok = false;
        }

        const int chain_len = cert_auth_chain ? sk_X509_num(cert_auth_chain.get()) : 0;
        for (int i = 0; i < chain_len; ++i) {
            X509 *chain_cert = sk_X509_value(cert_auth_chain.get(), i);
            if (X509_cmp_time(X509_get0_notAfter(chain_cert), &now) <= 0) {
                char name_buf[256] = {0};
                X509_NAME_oneline(X509_get_subject_name(chain_cert), name_buf, sizeof(name_buf));
                log_err_printf(pvacms, "Self-test FAILED: chain certificate expired: %s\n", name_buf);
                all_ok = false;
            }
        }

        if (chain_len > 0) {
            ossl_ptr<X509_STORE> store(X509_STORE_new());
            for (int i = 0; i < chain_len; ++i) {
                X509_STORE_add_cert(store.get(), sk_X509_value(cert_auth_chain.get(), i));
            }
            ossl_ptr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
            X509_STORE_CTX_init(ctx.get(), store.get(), cert_auth_cert.get(), cert_auth_chain.get());
            if (X509_verify_cert(ctx.get()) != 1) {
                log_err_printf(pvacms, "Self-test FAILED: CA chain verification error: %s\n",
                               X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get())));
                all_ok = false;
            }
        }

        if (all_ok) {
            log_info_printf(pvacms, "Self-test PASSED: CA certificate chain valid (chain depth %d)%s\n",
                            chain_len, "");
        }
    }

    {
        if (X509_check_private_key(cert_auth_cert.get(), cert_auth_pkey.get()) != 1) {
            log_err_printf(pvacms, "Self-test FAILED: CA private key does not match CA certificate%s\n", "");
            all_ok = false;
        } else {
            log_info_printf(pvacms, "Self-test PASSED: CA private key matches certificate%s\n", "");
        }
    }

    {
        sqlite3_stmt *ver_stmt = nullptr;
        if (sqlite3_prepare_v2(certs_db.get(), SQL_GET_SCHEMA_VERSION, -1, &ver_stmt, nullptr) != SQLITE_OK) {
            log_err_printf(pvacms, "Self-test FAILED: cannot query schema version: %s\n",
                           sqlite3_errmsg(certs_db.get()));
            all_ok = false;
        } else if (sqlite3_step(ver_stmt) == SQLITE_ROW) {
            const int db_version = sqlite3_column_int(ver_stmt, 0);
            sqlite3_finalize(ver_stmt);
            if (db_version != PVACMS_SCHEMA_VERSION) {
                log_err_printf(pvacms, "Self-test FAILED: schema version %d does not match expected %d\n",
                               db_version, PVACMS_SCHEMA_VERSION);
                all_ok = false;
            } else {
                log_info_printf(pvacms, "Self-test PASSED: schema version %d%s\n", db_version, "");
            }
        } else {
            sqlite3_finalize(ver_stmt);
            log_err_printf(pvacms, "Self-test FAILED: no schema version found in database%s\n", "");
            all_ok = false;
        }
    }

    {
        const unsigned char test_data[] = "pvacms-self-test";
        ossl_ptr<EVP_MD_CTX> sign_ctx(EVP_MD_CTX_new());
        bool sign_ok = false;

        if (EVP_DigestSignInit(sign_ctx.get(), nullptr, EVP_sha256(), nullptr, cert_auth_pkey.get()) == 1) {
            size_t sig_len = 0;
            if (EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, test_data, sizeof(test_data)) == 1) {
                std::vector<unsigned char> sig(sig_len);
                if (EVP_DigestSign(sign_ctx.get(), sig.data(), &sig_len, test_data, sizeof(test_data)) == 1) {
                    ossl_ptr<EVP_MD_CTX> verify_ctx(EVP_MD_CTX_new());
                    ossl_ptr<EVP_PKEY> pub_key(X509_get_pubkey(cert_auth_cert.get()));
                    if (EVP_DigestVerifyInit(verify_ctx.get(), nullptr, EVP_sha256(), nullptr, pub_key.get()) == 1 &&
                        EVP_DigestVerify(verify_ctx.get(), sig.data(), sig_len, test_data, sizeof(test_data)) == 1) {
                        sign_ok = true;
                    }
                }
            }
        }

        if (sign_ok) {
            log_info_printf(pvacms, "Self-test PASSED: OpenSSL sign/verify operational%s\n", "");
        } else {
            log_err_printf(pvacms, "Self-test FAILED: OpenSSL test sign/verify failed%s\n", "");
            all_ok = false;
        }
    }

    return all_ok;
}

void getOrCreateCertAuthCertificate(const ConfigCms &config,
                                    sql_ptr &certs_db,
                                    ossl_ptr<X509> &cert_auth_cert,
                                    ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                    ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
                                    ossl_ptr<X509> &cert_auth_root_cert,
                                    bool &is_initialising) {
    CertData cert_data;
    try {
        log_debug_printf(pvacms, "Attempting to read certificate authority from: %s with %s\n", config.cert_auth_keychain_file.c_str(), (config.cert_auth_keychain_pwd.empty()?"no password":"pwd: *****"));
        cert_data =
            IdFileFactory::create(config.cert_auth_keychain_file, config.cert_auth_keychain_pwd)->getCertDataFromFile();
    } catch (...) {}
    auto key_pair = cert_data.key_pair;

    if (!key_pair) {
        is_initialising = true;  // Let the caller know that we've created a new Cert and Key
        log_debug_printf(pvacms, "Creating Key Pair for certificate authority%s\n","");
        key_pair = IdFileFactory::createKeyPair();
        cert_data = createCertAuthCertificate(config, certs_db, key_pair);
    } else {
        // Existing CA cert loaded: ensure it is present in the DB (validate status extension and prefix)
        try {
            insertLoadedCertIfMissing(config, certs_db, cert_data.cert, cert_data.cert_auth_chain, "", true);
        } catch (std::exception &e) {
            log_err_printf(pvacms, "CA certificate validation/DB preload failed: %s\n", e.what());
            throw; // fail fast
        }
    }

    createDefaultAdminACF(config, cert_data);

    if (is_initialising) {
        createAdminClientCert(config, certs_db, key_pair->pkey, cert_data.cert, cert_data.cert_auth_chain);
    }

    cert_auth_pkey = std::move(key_pair->pkey);
    cert_auth_cert = std::move(cert_data.cert);
    cert_auth_chain = cert_data.cert_auth_chain;
    if (sk_X509_num(cert_auth_chain.get()) <= 0) {
        cert_auth_root_cert.reset(X509_dup(cert_auth_cert.get()));
    } else {
        cert_auth_root_cert.reset(X509_dup(CertStatus::getRootCa(cert_auth_chain)));
    }
}

std::vector<std::string> getCertPaths(const CertData &cert_data) {
    std::vector<std::string> common_names;
    if (cert_data.cert_auth_chain) {
        const auto N = sk_X509_num(cert_data.cert_auth_chain.get());
        if (N > 0) {
            // Get common names from all certificates in the chain
            for (int i = N - 1; i >= 0; i--) {
                auto cert = ossl_ptr<X509>(X509_dup(sk_X509_value(cert_data.cert_auth_chain.get(), i)));
                const auto common_name = CertStatus::getCommonName(cert);
                common_names.push_back(common_name);
            }
        }
    }
    if (cert_data.cert) {
        common_names.push_back(CertStatus::getCommonName(cert_data.cert));
    }
    return common_names;
}

/**
 * @brief Convert the certificate data to an Admin Auth ACF file
 *
 * @param id the id of the certificate authority to insert into the Admin Auth ACF file
 * @param cert_data the certificate data to use to get the common names for the Authorities section of the Admin Auth
 * ACF file
 * @return the Admin Auth ACF file
 */
std::string toACFAuth(const std::string &id, const CertData &cert_data) {
    if (!cert_data.cert)
        return "";

    const auto common_names = getCertPaths(cert_data);

    // Build the nested structure from root to issuer
    std::string result;
    const auto N = common_names.size();
    for (size_t i = 0; i < N; i++) {
        const std::string &cn = common_names[i];
        std::string indent(4 * i, ' ');

        result += indent + "AUTHORITY(";
        // Add id parameter only for the last (issuer) certificate
        if (i == N - 1)
            result += id + ", ";
        result += "\"" + cn + "\")";

        // Add braces and newline for all but the innermost authority
        if (i != N - 1)
            result += " {\n";
    }

    // Close all brackets except for the innermost one
    for (size_t i = 1; i < N; ++i) {
        std::string indent(4 * (N - i - 1), ' ');
        result += "\n" + indent + "}";
    }

    return result;
}

/**
 * @brief Convert the certificate data to a YAML formatted Admin ACF file
 *
 * @param id the id of the certificate authority to insert into the Admin ACF file
 * @param cert_data the certificate data to use to get the common names for the Authorities section
 * @return the YAML formatted Admin ACF file
 */
std::string toACFYamlAuth(const std::string &id, const CertData &cert_data) {
    if (!cert_data.cert)
        return "";

    const auto common_names = getCertPaths(cert_data);

    if (common_names.empty())
        return "";

    std::string result = "authorities:\n";

    // For single certificate case
    if (common_names.size() == 1) {
        result += "  - id: " + id + "\n";
        result += "    name: " + common_names[0];
        return result;
    }

    // For certificate chain
    std::string indent = "  ";
    size_t current_level = 1;

    // Start with root
    result += indent + "- name: " + common_names.back() + "\n";

    // Handle intermediate certificates and issuer
    for (size_t i = common_names.size() - 1; i > 0; --i) {
        current_level++;
        std::string current_indent(current_level * 2, ' ');

        result += current_indent + "authorities:\n";
        current_indent += "  ";

        result += current_indent + "- ";

        // Add id only for the last (issuer) certificate
        if (i == 1) {
            result += "id: " + id + "\n";
            result += current_indent + "  name: " + common_names[i - 1];
        } else {
            result += "name: " + common_names[i - 1] + "\n";
        }
    }

    return result;
}

/*
 * Create the default admin ACF file
 *
 * @param config the config to use to get the ACF filename
 * @param cert_data the certificate data to use to get the common names
 */
void createDefaultAdminACF(const ConfigCms &config, const CertData &cert_data) {
    log_debug_printf(pvacms, "Attempting to read ACF file from: %s\n", config.pvacms_acf_filename.c_str());
    std::ifstream file(config.pvacms_acf_filename);
    if (file.good()) {
        log_debug_printf(pvacms, "ACF file exists: %s\n", config.pvacms_acf_filename.c_str());
        return;
    }

    log_debug_printf(pvacms, "Creating default ACF file into: %s\n", config.pvacms_acf_filename.c_str());
    std::string extension = config.pvacms_acf_filename.substr(config.pvacms_acf_filename.find_last_of(".") + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), tolower);

    std::ofstream out_file(config.pvacms_acf_filename, std::ios::out | std::ios::trunc);
    if (!out_file) {
        throw std::runtime_error("Failed to open ACF file for writing: " + config.pvacms_acf_filename);
    }

    extension == "yaml" || extension == "yml" ? out_file << "# EPICS YAML\n"
                                                            "version: 1.0\n"
                                                            "\n"
                                                            "# certificate authorities\n"
                                                         << toACFYamlAuth("CMS_AUTH", cert_data) << "\n"
                                                         << "\n"
                                                             "# user access groups\n"
                                                             "uags:\n"
                                                             "  - name: CMS_ADMIN\n"
                                                             "    users:\n"
                                                             "      - admin\n"
                                                             "\n"
                                                             "# Access security group definitions\n"
                                                             "asgs:\n"
                                                             "  - name: DEFAULT\n"
                                                             "    rules:\n"
                                                             "      - level: 0\n"
                                                             "        access: READ\n"
                                                             "      - level: 1\n"
                                                             "        access: WRITE\n"
                                                             "        uags:\n"
                                                             "          - CMS_ADMIN\n"
                                                             "        methods:\n"
                                                             "          - x509\n"
                                                             "        authorities:\n"
                                                             "          - CMS_AUTH"
                                                         << std::endl
                                              : out_file << toACFAuth("CMS_AUTH", cert_data)
                                                          << "\n"
                                                             "\n"
                                                             "UAG(CMS_ADMIN) {admin}\n"
                                                             "\n"
                                                             "ASG(DEFAULT) {\n"
                                                             "    RULE(0,READ)\n"
                                                             "    RULE(1,WRITE) {\n"
                                                             "        UAG(CMS_ADMIN)\n"
                                                             "        METHOD(\"x509\")\n"
                                                             "        AUTHORITY(CMS_AUTH)\n"
                                                             "    }\n"
                                                             "}"
                                                         << std::endl;

    out_file.close();

    std::cout << "Created Default ACF file: " << config.pvacms_acf_filename << std::endl;
}

/**
 * @brief Add a new admin user to the ACF file
 *
 * @param filename The path to the ACF file
 * @param admin_name The name of the new admin to add
 */
void addNewAdminToAcfFile(const std::string &filename, const std::string &admin_name) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    // Read the file into a string
    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string content = buffer.str();
    infile.close();

    // Regex to find and update the UAG(CMS_ADMIN) block
    std::regex uag_regex(R"(UAG\(CMS_ADMIN\)\s*\{([^}]*)\})");
    std::smatch match;

    // Check if the UAG(CMS_ADMIN) block exists
    if (std::regex_search(content, match, uag_regex)) {
        std::string admins = match[1].str();

        // Split the admins string into a list of admin names
        std::vector<std::string> admin_list;
        size_t start = 0, end;
        while ((end = admins.find(", ", start)) != std::string::npos) {
            admin_list.push_back(admins.substr(start, end - start));
            start = end + 2;
        }
        if (start < admins.size()) {
            admin_list.push_back(admins.substr(start));
        }

        // Check if admin_name is already in the list
        if (std::find(admin_list.begin(), admin_list.end(), admin_name) == admin_list.end()) {
            admin_list.push_back(admin_name);
        }

        // Rebuild the admins string with ", " separation
        admins = "";
        for (size_t i = 0; i < admin_list.size(); ++i) {
            if (i > 0) {
                admins += ", ";
            }
            admins += admin_list[i];
        }

        // Replace the matched UAG block with the updated list
        content = std::regex_replace(content, uag_regex, "UAG(CMS_ADMIN) {" + admins + "}");
    } else {
        throw std::runtime_error("UAG(CMS_ADMIN) block not found in file: " + filename);
    }

    // Write back to the file
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    outfile << content;
    outfile.close();
}

/**
 * @brief Adds a new admin entry to a YAML file.
 *
 * This method modifies the specified YAML file by adding a new admin user to the
 * users list in the CMS_ADMIN user access group
 *
 * @param filename The path to the YAML file where the admin information will be added.
 * @param admin_name The name of the new admin to be added.
 */
void addNewAdminToYamlFile(const std::string &filename, const std::string &admin_name) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    std::ostringstream buffer;
    buffer << infile.rdbuf();
    std::string content = buffer.str();
    infile.close();

    // Regex to find the `CMS_ADMIN` section and `users` list
    std::regex yaml_regex(R"(- name:\s*CMS_ADMIN\s*[\r\n]+[^\S\r\n]*users:\s*[\r\n]+((?:[^\S]*-\s+[^\r\n]+[\r\n]*)*))");
    std::smatch match;

    if (std::regex_search(content, match, yaml_regex)) {
        std::string users_block = match[1].str();  // The captured `users` list (indented list of users)

        // Check if `admin_name` is already in the list
        std::regex user_regex("-\\s+" +
                              std::regex_replace(admin_name, std::regex(R"([\\.^$|()\[\]{}*+?])"), R"(\\$&)"));
        if (!std::regex_search(users_block, user_regex)) {
            // Append the new admin with correct indentation
            users_block = users_block.substr(0, users_block.length() - 1);
            users_block += "      - " + admin_name + "\n\n";
        }

        // Replace the matched users block with the updated block
        content.replace(match.position(1), match.length(1), users_block);

        // Write back the updated YAML
        std::ofstream outfile(filename);
        if (!outfile.is_open()) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }
        outfile << content;
        outfile.close();

        std::cout << "Admin user '" << admin_name << "' successfully added to 'CMS_ADMIN'." << std::endl;
    } else {
        throw std::runtime_error("CMS_ADMIN users list not found in YAML file: " + filename);
    }
}

/**
 * @brief Add new admin user to the existing ACF file
 *
 * Handles both legacy and new yaml format
 *
 * @param config the config to read to find out the name of the acf file
 * @param admin_name the admin name to add
 */
void addUserToAdminACF(const ConfigCms &config, const std::string &admin_name) {
    std::string extension = config.pvacms_acf_filename.substr(config.pvacms_acf_filename.find_last_of(".") + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), tolower);

    if (extension == "acf") {
        addNewAdminToAcfFile(config.pvacms_acf_filename, admin_name);
    } else if (extension == "yaml" || extension == "yml") {
        addNewAdminToYamlFile(config.pvacms_acf_filename, admin_name);
    } else {
        throw std::invalid_argument("Unsupported file extension: " + extension);
    }
}

/**
 * @brief Create a default admin client certificate
 *
 * @param config The configuration to use to get the parameters to create cert
 * @param certs_db The database to store the certificate in
 * @param cert_auth_pkey The certificate authority's private key to sign the certificate
 * @param cert_auth_cert The certificate authority's certificate
 * @param cert_auth_cert_chain The certificate authority's certificate chain
 * @param cert_auth_pkey The certificate authority's key pair to use to create the certificate
 * @param admin_name The optional name of the administrator (defaults to admin if not specified)
 */
void createAdminClientCert(const ConfigCms &config,
                           sql_ptr &certs_db,
                           const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                           const ossl_ptr<X509> &cert_auth_cert,
                           const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain,
                           const std::string &admin_name) {
    log_debug_printf(pvacms, "Attempting to read default Admin Keychain File from: %s\n", config.admin_keychain_file.c_str());
    std::ifstream file(config.admin_keychain_file);
    if (file.good()) {
        log_debug_printf(pvacms, "Default Admin Keychain File exists: %s\n", config.admin_keychain_file.c_str());
        return;
    }

    log_debug_printf(pvacms, "Creating default Admin Keychain File into: %s\n", config.admin_keychain_file.c_str());
    auto key_pair = IdFileFactory::createKeyPair();
    auto serial = generateSerial();

    // Get other certificate parameters from request
    auto country = getCountryCode();
    auto name = admin_name;
    auto organization = "";
    auto organization_unit = "";
    time_t not_before(time(nullptr));
    time_t not_after(not_before + (365 + 1) * 24 * 60 * 60);  // 1yrs

    // Create a certificate factory
    auto certificate_factory = CertFactory(serial,
                                           key_pair,
                                           name,
                                           country,
                                           organization,
                                           organization_unit,
                                           not_before,
                                           not_after,
                                           0,
                                           cms::ssl::kForClient,
                                           config.getCertPvPrefix(),
                                           YES,
                                           false,
                                           false,
                                           cert_auth_cert.get(),
                                           cert_auth_pkey.get(),
                                           cert_auth_cert_chain.get(),
                                           VALID);
    certificate_factory.allow_duplicates_ = false;

    // Create the certificate using the certificate factory, store it in the database and return the PEM string
    auto pem_string = createCertificatePemString(certs_db, certificate_factory);

    auto cert_file_factory = IdFileFactory::create(config.admin_keychain_file,
                                                   config.admin_keychain_pwd,
                                                   key_pair,
                                                   nullptr,
                                                   nullptr,
                                                   pem_string);
    cert_file_factory->writeIdentityFile();
    std::cout << "Keychain file created   : " << config.admin_keychain_file << std::endl;

    std::string from = std::ctime(&certificate_factory.not_before_);
    std::string to = std::ctime(&certificate_factory.not_after_);
}

// Helper: ensure a loaded certificate is present in the DB, validating status extension and issuer
// External linkage required: serverHandle.cpp's prepareCmsState calls this via the pvacms.h declaration.
void insertLoadedCertIfMissing(const ConfigCms &config,
                               sql_ptr &certs_db,
                               const ossl_ptr<X509> &cert,
                               const ossl_shared_ptr<STACK_OF(X509)> & /*chain*/,
                               const std::string &expected_issuer_id,
                               bool is_ca)
{
    if (!cert) return;

    // Check if already in DB
    const auto serial = CertStatusFactory::getSerialNumber(cert);
    const auto validity = getCertificateValidity(certs_db, serial);
    if (validity.not_after != 0) {
        // already present
        return;
    }

    // Validate status extension
    std::string status_uri;
    try {
        status_uri = CmsStatusManager::getStatusPvFromCert(cert);
    } catch (...) {
        // No certificate monitoring is included, so don't add
        return;
    }

    // Expected prefix: CERT:STATUS:<issuer>:<serial>
    const auto expected_prefix = getCertStatusPvBase(config.getCertPvPrefix()) + ":";
    if (status_uri.rfind(expected_prefix, 0) != 0) {
        throw std::runtime_error(SB() << "Loaded certificate status URI has wrong prefix. Expected '" << expected_prefix << "*' got '" << status_uri << "'");
    }

    // Extract issuer id part from URI
    const auto rest = status_uri.substr(expected_prefix.size());
    const auto pos_colon = rest.find(':');
    if (pos_colon == std::string::npos) {
        throw std::runtime_error(SB() << "Malformed status URI in loaded certificate: '" << status_uri << "'");
    }
    const auto issuer_in_cert = rest.substr(0, pos_colon);
    if (!is_ca) {
        if (!expected_issuer_id.empty() && issuer_in_cert != expected_issuer_id) {
            throw std::runtime_error(SB() << "Loaded certificate issuer id '" << issuer_in_cert << "' does not match PVACMS issuer id '" << expected_issuer_id << "'");
        }
    }

    // Extract subject fields
    auto *subj = X509_get_subject_name(cert.get());
    auto get_nid = [subj](int nid) -> std::string {
        char buf[512] = {0};
        const int len = X509_NAME_get_text_by_NID(subj, nid, buf, sizeof(buf));
        if (len < 0) return std::string();
        return std::string(buf, (size_t)len);
    };

    const std::string cn = get_nid(NID_commonName);
    const std::string o  = get_nid(NID_organizationName);
    const std::string ou = get_nid(NID_organizationalUnitName);
    const std::string c  = get_nid(NID_countryName);

    // Times
    const time_t not_before = getNotBeforeTimeFromCert(cert.get());
    const time_t not_after  = getNotAfterTimeFromCert(cert.get());

    // Compute full SKID (hex)
    std::string full_skid;
    {
        int pos = -1;
        pos = X509_get_ext_by_NID(cert.get(), NID_subject_key_identifier, pos);
        X509_EXTENSION *ex = X509_get_ext(cert.get(), pos);
        const ossl_ptr<ASN1_OCTET_STRING> skid(static_cast<ASN1_OCTET_STRING *>(X509V3_EXT_d2i(ex)), false);
        if (skid) {
            std::ostringstream ss;
            for (int i = 0; i < skid->length; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)skid->data[i];
            full_skid = ss.str();
        }
    }

    // Determine effective status at load time
    const auto now = std::time(nullptr);
    const certstatus_t effective_status = now < not_before ? PENDING : (now >= not_after ? EXPIRED : VALID);
    const int approved = (effective_status == VALID) ? 1 : 0;

    // Insert into DB using SQL_CREATE_CERT
    sqlite3_stmt *stmt = nullptr;
    int rc = sqlite3_prepare_v2(certs_db.get(), SQL_CREATE_CERT, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        if (stmt) sqlite3_finalize(stmt);
        throw std::runtime_error(SB() << "Failed to prepare insert for loaded certificate: " << sqlite3_errmsg(certs_db.get()));
    }

    const int64_t db_serial = *reinterpret_cast<const int64_t *>(&serial);
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), db_serial);
    sqlite3_bind_text (stmt, sqlite3_bind_parameter_index(stmt, ":skid"), full_skid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, sqlite3_bind_parameter_index(stmt, ":CN"),   cn.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, sqlite3_bind_parameter_index(stmt, ":O"),    o.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, sqlite3_bind_parameter_index(stmt, ":OU"),   ou.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, sqlite3_bind_parameter_index(stmt, ":C"),    c.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_null (stmt, sqlite3_bind_parameter_index(stmt, ":san"));
    sqlite3_bind_int  (stmt, sqlite3_bind_parameter_index(stmt, ":not_before"), (int)not_before);
    sqlite3_bind_int  (stmt, sqlite3_bind_parameter_index(stmt, ":not_after"),  (int)not_after);
    sqlite3_bind_int  (stmt, sqlite3_bind_parameter_index(stmt, ":renew_by"),   (int)not_after);
    sqlite3_bind_int  (stmt, sqlite3_bind_parameter_index(stmt, ":status"),     (int)effective_status);
    sqlite3_bind_int  (stmt, sqlite3_bind_parameter_index(stmt, ":approved"),   approved);
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":status_date"), now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_OK && rc != SQLITE_DONE) {
        throw std::runtime_error(SB() << "Failed to insert loaded certificate into DB: " << sqlite3_errmsg(certs_db.get()));
    }
    std::cout << "Pre-loaded Certificate  : " << status_uri << " : " << cn  << std::endl;
}

/**
 * @brief Ensure that the PVACMS server has a valid certificate.
 *
 * This will check whether the configured certificate exists, can be opened,
 * whether a p12 object can be read from it, and whether the p12 object
 * can be parsed to extract the private key, certificate and certificate chain.
 * Whether we can extract the root certificate from the certificate
 * chain and finally whether we can verify the integrity of the certificate
 *
 * If any of these checks fail this function will create a new certificate
 * at the location referenced in the config, using the configured values
 * as parameters.
 *
 * @param config the config to determine the location of the certificate
 * @param certs_db the database to store a new certificate if necessary
 * @param cert_auth_cert the certificate authority certificate to use as the issuer of this certificate
 * if necessary
 * @param cert_auth_pkey the certificate authority's private key used to sign the new
 * certificate if necessary
 * @param cert_auth_cert_chain the certificate authority's certificate Chain
 */
void ensureServerCertificateExists(const ConfigCms &config,
                                   sql_ptr &certs_db,
                                   const ossl_ptr<X509> &cert_auth_cert,
                                   const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain) {
    CertData cert_data;
    try {
        log_debug_printf(pvacms, "Attempting to read PVACMS server certificate from: %s with %s\n", config.tls_keychain_file.c_str(), (config.getKeychainPassword().empty()?"no password":"pwd: *****"));
        cert_data = IdFileFactory::create(config.tls_keychain_file, config.getKeychainPassword())->getCertDataFromFile();
    } catch (...) {}

    if (!cert_data.key_pair) {
        createServerCertificate(config,
                                certs_db,
                                cert_auth_cert,
                                cert_auth_pkey,
                                cert_auth_cert_chain,
                                IdFileFactory::createKeyPair());
    } else {
        // Existing server cert loaded: ensure it is present in the DB and matches our issuer
        try {
            const std::string issuer_id = CertStatus::getSkId(cert_auth_cert);
            insertLoadedCertIfMissing(config, certs_db, cert_data.cert, cert_data.cert_auth_chain, issuer_id, false);
        } catch (std::exception &e) {
            log_err_printf(pvacms, "Server certificate validation/DB preload failed: %s\n", e.what());
            throw; // fail fast
        }
    }
}

/**
 * @brief Create a certificate authority certificate
 *
 * This function creates a certificate authority certificate based on the configured parameters
 * and stores it in the given database as well as writing it out to the
 * configured P12 file protected by the optionally specified password.
 *
 * @param config the configuration to use to get certificate authority creation parameters
 * @param certs_db the reference to the certificate database to write the certificate authority certificate to
 * @param key_pair the key pair to use for the certificate
 * @return a cert data structure containing the cert and chain and a copy of the key
 */
CertData createCertAuthCertificate(const ConfigCms &config,
                                   sql_ptr &certs_db,
                                   const std::shared_ptr<KeyPair> &key_pair) {
    log_debug_printf(pvacms, "Creating certificate authority into: %s with %s\n", config.cert_auth_keychain_file.c_str(), (config.cert_auth_keychain_pwd.empty()?"no password":"pwd: *****"));

    // Set validity to 4 yrs
    const time_t not_before(time(nullptr));
    const time_t not_after(not_before + (4 * 365 + 1) * 24 * 60 * 60);  // 4yrs

    // Generate a new serial number
    const auto serial = generateSerial();

    auto certificate_factory = CertFactory(serial,
                                           key_pair,
                                           config.cert_auth_name,
                                           config.cert_auth_country,
                                           config.cert_auth_organization,
                                           config.cert_auth_organizational_unit,
                                           not_before,
                                           not_after,
                                           0,
                                           cms::ssl::kForCertAuth,
                                           config.getCertPvPrefix(),
                                           config.cert_status_subscription,
                                           false,
                                           false);

    const auto pem_string = createCertificatePemString(certs_db, certificate_factory);

    // Create keychain file containing certs, private key and chain
    const auto cert_file_factory = IdFileFactory::create(config.cert_auth_keychain_file,
                                                         config.cert_auth_keychain_pwd,
                                                         key_pair,
                                                         nullptr,
                                                         nullptr,
                                                         pem_string);

    cert_file_factory->writeIdentityFile();
    std::cout << "Keychain file created   : " << config.cert_auth_keychain_file << std::endl;

    return cert_file_factory->getCertData(key_pair);
}

/**
 * @brief Create a PVACMS server certificate
 *
 * If private key file is configured then don't add key to cert file
 *
 * @param config the configuration use to get the parameters to create cert
 * @param certs_db the db to store the certificate in
 * @param cert_auth_pkey the certificate authority's private key to sign the certificate
 * @param cert_auth_cert the certificate authority certificate
 * @param cert_auth_chain the certificate authority's certificate chain
 * @param key_pair the key pair to use to create the certificate
 */
void createServerCertificate(const ConfigCms &config,
                             sql_ptr &certs_db,
                             const ossl_ptr<X509> &cert_auth_cert,
                             const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
                             const std::shared_ptr<KeyPair> &key_pair) {
    log_debug_printf(pvacms, "Creating PVACMS server certificate into: %s with %s\n", config.tls_keychain_file.c_str(), (config.getKeychainPassword().empty()?"no password":"pwd: *****"));

    // Generate a new serial number
    const auto serial = generateSerial();

    auto certificate_factory = CertFactory(serial,
                                           key_pair,
                                           config.pvacms_name,
                                           config.pvacms_country,
                                           config.pvacms_organization,
                                           config.pvacms_organizational_unit,
                                           getNotBeforeTimeFromCert(cert_auth_cert.get()),
                                           getNotAfterTimeFromCert(cert_auth_cert.get()),
                                           0,
                                           cms::ssl::kForCMS,
                                           config.getCertPvPrefix(),
                                           NO,
                                           true,
                                           true,  // allow duplicates: multiple PVACMS nodes share the same subject
                                           cert_auth_cert.get(),
                                           cert_auth_pkey.get(),
                                           cert_auth_chain.get());

    const auto cert = createCertificate(certs_db, certificate_factory);

    // Create keychain file containing certs, private key and null chain
    const auto pem_string = CertFactory::certAndCasToPemString(cert, certificate_factory.certificate_chain_.get());
    const auto cert_file_factory = IdFileFactory::create(config.tls_keychain_file,
                                                         config.getKeychainPassword(),
                                                         key_pair,
                                                         nullptr,
                                                         nullptr,
                                                         pem_string);

    cert_file_factory->writeIdentityFile();
    std::cout << "Keychain file created   : " << config.tls_keychain_file << std::endl;
}

/**
 * @brief Ensure that start and end dates are within the validity of issuer cert
 *
 * @param cert_factory the cert factory to check
 */
void ensureValidityCompatible(const CertFactory &cert_factory) {
    const time_t issuer_not_before = getNotBeforeTimeFromCert(cert_factory.issuer_certificate_ptr_);
    const time_t issuer_not_after = getNotAfterTimeFromCert(cert_factory.issuer_certificate_ptr_);

    if (cert_factory.not_before_ < issuer_not_before) {
        throw std::runtime_error("Not before time is before issuer's not before time");
    }
    if (cert_factory.not_after_ > issuer_not_after) {
        throw std::runtime_error("Not after time is after issuer's not after time");
    }
}

/**
 * @brief Get the current country code of where the process is running
 * This returns the two letter country code.  It is always upper case.
 * For example for the United States it returns US, and for France, FR.
 *
 * @return the current country code of where the process is running
 */
std::string extractCountryCode(const std::string &locale_str) {
    // Look for underscore
    const auto pos = locale_str.find('_');
    if (pos == std::string::npos || pos + 3 > locale_str.size()) {
        return "";
    }

    std::string country_code = locale_str.substr(pos + 1, 2);
    std::transform(country_code.begin(), country_code.end(), country_code.begin(), toupper);
    return country_code;
}

/**
 * @brief Get the country code from the environment
 *
 * @return The country code
 */
std::string getCountryCode() {
    // 1. Try from std::locale("")
    {
        const std::locale loc("");
        const std::string name = loc.name();
        if (name != "C" && name != "POSIX") {
            std::string cc = extractCountryCode(name);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 2. If we failed, try the LANG environment variable
    {
        const char *lang = std::getenv("LANG");
        if (lang && *lang) {
            const std::string locale_str(lang);
            std::string cc = extractCountryCode(locale_str);
            if (!cc.empty()) {
                return cc;
            }
        }
    }

    // 3. Default to "US" if both attempts failed
    return "US";
}

/**
 * @brief Get the not after time from the given certificate
 * @param cert the certificate to look at for the not after time
 *
 * @return the time_t representation of the not after time in the certificate
 */
time_t getNotAfterTimeFromCert(const X509 *cert) {
    const ASN1_TIME *cert_not_after = X509_get_notAfter(cert);
    const time_t not_after = CertDate::asn1TimeToTimeT(cert_not_after);
    return not_after;
}

/**
 * @brief Get the not before time from the given certificate
 * @param cert the certificate to look at for the not before time
 *
 * @return the time_t representation of the not before time in the certificate
 */
time_t getNotBeforeTimeFromCert(const X509 *cert) {
    const ASN1_TIME *cert_not_before = X509_get_notBefore(cert);
    const time_t not_before = CertDate::asn1TimeToTimeT(cert_not_before);
    return not_before;
}

/**
 * @brief Set a value in a Value object marking any changes to the field if the values changed, and if not then
 * the field is unmarked.  Doesn't work for arrays or enums, so you need to do that manually.
 *
 * @param target The Value object to set the value in
 * @param field The field to set the value in
 * @param new_value The new value to set
 */
template <typename T>
void setValue(Value &target, const std::string &field, const T &new_value) {
    auto old_value = target[field].as<T>();
    if (old_value != new_value) {
        target[field] = new_value;
    } else {
        target[field].unmark(false, true);
    }
}

/**
 * @brief Posts the status of a certificate to the shared wildcard PV.
 *
 * This function posts the status of a certificate to a shared wildcard PV so that any listeners will be notified.
 * The shared wildcard PV is a data structure that can be accessed by multiple clients through a server.
 * The status of the certificate is represented by the CertStatus enum.
 *
 * @param status_pv The shared wildcard PV to post the status to.
 * @param pv_name The pv_name of the status to post.
 * @param serial The serial number of the certificate.
 * @param cert_status The status of the certificate (UNKNOWN, VALID, EXPIRED, REVOKED, PENDING_APPROVAL, PENDING).
 * @param certs_db the certs db
 * @param node_id the pvacms node ID
 */

Value postCertificateStatus(server::WildcardPV &status_pv,
                            const std::string &pv_name,
                            const uint64_t serial,
                            const PVACertificateStatus &cert_status,
                            const sql_ptr *certs_db,
                            const std::string &node_id) {
    Guard G(getStatusPvLock());
    Value status_value;
    const auto was_open = status_pv.isOpen(pv_name);
    if (was_open) {
        status_value = status_pv.fetch(pv_name);
        status_value["value.choices"].unmark();
        status_value["ocsp_status.value.choices"].unmark();
    } else {
        status_value = CertStatus::getStatusPrototype();
    }
    const auto now = time(nullptr);
    setValue<uint64_t>(status_value, "serial", serial);
    setValue<uint32_t>(status_value, "value.index", cert_status.status.i);
    setValue<time_t>(status_value, "timeStamp.secondsPastEpoch", now - POSIX_TIME_AT_EPICS_EPOCH);
    setValue<std::string>(status_value, "state", cert_status.status.s);
    setValue<time_t>(status_value, "renew_by",
                     cert_status.renew_by.t > 0 ? cert_status.renew_by.t - POSIX_TIME_AT_EPICS_EPOCH : 0);
    setValue<bool>(status_value, "renewal_due", cert_status.renewal_due);
    setValue<time_t>(status_value, "ocsp_status.timeStamp.secondsPastEpoch", now - POSIX_TIME_AT_EPICS_EPOCH);
    setValue<uint32_t>(status_value, "ocsp_status.value.index", cert_status.ocsp_status.i);
    // Get ocsp info if specified
    if (cert_status.ocsp_bytes.empty()) {
        const std::string uncertified_state = SB() << "**UNCERTIFIED**: " << cert_status.ocsp_status.s;
        setValue<std::string>(status_value, "ocsp_state", uncertified_state);
    } else {
        setValue<std::string>(status_value, "ocsp_state", cert_status.ocsp_status.s);
        setValue<std::string>(status_value, "ocsp_status_date", cert_status.status_date.s);
        setValue<std::string>(status_value, "ocsp_certified_until", cert_status.status_valid_until_date.s);
        setValue<std::string>(status_value, "ocsp_revocation_date", cert_status.revocation_date.s);
        auto ocsp_bytes = shared_array<const uint8_t>(cert_status.ocsp_bytes.begin(), cert_status.ocsp_bytes.end());
        status_value["ocsp_response"] = ocsp_bytes.freeze();
    }

    if (!node_id.empty()) {
        setValue<std::string>(status_value, "pvacms_node_id", node_id);
    }

    if (certs_db) {
        assignSchedule(status_value, loadScheduleWindows(certs_db->get(), serial));
        auto san_json = loadSanFromDb(certs_db->get(), serial);
        auto san_entries = sanFromJson(san_json);
        assignSan(status_value, san_entries);
    }

    log_debug_printf(pvacms, "Posting Certificate Status: %s = %s\n", pv_name.c_str(), cert_status.status.s.c_str());
    if (was_open) {
        status_pv.post(pv_name, status_value);
    } else {
        status_pv.open(pv_name, status_value);
    }
    return status_value;
}

/**
 * @brief Post an update to the next certificate that is becoming valid
 *
 * This function will post an update to the next certificate that is becoming VALID.
 * Certificates that are becoming valid are those that are in the PENDING state
 * and the not before time is now in the past.
 *
 * We can change the status of the certificate to VALID and post the status to the shared wildcard PV.
 *
 * We only do one at a time so we can reschedule the rest for the next loop
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
bool postUpdateToNextCertBecomingValid(const CertStatusFactory &cert_status_creator,
                                       const StatusMonitor &status_monitor_params) {
    bool changed = false;
    Guard G(getStatusUpdateLock());
    sqlite3_stmt *stmt;
    std::string valid_sql(SQL_CERT_TO_VALID);
    const std::vector<certstatus_t> valid_status{PENDING};
    valid_sql += getValidStatusesClause(valid_status);
    if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(), valid_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, valid_status);

        // Do one then reschedule the rest
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            const uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertStatusURI(status_monitor_params.config_.getCertPvPrefix(),
                                                           status_monitor_params.issuer_id_,
                                                           serial));
                updateCertificateStatus(status_monitor_params.certs_db_, serial, VALID, 1, {PENDING});
                const auto status_date = std::time(nullptr);
                const auto db_cert = getCertificateValidity(status_monitor_params.certs_db_, serial);
                const auto cert_status = cert_status_creator.createPVACertificateStatus(
                    serial, VALID, status_date, CertDate(std::time(nullptr)),
                    CertDate(db_cert.renew_by), false);
                postCertificateStatus(status_monitor_params.status_pv_, pv_name, serial, cert_status, &status_monitor_params.certs_db_);
                log_info_printf(pvacmsmonitor,
                                "%s ==> VALID\n",
                                getCertId(status_monitor_params.issuer_id_, serial).c_str());
                changed = true;
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor,
                       "PVACMS Certificate Monitor Error: %s\n",
                       sqlite3_errmsg(status_monitor_params.certs_db_.get()));
    }
    return changed;
}

/**
 * @brief Post an update to the next certificate that is becoming expired
 *
 * This function will post an update to the next certificate that is becoming expired.
 * Certificates that are becoming expired are those that are in the VALID, PENDING_APPROVAL, or PENDING state,
 * and the not-after time is now in the past.
 *
 * We can change the status of the certificate to EXPIRED and post the status to the shared wildcard PV.
 *
 * We only do one at a time so we can reschedule the rest for the next loop
 *
 * @param cert_status_factory The certificate status creator
 * @param status_pv the status pv
 * @param certs_db the database
 * @param cert_pv_prefix Specifies the prefix for all PVs published by this PVACMS.  Default `CERT`
 * @param issuer_id The issuer ID of this PVACMS.
 * @param full_skid optional full SKID - if provided will search only for a certificate that matches
 */
bool postUpdateToNextCertToExpire(const CertStatusFactory &cert_status_factory,
                                  server::WildcardPV &status_pv,
                                  const sql_ptr &certs_db,
                                  const std::string &cert_pv_prefix,
                                  const std::string &issuer_id,
                                  const std::string &full_skid) {
    Guard G(getStatusUpdateLock());
    bool updated{false};
    sqlite3_stmt *stmt;
    std::string expired_sql(full_skid.empty() ? SQL_CERT_TO_EXPIRED : SQL_CERT_TO_EXPIRED_WITH_FULL_SKID);
    const std::vector<certstatus_t> expired_status{VALID, PENDING_APPROVAL, PENDING_RENEWAL, PENDING};
    expired_sql += getValidStatusesClause(expired_status);
    if (sqlite3_prepare_v2(certs_db.get(), expired_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, expired_status);
        if (!full_skid.empty())
            sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":skid"), full_skid.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            updated = true;
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            const uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertStatusURI(cert_pv_prefix, issuer_id, serial));
                updateCertificateStatus(certs_db, serial, EXPIRED, -1, {VALID, PENDING_APPROVAL, PENDING_RENEWAL, PENDING});
                const auto status_date = std::time(nullptr);
                const auto db_cert = getCertificateValidity(certs_db, serial);
                const auto cert_status = cert_status_factory.createPVACertificateStatus(
                    serial, EXPIRED, status_date, CertDate(std::time(nullptr)),
                    CertDate(db_cert.renew_by), false);
                postCertificateStatus(status_pv, pv_name, serial, cert_status, &certs_db);
                log_info_printf(pvacmsmonitor, "%s ==> EXPIRED\n", getCertId(issuer_id, serial).c_str());
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(certs_db.get()));
    }
    return updated;
}

/**
 * @brief Get the original certificate (a cert with the same subject that is not EXPIRED or REVOKED)
 *
 * @param cert_factory The certificate factory
 * @param certs_db the database to look in
 * @param issuer_id the issuer of the certificates
 */
DbCert getOriginalCert(CertFactory &cert_factory, const sql_ptr &certs_db, const std::string &issuer_id) {
    Guard G(getStatusUpdateLock());
    const std::vector<certstatus_t> valid_statuses{VALID, PENDING_APPROVAL, PENDING_RENEWAL, PENDING};
    const int64_t db_serial = *reinterpret_cast<int64_t*>(&cert_factory.serial_);

    // Get the original cert
    serial_number_t serial{0};
    time_t not_after{0}, renew_by{0};
    certstatus_t status{UNKNOWN};
    {
        sqlite3_stmt *stmt;
        const std::string renewable_cert_sql(SQL_GET_RENEWED_CERT);
        if (sqlite3_prepare_v2(certs_db.get(), renewable_cert_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"), db_serial);
            sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":CN"), cert_factory.name_.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":O"),  cert_factory.org_.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":OU"), cert_factory.org_unit_.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":C"),  cert_factory.country_.c_str(), -1, SQLITE_STATIC);
            bindValidStatusClauses(stmt, valid_statuses);

            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int64_t db_serial_out = sqlite3_column_int64(stmt, 0);
                serial = *reinterpret_cast<uint64_t*>(&db_serial_out);
                not_after = sqlite3_column_int64(stmt, 1);
                renew_by = sqlite3_column_int64(stmt, 2);
                status = static_cast<certstatus_t>(sqlite3_column_int(stmt, 3));
                log_info_printf(pvacms, "%s ..↻\n", getCertId(issuer_id, serial).c_str());
            }
            sqlite3_finalize(stmt);
        }
    }
    return {serial, not_after, renew_by, status};
}

/**
 * @brief Post an update to the next certificate that is nearing renewal
 *
 * This function will post an update to the next certificate that is nearing renewal.
 * Certificates that are nearing renewal are those that are in the VALID, PENDING_APPROVAL, or PENDING state
 * and the current time is more than halfway between the last status update and the renew by date
 *
 * We can set the `renewal_due` field to true and post the status to the shared wildcard PV, so that any
 * listening authenticator can send a renewal request to renew the certificate in time.
 *
 * Return true if we updated anything
 *
 * @param cert_status_creator The certificate status creator
 * @param status_pv the status pv
 * @param certs_db the database
 * @param cert_pv_prefix Specifies the prefix for all PVs published by this PVACMS.  Default `CERT`
 * @param issuer_id The issuer ID of this PVACMS.
 */
bool postUpdateToNextCertNearingRenewal(const CertStatusFactory &cert_status_creator,
                                  server::WildcardPV &status_pv,
                                  const sql_ptr &certs_db,
                                  const std::string &cert_pv_prefix,
                                  const std::string &issuer_id) {
    Guard G(getStatusUpdateLock());
    bool updated{false};
    sqlite3_stmt *stmt;
    std::string nearing_renewal_sql(SQL_CERT_NEARING_RENEWAL);
    const std::vector<certstatus_t> pending_renewal_status{VALID};
    nearing_renewal_sql += getValidStatusesClause(pending_renewal_status);
    if (sqlite3_prepare_v2(certs_db.get(), nearing_renewal_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, pending_renewal_status);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            updated = true;
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            time_t renew_by = sqlite3_column_int64(stmt, 1);
            const uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertStatusURI(cert_pv_prefix, issuer_id, serial));
                // Change the status date and nothing else
                updateCertificateStatus(certs_db, serial, VALID, -1, {});
                // Create a status that has a renewal due
                const auto status_date = std::time(nullptr);
                const auto cert_status = cert_status_creator.createPVACertificateStatus(serial, VALID, status_date,
                    CertDate(std::time(nullptr)), renew_by, true);

                // Post the status
                postCertificateStatus(status_pv, pv_name, serial, cert_status, &certs_db);
                log_info_printf(pvacmsmonitor, "%s ==> RENEWAL DUE\n", getCertId(issuer_id, serial).c_str());
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(certs_db.get()));
    }
    return updated;
}

/**
 * @brief Post an update to the next certificate that is needs renewal
 *
 * This function will post an update to the next certificate that is needs renewal.
 * Certificates that need renewal are those that are in the VALID, PENDING_APPROVAL, or PENDING state,
 * and the renew_by time is now in the past.
 *
 * We can change the status of the certificate to PENDING_RENEWAL and post the status to the shared wildcard PV.
 *
 * Return true if we updated anything
 *
 * @param cert_status_creator The certificate status creator
 * @param status_pv the status pv
 * @param certs_db the database
 * @param cert_pv_prefix Specifies the prefix for all PVs published by this PVACMS.  Default `CERT`
 * @param issuer_id The issuer ID of this PVACMS.
 */
bool postUpdateToNextCertToNeedRenewal(const CertStatusFactory &cert_status_creator,
                                  server::WildcardPV &status_pv,
                                  const sql_ptr &certs_db,
                                  const std::string &cert_pv_prefix,
                                  const std::string &issuer_id) {
    Guard G(getStatusUpdateLock());
    bool updated{false};
    sqlite3_stmt *stmt;
    std::string pending_renewal_sql(SQL_CERT_TO_PENDING_RENEWAL);
    const std::vector<certstatus_t> pending_renewal_status{VALID};
    pending_renewal_sql += getValidStatusesClause(pending_renewal_status);
    if (sqlite3_prepare_v2(certs_db.get(), pending_renewal_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bindValidStatusClauses(stmt, pending_renewal_status);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            updated = true;
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            const uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertStatusURI(cert_pv_prefix, issuer_id, serial));
                updateCertificateStatus(certs_db, serial, PENDING_RENEWAL, -1, {VALID, PENDING_APPROVAL, PENDING});
                const auto status_date = std::time(nullptr);
                const auto db_cert = getCertificateValidity(certs_db, serial);
                const auto cert_status = cert_status_creator.createPVACertificateStatus(
                    serial, PENDING_RENEWAL, status_date, CertDate(std::time(nullptr)),
                    CertDate(db_cert.renew_by), false);
                postCertificateStatus(status_pv, pv_name, serial, cert_status, &certs_db);
                log_info_printf(pvacmsmonitor, "%s ==> PENDING_RENEWAL\n", getCertId(issuer_id, serial).c_str());
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(certs_db.get()));
    }
    return updated;
}

/**
 * @brief Post an update to the next certificate status that is about to become invalid
 *
 * This function will post an update to the next certificate status that is becoming invalid.
 *
 * Return true if we updated anything
 *
 * @param cert_status_creator The certificate status creator
 * @param status_pv the status pv
 * @param certs_db the database
 * @param cert_pv_prefix Specifies the prefix for all PVs published by this PVACMS.  Default `CERT`
 * @param issuer_id The issuer ID of this PVACMS.
 */
bool postUpdatesToNextCertStatusToBecomeInvalid(const CertStatusFactory &cert_status_creator,
                                  server::WildcardPV &status_pv,
                                  const sql_ptr &certs_db,
                                  const std::string &cert_pv_prefix,
                                  const std::string &issuer_id) {
    Guard G(getStatusUpdateLock());
    bool updated{false};
    sqlite3_stmt *stmt;
    std::string cert_status_nearly_invalid_sql(SQL_CERT_STATUS_NEARLY_INVALID);
    if (sqlite3_prepare_v2(certs_db.get(), cert_status_nearly_invalid_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":status_validity"), (cert_status_creator.cert_status_validity_mins_*60) + cert_status_creator.cert_status_validity_secs_);
        bindValidStatusClauses(stmt);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            updated = true;
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            auto status = static_cast<certstatus_t>(sqlite3_column_int(stmt, 1));
            const uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertStatusURI(cert_pv_prefix, issuer_id, serial));
                touchCertificateStatus(certs_db, serial);
                const auto status_date = std::time(nullptr);
                const auto db_cert = getCertificateValidity(certs_db, serial);
                const auto cert_status = cert_status_creator.createPVACertificateStatus(
                    serial, status, status_date, CertDate(std::time(nullptr)),
                    CertDate(db_cert.renew_by), false);
                postCertificateStatus(status_pv, pv_name, serial, cert_status, &certs_db);
                log_info_printf(pvacmsmonitor, "%s Certificate Status Keep Alive\n", getCertId(issuer_id, serial).c_str());
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", sqlite3_errmsg(certs_db.get()));
    }
    return updated;
}

/**
 * @brief Post an update to the next certificates that are expiring
 *
 * This function will post an update to the next certificates that are expiring.
 * Certificates that are expiring are those that are in the VALID, PENDING_APPROVAL, or PENDING state,
 * and the not-after time is now in the past.
 *
 * We can change the status of the certificate to EXPIRED and post the status to the shared wildcard PV.
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
bool postUpdateToNextCertToExpire(const CertStatusFactory &cert_status_creator,
                                   const StatusMonitor &status_monitor_params) {
    bool changed = false;
    while (postUpdateToNextCertToExpire(cert_status_creator,
                                 status_monitor_params.status_pv_,
                                 status_monitor_params.certs_db_,
                                 status_monitor_params.config_.getCertPvPrefix(),
                                 status_monitor_params.issuer_id_))
        changed = true;
    return changed;
}

/**
 * @brief Post an update to the next certificates that need renewal
 *
 * This function will post an update to the next certificates that need renewal.
 * Certificates that need renewal are those that are in the VALID, PENDING_APPROVAL, or PENDING state,
 * and the not-after time is now in the past.
 *
 * We can change the status of the certificates to PENDING_RENEWAL and post the status to the shared wildcard PV.
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
bool postUpdateToNextCertToNeedRenewal(const CertStatusFactory &cert_status_creator,
                                   const StatusMonitor &status_monitor_params) {
    bool changed = false;
    while (postUpdateToNextCertToNeedRenewal(cert_status_creator,
                                 status_monitor_params.status_pv_,
                                 status_monitor_params.certs_db_,
                                 status_monitor_params.config_.getCertPvPrefix(),
                                 status_monitor_params.issuer_id_))
        changed = true;
    while (postUpdateToNextCertNearingRenewal(cert_status_creator,
                                 status_monitor_params.status_pv_,
                                 status_monitor_params.certs_db_,
                                 status_monitor_params.config_.getCertPvPrefix(),
                                 status_monitor_params.issuer_id_))
        changed = true;
    return changed;
}

/**
 * @brief Post an update to the next certificate statuses that are becoming invalid
 *
 * This function will post an update to the next certificate statuses that are becoming invalid.
 * Certificate statuses that are becoming invalid are those that are in the VALID, PENDING_APPROVAL, or PENDING state,
 * we are now more than halfway between the last status update and the status lifetime.
 *
 * We update the status date and post it to the shared wildcard PV.
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
bool postUpdatesToNextCertStatusToBecomeInvalid(const CertStatusFactory &cert_status_creator,
                                   const StatusMonitor &status_monitor_params) {
    bool changed = false;
    while (postUpdatesToNextCertStatusToBecomeInvalid(cert_status_creator,
                                 status_monitor_params.status_pv_,
                                 status_monitor_params.certs_db_,
                                 status_monitor_params.config_.getCertPvPrefix(),
                                 status_monitor_params.issuer_id_))
        changed = true;
    return changed;
}

/**
 * @brief Post an update to the all certificates whose statuses are becoming invalid
 *
 * This function will post an update to the all certificates whose statuses are becoming invalid.
 * Certificates that are becoming invalid are those that are in the VALID, PENDING, or PENDING_APPROVAL state,
 * and the status validity time is now nearly up.  We use the timeout value (default 5 seconds) to determine
 * "nearly up".
 *
 * It uses the set of active serials that are updated every time a connection is opened or closed.
 * So only certificates that are currently active will be updated.
 *
 * @param cert_status_creator The certificate status creator
 * @param status_monitor_params The status monitor parameters
 */
bool postUpdatesToExpiredStatuses(const CertStatusFactory &cert_status_creator,
                                   const StatusMonitor &status_monitor_params) {
    bool changed = false;
    auto const serials = status_monitor_params.getActiveSerials();
    if (serials.empty())
        return false;

    sqlite3_stmt *stmt;
    std::string validity_sql(SQL_CERT_BECOMING_INVALID);
    validity_sql += getSelectedSerials(serials);
    const std::vector<certstatus_t> validity_status{VALID, PENDING, PENDING_APPROVAL};
    validity_sql += getValidStatusesClause(validity_status);
    if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(), validity_sql.c_str(), -1, &stmt, nullptr) ==
        SQLITE_OK) {
        bindValidStatusClauses(stmt, validity_status);

        // For each status in this state
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t db_serial = sqlite3_column_int64(stmt, 0);
            int status = sqlite3_column_int(stmt, 1);
            uint64_t serial = *reinterpret_cast<uint64_t *>(&db_serial);
            try {
                const std::string pv_name(getCertStatusURI(status_monitor_params.config_.getCertPvPrefix(),
                                                           status_monitor_params.issuer_id_,
                                                           serial));
                auto status_date = std::time(nullptr);
                const auto db_cert = getCertificateValidity(status_monitor_params.certs_db_, serial);
                auto cert_status = cert_status_creator.createPVACertificateStatus(
                    serial, static_cast<certstatus_t>(status), status_date,
                    CertDate(std::time(nullptr)), CertDate(db_cert.renew_by), false);
                postCertificateStatus(status_monitor_params.status_pv_, pv_name, serial, cert_status, &status_monitor_params.certs_db_);
                status_monitor_params.setValidity(serial, cert_status.status_valid_until_date.t);
                log_debug_printf(pvacmsmonitor,
                                 "%s ==> \u21BA \n",
                                 getCertId(status_monitor_params.issuer_id_, serial).c_str());
                changed = true;
            } catch (const std::runtime_error &e) {
                log_err_printf(pvacmsmonitor, "PVACMS Certificate Monitor Error: %s\n", e.what());
            }
        }
        sqlite3_finalize(stmt);
    } else {
        log_err_printf(pvacmsmonitor,
                       "PVACMS Certificate Monitor Error: %s\n",
                       sqlite3_errmsg(status_monitor_params.certs_db_.get()));
    }
    return changed;
}

/**
 * @brief The main loop for the certificate monitor.
 *
 * This function will post an update to the next certificate that is becoming valid,
 * the next certificate that is becoming expired,
 * and any certificates whose statuses are becoming invalid.
 *
 * @param status_monitor_params The status monitor parameters
 * @return true if we should continue to run the loop, false if we should exit
 */
timeval statusMonitor(const StatusMonitor &status_monitor_params) {
    log_debug_printf(pvacmsmonitor, "Certificate Monitor Thread Wake Up%s", "\n");
    const auto cert_status_creator(CertStatusFactory(status_monitor_params.cert_auth_cert_,
                                                     status_monitor_params.cert_auth_pkey_,
                                                     status_monitor_params.cert_auth_cert_chain_,
                                                     status_monitor_params.config_.cert_status_validity_mins));

    postUpdateToNextCertBecomingValid(cert_status_creator, status_monitor_params);
    postUpdateToNextCertToExpire(cert_status_creator, status_monitor_params);
    postUpdateToNextCertToNeedRenewal(cert_status_creator, status_monitor_params);

    if (!status_monitor_params.active_status_validity_.empty()) {
        postUpdatesToExpiredStatuses(cert_status_creator, status_monitor_params);
    }

    postUpdatesToNextCertStatusToBecomeInvalid(cert_status_creator, status_monitor_params);

    {
        sqlite3_stmt *sched_certs_stmt = nullptr;
        if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(),
                               SQL_SELECT_CERTS_WITH_SCHEDULES, -1, &sched_certs_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(sched_certs_stmt,
                             sqlite3_bind_parameter_index(sched_certs_stmt, ":valid_status"), VALID);
            sqlite3_bind_int(sched_certs_stmt,
                             sqlite3_bind_parameter_index(sched_certs_stmt, ":scheduled_offline_status"), SCHEDULED_OFFLINE);

            const auto now_utc = time(nullptr);
            while (sqlite3_step(sched_certs_stmt) == SQLITE_ROW) {
                const auto serial = static_cast<uint64_t>(sqlite3_column_int64(sched_certs_stmt, 0));
                const auto current_status = static_cast<certstatus_t>(sqlite3_column_int(sched_certs_stmt, 1));
                const auto windows = loadScheduleWindows(status_monitor_params.certs_db_.get(), serial);
                const bool in_window = isWithinSchedule(now_utc, windows);
                certstatus_t new_status = current_status;

                if (current_status == VALID && !in_window) {
                    new_status = SCHEDULED_OFFLINE;
                } else if (current_status == SCHEDULED_OFFLINE && in_window) {
                    new_status = VALID;
                }

                if (new_status != current_status) {
                    Guard G(getStatusUpdateLock());
                    updateCertificateStatus(status_monitor_params.certs_db_, serial, new_status, 0);
                    const auto db_cert = getCertificateValidity(status_monitor_params.certs_db_, serial);
                    const auto cert_status = cert_status_creator.createPVACertificateStatus(
                        serial, new_status, now_utc, CertDate(std::time(nullptr)),
                        CertDate(db_cert.renew_by), false);
                    auto cert_id = getCertId(status_monitor_params.issuer_id_, serial);
                    auto status_pv_name = getCertStatusURI(status_monitor_params.config_.getCertPvPrefix(), cert_id);
                    postCertificateStatus(status_monitor_params.status_pv_, status_pv_name, serial, cert_status, &status_monitor_params.certs_db_);
                    log_info_printf(pvacmsmonitor, "%s ==> %s (schedule)\n", cert_id.c_str(), CERT_STATE(new_status));
                }
            }
            sqlite3_finalize(sched_certs_stmt);
        }
    }

    // No cluster sync here: time-based transitions are computed independently by every node.
    // Only CCR/admin actions (create, revoke, approve, renew) publish sync snapshots.

    // Periodic SQLite maintenance: integrity check + WAL checkpoint
    if (status_monitor_params.shouldRunMaintenance()) {
        status_monitor_params.recordMaintenanceRun();

        sqlite3_stmt *ic_stmt = nullptr;
        if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(),
                               "PRAGMA integrity_check", -1, &ic_stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(ic_stmt) == SQLITE_ROW) {
                const auto *result = reinterpret_cast<const char *>(sqlite3_column_text(ic_stmt, 0));
                if (result && std::string(result) == "ok") {
                    log_info_printf(pvacms, "SQLite integrity check passed%s\n", "");
                    status_monitor_params.setDbIntegrityOk(true);
                } else {
                    log_err_printf(pvacms, "SQLite integrity check FAILED: %s\n",
                                   result ? result : "(null)");
                    status_monitor_params.setDbIntegrityOk(false);
                }
            }
            sqlite3_finalize(ic_stmt);
        } else {
            log_err_printf(pvacms, "Failed to prepare integrity check: %s\n",
                           sqlite3_errmsg(status_monitor_params.certs_db_.get()));
        }

        if (status_monitor_params.shouldRunCheckpoint()) {
            status_monitor_params.recordCheckpointRun();
            int wal_log = 0, wal_ckpt = 0;
            const int wal_rc = sqlite3_wal_checkpoint_v2(
                status_monitor_params.certs_db_.get(), nullptr,
                SQLITE_CHECKPOINT_PASSIVE, &wal_log, &wal_ckpt);
            if (wal_rc == SQLITE_OK) {
                log_debug_printf(pvacms, "WAL checkpoint: %d/%d frames flushed%s\n", wal_ckpt, wal_log, "");
            } else if (wal_rc != SQLITE_BUSY) {
                log_warn_printf(pvacms, "WAL checkpoint failed: %s\n",
                                sqlite3_errmsg(status_monitor_params.certs_db_.get()));
            }
        }

        // Audit log pruning
        if (status_monitor_params.config_.audit_retention_days > 0) {
            const auto cutoff = static_cast<sqlite3_int64>(
                time(nullptr) - static_cast<time_t>(status_monitor_params.config_.audit_retention_days) * 86400);
            sqlite3_stmt *prune_stmt = nullptr;
            if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(),
                                   SQL_PRUNE_AUDIT, -1, &prune_stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int64(prune_stmt,
                                   sqlite3_bind_parameter_index(prune_stmt, ":cutoff"), cutoff);
                sqlite3_step(prune_stmt);
                sqlite3_finalize(prune_stmt);
                log_debug_printf(pvacms, "Audit log pruning completed%s\n", "");
            } else {
                log_warn_printf(pvacms, "Failed to prepare audit prune: %s\n",
                                sqlite3_errmsg(status_monitor_params.certs_db_.get()));
            }
        }
    }

    const uint32_t interval_min = status_monitor_params.config_.monitor_interval_min_secs;
    const uint32_t interval_max = status_monitor_params.config_.monitor_interval_max_secs;
    const uint32_t clamped_interval_min = std::min(interval_min, interval_max);
    const uint32_t clamped_interval_max = std::max(interval_min, interval_max);
    const int pending_status = PENDING;
    const int valid_status = VALID;

    const time_t now = time(nullptr);
    const time_t lookahead = now + static_cast<time_t>(clamped_interval_max) * 2;

    const std::string count_sql =
        "SELECT COUNT(*) FROM certs WHERE "
        "(status = " + std::to_string(pending_status) + " AND not_before <= ?) OR "
        "(status = " + std::to_string(valid_status) + " AND not_after <= ?) OR "
        "(status = " + std::to_string(valid_status) + " AND renew_by > 0 AND renew_by <= ?)";

    sqlite3_stmt *count_stmt = nullptr;
    uint32_t near_transition_count = 0;

    if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(),
                           count_sql.c_str(), -1, &count_stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(count_stmt, 1, static_cast<sqlite3_int64>(lookahead));
        sqlite3_bind_int64(count_stmt, 2, static_cast<sqlite3_int64>(lookahead));
        sqlite3_bind_int64(count_stmt, 3, static_cast<sqlite3_int64>(lookahead));
        if (sqlite3_step(count_stmt) == SQLITE_ROW) {
            near_transition_count = static_cast<uint32_t>(sqlite3_column_int(count_stmt, 0));
        } else {
            sqlite3_finalize(count_stmt);
            log_warn_printf(pvacms, "Adaptive monitor: transition query failed: %s\n",
                            sqlite3_errmsg(status_monitor_params.certs_db_.get()));
            return {};
        }
        sqlite3_finalize(count_stmt);
    } else {
        log_warn_printf(pvacms, "Adaptive monitor: transition query failed: %s\n",
                        sqlite3_errmsg(status_monitor_params.certs_db_.get()));
        return {};
    }

    if (auto *health_pv = status_monitor_params.getHealthPV()) {
        try {
            const time_t now_time = time(nullptr);
            bool db_ok = status_monitor_params.isDbIntegrityOk();
            uint64_t cert_count = 0u;

            sqlite3_stmt *health_count_stmt = nullptr;
            if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(),
                                   "SELECT COUNT(*) FROM certs", -1, &health_count_stmt, nullptr) == SQLITE_OK) {
                if (sqlite3_step(health_count_stmt) == SQLITE_ROW) {
                    cert_count = static_cast<uint64_t>(sqlite3_column_int64(health_count_stmt, 0));
                } else {
                    db_ok = false;
                }
            } else {
                db_ok = false;
            }
            if (health_count_stmt) {
                sqlite3_finalize(health_count_stmt);
            }

            bool ca_valid = false;
            if (status_monitor_params.cert_auth_cert_) {
                const ASN1_TIME *not_after = X509_get0_notAfter(status_monitor_params.cert_auth_cert_.get());
                ca_valid = not_after && (X509_cmp_current_time(not_after) > 0);
            }

            char time_buf[32] = {0};
            struct tm tm_buf;
            gmtime_r(&now_time, &tm_buf);
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

            const bool overall_ok = db_ok && ca_valid;
            auto value = status_monitor_params.cloneHealthValue();
            value["value.index"] = static_cast<int32_t>(overall_ok ? 1 : 0);
            value["db_ok"] = db_ok;
            value["ca_valid"] = ca_valid;
            value["uptime_secs"] = static_cast<uint64_t>(now_time - status_monitor_params.getStartTime());
            value["cert_count"] = cert_count;
            value["cluster_members"] = status_monitor_params.getClusterMemberCount();
            value["last_check"] = std::string(time_buf);

            value["alarm.severity"] = static_cast<int32_t>(overall_ok ? 0 : 2);
            value["alarm.status"] = static_cast<int32_t>(overall_ok ? 0 : 1);
            value["alarm.message"] = overall_ok ? std::string()
                                    : !db_ok    ? std::string("DB integrity check failed")
                                    : !ca_valid ? std::string("CA certificate invalid or expired")
                                                : std::string("Health check failed");

            value["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(now_time - POSIX_TIME_AT_EPICS_EPOCH);
            value["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
            value["timeStamp.userTag"] = static_cast<int32_t>(0);

            health_pv->post(value);
        } catch (const std::exception &e) {
            log_warn_printf(pvacms, "Health PV update failed: %s\n", e.what());
        }
    }

    if (auto *metrics_pv = status_monitor_params.getMetricsPV()) {
        try {
            auto value = status_monitor_params.cloneMetricsValue();
            value["certs_created"] = getCertsCreatedCounter().load();
            value["certs_revoked"] = getCertsRevokedCounter().load();

            uint64_t active_count = 0u;
            sqlite3_stmt *active_stmt = nullptr;
            if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(),
                                   "SELECT COUNT(*) FROM certs WHERE status = 1", -1, &active_stmt, nullptr) == SQLITE_OK) {
                if (sqlite3_step(active_stmt) == SQLITE_ROW) {
                    active_count = static_cast<uint64_t>(sqlite3_column_int64(active_stmt, 0));
                }
            }
            if (active_stmt) sqlite3_finalize(active_stmt);
            value["value"] = active_count;

            value["avg_ccr_time_ms"] = getCcrTimingTracker().averageMs();

            uint64_t db_size = 0u;
            struct stat st;
            if (stat(status_monitor_params.config_.certs_db_filename.c_str(), &st) == 0) {
                db_size = static_cast<uint64_t>(st.st_size);
                std::string wal_path = status_monitor_params.config_.certs_db_filename + "-wal";
                struct stat wal_st;
                if (stat(wal_path.c_str(), &wal_st) == 0) {
                    db_size += static_cast<uint64_t>(wal_st.st_size);
                }
            }
            value["db_size_bytes"] = db_size;
            const time_t metrics_now = time(nullptr);
            value["uptime_secs"] = static_cast<uint64_t>(metrics_now - status_monitor_params.getStartTime());

            value["alarm.severity"] = static_cast<int32_t>(0);
            value["alarm.status"] = static_cast<int32_t>(0);
            value["alarm.message"] = std::string();

            value["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(metrics_now - POSIX_TIME_AT_EPICS_EPOCH);
            value["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
            value["timeStamp.userTag"] = static_cast<int32_t>(0);

            metrics_pv->post(value);
        } catch (const std::exception &e) {
            log_warn_printf(pvacms, "Metrics PV update failed: %s\n", e.what());
        }
    }

    if (status_monitor_params.shouldRunBackup()) {
        try {
            std::string backup_dir = status_monitor_params.config_.backup_dir;
            if (backup_dir.empty()) {
                const auto pos = status_monitor_params.config_.certs_db_filename.find_last_of('/');
                backup_dir = (pos != std::string::npos)
                    ? status_monitor_params.config_.certs_db_filename.substr(0, pos)
                    : ".";
            }

            char time_buf[32] = {0};
            const time_t now_time = time(nullptr);
            struct tm tm_buf;
            gmtime_r(&now_time, &tm_buf);
            strftime(time_buf, sizeof(time_buf), "%Y%m%d_%H%M%S", &tm_buf);
            std::string backup_path = backup_dir + "/certs_backup_" + time_buf + ".db";
            ensureDirectoryExists(backup_path);

            if (performBackup(status_monitor_params.certs_db_.get(), backup_path)) {
                status_monitor_params.recordBackupRun();
                pruneOldBackups(backup_dir, status_monitor_params.config_.backup_retention);
            }
        } catch (const std::exception &e) {
            log_err_printf(pvacms, "Periodic backup failed: %s\n", e.what());
        }
    }

    uint32_t computed_secs;
    if (near_transition_count == 0) {
        computed_secs = clamped_interval_max;
    } else if (near_transition_count >= 100) {
        computed_secs = clamped_interval_min;
    } else {
        computed_secs = clamped_interval_max
            - (clamped_interval_max - clamped_interval_min) * near_transition_count / 100;
    }

    if (computed_secs < clamped_interval_min) computed_secs = clamped_interval_min;
    if (computed_secs > clamped_interval_max) computed_secs = clamped_interval_max;

    {
        struct tm now_tm;
        gmtime_r(&now, &now_tm);
        int now_mins = now_tm.tm_hour * 60 + now_tm.tm_min;
        int now_day = now_tm.tm_wday;
        uint32_t min_sched_secs = computed_secs;

        sqlite3_stmt *sched_stmt = nullptr;
        if (sqlite3_prepare_v2(status_monitor_params.certs_db_.get(),
                               "SELECT DISTINCT cs.start_time, cs.end_time, cs.day_of_week "
                               "FROM cert_schedules cs "
                               "INNER JOIN certs c ON c.serial = cs.serial "
                               "WHERE c.status IN (?, ?)",
                               -1,
                               &sched_stmt,
                               nullptr) == SQLITE_OK) {
            sqlite3_bind_int(sched_stmt, 1, VALID);
            sqlite3_bind_int(sched_stmt, 2, SCHEDULED_OFFLINE);
            while (sqlite3_step(sched_stmt) == SQLITE_ROW) {
                auto col = [&](int c) -> std::string {
                    auto t = sqlite3_column_text(sched_stmt, c);
                    return t ? reinterpret_cast<const char*>(t) : "";
                };
                auto start_str = col(0);
                auto end_str = col(1);
                auto day_str = col(2);

                if (day_str != "*") {
                    int day = day_str[0] - '0';
                    if (day != now_day) continue;
                }

                int start_mins = std::stoi(start_str.substr(0, 2)) * 60 + std::stoi(start_str.substr(3, 2));
                int end_mins = std::stoi(end_str.substr(0, 2)) * 60 + std::stoi(end_str.substr(3, 2));

                auto secsUntil = [&](int boundary_mins) -> uint32_t {
                    int diff = boundary_mins - now_mins;
                    if (diff <= 0) return std::numeric_limits<uint32_t>::max();
                    return static_cast<uint32_t>(diff * 60);
                };

                uint32_t to_start = secsUntil(start_mins);
                uint32_t to_end = secsUntil(end_mins);
                min_sched_secs = std::min(min_sched_secs, std::min(to_start, to_end));
            }
            sqlite3_finalize(sched_stmt);
        }
        if (min_sched_secs < computed_secs) {
            computed_secs = std::max(min_sched_secs, clamped_interval_min);
            log_debug_printf(pvacmsmonitor, "Adaptive monitor: schedule boundary in %us, using interval=%us\n",
                             min_sched_secs, computed_secs);
        }
    }

    log_debug_printf(pvacmsmonitor, "Adaptive monitor: %u certs near transition, interval=%us\n",
                     near_transition_count, computed_secs);

    log_debug_printf(pvacmsmonitor, "Certificate Monitor Thread Sleep%s", "\n");
    return {static_cast<long>(computed_secs), 0};
}

std::map<const std::string, std::unique_ptr<client::Config>> getAuthNConfigMap() {
    std::map<const std::string, std::unique_ptr<client::Config>> authn_config_map;

    for (auto &authn_entry : AuthRegistry::getRegistry()) {
        auto &auth = authn_entry.second;
        std::unique_ptr<client::Config> auth_config;
        auth->fromEnv(auth_config);
        auth->configure(*auth_config);
        authn_config_map[authn_entry.first] = std::move(auth_config);
    }
    return authn_config_map;
}

int readParameters(int argc,
                   char *argv[],
                   const char *program_name,
                   ConfigCms &config,
                   std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map,
                   bool &verbose,
                   std::string &admin_name,
                   std::string &admin_name_ensure) {
    std::string cert_auth_password_file, pvacms_password_file, admin_password_file;
    bool show_version{false}, help{false};
    bool create_client_cert_in_valid_state{false}, create_server_cert_in_valid_state{false},
        create_ioc_cert_in_valid_state{false}, create_all_certs_in_valid_state{false};
    bool disallow_custom_durations_client{false}, disallow_custom_durations_server{false},
        disallow_custom_durations_ioc{false}, disallow_custom_durations{false};
    std::string cert_status_subscription, cert_validity, cert_pv_prefix;

    CLI::App app{"PVACMS - Certificate Management Service"};

    // Define options
    app.set_help_flag("", "");  // deactivate built-in help

    app.add_flag("-h,--help", help);
    app.add_flag("-v,--verbose", verbose, "Make more noise");
    app.add_flag("-V,--version", show_version, "Print version and exit.");

    app.add_option("-c,--cert-auth-keychain",
                   config.cert_auth_keychain_file,
                   "Specify Certificate Authority keychain file location");
    app.add_option("--cert-auth-keychain-pwd",
                   cert_auth_password_file,
                   "Specify Certificate Authority keychain password file location");
    app.add_option("--cert-auth-name",
                   config.cert_auth_name,
                   "Specify the Certificate Authority's name. Used if we need to create a root certificate");
    app.add_option("--cert-auth-org",
                   config.cert_auth_organization,
                   "Specify the Certificate Authority's Organization. Used if we need to create a root certificate");
    app.add_option("--cert-auth-org-unit",
                   config.cert_auth_organizational_unit,
                   "Specify the Certificate Authority's Organization Unit. Used if we need to create a root "
                   "certificate");
    app.add_option("--cert-auth-country",
                   config.cert_auth_country,
                   "Specify the Certificate Authority's Country. Used if we need to create a root certificate");
    app.add_option("-d,--cert-db", config.certs_db_filename, "Specify cert db file location");

    app.add_option("-p,--pvacms-keychain", config.tls_keychain_file, "Specify PVACMS keychain file location");
    app.add_option("--pvacms-keychain-pwd", pvacms_password_file, "Specify PVACMS keychain password file location");
    app.add_option("--pvacms-name",
                   config.pvacms_name,
                   "Specify the PVACMS name. Used if we need to create a PVACMS certificate");
    app.add_option("--pvacms-org",
                   config.pvacms_organization,
                   "Specify the PVACMS Organization. Used if we need to create a PVACMS certificate");
    app.add_option("--pvacms-org-unit",
                   config.pvacms_organizational_unit,
                   "Specify the PVACMS Organization Unit. Used if we need to create a PVACMS certificate");
    app.add_option("--pvacms-country",
                   config.pvacms_country,
                   "Specify the PVACMS Country. Used if we need to create a PVACMS certificate");
    app.add_option("--preload-cert", config.preload_cert_files, "Certificate keychain file(s) to preload into the certs DB");
    app.add_option("-a,--admin-keychain",
                   config.admin_keychain_file,
                   "Specify PVACMS admin user's keychain file location");
    app.add_option("--admin-keychain-new", admin_name, "Generate a new admin keychain and exit.");
    app.add_option("--admin-keychain-ensure",
                   admin_name_ensure,
                   "Ensure the admin keychain exists at startup: create one if missing, skip with a warning if a cert "
                   "with the same subject is already registered, then continue running PVACMS.");
    app.add_option("--admin-keychain-pwd",
                   admin_password_file,
                   "Specify PVACMS admin user's keychain password file location");
    app.add_option("--acf", config.pvacms_acf_filename, "Admin Security Configuration File");

    app.add_flag("--client-dont-require-approval",
                 create_client_cert_in_valid_state,
                 "Generate Client Certificates in VALID state");
    app.add_flag("--server-dont-require-approval",
                 create_server_cert_in_valid_state,
                 "Generate Server Certificates in VALID state");
    app.add_flag("--ioc-dont-require-approval",
                 create_ioc_cert_in_valid_state,
                 "Generate IOC Certificates in VALID state");
    app.add_flag("--certs-dont-require-approval",
                 create_all_certs_in_valid_state,
                 "Generate All Certificates in VALID state");

    app.add_option("--cert_validity-client",
                   config.default_client_cert_validity,
                   "Specify PVACMS default duration for client certificates");

    app.add_option("--cert_validity-server",
                   config.default_client_cert_validity,
                   "Specify PVACMS default duration for server certificates");

    app.add_option("--cert_validity-ioc",
                   config.default_client_cert_validity,
                   "Specify PVACMS default duration for IOC certificates");

    app.add_option("--cert_validity",
                   cert_validity,
                   "Specify PVACMS default duration for all certificates");

    app.add_flag("--disallow-custom-durations-client",
                 disallow_custom_durations_client,
                 "Disallow custom durations for client certificates");
    app.add_flag("--disallow-custom-durations-server",
                 disallow_custom_durations_server,
                 "Disallow custom durations for server certificates");
    app.add_flag("--disallow-custom-durations-ioc",
                 disallow_custom_durations_ioc,
                 "Disallow custom durations for IOC certificates");
    app.add_flag("--disallow-custom-durations", disallow_custom_durations, "Disallow custom durations");

    app.add_option("--status-validity-mins", config.cert_status_validity_mins, "Set Status Validity Time in Minutes");
    app.add_option("--status-monitoring-enabled",
                 cert_status_subscription,
                 "Require Peers to monitor Status of Certificates Generated by this server by default.  Can be "
                 "overridden in each CCR");
    app.add_option("--cert-pv-prefix",
                   cert_pv_prefix,
                   "Specifies the prefix for all PVs published by this PVACMS.  Default `CERT`");
    app.add_option("--health-pv-prefix",
                   config.health_pv_prefix,
                   "Prefix for health check PV name.  Default `CERT:HEALTH`");
    app.add_option("--metrics-pv-prefix",
                   config.metrics_pv_prefix,
                   "Prefix for operational metrics PV name.  Default `CERT:METRICS`");
    app.add_option("--cluster-pv-prefix",
                   config.cluster_pv_prefix,
                   "Prefix for cluster PV names.  Default `CERT:CLUSTER`");
    app.add_flag("--cluster-mode",
                config.cluster_mode,
                "Enable cluster mode for multi-node replication");
    app.add_option("--cluster-discovery-timeout",
                   config.cluster_discovery_timeout_secs,
                   "Seconds to wait for cluster discovery before bootstrapping.  Default 10");
    app.add_option("--cluster-bidi-timeout",
                   config.cluster_bidi_timeout_secs,
                   "Seconds to wait for bidirectional connectivity check during join.  Default 5");
    app.add_option("--integrity-check-interval",
                   config.integrity_check_interval_secs,
                   "Seconds between SQLite integrity checks and WAL checkpoints.  0 to disable.  Default 86400");
    app.add_option("--audit-retention-days",
                   config.audit_retention_days,
                   "Days to retain audit log records.  0 to disable pruning.  Default 365");
    app.add_option("--rate-limit",
                   config.rate_limit,
                   "Sustained certificate creation rate limit in requests per second.  0 to disable.  Default 10");
    app.add_option("--rate-limit-burst",
                   config.rate_limit_burst,
                   "Certificate creation burst capacity.  Default 50");
    app.add_option("--max-concurrent-ccr",
                   config.max_concurrent_ccr,
                   "Maximum number of in-flight certificate creation requests.  Default 100");
    app.add_option("--monitor-interval-min",
                   config.monitor_interval_min_secs,
                   "Minimum status monitor interval in seconds.  Default 5");
    app.add_option("--monitor-interval-max",
                   config.monitor_interval_max_secs,
                   "Maximum status monitor interval in seconds.  Default 60");
    app.add_option("--backup", config.backup_path,
                   "Perform one-shot database backup to specified path, then exit");
    app.add_option("--backup-interval", config.backup_interval_secs,
                   "Seconds between periodic database backups.  0=disabled.  Default 0");
    app.add_option("--backup-dir", config.backup_dir,
                   "Directory for periodic backup files.  Default: same as database file");
    app.add_option("--backup-retention", config.backup_retention,
                   "Maximum number of backup files to keep.  Default 7");
    // Add any parameters for any registered authn methods
    for (auto &authn_entry : AuthRegistry::getRegistry())
        authn_entry.second->addOptions(app, authn_config_map);

    CLI11_PARSE(app, argc, argv);

    if (help) {
        std::string authn_help, authn_options;
        for (auto &authn_entry : AuthRegistry::getRegistry())
            authn_options += authn_entry.second->getOptionsPlaceholderText();
        for (auto &authn_entry : AuthRegistry::getRegistry())
            authn_help += authn_entry.second->getOptionsHelpText();

        std::cout
            << "PVACMS: PVAccess Certificate Management Service v"
            << PVACMS_MAJOR_VERSION << "."
            << PVACMS_MINOR_VERSION << "."
            << PVACMS_MAINTENANCE_VERSION << "\n"
            << std::endl
            << "Manages Certificates for a Secure PVAccess network.  The Certificate Authority.  Handles Create \n"
            << "and Revoke requests.  Manages Certificate lifecycles and provides live OCSP certificate status.\n"
            << std::endl
            << "Also can be used to re-generate the admin certificate that is required to administer the "
               "certificates.\n"
            << std::endl
            << "usage:\n"
            << "  " << program_name << " [admin options]" << authn_options << " [options]\n"
            << "                                             Run PVACMS.  Interrupt to quit\n"
            << "  " << program_name << " (-h | --help)                       Show this help message and exit\n"
            << "  " << program_name << " (-V | --version)                    Print version and exit\n"
            << "  " << program_name << " [admin options] --admin-keychain-new <new_name>\n"
            << "                                             Generate a new Admin User's keychain file, update the ACF "
               "file, and exit\n"
            << std::endl
            << "options:\n"
            << "  (-c | --cert-auth-keychain) <cert_auth_keychain>\n"
            << "                                             Specify Certificate Authority keychain file location. "
               "Default "
               "${XDG_CONFIG_HOME}/pva/1.5/cert_auth.p12\n"
            << "        --cert-auth-keychain-pwd <file>      Specify location of file containing Certificate Authority "
               "keychain file's password\n"
            << "        --cert-auth-name <name>              Specify name (CN) to be used for certificate authority "
               "certificate. Default `EPICS Root "
               "Certificate Authority`\n"
            << "        --cert-auth-org <name>               Specify organisation (O) to be used for certificate "
               "authority certificate. Default "
               "`certs.epics.org`\n"
            << "        --cert-auth-org-unit <name>          Specify organisational unit (OU) to be used for "
               "certificate authority certificate. Default "
               "`EPICS Certificate "
               "Authority`\n"
            << "        --cert-auth-country <name>           Specify country (C) to be used for certificate authority "
               "certificate. Default `US`\n"
            << "  (-d | --cert-db) <db_name>                 Specify cert db file location. Default "
               "${XDG_DATA_HOME}/pva/1.5/certs.db\n"
            << "  (-p | --pvacms-keychain) <pvacms_keychain> Specify PVACMS keychain file location. Default "
               "${XDG_CONFIG_HOME}/pva/1.5/pvacms.p12\n"
            << "        --pvacms-keychain-pwd <file>         Specify location of file containing PVACMS keychain "
               "file's password\n"
            << "        --pvacms-name <name>                 Specify name (CN) to be used for PVACMS certificate. "
               "Default `PVACMS Service`\n"
            << "        --pvacms-org <name>                  Specify organisation (O) to be used for PVACMS "
               "certificate. Default `certs.epics.org`\n"
            << "        --pvacms-org-unit <name>             Specify organisational unit (OU) to be used for PVACMS "
               "certificate. Default `EPICS PVA "
               "Certificate Management Service`\n"
            << "        --pvacms-country <name>              Specify country (C) to be used for PVACMS certificate. "
               "Default US\n"
            << "        --client-dont-require-approval       Generate Client Certificates in VALID state\n"
            << "        --ioc-dont-require-approval          Generate IOC Certificates in VALID state\n"
            << "        --server-dont-require-approval       Generate Server Certificates in VALID state\n"
            << "        --certs-dont-require-approval        Generate All Certificates in VALID state\n"
            << "        --cert_validity-client <duration>    Default duration for client certificates\n"
            << "        --cert_validity-server <duration>    Default duration for server certificates\n"
            << "        --cert_validity-ioc <duration>       Default duration for IOC certificates\n"
            << "        --cert_validity <duration>           Default duration for all certificates\n"
            << "        --disallow-custom-durations-client   Disallow custom durations for client certificates\n"
            << "        --disallow-custom-durations-server   Disallow custom durations for server certificates\n"
            << "        --disallow-custom-durations-ioc      Disallow custom durations for IOC certificates\n"
            << "        --disallow-custom-durations          Disallow custom durations\n"
            << "        --status-monitoring-enabled <YES|NO> Require Peers to monitor Status of Certificates Generated "
               "by this\n"
            << "                                             server by default. Can be overridden in each CCR\n"
            << "        --preload-cert <cert_file> ...       A list of certificate files you want to pre-load on startup\n"
            << "        --status-validity-mins               Set Status Validity Time in Minutes\n"
            << "        --cert-pv-prefix <cert_pv_prefix>    Specifies the prefix for all PVs published by this "
               "PVACMS.  Default `CERT`\n"
            << "        --health-pv-prefix <prefix>          Health check PV name prefix. Default `CERT:HEALTH`\n"
            << "        --metrics-pv-prefix <prefix>         Operational metrics PV name prefix. Default `CERT:METRICS`\n"
            << "        --cluster-mode                        Enable cluster mode for multi-node replication\n"
            << "        --cluster-pv-prefix <prefix>         Prefix for cluster PV names. Default `CERT:CLUSTER`\n"
            << "        --cluster-discovery-timeout <secs>   Seconds to wait for cluster discovery. Default 10\n"
            << "        --cluster-bidi-timeout <secs>        Seconds to wait for bidirectional connectivity check during join. Default 5\n"
            << "        --integrity-check-interval <secs>    Seconds between SQLite integrity checks. 0=disabled. Default 86400\n"
            << "        --audit-retention-days <days>        Days to retain audit log records. 0=disabled. Default 365\n"
            << "        --rate-limit <reqs/sec>              Sustained certificate creation rate limit. 0=disabled. Default 10\n"
            << "        --rate-limit-burst <count>           Certificate creation burst capacity. Default 50\n"
            << "        --max-concurrent-ccr <count>         Maximum in-flight certificate creation requests. Default 100\n"
            << "        --monitor-interval-min <secs>        Minimum status monitor interval. Default 5\n"
            << "        --monitor-interval-max <secs>        Maximum status monitor interval. Default 60\n"
            << "        --backup <path>                      One-shot backup to specified path, then exit\n"
            << "        --backup-interval <secs>             Seconds between periodic backups. 0=disabled. Default 0\n"
            << "        --backup-dir <path>                  Directory for periodic backup files\n"
            << "        --backup-retention <count>           Maximum backup files to keep. Default 7\n"
            << "  (-v | --verbose)                           Verbose mode\n"
            << std::endl
            << "admin options:\n"
            << "        --acf <acf_file>                     Specify Admin Security Configuration File. Default "
               "${XDG_CONFIG_HOME}/pva/1.5/pvacms.acf\n"
            << "  (-a | --admin-keychain) <admin_keychain>   Specify Admin User's keychain file location. Default "
               "${XDG_CONFIG_HOME}/pva/1.5/admin.p12\n"
            << "        --admin-keychain-pwd <file>          Specify location of file containing Admin User's keychain "
               "file password\n"
            << "        --admin-keychain-ensure <new_name>   Ensure the Admin User's keychain exists at startup:\n"
            << "                                             create one if missing; skip with a warning if a certificate\n"
            << "                                             with that subject is already registered; update the ACF file;\n"
            << "                                             then continue running PVACMS.\n"
            << "                                             Mutually exclusive with --admin-keychain-new.\n"
            << authn_help << std::endl;
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

    // --admin-keychain-new and --admin-keychain-ensure are mutually exclusive
    if (!admin_name.empty() && !admin_name_ensure.empty()) {
        std::cerr << "Error: --admin-keychain-new and --admin-keychain-ensure cannot be used together.\n";
        exit(12);
    }

    // New admin can only be specified with --acf and/or --admin-keychain-pwd, and/or --admin-keychain-pwd
    if (!admin_name.empty()) {
        for (auto arg = 1; arg < argc; ++arg) {
            const std::string option = argv[arg];
            if (option == "-a" || option == "--admin-keychain" || option == "--admin-keychain-pwd" ||
                option == "--acf" || option == "--admin-keychain-new") {
                arg++;
            } else {
                std::cerr << "Error: --admin-keychain-new option cannot be used with any options other than -a, "
                             "--admin-keychain, --admin-keychain-pwd, or --acf.\n";
                exit(11);
            }
        }
    }

    // Make sure some directories exist and read some passwords
    if (!config.cert_auth_keychain_file.empty())
        ensureDirectoryExists(config.cert_auth_keychain_file);
    if (!config.tls_keychain_file.empty())
        ensureDirectoryExists(config.tls_keychain_file);
    if (!config.pvacms_acf_filename.empty())
        ensureDirectoryExists(config.pvacms_acf_filename);
    if (!config.admin_keychain_file.empty())
        ensureDirectoryExists(config.admin_keychain_file);
    if (!config.certs_db_filename.empty())
        ensureDirectoryExists(config.certs_db_filename);
    if (!config.backup_path.empty())
        ensureDirectoryExists(config.backup_path);
    if (!cert_auth_password_file.empty()) {
        ensureDirectoryExists(cert_auth_password_file);
        config.cert_auth_keychain_pwd = getFileContents(cert_auth_password_file);
    }
    if (!pvacms_password_file.empty()) {
        ensureDirectoryExists(pvacms_password_file);
        config.setKeychainPassword(getFileContents(pvacms_password_file));
    }
    if (!admin_password_file.empty()) {
        ensureDirectoryExists(admin_password_file);
        config.admin_keychain_pwd = getFileContents(admin_password_file);
    }

    if (create_all_certs_in_valid_state)
        config.cert_client_require_approval = config.cert_server_require_approval = config.cert_ioc_require_approval =
            false;
    if (create_client_cert_in_valid_state)
        config.cert_client_require_approval = false;
    if (create_server_cert_in_valid_state)
        config.cert_server_require_approval = false;
    if (create_ioc_cert_in_valid_state)
        config.cert_ioc_require_approval = false;

    if (!cert_validity.empty()) {
        config.default_client_cert_validity = config.default_server_cert_validity = config.default_ioc_cert_validity =
            cert_validity;
    }

    if (disallow_custom_durations)
        config.cert_disallow_client_custom_duration = config.cert_disallow_server_custom_duration =
            config.cert_disallow_ioc_custom_duration = true;
    if (disallow_custom_durations_client)
        config.cert_disallow_client_custom_duration = true;
    if (disallow_custom_durations_server)
        config.cert_disallow_server_custom_duration = true;
    if (disallow_custom_durations_ioc)
        config.cert_disallow_ioc_custom_duration = true;

    // Override some settings for PVACMS
    config.tls_client_cert_required = ConfigCommon::Optional;

    if (!cert_status_subscription.empty()) {
        try {
            config.cert_status_subscription = static_cast<CertStatusSubscription>(parseTo<int8_t>(cert_status_subscription));
        } catch (const NoConvert &e) {
            std::cerr << "Error: --status-monitoring-enabled: " << e.what() << std::endl;
            exit(11);
        }
    }

    if ( !cert_pv_prefix.empty() ) {
        config.setCertPvPrefix(cert_pv_prefix);
    }

    return 0;
}

}  // namespace cms
