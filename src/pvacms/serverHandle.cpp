/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <future>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <asLib.h>
#include <epicsThread.h>
#include <epicsTime.h>

#include <openssl/bio.h>
#include <openssl/x509.h>

#include <pvxs/client.h>
#include <pvxs/credentials.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/sharedpv.h>

#include "pvacms.h"
#include "certstatusfactory.h"
#include "clusterctrl.h"
#include "clusterdiscovery.h"
#include "clustersync.h"
#include "serverev.h"
#include "sqlite3.h"
#include "utilpvt.h"

#include <dbBase.h>

#include <pvxs/cms/pvacms.h>

DEFINE_LOGGER(pvacmsserver, "cms.certs.cms");

namespace {

using ::cms::cert::ScheduleWindow;

bool isValidScheduleTime(const std::string &t)
{
    if (t.size() != 5u || t[2] != ':') {
        return false;
    }
    if (!std::isdigit(static_cast<unsigned char>(t[0])) ||
        !std::isdigit(static_cast<unsigned char>(t[1])) ||
        !std::isdigit(static_cast<unsigned char>(t[3])) ||
        !std::isdigit(static_cast<unsigned char>(t[4]))) {
        return false;
    }
    const int h = std::stoi(t.substr(0u, 2u));
    const int m = std::stoi(t.substr(3u, 2u));
    return h >= 0 && h <= 23 && m >= 0 && m <= 59;
}

std::vector<ScheduleWindow> loadScheduleWindows(sqlite3 *db, uint64_t serial)
{
    std::vector<ScheduleWindow> windows;
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db,
                           SQL_SELECT_SCHEDULES_BY_SERIAL,
                           -1,
                           &stmt,
                           nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt,
                           sqlite3_bind_parameter_index(stmt, ":serial"),
                           static_cast<sqlite3_int64>(serial));
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
    if (stmt) {
        sqlite3_finalize(stmt);
    }
    return windows;
}

bool isWithinSchedule(time_t now_utc, const std::vector<ScheduleWindow> &windows)
{
    if (windows.empty()) {
        return true;
    }

    struct tm tm_buf;
    gmtime_r(&now_utc, &tm_buf);
    int current_day = tm_buf.tm_wday;
    int current_mins = tm_buf.tm_hour * 60 + tm_buf.tm_min;

    for (const auto &w : windows) {
        if (w.day_of_week != "*") {
            int day = w.day_of_week[0] - '0';
            if (day != current_day) {
                continue;
            }
        }
        int start_h = std::stoi(w.start_time.substr(0u, 2u));
        int start_m = std::stoi(w.start_time.substr(3u, 2u));
        int end_h = std::stoi(w.end_time.substr(0u, 2u));
        int end_m = std::stoi(w.end_time.substr(3u, 2u));
        int start_mins = start_h * 60 + start_m;
        int end_mins = end_h * 60 + end_m;

        if (end_mins > start_mins) {
            if (current_mins >= start_mins && current_mins < end_mins) {
                return true;
            }
        } else if (current_mins >= start_mins || current_mins < end_mins) {
            return true;
        }
    }
    return false;
}

} // namespace

namespace cms {
using pvxs::Value;
using cms::detail::SB;
using cms::cert::CertStatus;
using cms::cert::CertStatusFactory;
using cms::cert::IdFileFactory;

struct ASMember {
    std::string name{};
    ASMEMBERPVT mem{};

    ASMember() : ASMember("DEFAULT") {}

    explicit ASMember(const std::string &n)
        : name(n)
    {
        if (auto err = asAddMember(&mem, name.c_str())) {
            throw std::runtime_error(SB() << "Unable to create ASMember " << n << " : " << err);
        }
    }

    ~ASMember()
    {
        if (asRemoveMember(&mem)) {
            log_err_printf(pvacmsserver, "Unable to cleanup ASMember %s\n", name.c_str());
        }
    }
};

pvxs::cms::detail::PreparedCmsState prepareCmsState(const ConfigCms &config)
{
    pvxs::cms::detail::PreparedCmsState state;

    initCertsDatabase(state.certs_db, config.certs_db_filename);

    getOrCreateCertAuthCertificate(config,
                                   state.certs_db,
                                   state.cert_auth_cert,
                                   state.cert_auth_pkey,
                                   state.cert_auth_chain,
                                   state.cert_auth_root_cert,
                                   state.is_initialising);
    state.our_issuer_id = CertStatus::getSkId(state.cert_auth_cert);

    ensureServerCertificateExists(config,
                                  state.certs_db,
                                  state.cert_auth_cert,
                                  state.cert_auth_pkey,
                                  state.cert_auth_chain);

    auto server_cert_data = IdFileFactory::create(config.tls_keychain_file,
                                                  config.getKeychainPassword())
                                ->getCertDataFromFile();
    state.our_node_id = CertStatus::getSkId(server_cert_data.cert);
    state.our_serial = CertStatusFactory::getSerialNumber(server_cert_data.cert);

    for (const auto &preload_path : config.preload_cert_files) {
        try {
            auto preload = IdFileFactory::create(preload_path, std::string())
                               ->getCertDataFromFile();
            if (preload.cert) {
                insertLoadedCertIfMissing(config,
                                          state.certs_db,
                                          preload.cert,
                                          preload.cert_auth_chain,
                                          state.our_issuer_id,
                                          false);
            }
        } catch (const std::exception &e) {
            log_err_printf(pvacmsserver,
                           "Failed to preload certificate '%s': %s\n",
                           preload_path.c_str(),
                           e.what());
        }
    }

    return state;
}

} // namespace cms

namespace pvxs {
namespace cms {

using ::cms::ConfigCms;
namespace server = ::pvxs::server;
namespace client = ::pvxs::client;

struct ServerHandle::Pvt {
    explicit Pvt(const ConfigCms &config, detail::PreparedCmsState &&state);

    void configureHandlers();
    void openPreparedPvs();
    void prepareClusterRuntime(const std::vector<std::string> *peers);
    void runUntilShutdown();
    void stop();

    ConfigCms config_copy;
    pvxs::sql_ptr certs_db;
    pvxs::ossl_ptr<EVP_PKEY> cert_auth_pkey;
    pvxs::ossl_ptr<X509> cert_auth_cert;
    pvxs::ossl_ptr<X509> cert_auth_root_cert;
    pvxs::ossl_shared_ptr<STACK_OF(X509)> cert_auth_chain;
    pvxs::ossl_ptr<EVP_PKEY> cert_auth_pub_key;
    std::string our_issuer_id;
    std::string our_node_id;
    serial_number_t our_serial{0u};
    bool is_initialising{false};
    std::map<serial_number_t, time_t> active_status_validity;
    ::cms::ASMember as_cluster_member;
    ::cms::cluster::ClusterSyncPublisher cluster_sync;
    ::cms::cluster::ClusterController cluster_ctrl;
    server::SharedPV create_pv;
    server::SharedPV schedule_pv;
    server::SharedPV health_pv;
    server::SharedPV metrics_pv;
    server::SharedPV root_pv;
    server::SharedPV issuer_pv;
    server::WildcardPV status_pv;
    Value root_pv_value;
    Value issuer_pv_value;
    std::function<void(const std::string& skid)> check_cms_node_revocation;
    std::unique_ptr<::cms::cluster::ClusterDiscovery> cluster_discovery;
    ::cms::StatusMonitor status_monitor;
    std::shared_ptr<server::Source> wildcard_source;
    ::cms::detail::ServerEv pva_server;
    std::string cluster_status;
    bool started_{false};
    bool stopped_{false};
};

ServerHandle::Pvt::Pvt(const ConfigCms &config,
                       detail::PreparedCmsState &&state)
    : config_copy(config)
    , certs_db(std::move(state.certs_db))
    , cert_auth_pkey(std::move(state.cert_auth_pkey))
    , cert_auth_cert(std::move(state.cert_auth_cert))
    , cert_auth_root_cert(std::move(state.cert_auth_root_cert))
    , cert_auth_chain(std::move(state.cert_auth_chain))
    , cert_auth_pub_key(X509_get_pubkey(cert_auth_cert.get()))
    , our_issuer_id(std::move(state.our_issuer_id))
    , our_node_id(std::move(state.our_node_id))
    , our_serial(state.our_serial)
    , is_initialising(state.is_initialising)
    , as_cluster_member("CLUSTER")
    , cluster_sync(our_node_id,
                   our_issuer_id,
                   config_copy.cluster_pv_prefix,
                   certs_db.get(),
                   cert_auth_pkey,
                   ::cms::getStatusUpdateLock())
    , cluster_ctrl(our_issuer_id,
                   our_node_id,
                   config_copy.cluster_pv_prefix,
                   cert_auth_pkey,
                   cert_auth_pub_key,
                   cluster_sync,
                   as_cluster_member.mem,
                   config_copy.cluster_bidi_timeout_secs)
    , create_pv(server::SharedPV::buildReadonly())
    , schedule_pv(server::SharedPV::buildReadonly())
    , health_pv(server::SharedPV::buildReadonly())
    , metrics_pv(server::SharedPV::buildReadonly())
    , root_pv(server::SharedPV::buildReadonly())
    , issuer_pv(server::SharedPV::buildReadonly())
    , status_pv(server::WildcardPV::buildMailbox())
    , root_pv_value(::cms::getRootValue(our_issuer_id, cert_auth_root_cert))
    , issuer_pv_value(::cms::getIssuerValue(our_issuer_id,
                                            cert_auth_cert,
                                            cert_auth_chain))
    , status_monitor(config_copy,
                     certs_db,
                     our_issuer_id,
                     status_pv,
                     cert_auth_cert,
                     cert_auth_pkey,
                     cert_auth_chain,
                     active_status_validity)
    , pva_server(config_copy,
                 [this](short) {
                     return ::cms::statusMonitor(status_monitor);
                 })
{
    cluster_sync.skip_peer_identity_check = config_copy.cluster_skip_peer_identity_check;
    status_monitor.setHealthPV(&health_pv);
    status_monitor.setMetricsPV(&metrics_pv);
    if (config_copy.cluster_mode) {
        status_monitor.setClusterMemberCount([this]() -> uint32_t {
            return static_cast<uint32_t>(cluster_ctrl.getMembers().size());
        });
    }
}

void ServerHandle::Pvt::configureHandlers()
{
    const auto cert_auth_chain_copy = cert_auth_chain;

    create_pv.onRPC([this, cert_auth_chain_copy](const server::SharedPV &,
                                                 std::unique_ptr<server::ExecOp> &&op,
                                                 Value &&args) {
        auto created_serial = ::cms::onCreateCertificate(config_copy,
                                                         certs_db,
                                                         status_pv,
                                                         std::move(op),
                                                         std::move(args),
                                                         cert_auth_pkey,
                                                         cert_auth_cert,
                                                         cert_auth_chain_copy,
                                                         our_issuer_id);
        if (created_serial > 0) {
            cluster_sync.publishCertChange(created_serial);
        } else {
            cluster_sync.publishSnapshot();
        }
    });

    schedule_pv.onRPC([this, cert_auth_chain_copy](const server::SharedPV &,
                                                   std::unique_ptr<server::ExecOp> &&op,
                                                   Value &&args) {
        try {
            const auto creds = op->credentials();
            pvxs::ioc::Credentials credentials(*creds);
            pvxs::ioc::SecurityClient securityClient;
            static ::cms::ASMember as_member;
            securityClient.update(as_member.mem, ASL1, credentials);
            const std::string operator_str = pvxs::SB() << *creds;

            auto query = args["query"];
            auto serial = query["serial"].as<uint64_t>();
            if (serial == 0u) {
                op->error("serial is required");
                return;
            }

            const bool read_only = query["read_only"] && query["read_only"].as<bool>();
            const bool is_admin = securityClient.canWrite();
            const bool is_own_cert =
                (credentials.issuer_id == our_issuer_id &&
                 std::to_string(serial) == credentials.serial);

            if (!is_admin && !(read_only && is_own_cert)) {
                op->error("CERT:SCHEDULE operation not authorized");
                return;
            }

            std::vector<ScheduleWindow> new_windows;
            if (!read_only) {
                auto sched_arr = query["schedule"];
                if (sched_arr) {
                    auto sched = sched_arr.as<pvxs::shared_array<const Value> >();
                    for (const auto &win : sched) {
                        ScheduleWindow sw;
                        sw.day_of_week = win["day_of_week"].as<std::string>();
                        sw.start_time = win["start_time"].as<std::string>();
                        sw.end_time = win["end_time"].as<std::string>();
                        if (sw.day_of_week != "*" &&
                            (sw.day_of_week.size() != 1u ||
                             sw.day_of_week[0] < '0' ||
                             sw.day_of_week[0] > '6')) {
                            throw std::runtime_error("Invalid day_of_week: must be 0-6 or *");
                        }
                        if (!isValidScheduleTime(sw.start_time) ||
                            !isValidScheduleTime(sw.end_time)) {
                            throw std::runtime_error("Invalid time format: must be HH:MM");
                        }
                        new_windows.push_back(std::move(sw));
                    }
                }

                {
                    Guard G(::cms::getStatusUpdateLock());
                    sqlite3_stmt *del_stmt = nullptr;

                    if (sqlite3_prepare_v2(certs_db.get(),
                                           SQL_DELETE_SCHEDULES_BY_SERIAL,
                                           -1,
                                           &del_stmt,
                                           nullptr) == SQLITE_OK) {
                        sqlite3_bind_int64(del_stmt,
                                           sqlite3_bind_parameter_index(del_stmt, ":serial"),
                                           static_cast<sqlite3_int64>(serial));
                        sqlite3_step(del_stmt);
                        sqlite3_finalize(del_stmt);
                    }
                    for (const auto &sw : new_windows) {
                        sqlite3_stmt *ins_stmt = nullptr;
                        if (sqlite3_prepare_v2(certs_db.get(),
                                               SQL_INSERT_SCHEDULE,
                                               -1,
                                               &ins_stmt,
                                               nullptr) == SQLITE_OK) {
                            sqlite3_bind_int64(ins_stmt,
                                               sqlite3_bind_parameter_index(ins_stmt, ":serial"),
                                               static_cast<sqlite3_int64>(serial));
                            sqlite3_bind_text(ins_stmt,
                                              sqlite3_bind_parameter_index(ins_stmt, ":day_of_week"),
                                              sw.day_of_week.c_str(),
                                              -1,
                                              SQLITE_TRANSIENT);
                            sqlite3_bind_text(ins_stmt,
                                              sqlite3_bind_parameter_index(ins_stmt, ":start_time"),
                                              sw.start_time.c_str(),
                                              -1,
                                              SQLITE_TRANSIENT);
                            sqlite3_bind_text(ins_stmt,
                                              sqlite3_bind_parameter_index(ins_stmt, ":end_time"),
                                              sw.end_time.c_str(),
                                              -1,
                                              SQLITE_TRANSIENT);
                            sqlite3_step(ins_stmt);
                            sqlite3_finalize(ins_stmt);
                        }
                    }

                    ::cms::cert::certstatus_t current_status;
                    time_t status_date;
                    std::tie(current_status, status_date) = ::cms::getCertificateStatus(certs_db, serial);
                    if (current_status == ::cms::cert::VALID || current_status == ::cms::cert::SCHEDULED_OFFLINE) {
                        const bool in_window = isWithinSchedule(time(nullptr), new_windows);
                        ::cms::cert::certstatus_t target = in_window
                                                               ? ::cms::cert::VALID
                                                               : (new_windows.empty()
                                                                      ? ::cms::cert::VALID
                                                                      : ::cms::cert::SCHEDULED_OFFLINE);
                        if (target != current_status) {
                            ::cms::updateCertificateStatus(certs_db,
                                                           serial,
                                                           target,
                                                           -1,
                                                           {::cms::cert::VALID, ::cms::cert::SCHEDULED_OFFLINE});
                            const auto cert_status_creator(
                                ::cms::cert::CertStatusFactory(cert_auth_cert,
                                                         cert_auth_pkey,
                                                         cert_auth_chain_copy,
                                                         config_copy.cert_status_validity_mins));
                            const auto now = std::time(nullptr);
                            const auto cert_status = cert_status_creator.createPVACertificateStatus(serial,
                                                                                                     target,
                                                                                                     now,
                                                                                                     {});
                            auto cert_id = ::cms::cert::getCertId(our_issuer_id, serial);
                            auto status_pv_name = ::cms::cert::getCertStatusURI(config_copy.getCertPvPrefix(),
                                                                          cert_id);
                            ::cms::postCertificateStatus(status_pv,
                                                         status_pv_name,
                                                         serial,
                                                         cert_status,
                                                         &certs_db);
                            log_info_printf(pvacmsserver,
                                            "%s ==> %s (schedule RPC)\n",
                                            cert_id.c_str(),
                                            CERT_STATE(target));
                        }
                    }

                    std::string detail = new_windows.empty()
                                             ? "removed"
                                             : std::to_string(new_windows.size()) + " windows";
                    ::cms::insertAuditRecord(certs_db.get(),
                                             AUDIT_ACTION_SCHEDULE,
                                             operator_str,
                                             serial,
                                             detail);
                }

                cluster_sync.publishCertChange(static_cast<int64_t>(serial));
            }

            const auto current_windows = loadScheduleWindows(certs_db.get(), serial);
            auto reply = pvxs::TypeDef(pvxs::TypeCode::Struct, {
                pvxs::members::String("result"),
                pvxs::members::StructA("schedule", {
                    pvxs::members::String("day_of_week"),
                    pvxs::members::String("start_time"),
                    pvxs::members::String("end_time"),
                }),
            }).create();
            reply["result"] = "ok";
            if (!current_windows.empty()) {
                pvxs::shared_array<Value> sched_arr(current_windows.size());
                for (size_t i = 0u; i < current_windows.size(); i++) {
                    sched_arr[i] = reply["schedule"].allocMember();
                    sched_arr[i]["day_of_week"] = current_windows[i].day_of_week;
                    sched_arr[i]["start_time"] = current_windows[i].start_time;
                    sched_arr[i]["end_time"] = current_windows[i].end_time;
                }
                reply["schedule"] = sched_arr.freeze();
            }
            op->reply(reply);
        } catch (const std::exception &e) {
            op->error(pvxs::SB() << "CERT:SCHEDULE error: " << e.what());
        }
    });

    status_pv.onFirstConnect([this](server::WildcardPV &pv,
                                    const std::string &pv_name,
                                    const std::list<std::string> &parameters) {
        auto serial = ::cms::getParameters(parameters);
        ::cms::onGetStatus(config_copy,
                           certs_db,
                           our_issuer_id,
                           pv,
                           pv_name,
                           serial,
                           our_issuer_id,
                           cert_auth_pkey,
                           cert_auth_cert,
                           cert_auth_chain,
                           our_node_id);
        active_status_validity.emplace(serial, 0);
    });

    status_pv.onLastDisconnect([this](server::WildcardPV &pv,
                                      const std::string &pv_name,
                                      const std::list<std::string> &parameters) {
        pv.close(pv_name);
        active_status_validity.erase(::cms::getParameters(parameters));
    });

    status_pv.onPut([this](server::WildcardPV &pv,
                           std::unique_ptr<server::ExecOp> &&op,
                           const std::string &pv_name,
                           const std::list<std::string> &parameters,
                           Value &&value) {
        if (!pv.isOpen(pv_name)) {
            pv.open(pv_name, ::cms::CertStatus::getStatusPrototype());
        }

        const auto serial = ::cms::getParameters(parameters);
        auto state = value["state"].as<std::string>();
        std::transform(state.begin(), state.end(), state.begin(), toupper);

        const auto creds = op->credentials();
        const std::string operator_str = pvxs::SB() << *creds;

        pvxs::ioc::Credentials credentials(*creds);
        pvxs::ioc::SecurityClient securityClient;
        static ::cms::ASMember as_member;
        securityClient.update(as_member.mem, ASL1, credentials);

        const auto is_admin = securityClient.canWrite();
        const auto is_own_cert =
            (credentials.issuer_id == our_issuer_id &&
             std::to_string(serial) == credentials.serial);
        const auto is_revoke = (state == "REVOKED");

        if (is_revoke && is_own_cert) {
            if (is_admin) {
                log_err_printf(pvacmsserver,
                               "PVACMS Admin Not Allowed to Self-Revoke%s",
                               "\n");
                op->error(pvxs::SB() << state << " Admin Self-Revoke not permitted on "
                                     << our_issuer_id << ":" << serial << " by " << *creds);
                return;
            }
        } else if (!is_admin) {
            log_err_printf(pvacmsserver,
                           "PVACMS Client Not Authorised%s",
                           "\n");
            op->error(pvxs::SB() << state << " operation not authorized on "
                                 << our_issuer_id << ":" << serial << " by " << *creds);
            return;
        }

        if (is_revoke) {
            ::cms::onRevoke(config_copy,
                            certs_db,
                            our_issuer_id,
                            pv,
                            std::move(op),
                            pv_name,
                            parameters,
                            cert_auth_pkey,
                            cert_auth_cert,
                            cert_auth_chain,
                            operator_str);
            cluster_sync.publishCertChange(serial);
            if (check_cms_node_revocation) {
                auto skid = ::cms::getCertificateSkid(certs_db, serial);
                if (!skid.empty()) {
                    check_cms_node_revocation(skid);
                }
            }
        } else if (state == "APPROVED") {
            ::cms::onApprove(config_copy,
                             certs_db,
                             our_issuer_id,
                             pv,
                             std::move(op),
                             pv_name,
                             parameters,
                             cert_auth_pkey,
                             cert_auth_cert,
                             cert_auth_chain,
                             operator_str);
            cluster_sync.publishCertChange(serial);
        } else if (state == "DENIED") {
            ::cms::onDeny(config_copy,
                          certs_db,
                          our_issuer_id,
                          pv,
                          std::move(op),
                          pv_name,
                          parameters,
                          cert_auth_pkey,
                          cert_auth_cert,
                          cert_auth_chain,
                          operator_str);
            cluster_sync.publishCertChange(serial);
            if (check_cms_node_revocation) {
                auto skid = ::cms::getCertificateSkid(certs_db, serial);
                if (!skid.empty()) {
                    check_cms_node_revocation(skid);
                }
            }
        } else {
            op->error(pvxs::SB() << "Invalid certificate state requested: " << state);
        }
    });
}

void ServerHandle::Pvt::openPreparedPvs()
{
    auto wildcard = server::WildcardSource::build();
    wildcard->add(::cms::cert::getCertStatusPv(config_copy.getCertPvPrefix(), our_issuer_id), status_pv);
    wildcard_source = wildcard;
    pva_server.addSource("__wildcard", wildcard_source);

    if (config_copy.cluster_mode) {
        cluster_sync.setEnabled(true);
        pva_server.addSource("syncsrc", cluster_sync.getSource());
        pva_server.addSource("ctrlsrc", cluster_ctrl.getSource());
    }

    pva_server.addPV(::cms::cert::getCertCreatePv(config_copy.getCertPvPrefix()), create_pv)
        .addPV(::cms::cert::getCertCreatePv(config_copy.getCertPvPrefix(), our_issuer_id), create_pv)
        .addPV(config_copy.getCertPvPrefix() + ":SCHEDULE", schedule_pv)
        .addPV(config_copy.getCertPvPrefix() + ":SCHEDULE:" + our_issuer_id, schedule_pv)
        .addPV(::cms::cert::getCertAuthRootPv(config_copy.getCertPvPrefix()), root_pv)
        .addPV(::cms::cert::getCertAuthRootPv(config_copy.getCertPvPrefix(), our_issuer_id), root_pv)
        .addPV(::cms::cert::getCertIssuerPv(config_copy.getCertPvPrefix()), issuer_pv)
        .addPV(::cms::cert::getCertIssuerPv(config_copy.getCertPvPrefix(), our_issuer_id), issuer_pv)
        .addPV(config_copy.health_pv_prefix, health_pv)
        .addPV(config_copy.health_pv_prefix + ":" + our_issuer_id, health_pv)
        .addPV(config_copy.metrics_pv_prefix, metrics_pv)
        .addPV(config_copy.metrics_pv_prefix + ":" + our_issuer_id, metrics_pv);

    auto health_value = ::cms::makeHealthValue();
    health_value["value.index"] = static_cast<int32_t>(1);
    health_value["db_ok"] = true;
    health_value["ca_valid"] = true;
    health_value["uptime_secs"] = static_cast<uint64_t>(0u);
    health_value["cert_count"] = static_cast<uint64_t>(0u);
    health_value["cluster_members"] = config_copy.cluster_mode
                                            ? static_cast<uint32_t>(0u)
                                            : static_cast<uint32_t>(1u);
    health_value["last_check"] = std::string();
    health_value["alarm.severity"] = static_cast<int32_t>(0);
    health_value["alarm.status"] = static_cast<int32_t>(0);
    health_value["alarm.message"] = std::string();
    health_value["timeStamp.secondsPastEpoch"] =
        static_cast<int64_t>(time(nullptr) - POSIX_TIME_AT_EPICS_EPOCH);
    health_value["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
    health_value["timeStamp.userTag"] = static_cast<int32_t>(0);

    auto metrics_value = ::cms::makeMetricsValue();
    metrics_value["value"] = static_cast<uint64_t>(0u);
    metrics_value["certs_created"] = static_cast<uint64_t>(0u);
    metrics_value["certs_revoked"] = static_cast<uint64_t>(0u);
    metrics_value["avg_ccr_time_ms"] = 0.0;
    metrics_value["db_size_bytes"] = static_cast<uint64_t>(0u);
    metrics_value["uptime_secs"] = static_cast<uint64_t>(0u);
    metrics_value["alarm.severity"] = static_cast<int32_t>(0);
    metrics_value["alarm.status"] = static_cast<int32_t>(0);
    metrics_value["alarm.message"] = std::string();
    metrics_value["timeStamp.secondsPastEpoch"] =
        static_cast<int64_t>(time(nullptr) - POSIX_TIME_AT_EPICS_EPOCH);
    metrics_value["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
    metrics_value["timeStamp.userTag"] = static_cast<int32_t>(0);

    auto schedule_rpc_proto = pvxs::TypeDef(pvxs::TypeCode::Struct, {
        pvxs::members::Struct("query", {
            pvxs::members::UInt64("serial"),
            pvxs::members::Bool("read_only"),
            pvxs::members::StructA("schedule", {
                pvxs::members::String("day_of_week"),
                pvxs::members::String("start_time"),
                pvxs::members::String("end_time"),
            }),
        }),
    }).create();

    schedule_pv.open(schedule_rpc_proto);
    health_pv.open(health_value);
    metrics_pv.open(metrics_value);
    root_pv.open(root_pv_value);
    issuer_pv.open(issuer_pv_value);
    status_monitor.setHealthProto(health_value);
    status_monitor.setMetricsProto(metrics_value);
}

void ServerHandle::Pvt::prepareClusterRuntime(const std::vector<std::string> *peers)
{
    if (!config_copy.cluster_mode) {
        return;
    }

    auto cluster_client_config = pva_server.clientConfig();
    cluster_client_config.tls_keychain_file = config_copy.tls_keychain_file;
    cluster_client_config.setKeychainPassword(config_copy.getKeychainPassword());
    if (peers) {
        cluster_client_config.nameServers.clear();
        for (const auto &peer : *peers) {
            cluster_client_config.nameServers.push_back(peer);
        }
    } else if (auto *ns = getenv("EPICS_PVACMS_CLUSTER_NAME_SERVERS")) {
        std::istringstream iss(ns);
        std::string entry;
        while (iss >> entry) {
            cluster_client_config.nameServers.push_back(entry);
        }
    }
    auto cluster_client = cluster_client_config.build();

    cluster_ctrl.verify_bidirectional = [cluster_client](const std::string &sync_pv,
                                                         uint32_t timeout_secs) mutable -> bool {
        auto connected = std::make_shared<std::promise<void> >();
        auto future = connected->get_future();
        auto sub = cluster_client.monitor(sync_pv)
            .maskConnected(false)
            .event([connected](client::Subscription &sub) {
                try {
                    while (sub.pop()) {}
                } catch (client::Connected &) {
                    try {
                        connected->set_value();
                    } catch (...) {}
                } catch (...) {}
            })
            .exec();
        return future.wait_for(std::chrono::seconds(timeout_secs)) == std::future_status::ready;
    };

    cluster_discovery.reset(new ::cms::cluster::ClusterDiscovery(our_node_id,
                                                                 our_issuer_id,
                                                                 config_copy.cluster_pv_prefix,
                                                                 config_copy.cluster_discovery_timeout_secs,
                                                                 config_copy.cluster_skip_peer_identity_check,
                                                                 certs_db.get(),
                                                                 cert_auth_pkey,
                                                                 cert_auth_pub_key,
                                                                 ::cms::getStatusUpdateLock(),
                                                                 cluster_sync,
                                                                 cluster_ctrl,
                                                                 std::move(cluster_client)));

    cluster_sync.is_peer_connected = [this](const std::string &node_id) -> bool {
        return cluster_discovery && cluster_discovery->isPeerConnected(node_id);
    };

    check_cms_node_revocation = [this](const std::string &skid) {
        if (skid.size() < 8u) {
            return;
        }
        auto short_skid = skid.substr(0u, 8u);
        if (!cluster_ctrl.isCmsNode(skid)) {
            return;
        }
        if (short_skid == our_node_id) {
            log_err_printf(pvacmsserver,
                           "Own PVACMS certificate has been revoked (SKID: %s), shutting down\n",
                           skid.c_str());
            epicsThreadSleep(1.0);
            pva_server.interrupt();
            return;
        }
        for (const auto &m : cluster_ctrl.getMembers()) {
            if (m.node_id == short_skid) {
                log_err_printf(pvacmsserver,
                               "PVACMS peer certificate revoked, disconnecting peer %s\n",
                               m.node_id.c_str());
                cluster_sync.publishSnapshot();
                epicsThreadSleep(1.0);
                if (cluster_discovery) {
                    cluster_discovery->handleDisconnect(m.node_id);
                }
                return;
            }
        }
    };
    cluster_discovery->on_node_cert_revoked = check_cms_node_revocation;
    cluster_ctrl.is_node_revoked = [this](const std::string &node_id) {
        return ::cms::isNodeCertRevoked(certs_db, node_id);
    };
}

void ServerHandle::Pvt::runUntilShutdown()
{
    if (!is_initialising) {
        auto status_tuple = ::cms::getCertificateStatus(certs_db, our_serial);
        if (std::get<0>(status_tuple) == ::cms::REVOKED) {
            log_err_printf(pvacmsserver,
                           "****EXITING****: Cannot start PVACMS with revoked certificate, SKID: %s\n",
                           our_node_id.c_str());
            throw ::cms::StartupAbort("revoked local PVACMS certificate");
        }
    }

    if (config_copy.cluster_mode) {
        cluster_ctrl.initAsSoleNode(our_node_id, cluster_sync.getSyncPvName());
        cluster_sync.publishSnapshot();
    }
    pva_server.start();
    started_ = true;

    if (config_copy.cluster_mode) {
        if (is_initialising) {
            log_info_printf(pvacmsserver,
                            "Fresh CA init - bootstrapping as sole cluster node%s",
                            "\n");
            cluster_status = "Created new cluster";
        } else {
            log_info_printf(pvacmsserver,
                            "Attempting to join existing cluster...%s",
                            "\n");
            auto join_result = cluster_discovery->joinCluster();
            if (join_result == ::cms::cluster::ClusterDiscovery::JoinResult::Revoked) {
                log_err_printf(pvacmsserver,
                               "****EXITING****: This node's PVACMS certificate has been revoked by the cluster\n%s",
                               "");
                throw ::cms::StartupAbort("cluster revoked this PVACMS certificate");
            } else if (join_result == ::cms::cluster::ClusterDiscovery::JoinResult::Joined) {
                cluster_sync.publishSnapshot();
                cluster_status = "Joined existing cluster";
            } else {
                log_info_printf(pvacmsserver,
                                "No existing cluster found - remaining sole node%s",
                                "\n");
                cluster_status = "Created new cluster (no existing cluster found)";
            }
        }
    } else {
        cluster_status = "Disabled";
    }

    pvxs::ossl_ptr<BIO> io(BIO_new(BIO_s_mem()));
    X509_NAME_print_ex(io.get(), X509_get_subject_name(cert_auth_cert.get()), 0, XN_FLAG_ONELINE);
    char *data = nullptr;
    auto len = BIO_get_mem_data(io.get(), &data);
    auto subject_string = std::string(data, len);

    try {
        std::cout << "+=======================================+======================================="
                  << std::endl;
        std::cout << "| EPICS Secure PVAccess Certificate Management Service v"
                  << PVACMS_MAJOR_VERSION << "."
                  << PVACMS_MINOR_VERSION << "."
                  << PVACMS_MAINTENANCE_VERSION << std::endl;
        std::cout << "+---------------------------------------+---------------------------------------"
                  << std::endl;
        std::cout << "| Certificate Database                  : " << config_copy.certs_db_filename << std::endl;
        std::cout << "| Certificate Authority                 : " << subject_string << std::endl;
        std::cout << "| Certificate Authority Keychain File   : " << config_copy.cert_auth_keychain_file << std::endl;
        std::cout << "| PVACMS Keychain File                  : " << config_copy.tls_keychain_file << std::endl;
        std::cout << "| PVACMS Access Control File            : " << config_copy.pvacms_acf_filename << std::endl;
        std::cout << "+---------------------------------------+---------------------------------------"
                  << std::endl;
        std::cout << "| Cluster Node ID                       : " << our_node_id << std::endl;
        std::cout << "| Cluster Sync PV                       : " << cluster_sync.getSyncPvName() << std::endl;
        std::cout << "| Cluster Ctrl PV                       : " << cluster_ctrl.getCtrlPvName() << std::endl;
        std::cout << "| Cluster Status                        : " << cluster_status << std::endl;
        std::cout << "+---------------------------------------+---------------------------------------"
                  << std::endl;
        std::cout << "| PVACMS [" << our_issuer_id << "] Service Running     |" << std::endl;
        std::cout << "+=======================================+======================================="
                  << std::endl;

        // Intentionally keep the blocking run() here so the standalone pvacms
        // binary preserves the exact run-until-shutdown behavior it had before
        // this refactor.
        pva_server.run();

        std::cout << "\n+=======================================+======================================="
                  << std::endl;
        std::cout << "| PVACMS [" << our_issuer_id << "] Service Exiting     |" << std::endl;
        std::cout << "+=======================================+======================================="
                  << std::endl;
    } catch (const std::exception &e) {
        log_err_printf(pvacmsserver, "PVACMS error: %s\n", e.what());
    }
}

void ServerHandle::Pvt::stop()
{
    if (stopped_) {
        return;
    }
    stopped_ = true;

    check_cms_node_revocation = std::function<void(const std::string&)>{};
    cluster_sync.is_peer_connected = std::function<bool(const std::string&)>{};
    cluster_ctrl.verify_bidirectional = std::function<bool(const std::string&, uint32_t)>{};
    cluster_ctrl.is_node_revoked = std::function<bool(const std::string&)>{};
    cluster_sync.setEnabled(false);

    if (cluster_discovery) {
        cluster_discovery->on_node_cert_revoked = std::function<void(const std::string&)>{};
        cluster_discovery.reset();
    }

    if (started_) {
        pva_server.interrupt();
        pva_server.stop();
        started_ = false;
    }
}

ServerHandle::ServerHandle()
{}

ServerHandle::ServerHandle(ServerHandle&&) noexcept = default;
ServerHandle& ServerHandle::operator=(ServerHandle&&) noexcept = default;
ServerHandle::~ServerHandle() = default;

const server::Server& ServerHandle::pvaServer() const
{
    if (!pvt_) {
        throw std::logic_error("NULL ServerHandle");
    }
    return pvt_->pva_server.server();
}

namespace detail {

ServerHandle prepareServerFromState(const ConfigCms &config,
                                    PreparedCmsState &&state)
{
    ServerHandle handle;
    handle.pvt_.reset(new ServerHandle::Pvt(config, std::move(state)));

    ::cms::getCreateCertificateRateLimiter().configure(config.rate_limit,
                                                       config.rate_limit_burst);
    ::cms::getCreateCertificateInflightCount().store(0u);

    handle.pvt_->configureHandlers();
    if (!::cms::runSelfTests(handle.pvt_->certs_db,
                             handle.pvt_->cert_auth_cert,
                             handle.pvt_->cert_auth_pkey,
                             handle.pvt_->cert_auth_chain)) {
        log_err_printf(pvacmsserver,
                       "****EXITING****: Startup self-tests failed%s\n",
                       "");
        throw ::cms::StartupAbort("startup self-tests failed");
    }
    handle.pvt_->openPreparedPvs();

    return handle;
}

} // namespace detail

ServerHandle prepareServer(const ConfigCms &config)
{
    return detail::prepareServerFromState(config, ::cms::prepareCmsState(config));
}

void startCluster(ServerHandle &handle)
{
    if (!handle.pvt_) {
        throw std::logic_error("NULL ServerHandle");
    }
    if (handle.pvt_->started_) {
        throw std::logic_error("ServerHandle has already been started");
    }
    if (handle.pvt_->stopped_) {
        throw std::logic_error("ServerHandle has already been stopped");
    }

    handle.pvt_->prepareClusterRuntime(nullptr);
    handle.pvt_->runUntilShutdown();
}

void startCluster(ServerHandle &handle,
                  const std::vector<std::string> &peers)
{
    if (!handle.pvt_) {
        throw std::logic_error("NULL ServerHandle");
    }
    if (handle.pvt_->started_) {
        throw std::logic_error("ServerHandle has already been started");
    }
    if (handle.pvt_->stopped_) {
        throw std::logic_error("ServerHandle has already been stopped");
    }

    handle.pvt_->prepareClusterRuntime(&peers);
    handle.pvt_->runUntilShutdown();
}

void stopServer(ServerHandle &handle)
{
    if (!handle.pvt_) {
        return;
    }
    handle.pvt_->stop();
}

} // namespace cms
} // namespace pvxs
