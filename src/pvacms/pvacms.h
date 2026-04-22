/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The PVAccess Certificate Management Service.
 *
 *   pvacms.h
 *
 */
#ifndef PVXS_PVACMS_H
#define PVXS_PVACMS_H

#include <ctime>
#include <functional>
#include <iostream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <pvxs/sharedpv.h>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "configcms.h"
#include "openssl.h"
#include "ownedptr.h"
#include "wildcardpv.h"

#define SQL_CREATE_DB_FILE              \
    "BEGIN TRANSACTION; "               \
    "CREATE TABLE IF NOT EXISTS certs(" \
    "     serial INTEGER PRIMARY KEY,"  \
    "     skid TEXT,"                   \
    "     CN TEXT,"                     \
    "     O TEXT,"                      \
    "     OU TEXT,"                     \
    "     C TEXT,"                      \
    "     san TEXT,"                    \
    "     approved INTEGER,"            \
    "     not_before INTEGER,"          \
    "     not_after INTEGER,"           \
    "     renew_by INTEGER,"            \
    "     renewal_due INTEGER,"         \
    "     status INTEGER,"              \
    "     status_date INTEGER"          \
    "); "                               \
    "CREATE INDEX IF NOT EXISTS idx_certs_skid " \
    "     ON certs(skid); "            \
    "CREATE INDEX IF NOT EXISTS idx_certs_status " \
    "     ON certs(status); "          \
    "CREATE INDEX IF NOT EXISTS idx_certs_identity " \
    "     ON certs(CN, O, OU, C, status, not_before); "     \
    "CREATE INDEX IF NOT EXISTS idx_certs_not_after_skid " \
    "     ON certs(not_after, skid); " \
    "CREATE INDEX IF NOT EXISTS idx_certs_validity " \
    "     ON certs(not_before, not_after) ; " \
    "COMMIT;"

#define SQL_CREATE_SCHEMA_VERSION                                       \
    "CREATE TABLE IF NOT EXISTS schema_version("                        \
    "     version INTEGER NOT NULL,"                                    \
    "     applied_at INTEGER NOT NULL"                                  \
    ");"

#define SQL_INSERT_SCHEMA_VERSION                                       \
    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?);"

#define SQL_GET_SCHEMA_VERSION                                          \
    "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1;"

#define SQL_CHECK_SCHEMA_VERSION_EXISTS                                 \
    "SELECT name "                                                      \
    "FROM sqlite_master "                                               \
    "WHERE type='table' "                                               \
    "  AND name='schema_version';"

#define PVACMS_SCHEMA_VERSION 5

#define SQL_CREATE_AUDIT_TABLE                                              \
    "CREATE TABLE IF NOT EXISTS audit("                                     \
    "     id INTEGER PRIMARY KEY AUTOINCREMENT,"                            \
    "     timestamp INTEGER NOT NULL,"                                      \
    "     action TEXT NOT NULL,"                                            \
    "     operator TEXT NOT NULL,"                                          \
    "     serial INTEGER,"                                                  \
    "     detail TEXT"                                                      \
    ");"                                                                    \
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp);"

#define SQL_CREATE_CERT_SCHEDULES_TABLE                                     \
    "CREATE TABLE IF NOT EXISTS cert_schedules("                            \
    "     id INTEGER PRIMARY KEY AUTOINCREMENT,"                            \
    "     serial INTEGER NOT NULL REFERENCES certs(serial),"                \
    "     day_of_week TEXT NOT NULL,"                                       \
    "     start_time TEXT NOT NULL,"                                        \
    "     end_time TEXT NOT NULL"                                           \
    ");"                                                                    \
    "CREATE INDEX IF NOT EXISTS idx_cert_schedules_serial "                 \
    "     ON cert_schedules(serial);"

#define SQL_INSERT_SCHEDULE                                                 \
    "INSERT INTO cert_schedules(serial, day_of_week, start_time, end_time) "\
    "VALUES(:serial, :day_of_week, :start_time, :end_time)"

#define SQL_DELETE_SCHEDULES_BY_SERIAL                                      \
    "DELETE FROM cert_schedules WHERE serial = :serial"

#define SQL_SELECT_SCHEDULES_BY_SERIAL                                      \
    "SELECT day_of_week, start_time, end_time "                             \
    "FROM cert_schedules WHERE serial = :serial"

#define SQL_SELECT_CERTS_WITH_SCHEDULES                                     \
    "SELECT DISTINCT c.serial, c.status "                                   \
    "FROM certs c "                                                         \
    "INNER JOIN cert_schedules cs ON c.serial = cs.serial "                 \
    "WHERE c.status IN (:valid_status, :scheduled_offline_status)"

#define SQL_INSERT_AUDIT                                                    \
    "INSERT INTO audit(timestamp, action, operator, serial, detail) "       \
    "VALUES(:timestamp, :action, :operator, :serial, :detail)"

#define SQL_PRUNE_AUDIT                                                     \
    "DELETE FROM audit WHERE timestamp < :cutoff"

#define SQL_GET_RECENT_AUDIT                                                \
    "SELECT id, timestamp, action, operator, serial, detail "               \
    "FROM audit ORDER BY id DESC LIMIT :limit"

#define AUDIT_ACTION_CREATE   "CREATE"
#define AUDIT_ACTION_APPROVE  "APPROVE"
#define AUDIT_ACTION_REVOKE   "REVOKE"
#define AUDIT_ACTION_DENY     "DENY"
#define AUDIT_ACTION_SCHEDULE "SCHEDULE"
#define AUDIT_ACTION_SYNC     "SYNC"

#define SQL_CHECK_EXISTS_DB_FILE       \
    "SELECT name "                     \
    "FROM sqlite_master "              \
    "WHERE type='table' "              \
    "  AND name='certs';"

#define SQL_CREATE_CERT               \
    "INSERT INTO certs ( "            \
    "     serial,"                    \
    "     skid,"                      \
    "     CN,"                        \
    "     O,"                         \
    "     OU,"                        \
    "     C,"                         \
    "     san,"                       \
    "     approved,"                  \
    "     not_before,"                \
    "     not_after,"                 \
    "     renew_by,"                  \
    "     renewal_due,"               \
    "     status,"                    \
    "     status_date"                \
    ") "                              \
    "VALUES ("                        \
    "     :serial,"                   \
    "     :skid,"                     \
    "     :CN,"                       \
    "     :O,"                        \
    "     :OU,"                       \
    "     :C,"                        \
    "     :san,"                      \
    "     :approved,"                 \
    "     :not_before,"               \
    "     :not_after,"                \
    "     :renew_by,"                 \
    "     0,"                         \
    "     :status,"                   \
    "     :status_date"               \
    ")"

#define SQL_DUPS_SUBJECT              \
    "SELECT COUNT(*) "                \
    "FROM certs "                     \
    "WHERE CN = :CN "                 \
    "  AND O = :O "                   \
    "  AND OU = :OU "                 \
    "  AND C = :C "

#define SQL_DUPS_SUBJECT_KEY_IDENTIFIER \
    "SELECT COUNT(*) "                  \
    "FROM certs "                       \
    "WHERE skid = :skid "

// Get the certificate due to be renewed
#define SQL_GET_RENEWED_CERT          \
    "SELECT serial"                   \
    "     , not_after "               \
    "     , renew_by "                \
    "     , status "                  \
    "     , san "                     \
    "FROM certs "                     \
    "WHERE CN = :CN "                 \
    "  AND O = :O "                   \
    "  AND OU = :OU "                 \
    "  AND C = :C "                   \
    "  AND status IN (:status0, :status1, :status2, :status3) " \
    "  AND serial != :serial "        \
    "  AND renewal_due != 0 "         \
    "LIMIT 1 "                        \

#define SQL_TOUCH_CERT_STATUS         \
    "UPDATE certs "                   \
    "SET status_date = :status_date " \
    "WHERE serial = :serial "

#define SQL_RENEW_CERTS               \
    "UPDATE certs "                   \
    "SET status = :status "           \
    "  , status_date = :status_date " \
    "  , renew_by = :renew_by "       \
    "  , renewal_due = 0 " \
    "WHERE serial = :serial "

#define SQL_FLAG_RENEW_CERTS          \
    "UPDATE certs "                   \
    "SET status_date = :status_date " \
    "  , renewal_due = 1 " \
    "WHERE serial = :serial "

#define SQL_CERT_STATUS               \
    "SELECT status "                  \
    "     , status_date "             \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_SKID_BY_SERIAL       \
    "SELECT skid "                    \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_IS_NODE_REVOKED      \
    "SELECT 1 "                       \
    "FROM certs "                     \
    "WHERE skid LIKE :skid_prefix "   \
    "  AND status = :revoked "        \
    "LIMIT 1"

#define SQL_CERT_VALIDITY             \
    "SELECT not_before "              \
    "     , not_after "               \
    "     , renew_by "                \
    "FROM certs "                     \
    "WHERE serial = :serial"

#define SQL_CERT_SET_STATUS           \
    "UPDATE certs "                   \
    "SET status = :status "           \
    "  , status_date = :status_date " \
    "  , renewal_due = 0 "            \
    "WHERE serial = :serial "

#define SQL_CERT_SET_STATUS_W_APPROVAL \
    "UPDATE certs "                    \
    "SET status = :status "            \
    "  , approved = :approved "        \
    "  , status_date = :status_date "  \
    "  , renewal_due = 0 "            \
    "WHERE serial = :serial "

#define SQL_CERT_TO_VALID              \
    "SELECT serial "                   \
    "FROM certs "                      \
    "WHERE not_before <= :now "        \
    "  AND not_after > :now "          \
    "  AND (renew_by = 0 OR renew_by > :now) "

#define SQL_CERT_BECOMING_INVALID      \
    "SELECT serial, status "           \
    "FROM certs "                      \
    "WHERE "

#define SQL_CERT_TO_EXPIRED            \
    "SELECT serial "                   \
    "FROM certs "                      \
    "WHERE not_after <= :now "

#define SQL_CERT_TO_EXPIRED_WITH_FULL_SKID \
    "SELECT serial "                       \
    "FROM certs "                          \
    "WHERE not_after <= :now "             \
    "  AND skid = :skid "

#define SQL_CERT_TO_PENDING_RENEWAL \
    "SELECT serial "                \
    "FROM certs "                   \
    "WHERE not_before <= :now "     \
    "  AND not_after > :now "       \
    "  AND renew_by != 0 "          \
    "  AND renew_by <= :now "

#define SQL_CERT_STATUS_NEARLY_INVALID \
    "SELECT serial, status "        \
    "FROM certs "                   \
    "WHERE not_before <= :now "     \
    "  AND not_after > :now "       \
    "  AND 2 * (:now - status_date) >= :status_validity "

#define SQL_CERT_NEARING_RENEWAL   \
    "SELECT serial "               \
    "FROM certs "                  \
    "WHERE renewal_due = 0 "       \
    "  AND not_before <= :now "    \
    "  AND not_after > :now "      \
    "  AND renew_by != 0 "         \
    "  AND 2 * :now >= status_date + renew_by "

#define SQL_PRIOR_APPROVAL_STATUS \
    "SELECT approved "            \
    "FROM certs "                 \
    "WHERE CN = :CN "             \
    "  AND O = :O "               \
    "  AND OU = :OU "             \
    "  AND C = :C "               \
    "ORDER BY status_date DESC "  \
    "LIMIT 1 "

/**
 * @brief Search certificates by SAN value.
 *
 * Uses boundary-aware JSON matching to find certificates whose san column
 * contains a specific value.  Bind :san_pattern as e.g. '%"10.0.0.1"%'.
 *
 * @since UNRELEASED
 */
#define SQL_SEARCH_CERTS_BY_SAN \
    "SELECT serial, CN, san "   \
    "FROM certs "               \
    "WHERE san LIKE :san_pattern "

namespace pvxs {
namespace certs {

struct SanEntry;

std::string sanToJson(const std::vector<SanEntry> &entries);
std::vector<SanEntry> sanFromJson(const std::string &json);

/**
 * @brief Monitors the certificate status and updates the shared wildcard status pv when any become valid or expire.
 *
 * This function monitors the certificate status by connecting to the Certificate database, and searching
 * for all certificates that have just expired and all certificates that have just become valid.  If any
 * are found then the associated shared wildcard PV is updated and the new status stored in the database.
 *
 * @param certs_db The certificates-database object.
 * @param issuer_id The issuer ID.
 * @param status_pv The shared wildcard PV to notify.
 *
 * @note This function assumes that the certificate database and the status PV have been properly configured and initialized.
 * @note The status_pv parameter must be a valid WildcardPV object.
 */
class StatusMonitor {
   public:
    ConfigCms &config_;
    sql_ptr &certs_db_;
    std::string &issuer_id_;
    server::WildcardPV &status_pv_;
    ossl_ptr<X509> &cert_auth_cert_;
    ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    pvxs::ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain_;
    std::map<serial_number_t, time_t> &active_status_validity_;
   private:
    mutable epicsMutex lock_;
    mutable time_t last_maintenance_time_{0};
    mutable time_t last_checkpoint_time_{time(nullptr)};
    mutable time_t last_backup_time_{0};
    mutable bool db_integrity_ok_{true};
    server::SharedPV *health_pv_{nullptr};
    server::SharedPV *metrics_pv_{nullptr};
    Value health_proto_{};
    Value metrics_proto_{};
    time_t start_time_{0};
    std::function<uint32_t()> get_cluster_member_count_;
  public:
    StatusMonitor(ConfigCms &config, sql_ptr &certs_db, std::string &issuer_id, server::WildcardPV &status_pv, ossl_ptr<X509> &cert_auth_cert,
                  ossl_ptr<EVP_PKEY> &cert_auth_pkey, ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
                  std::map<serial_number_t, time_t> &active_status_validity)
        : config_(config),
          certs_db_(certs_db),
          issuer_id_(issuer_id),
          status_pv_(status_pv),
          cert_auth_cert_(cert_auth_cert),
          cert_auth_pkey_(cert_auth_pkey),
          cert_auth_cert_chain_(cert_auth_chain),
          active_status_validity_(active_status_validity),
          start_time_(time(nullptr)) {}

    std::vector<serial_number_t> getActiveSerials() const {
        const auto cutoff{time(nullptr) - static_cast<uint64_t>(config_.getRequestTimeout())};
        std::vector<serial_number_t> result;
        Guard G(lock_);
        for (const auto &pair : active_status_validity_) {
            if (static_cast<uint64_t>(pair.second) > cutoff) {
                result.push_back(pair.first);
            }
        }
        return result;
    }

    /**
     * @brief Set the new validity timeout after we've updated the database
     * Note that its possible that the serial has been removed by another thread during the operation
     * @param serial the serial number of the validity we need to update
     * @param validity_date the new validity date
     */
    void setValidity(const serial_number_t serial, const time_t validity_date) const {
        Guard G(lock_);
        const auto it = active_status_validity_.find(serial);
        if (it != active_status_validity_.end()) {
            it->second = validity_date;
        }
    }

    bool isDbIntegrityOk() const { return db_integrity_ok_; }

    bool shouldRunMaintenance() const {
        const auto interval = config_.integrity_check_interval_secs;
        if (interval == 0) return false;
        return (time(nullptr) - last_maintenance_time_) >= static_cast<time_t>(interval);
    }

    bool shouldRunBackup() const {
        const auto interval = config_.backup_interval_secs;
        if (interval == 0) return false;
        return (time(nullptr) - last_backup_time_) >= static_cast<time_t>(interval);
    }

    void recordMaintenanceRun() const { last_maintenance_time_ = time(nullptr); }
    void recordCheckpointRun() const { last_checkpoint_time_ = time(nullptr); }
    void recordBackupRun() const { last_backup_time_ = time(nullptr); }

    bool shouldRunCheckpoint() const {
        const auto interval = config_.integrity_check_interval_secs;
        if (interval == 0) return false;
        return (time(nullptr) - last_checkpoint_time_) >= static_cast<time_t>(interval);
    }
    void setDbIntegrityOk(bool ok) const { db_integrity_ok_ = ok; }
    void setHealthPV(server::SharedPV *pv) { health_pv_ = pv; }
    void setMetricsPV(server::SharedPV *pv) { metrics_pv_ = pv; }
    void setHealthProto(const Value &proto) { health_proto_ = proto; }
    void setMetricsProto(const Value &proto) { metrics_proto_ = proto; }
    void setClusterMemberCount(std::function<uint32_t()> fn) { get_cluster_member_count_ = std::move(fn); }
    uint32_t getClusterMemberCount() const { return get_cluster_member_count_ ? get_cluster_member_count_() : 1u; }
    server::SharedPV *getHealthPV() const { return health_pv_; }
    server::SharedPV *getMetricsPV() const { return metrics_pv_; }
    Value cloneHealthValue() const { return health_proto_.cloneEmpty(); }
    Value cloneMetricsValue() const { return metrics_proto_.cloneEmpty(); }
    time_t getStartTime() const { return start_time_; }
};

void checkForDuplicates(const sql_ptr &certs_db, const CertFactory &cert_factory);

CertData createCertAuthCertificate(const ConfigCms &config, sql_ptr &certs_db, const std::shared_ptr<KeyPair> &key_pair);

ossl_ptr<X509> createCertificate(sql_ptr &certs_db, CertFactory &cert_factory);

std::string createCertificatePemString(sql_ptr &certs_db, CertFactory &cert_factory);

void createServerCertificate(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                             const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, const std::shared_ptr<KeyPair> &key_pair);

void ensureServerCertificateExists(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                   const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain);

void ensureValidityCompatible(const CertFactory &cert_factory);

uint64_t generateSerial();

std::tuple<certstatus_t, time_t> getCertificateStatus(const sql_ptr &certs_db, uint64_t serial);
void getWorstCertificateStatus(const sql_ptr &certs_db, uint64_t serial, certstatus_t &worst_status_so_far, time_t &worst_status_time_so_far);
DbCert getCertificateValidity(const sql_ptr &certs_db, uint64_t serial);
std::string getCertificateSkid(const sql_ptr &certs_db, uint64_t serial);
bool isNodeCertRevoked(const sql_ptr &certs_db, const std::string &node_id);

std::string extractCountryCode(const std::string &locale_str);

std::string getCountryCode();

Value getCreatePrototype();

time_t getNotAfterTimeFromCert(const X509 *cert);

time_t getNotBeforeTimeFromCert(const X509 *cert);

void getOrCreateCertAuthCertificate(const ConfigCms &config, sql_ptr &certs_db, ossl_ptr<X509> &cert_auth_cert, ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                              ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, ossl_ptr<X509> &cert_auth_root_cert, bool &is_initialising);

std::vector<std::string> getCertPaths(const CertData &cert_data);
std::string toACFAuth(const std::string &id, const CertData &cert_data);
std::string toACFYamlAuth(const std::string &id, const CertData &cert_data);

void createDefaultAdminACF(const ConfigCms &config, const CertData &cert_data);

void createAdminClientCert(const ConfigCms &config, sql_ptr &certs_db, const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert,
                           const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_cert_chain, const std::string &admin_name = "admin");

void initCertsDatabase(sql_ptr &certs_db, const std::string &db_file);

bool performBackup(sqlite3 *src_db, const std::string &dest_path);

void insertAuditRecord(sqlite3 *db, const std::string &action,
                       const std::string &operator_id, uint64_t serial,
                       const std::string &detail);

bool runSelfTests(const sql_ptr &certs_db, const ossl_ptr<X509> &cert_auth_cert,
                  const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                  const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain);

int64_t onCreateCertificate(ConfigCms &config, sql_ptr &certs_db, const server::SharedPV &pv, std::unique_ptr<server::ExecOp> &&op, Value &&args,
                         const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                         const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain, std::string issuer_id);

bool getPriorApprovalStatus(const sql_ptr &certs_db, const std::string &name, const std::string &country, const std::string &organization,
                            const std::string &organization_unit);

void onGetStatus(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
                 const std::string &pv_name, serial_number_t serial, const std::string &issuer_id, const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                 const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
                 const std::string &our_node_id = {});

void onRevoke(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
              std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
              const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
              const std::string &operator_id);

void onApprove(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
               std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
               const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
               const std::string &operator_id);

void onDeny(const ConfigCms &config, const sql_ptr &certs_db, const std::string &our_issuer_id, server::WildcardPV &status_pv,
            std::unique_ptr<server::ExecOp> &&op, const std::string &pv_name, const std::list<std::string> &parameters,
            const ossl_ptr<EVP_PKEY> &cert_auth_pkey, const ossl_ptr<X509> &cert_auth_cert, const ossl_shared_ptr<STACK_OF(X509)> &cert_auth_chain,
            const std::string &operator_id);

int readOptions(ConfigCms &config, int argc, char *argv[], bool &verbose);

void updateCertificateStatus(const sql_ptr &certs_db, uint64_t serial, certstatus_t cert_status, int approval_status,
                             const std::vector<certstatus_t> &valid_status = {PENDING_APPROVAL, PENDING, VALID});

void updateCertificateRenewalStatus(const sql_ptr &certs_db, serial_number_t serial, certstatus_t cert_status, time_t renew_by);

void touchCertificateStatus(const sql_ptr &certs_db, serial_number_t serial);

certstatus_t storeCertificate(const sql_ptr &certs_db, CertFactory &cert_factory);

timeval statusMonitor(const StatusMonitor &status_monitor_params);

Value postCertificateStatus(server::WildcardPV &status_pv,
                            const std::string &pv_name,
                            uint64_t serial,
                            const PVACertificateStatus &cert_status = {},
                            const sql_ptr *certs_db = nullptr,
                            const std::string &node_id = {});

std::string getValidStatusesClause(const std::vector<certstatus_t> &valid_status);
void bindValidStatusClauses(sqlite3_stmt *sql_statement, const std::vector<certstatus_t> &valid_status = {});
uint64_t getParameters(const std::list<std::string> &parameters);

template <typename T>
void setValue(Value &target, const std::string &field, const T &new_value);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_PVACMS_H
