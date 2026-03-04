/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clustersync.h"

#include <stdexcept>
#include <string>
#include <vector>

#include <epicsMutex.h>
#include <epicsGuard.h>

#include <pvxs/log.h>

#include <sqlite3.h>

DEFINE_LOGGER(pvacmscluster, "pvxs.certs.cluster");

namespace pvxs {
namespace certs {

typedef epicsGuard<epicsMutex> Guard;

ClusterSyncPublisher::ClusterSyncPublisher(const std::string &node_id,
                                           const std::string &issuer_id,
                                           const std::string &pv_prefix,
                                           sqlite3 *certs_db,
                                           const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                           epicsMutex &status_update_lock)
    : node_id_(node_id)
    , issuer_id_(issuer_id)
    , sync_pv_name_(pv_prefix + ":SYNC:" + issuer_id + ":" + node_id)
    , certs_db_(certs_db)
    , cert_auth_pkey_(cert_auth_pkey)
    , status_update_lock_(status_update_lock)
    , sync_pv_(server::SharedPV::buildReadonly())
    , members_({{node_id, sync_pv_name_}})
{}

Value serializeCertsTable(sqlite3 *certs_db,
                          const std::string &node_id,
                          const std::vector<ClusterMember> &members,
                          const Value &prototype) {
    auto val = prototype ? prototype.cloneEmpty() : makeClusterSyncValue();
    val["node_id"] = node_id;
    val["timestamp"] = static_cast<int64_t>(std::time(nullptr));

    shared_array<Value> members_arr(members.size());
    for (size_t i = 0; i < members.size(); i++) {
        members_arr[i] = val["members"].allocMember();
        members_arr[i]["node_id"] = members[i].node_id;
        members_arr[i]["sync_pv"] = members[i].sync_pv;
    }
    val["members"] = members_arr.freeze();

    sqlite3_stmt *stmt;
    const char *sql = "SELECT serial, skid, CN, O, OU, C, approved, "
                      "not_before, not_after, renew_by, renewal_due, "
                      "status, status_date FROM certs";
    if (sqlite3_prepare_v2(certs_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("Failed to query certs: ") + sqlite3_errmsg(certs_db));
    }

    std::vector<Value> cert_rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto row = val["certs"].allocMember();
        row["serial"] = static_cast<int64_t>(sqlite3_column_int64(stmt, 0));
        auto col_text = [&](int col) -> std::string {
            auto txt = sqlite3_column_text(stmt, col);
            return txt ? reinterpret_cast<const char*>(txt) : "";
        };
        row["skid"] = col_text(1);
        row["cn"] = col_text(2);
        row["o"] = col_text(3);
        row["ou"] = col_text(4);
        row["c"] = col_text(5);
        row["approved"] = static_cast<int32_t>(sqlite3_column_int(stmt, 6));
        row["not_before"] = static_cast<int64_t>(sqlite3_column_int64(stmt, 7));
        row["not_after"] = static_cast<int64_t>(sqlite3_column_int64(stmt, 8));
        row["renew_by"] = static_cast<int64_t>(sqlite3_column_int64(stmt, 9));
        row["renewal_due"] = static_cast<int32_t>(sqlite3_column_int(stmt, 10));
        row["status"] = static_cast<int32_t>(sqlite3_column_int(stmt, 11));
        row["status_date"] = static_cast<int64_t>(sqlite3_column_int64(stmt, 12));
        cert_rows.push_back(std::move(row));
    }
    sqlite3_finalize(stmt);

    shared_array<Value> certs_arr(cert_rows.size());
    for (size_t i = 0; i < cert_rows.size(); i++) {
        certs_arr[i] = std::move(cert_rows[i]);
    }
    val["certs"] = certs_arr.freeze();

    return val;
}

void ClusterSyncPublisher::publishSnapshot() {
    publishSnapshot(members_);
}

void ClusterSyncPublisher::publishSnapshot(const std::vector<ClusterMember> &members) {
    if (sync_ingestion_in_progress.load())
        return;

    members_ = members;

    Guard G(status_update_lock_);

    auto val = serializeCertsTable(certs_db_, node_id_, members_, prototype_);

    const auto canonical = canonicalizeSync(val);
    clusterSign(cert_auth_pkey_, val, canonical);

    auto cert_count = val["certs"].as<shared_array<const Value>>().size();

    if (!opened_) {
        prototype_ = val;
        sync_pv_.open(val);
        opened_ = true;
    } else {
        sync_pv_.post(val);
    }

    log_debug_printf(pvacmscluster, "Published sync snapshot with %zu certs\n", cert_count);
}

std::string ClusterSyncPublisher::getSyncPvName() const {
    return sync_pv_name_;
}

}  // namespace certs
}  // namespace pvxs
