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

#include "pvacmsVersion.h"

DEFINE_LOGGER(pvacmscluster, "pvxs.certs.cluster");

namespace pvxs {
namespace certs {

typedef epicsGuard<epicsMutex> Guard;

/**
 * @brief Constructs a ClusterSyncPublisher for the given node.
 *
 * @param node_id            Unique identifier for this PVACMS node.
 * @param issuer_id          Identifier of the certificate authority issuer.
 * @param pv_prefix          PV name prefix used to form the sync PV name.
 * @param certs_db           Open SQLite database handle containing the certificates table.
 * @param cert_auth_pkey     Private key of the certificate authority, used to sign snapshots.
 * @param status_update_lock Mutex that serializes certificate status updates.
 */
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
    , members_({{node_id, sync_pv_name_, PVACMS_MAJOR_VERSION, PVACMS_MINOR_VERSION, PVACMS_MAINTENANCE_VERSION}})
{}

/**
 * @brief Serializes the certificates table and cluster membership into a PVXS Value.
 *
 * Reads all rows from the @p certs_db certificates table and combines them with
 * the provided member list and node identity into a structured PVXS Value suitable
 * for signing and publishing on the cluster sync PV.
 *
 * @param certs_db  Open SQLite database handle containing the certificates table.
 * @param node_id   Identifier of the local node to embed in the serialized value.
 * @param members   List of cluster members to embed in the serialized value.
 * @param prototype Optional existing Value whose structure is cloned; if empty a
 *                  new Value is created via makeClusterSyncValue().
 * @return          A populated PVXS Value containing node identity, member list,
 *                  and all certificate rows from the database.
 */
Value serializeCertsTable(sqlite3 *certs_db,
                          const std::string &node_id,
                          const std::vector<ClusterMember> &members,
                          const Value &prototype) {
    auto val = prototype ? prototype.cloneEmpty() : makeClusterSyncValue();
    val["node_id"] = node_id;
    setTimeStamp(val);

    shared_array<Value> members_arr(members.size());
    for (size_t i = 0; i < members.size(); i++) {
        members_arr[i] = val["members"].allocMember();
        members_arr[i]["node_id"] = members[i].node_id;
        members_arr[i]["sync_pv"] = members[i].sync_pv;
        members_arr[i]["version_major"] = members[i].version_major;
        members_arr[i]["version_minor"] = members[i].version_minor;
        members_arr[i]["version_patch"] = members[i].version_patch;
    }
    val["members"] = members_arr.freeze();

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(certs_db, SQL_SYNC_SELECT_ALL_CERTS, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("Failed to query certs: ") + sqlite3_errmsg(certs_db));
    }

    std::vector<Value> cert_rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto row = val["certs"].allocMember();
        row["serial"] = sqlite3_column_int64(stmt, 0);
        auto col_text = [&](const int col) -> std::string {
            const auto txt = sqlite3_column_text(stmt, col);
            return txt ? reinterpret_cast<const char*>(txt) : "";
        };
        row["skid"] = col_text(1);
        row["cn"] = col_text(2);
        row["o"] = col_text(3);
        row["ou"] = col_text(4);
        row["c"] = col_text(5);
        row["approved"] = sqlite3_column_int(stmt, 6);
        row["not_before"] = sqlite3_column_int64(stmt, 7);
        row["not_after"] = sqlite3_column_int64(stmt, 8);
        row["renew_by"] = sqlite3_column_int64(stmt, 9);
        row["renewal_due"] = sqlite3_column_int(stmt, 10);
        row["status"] = sqlite3_column_int(stmt, 11);
        row["status_date"] = sqlite3_column_int64(stmt, 12);
        cert_rows.push_back(std::move(row));
    }
    sqlite3_finalize(stmt);

    shared_array<Value> certs_arr(cert_rows.size());
    for (size_t i = 0; i < cert_rows.size(); i++) certs_arr[i] = std::move(cert_rows[i]);
    val["certs"] = certs_arr.freeze();

    return val;
}

/**
 * @brief Publishes a snapshot of the current certificate table to the sync PV.
 *
 * Uses the previously known member list and marks the certificates as changed.
 */
void ClusterSyncPublisher::publishSnapshot() {
    doPublish(members_, false, true);
}

/**
 * @brief Publishes a snapshot with an updated cluster member list.
 *
 * Compares @p members against the cached list to detect changes, then
 * serializes and posts the full state including certificates.
 *
 * @param members Updated list of cluster member nodes.
 */
void ClusterSyncPublisher::publishSnapshot(const std::vector<ClusterMember> &members) {
    const bool members_changed = (members != members_);
    members_ = members;
    doPublish(members_, members_changed, false);
}

/**
 * @brief Serializes and publishes the certificate state to the sync PV.
 *
 * Builds a canonical, signed PVXS Value and either opens the PV (first call)
 * or posts a delta with only the changed fields marked.
 *
 * @param members         Current cluster member list to embed in the snapshot.
 * @param members_changed Whether the member list has changed since the last publish.
 * @param certs_changed   Whether the certificate table has changed since the last publish.
 */
void ClusterSyncPublisher::doPublish(const std::vector<ClusterMember> &members, const bool members_changed, const bool certs_changed) {
    if (sync_ingestion_in_progress.load())
        return;

    Guard G(status_update_lock_);

    // Always build the full Value - needed for canonicalization and signing
    auto val = serializeCertsTable(certs_db_, node_id_, members, prototype_);

    clusterSign(cert_auth_pkey_, val);

    const auto cert_count = val["certs"].as<shared_array<const Value>>().size();

    if (!opened_) {
        prototype_ = val;
        sync_pv_.open(val);
        opened_ = true;
    } else {
        sync_pv_.post(val);
    }

    log_debug_printf(pvacmscluster, "Published sync snapshot with %zu certs (members_changed=%d, certs_changed=%d)\n",
                     cert_count, members_changed, certs_changed);
}

/**
 * @brief Returns the fully-qualified PV name used for cluster synchronization.
 *
 * @return The sync PV name string.
 */
std::string ClusterSyncPublisher::getSyncPvName() const {
    return sync_pv_name_;
}

}  // namespace certs
}  // namespace pvxs
