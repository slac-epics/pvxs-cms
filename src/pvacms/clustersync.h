/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CLUSTERSYNC_H_
#define PVXS_CLUSTERSYNC_H_

#include <atomic>
#include <string>
#include <vector>

#include <epicsMutex.h>

#include <pvxs/sharedpv.h>

#include "clustertypes.h"
#include "ownedptr.h"
#include "pvacmsVersion.h"

#define SQL_SYNC_SELECT_ALL_CERTS          \
    "SELECT serial, skid, CN, O, OU, C, "  \
    "approved, not_before, not_after, "    \
    "renew_by, renewal_due, "              \
    "status, status_date "                 \
    "FROM certs"

#define SQL_SYNC_CHECK_CERT_STATUS         \
    "SELECT status "                       \
    "FROM certs "                          \
    "WHERE serial = :serial"

#define SQL_SYNC_UPDATE_CERT               \
    "UPDATE certs "                        \
    "SET skid = :skid"                     \
    "  , CN = :CN"                         \
    "  , O = :O"                           \
    "  , OU = :OU"                         \
    "  , C = :C"                           \
    "  , approved = :approved"             \
    "  , not_before = :not_before"         \
    "  , not_after = :not_after"           \
    "  , renew_by = :renew_by"             \
    "  , renewal_due = :renewal_due"       \
    "  , status = :status"                 \
    "  , status_date = :status_date "      \
    "WHERE serial = :serial"

#define SQL_SYNC_INSERT_CERT                    \
    "INSERT INTO certs ("                       \
    "     serial,"                              \
    "     skid,"                                \
    "     CN,"                                  \
    "     O,"                                   \
    "     OU,"                                  \
    "     C,"                                   \
    "     approved,"                            \
    "     not_before,"                          \
    "     not_after,"                           \
    "     renew_by,"                            \
    "     renewal_due,"                         \
    "     status,"                              \
    "     status_date"                          \
    ") "                                        \
    "VALUES ("                                  \
    "     :serial,"                             \
    "     :skid,"                               \
    "     :CN,"                                 \
    "     :O,"                                  \
    "     :OU,"                                 \
    "     :C,"                                  \
    "     :approved,"                           \
    "     :not_before,"                         \
    "     :not_after,"                          \
    "     :renew_by,"                           \
    "     :renewal_due,"                        \
    "     :status,"                             \
    "     :status_date"                         \
    ")"

// Forward declarations
struct sqlite3;

namespace pvxs {
namespace certs {

/**
 * @brief Represents a single member node of a CMS cluster.
 *
 * Holds the node identity, its synchronization PV name, and the
 * pvacms version it is running.
 */
struct ClusterMember {
    std::string node_id;
    std::string sync_pv;
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t version_patch;

    /**
     * @brief Compares two ClusterMember instances for equality.
     *
     * @param o The other ClusterMember to compare against.
     * @return true if all fields are identical, false otherwise.
     */
    bool operator==(const ClusterMember &o) const {
        return node_id == o.node_id && sync_pv == o.sync_pv &&
               version_major == o.version_major &&
               version_minor == o.version_minor &&
               version_patch == o.version_patch;
    }

    /**
     * @brief Compares two ClusterMember instances for inequality.
     *
     * @param o The other ClusterMember to compare against.
     * @return true if any field differs, false otherwise.
     */
    bool operator!=(const ClusterMember &o) const {
        return !(*this == o);
    }
};

/**
 * @brief Publishes certificate database snapshots over PVAccess for cluster synchronization.
 *
 * Each CMS node hosts one ClusterSyncPublisher that serializes the local certificate
 * table and membership list into a signed, canonical PVXS Value and posts it on
 * a well-known synchronization PV so peer nodes can replicate the state.
 */
class ClusterSyncPublisher {
public:
    /**
     * @brief Constructs a ClusterSyncPublisher for the given node.
     *
     * @param node_id            Unique identifier for this CMS node.
     * @param issuer_id          Identifier of the certificate authority issuer.
     * @param pv_prefix          PV name prefix used to form the sync PV name.
     * @param certs_db           Open SQLite database handle containing the certificates table.
     * @param cert_auth_pkey     Private key of the certificate authority, used to sign snapshots.
     * @param status_update_lock Mutex that serializes certificate status updates.
     */
    ClusterSyncPublisher(const std::string &node_id,
                         const std::string &issuer_id,
                         const std::string &pv_prefix,
                         sqlite3 *certs_db,
                         const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                         epicsMutex &status_update_lock);

    /**
     * @brief Publishes a snapshot of the current certificate table to the sync PV.
     *
     * Uses the previously known member list and marks the certificates as changed.
     */
    void publishSnapshot();

    /**
     * @brief Publishes a snapshot with an updated cluster member list.
     *
     * Compares @p members against the cached list to detect changes, then
     * serializes and posts the full state including certificates.
     *
     * @param members Updated list of cluster member nodes.
     */
    void publishSnapshot(const std::vector<ClusterMember> &members);

    /**
     * @brief Returns the fully-qualified PV name used for cluster synchronization.
     *
     * @return The sync PV name string.
     */
    std::string getSyncPvName() const;

    /**
     * @brief Returns a reference to the underlying SharedPV for this node.
     *
     * @return Reference to the PVXS SharedPV that serves the sync data.
     */
    server::SharedPV &getPV() { return sync_pv_; }

    /**
     * @brief Indicates that an incoming cluster snapshot is currently being ingested.
     *
     * When true, @ref doPublish will skip publishing to avoid re-entrancy conflicts
     * while processing a snapshot received from a peer node.
     */
    std::atomic<bool> sync_ingestion_in_progress{false};

private:
    std::string node_id_;
    std::string issuer_id_;
    std::string sync_pv_name_;
    sqlite3 *certs_db_;
    const ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    epicsMutex &status_update_lock_;
    server::SharedPV sync_pv_;
    bool opened_{false};
    Value prototype_;

    std::vector<ClusterMember> members_;

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
    void doPublish(const std::vector<ClusterMember> &members,
                   bool members_changed,
                   bool certs_changed);
};

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
                          const Value &prototype = Value());

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERSYNC_H_
