/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CLUSTERSYNC_H_
#define PVXS_CLUSTERSYNC_H_

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <epicsMutex.h>

#include <pvxs/source.h>

#include "clustertypes.h"
#include "ownedptr.h"
#include "pvacmsVersion.h"

#define SQL_SYNC_SELECT_ALL_CERTS          \
    "SELECT serial, skid, CN, O, OU, C, "  \
    "approved, not_before, not_after, "    \
    "renew_by, renewal_due, "              \
    "status, status_date, "                \
    "san "                                 \
    "FROM certs"

#define SQL_SYNC_SELECT_ALL_SCHEDULES \
    "SELECT serial, day_of_week, start_time, end_time FROM cert_schedules"

#define SQL_SYNC_SELECT_CERT_BY_SERIAL     \
    "SELECT serial, skid, CN, O, OU, C, "  \
    "approved, not_before, not_after, "    \
    "renew_by, renewal_due, "              \
    "status, status_date, "                \
    "san "                                 \
    "FROM certs WHERE serial = ?"

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
    "  , san = :san "                      \
    "WHERE serial = :serial"

#define SQL_SYNC_INSERT_CERT                    \
    "INSERT INTO certs ("                       \
    "     serial,"                              \
    "     skid,"                                \
    "     CN,"                                  \
    "     O,"                                   \
    "     OU,"                                  \
    "     C,"                                   \
    "     san,"                                 \
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
    "     :san,"                                \
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

namespace cms {
namespace cluster {

namespace server = ::pvxs::server;
using ::pvxs::Value;

/**
 * @brief Represents a single member node of a PVACMS cluster.
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
    bool connected;  ///< Whether this node has an active subscription to the peer.

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
               version_patch == o.version_patch &&
               connected == o.connected;
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
 * @brief Represents a single certificate change in the update log.
 *
 * Each entry captures a monotonic sequence number and the certificate data
 * fields at the time of the change, for incremental sync delivery.
 */
struct CertUpdate {
    int64_t sequence;       ///< Monotonic sequence number assigned by the publisher.
    int64_t serial;
    std::string skid;
    std::string cn;
    std::string o;
    std::string ou;
    std::string c;
    int32_t approved;
    int64_t not_before;
    int64_t not_after;
    int64_t renew_by;
    int32_t renewal_due;
    int32_t status;
    int64_t status_date;
    std::string san;
};

/**
 * @brief Per-subscriber monitor state for the incremental sync protocol.
 *
 * Tracks each subscriber's position in the update log and holds the
 * MonitorControlOp handle for per-subscriber posting.
 */
struct SubscriberState {
    std::unique_ptr<server::MonitorControlOp> op;
    int64_t sequence{0};
    bool needs_full_snapshot{true};
    std::deque<Value> pending;  ///< Updates queued due to back-pressure.
};

class ClusterSyncPublisher;

/**
 * @brief Custom pvxs Source that provides per-subscriber state tracking for the SYNC PV.
 *
 * Replaces SharedPV to enable per-subscriber incremental updates via
 * MonitorControlOp::tryPost(), watermarks, and onHighMark() callbacks.
 * Follows the pattern from pvxs test/spam.cpp.
 */
struct SyncSource : public server::Source {
    SyncSource(const std::string &pv_name, ClusterSyncPublisher &publisher);

    void onSearch(Search &op) override;
    void onCreate(std::unique_ptr<server::ChannelControl> &&chan) override;
    server::Source::List onList() override;

    epicsMutex lock_;
    std::shared_ptr<std::set<std::string>> names_;
    Value prototype_;
    uint64_t next_sub_id_{0};
    std::map<uint64_t, SubscriberState> subscribers_;
    ClusterSyncPublisher &publisher_;
};

/**
 * @brief Publishes certificate database snapshots over PVAccess for cluster synchronization.
 *
 * Each PVACMS node hosts one ClusterSyncPublisher that serializes the local certificate
 * table and membership list into a signed, canonical PVXS Value and posts it on
 * a well-known synchronization PV so peer nodes can replicate the state.
 */
class ClusterSyncPublisher {
public:
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
    ClusterSyncPublisher(const std::string &node_id,
                         const std::string &issuer_id,
                         const std::string &pv_prefix,
                         sqlite3 *certs_db,
                         const ::pvxs::ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                         epicsMutex &status_update_lock);

    /**
     * @brief Publishes a full snapshot of the current certificate database.
     *
     * Forces all subscribers to receive the complete database state.
     * Use for bootstrap, init, and membership-only changes.
     * For individual cert changes, prefer publishCertChange().
     */
    void publishSnapshot();

    /**
     * @brief Publishes a full snapshot with an updated cluster membership list.
     *
     * @param members The updated cluster member list.
     */
    void publishSnapshot(const std::vector<ClusterMember> &members);

    /**
     * @brief Publishes an incremental update for a single certificate change.
     *
     * Reads the specified certificate from the database, appends it to the
     * update log, and dispatches incrementally to connected subscribers.
     *
     * @param serial Serial number of the certificate that changed.
     */
    void publishCertChange(int64_t serial);

    /**
     * @brief Returns the fully-qualified PV name used for cluster synchronization.
     *
     * @return The sync PV name string.
     */
    std::string getSyncPvName() const;

    /**
     * @brief Returns a reference to the underlying SyncSource for this node.
     *
     * @return Shared pointer to the SyncSource that serves the sync data.
     */
    std::shared_ptr<SyncSource> getSource() { return sync_source_; }

    /**
     * @brief Indicates that an incoming cluster snapshot is currently being ingested.
     *
     * When true, @ref doPublish will skip publishing to avoid re-entrancy conflicts
     * while processing a snapshot received from a peer node.
     */
    bool enabled_{false};
    void setEnabled(bool enabled) { enabled_ = enabled; }
    bool isEnabled() const { return enabled_; }

    std::atomic<bool> sync_ingestion_in_progress{false};

    void appendToLog(CertUpdate update);

    static constexpr size_t kDefaultMaxLogSize = 10000;

    void addForwardingRelationship(const std::string &forwardee_node_id, const std::string &requester_node_id);
    void removeForwardingRelationship(const std::string &forwardee_node_id);
    bool isForwarding(const std::string &forwardee_node_id) const;
    std::map<std::string, std::string> getForwardingRelationships() const;

    std::function<bool(const std::string &node_id)> is_peer_connected;

private:
    std::string node_id_;
    std::string issuer_id_;
    std::string sync_pv_name_;
    sqlite3 *certs_db_;
    const ::pvxs::ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    epicsMutex &status_update_lock_;

    std::shared_ptr<SyncSource> sync_source_;
    Value prototype_;

    std::vector<ClusterMember> members_;

    std::deque<CertUpdate> update_log_;
    int64_t next_sequence_{1};
    size_t max_log_size_{kDefaultMaxLogSize};

    std::map<std::string, std::string> forwarding_;

    void dispatchToSubscribers();
    void doPublish(const std::vector<ClusterMember> &members,
                   bool members_changed,
                   bool certs_changed);

    friend struct SyncSource;
    void sendToSubscriber(SubscriberState &sub);
    void handleForwardRpc(std::unique_ptr<server::ExecOp> &&op, Value &&args);
    void handleCancelForwardRpc(std::unique_ptr<server::ExecOp> &&op, Value &&args);
    void handleResyncRpc(std::unique_ptr<server::ExecOp> &&op);
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

}  // namespace cluster
}  // namespace cms

#endif  // PVXS_CLUSTERSYNC_H_
