/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CLUSTERDISCOVERY_H_
#define PVXS_CLUSTERDISCOVERY_H_

#include <atomic>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <epicsMutex.h>
#include <epicsThread.h>

#include <pvxs/client.h>

#include "clusterctrl.h"
#include "clustersync.h"
#include "ownedptr.h"

struct sqlite3;

namespace cms {
namespace cluster {

namespace client = ::pvxs::client;
using ::pvxs::Value;

/** @brief Manages discovery of and synchronization with peer PVACMS cluster nodes. */
class ClusterDiscovery {
public:
    enum PeerConnState : int { CONN_PENDING = 0, CONN_CONNECTED = 1, CONN_UNREACHABLE = 2 };
    struct PeerConnectivity {
        std::atomic<int> state;
        std::atomic<bool> cancelled;
        PeerConnectivity() : state(CONN_PENDING), cancelled(false) {}
    };

    /**
     * @brief Constructs a ClusterDiscovery instance and registers the membership-change callback.
     *
     * @param node_id Unique identifier for this PVACMS node.
     * @param issuer_id Certificate authority issuer identifier shared by all cluster members.
     * @param pv_prefix PVAccess PV name prefix used to build control channel names.
     * @param discovery_timeout_secs Timeout in seconds for the join RPC call.
     * @param certs_db SQLite database handle used to persist certificate state.
     * @param cert_auth_pkey CA private key used to sign outgoing cluster messages.
     * @param cert_auth_pub_key CA public key used to verify incoming cluster messages.
     * @param status_update_lock Mutex protecting all certificate status updates.
     * @param sync_publisher Publisher that exposes this node's sync PV to peers.
     * @param controller Cluster controller managing membership state.
     * @param client_ctx PVAccess client context for RPC and monitor operations.
     */
    ClusterDiscovery(std::string node_id,
                     std::string issuer_id,
                     std::string pv_prefix,
                     uint32_t discovery_timeout_secs,
                     sqlite3 *certs_db,
                     const ::pvxs::ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                     const ::pvxs::ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                     epicsMutex &status_update_lock,
                     ClusterSyncPublisher &sync_publisher,
                     ClusterController &controller,
                     const client::Context& client_ctx);

    ~ClusterDiscovery();

    enum class JoinResult { Joined, NotFound, Revoked };

    /**
     * @brief Sends a signed join request to the cluster control PV and subscribes to member sync PVs.
     * @return Joined on success, NotFound if no cluster exists, Revoked if this node's cert is revoked.
     */
    JoinResult joinCluster();

    /**
     * @brief Creates a monitor subscription to a peer node's sync PV.
     * @param node_id Unique identifier of the peer node to subscribe to.
     * @param sync_pv PVAccess name of the peer's sync PV.
     */
    void subscribeToMember(const std::string &node_id, const std::string &sync_pv);

    /**
     * @brief Subscribes to any remote cluster members not yet tracked locally.
     * @param remote_members List of cluster members advertised by a peer in a sync snapshot.
     */
    void reconcileMembers(const std::string &sender_node_id,
                          const std::vector<ClusterMember> &remote_members);

    /**
     * @brief Removes all state for a peer node after its sync subscription disconnects.
     * @param peer_node_id Unique identifier of the node that disconnected.
     */
    void handleDisconnect(const std::string &peer_node_id);

    /**
     * @brief Clears all peer state and re-runs the join protocol on a background thread.
     *
     * Triggered when the node detects it has been evicted (self absent from a
     * peer's membership list) or when all peers disconnect.  Guarded by an
     * atomic flag to prevent concurrent rejoin attempts.
     */
    void rejoinCluster();

    bool isPeerConnected(const std::string &node_id) const;

    /** @brief Callback invoked when a certificate belonging to a PVACMS cluster node is revoked.
     *  Receives the full SKID of the revoked certificate. */
    std::function<void(const std::string& skid)> on_node_cert_revoked;

private:
    std::string node_id_;
    std::string issuer_id_;
    std::string pv_prefix_;
    uint32_t discovery_timeout_secs_;
    sqlite3 *certs_db_;
    const ::pvxs::ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    const ::pvxs::ossl_ptr<EVP_PKEY> &cert_auth_pub_key_;
    epicsMutex &status_update_lock_;
    ClusterSyncPublisher &sync_publisher_;
    ClusterController &controller_;
    client::Context client_ctx_;

    std::map<std::string, std::shared_ptr<client::Subscription>> subscriptions_;

    // Deferred-destruction list for Subscriptions whose handleDisconnect
    // fires from inside the tcp_loop event callback for that same Subscription.
    // Synchronously destroying ~Subscription on the tcp_loop self-deadlocks
    // (cancel() dispatches to tcp_loop and waits). We move the shared_ptr here
    // instead, leaving subscriptions_[node_id] free for immediate reconnection,
    // and drain this list from non-tcp_loop contexts (subscribeToMember entry,
    // joinCluster entry, ~ClusterDiscovery).
    std::vector<std::shared_ptr<client::Subscription>> dead_subscriptions_;
    epicsMutex dead_subscriptions_lock_;
    void drainDeadSubscriptions();

    std::atomic<bool> rejoin_in_progress_{false};
    std::set<std::string> acknowledged_by_;
    void doRejoin();
    friend void rejoinThreadEntry(void *arg);

    std::map<std::string, std::shared_ptr<PeerConnectivity>> peer_connectivity_;
    void onConnectivityTimeout(const std::string &node_id);
    void publishMemberConnectivity();
    friend void connTimerEntry(void *arg);

    struct ActiveForwarding {
        std::string intermediary_node_id;
        std::string intermediary_sync_pv;
    };
    std::map<std::string, ActiveForwarding> active_forwarding_;
    std::map<std::string, std::vector<ClusterMember>> peer_sync_members_;
    void seekForwarder(const std::string &unreachable_node_id);
    void cancelForwarding(const std::string &node_id);
    void rescanForwarders();

    std::atomic<int64_t> global_high_water_mark_{0};
    std::map<std::string, int64_t> peer_last_sequence_;
    static constexpr int64_t kClockSkewTolerance = 5;      ///< Maximum allowed clock skew between nodes, in seconds.
    static constexpr int64_t kJoinTimestampTolerance = 30; ///< Maximum allowed age of a join response timestamp, in seconds.

    /**
     * @brief Verifies and applies an incoming sync snapshot from a peer node.
     * @param peer_node_id Unique identifier of the node that sent the update.
     * @param val Incoming PVAccess Value containing the signed sync snapshot.
     */
    void handleSyncUpdate(const std::string &peer_node_id, Value &&val);
};

struct SyncMergeResult {
    std::vector<std::string> revoked_skids;
    bool had_changes{false};
};

SyncMergeResult applySyncSnapshot(sqlite3 *certs_db,
                                  epicsMutex &status_update_lock,
                                  const Value &snapshot,
                                  const std::string &peer_node_id);

}  // namespace cluster
}  // namespace cms

#endif  // PVXS_CLUSTERDISCOVERY_H_
