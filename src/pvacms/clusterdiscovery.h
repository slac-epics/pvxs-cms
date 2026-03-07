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
#include <string>
#include <vector>

#include <epicsMutex.h>

#include <pvxs/client.h>

#include "clusterctrl.h"
#include "clustersync.h"
#include "ownedptr.h"

struct sqlite3;

namespace pvxs {
namespace certs {

/** @brief Manages discovery of and synchronization with peer CMS cluster nodes. */
class ClusterDiscovery {
public:
    /**
     * @brief Constructs a ClusterDiscovery instance and registers the membership-change callback.
     *
     * @param node_id Unique identifier for this CMS node.
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
                     const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                     const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                     epicsMutex &status_update_lock,
                     ClusterSyncPublisher &sync_publisher,
                     ClusterController &controller,
                     const client::Context& client_ctx);

    /**
     * @brief Sends a signed join request to the cluster control PV and subscribes to member sync PVs.
     * @return true if the join handshake succeeded and the cluster was joined; false otherwise.
     */
    bool joinCluster();

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
    void reconcileMembers(const std::vector<ClusterMember> &remote_members);

private:
    std::string node_id_;
    std::string issuer_id_;
    std::string pv_prefix_;
    uint32_t discovery_timeout_secs_;
    sqlite3 *certs_db_;
    const ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    const ossl_ptr<EVP_PKEY> &cert_auth_pub_key_;
    epicsMutex &status_update_lock_;
    ClusterSyncPublisher &sync_publisher_;
    ClusterController &controller_;
    client::Context client_ctx_;

    std::map<std::string, std::shared_ptr<client::Subscription>> subscriptions_;

    std::atomic<int64_t> global_high_water_mark_{0};
    static constexpr int64_t kClockSkewTolerance = 5;      ///< Maximum allowed clock skew between nodes, in seconds.
    static constexpr int64_t kJoinTimestampTolerance = 30; ///< Maximum allowed age of a join response timestamp, in seconds.

    /**
     * @brief Verifies and applies an incoming sync snapshot from a peer node.
     * @param peer_node_id Unique identifier of the node that sent the update.
     * @param val Incoming PVAccess Value containing the signed sync snapshot.
     */
    void handleSyncUpdate(const std::string &peer_node_id, Value &&val);

    /**
     * @brief Removes all state for a peer node after its sync subscription disconnects.
     * @param peer_node_id Unique identifier of the node that disconnected.
     */
    void handleDisconnect(const std::string &peer_node_id);
};

/**
 * @brief Merges a peer's certificate snapshot into the local SQLite database.
 * @param certs_db SQLite database handle to update.
 * @param status_update_lock Mutex that must be held during database writes.
 * @param snapshot PVAccess Value containing the array of certificate records to merge.
 */
void applySyncSnapshot(sqlite3 *certs_db,
                       epicsMutex &status_update_lock,
                       const Value &snapshot);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERDISCOVERY_H_
