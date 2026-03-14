/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CLUSTERCTRL_H_
#define PVXS_CLUSTERCTRL_H_

#include <functional>
#include <string>
#include <vector>

#include <asLib.h>

#include <pvxs/sharedpv.h>

#include "clustersync.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

class ClusterSyncPublisher;

/**
 * @brief Manages the cluster control PV and membership for a CMS issuer node.
 *
 * Publishes a signed CTRL PV advertising the current cluster membership list,
 * handles incoming join RPC requests, and notifies subscribers when membership changes.
 */
class ClusterController {
public:
    /**
     * @brief Constructs a ClusterController and installs the RPC join handler.
     *
     * @param issuer_id         Unique identifier of this CMS issuer instance.
     * @param pv_prefix         PV name prefix used to derive the CTRL PV name.
     * @param cert_auth_pkey    CA private key used to sign cluster messages.
     * @param cert_auth_pub_key CA public key used to verify incoming join-request signatures.
     * @param sync_publisher    Publisher used to propagate membership snapshots to peers.
     * @param as_cluster_mem    EPICS access security member for the CLUSTER ASG.
     */
    ClusterController(const std::string &issuer_id,
                      const std::string &pv_prefix,
                      const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                      const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                      ClusterSyncPublisher &sync_publisher,
                      ASMEMBERPVT as_cluster_mem);

    /**
     * @brief Initialises the cluster with this node as the sole member and opens the CTRL PV.
     *
     * @param node_id  Unique identifier of this node within the cluster.
     * @param sync_pv  Name of the sync PV this node publishes for state replication.
     */
    void initAsSoleNode(const std::string &node_id, const std::string &sync_pv);

    /**
     * @brief Replaces the entire membership list and republishes the CTRL PV.
     *
     * @param members  Full set of cluster members to become the authoritative list.
     */
    void updateMembership(const std::vector<ClusterMember> &members);

    /**
     * @brief Removes a node from the cluster membership and republishes the CTRL PV.
     *
     * @param node_id  Identifier of the node to remove; no-op if not found.
     */
    void removeMember(const std::string &node_id);

    /**
     * @brief Adds a new node to the cluster membership and republishes if not already present.
     *
     * @param member  Descriptor of the node to add.
     */
    void addMember(const ClusterMember &member);

    /**
     * @brief Returns a snapshot of the current cluster membership list.
     *
     * @return Vector of ClusterMember descriptors representing the current members.
     */
    std::vector<ClusterMember> getMembers() const;

    /**
     * @brief Returns the fully-qualified PV name of the CTRL process variable.
     *
     * @return The CTRL PV name string.
     */
    std::string getCtrlPvName() const;

    /**
     * @brief Provides direct access to the underlying SharedPV object.
     *
     * @return Reference to the CTRL SharedPV.
     */
    server::SharedPV &getPV() { return ctrl_pv_; }

    /** @brief Optional callback invoked whenever cluster membership changes; receives the updated member list. */
    std::function<void(const std::vector<ClusterMember>&)> on_membership_changed;

private:
    std::string issuer_id_;
    std::string ctrl_pv_name_;
    const ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    const ossl_ptr<EVP_PKEY> &cert_auth_pub_key_;
    ClusterSyncPublisher &sync_publisher_;
    ASMEMBERPVT as_cluster_mem_;
    server::SharedPV ctrl_pv_;
    bool opened_{false};
    Value prototype_;  // Type prototype from first open() - post() requires matching type
    std::vector<ClusterMember> members_;

    /**
     * @brief Builds and publishes the signed CTRL PV value from the current membership list.
     */
    void postCtrlValue();

    /**
     * @brief Registers the RPC handler on the CTRL PV for processing join requests.
     */
    void setupRpcHandler();
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERCTRL_H_
