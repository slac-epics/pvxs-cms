/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clusterctrl.h"

#include <algorithm>

#include <pvxs/log.h>

#include "clustersync.h"
#include "pvacmsVersion.h"

DEFINE_LOGGER(pvacmscluster, "pvxs.certs.cluster");

namespace pvxs {
namespace certs {

/**
 * @brief Constructs the controller, derives the CTRL PV name, and installs the RPC join handler.
 *
 */
ClusterController::ClusterController(const std::string &issuer_id,
                                     const std::string &pv_prefix,
                                     const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                     const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                                     ClusterSyncPublisher &sync_publisher)
    : issuer_id_(issuer_id)
    , ctrl_pv_name_(pv_prefix + ":CTRL:" + issuer_id)
    , cert_auth_pkey_(cert_auth_pkey)
    , cert_auth_pub_key_(cert_auth_pub_key)
    , sync_publisher_(sync_publisher)
    , ctrl_pv_(server::SharedPV::buildReadonly())
{
    setupRpcHandler();
}

/**
 * @brief Registers the RPC handler on the CTRL PV to process incoming cluster join requests.
 *
 * Verifies the protocol version, validates the cryptographic signature and nonce,
 * calls addMember for the joining node, signs and returns the join response.
 */
void ClusterController::setupRpcHandler() {
    ctrl_pv_.onRPC([this](server::SharedPV &, std::unique_ptr<server::ExecOp> &&op, Value &&args) {
        try {
            auto req_major = args["version_major"].as<uint32_t>();
            if (req_major != 1) {
                log_warn_printf(pvacmscluster, "Join request unsupported major version %u from node %s\n",
                                req_major, args["node_id"].as<std::string>().c_str());
                op->error("Unsupported protocol version");
                return;
            }

            auto canonical = canonicalizeJoinRequest(args);
            if (!clusterVerify(cert_auth_pub_key_, args, canonical)) {
                log_warn_printf(pvacmscluster, "Join request signature verification failed from node %s\n",
                                args["node_id"].as<std::string>().c_str());
                op->error("Signature verification failed");
                return;
            }

            auto nonce = args["nonce"].as<shared_array<const uint8_t>>();
            if (nonce.empty()) {
                log_warn_printf(pvacmscluster, "Join request missing nonce from node %s\n",
                                args["node_id"].as<std::string>().c_str());
                op->error("Missing nonce");
                return;
            }

            auto joiner_node_id = args["node_id"].as<std::string>();
            auto joiner_sync_pv = args["sync_pv"].as<std::string>();
            auto joiner_minor = args["version_minor"].as<uint32_t>();
            auto joiner_patch = args["version_patch"].as<uint32_t>();

            addMember({joiner_node_id, joiner_sync_pv, req_major, joiner_minor, joiner_patch});

            auto resp = makeJoinResponseValue();
            resp["version_major"] = static_cast<uint32_t>(PVACMS_MAJOR_VERSION);
            resp["version_minor"] = static_cast<uint32_t>(PVACMS_MINOR_VERSION);
            resp["version_patch"] = static_cast<uint32_t>(PVACMS_MAINTENANCE_VERSION);
            resp["issuer_id"] = issuer_id_;
            setTimeStamp(resp);

            shared_array<Value> members_arr(members_.size());
            for (size_t i = 0; i < members_.size(); i++) {
                members_arr[i] = resp["members"].allocMember();
                members_arr[i]["node_id"] = members_[i].node_id;
                members_arr[i]["sync_pv"] = members_[i].sync_pv;
                members_arr[i]["version_major"] = members_[i].version_major;
                members_arr[i]["version_minor"] = members_[i].version_minor;
                members_arr[i]["version_patch"] = members_[i].version_patch;
            }
            resp["members"] = members_arr.freeze();
            resp["nonce"] = nonce;

            const auto resp_canonical = canonicalizeJoinResponse(resp);
            clusterSign(cert_auth_pkey_, resp, resp_canonical);

            log_info_printf(pvacmscluster, "Node %s joined cluster %s\n",
                            joiner_node_id.c_str(), issuer_id_.c_str());

            op->reply(resp);
        } catch (const std::exception &e) {
            log_warn_printf(pvacmscluster, "Join request error: %s\n", e.what());
            op->error(e.what());
        }
    });
}

/**
 * @brief Initializes the cluster as a single-node cluster containing only this node.
 *
 * @param node_id  Unique identifier of this node within the cluster.
 * @param sync_pv  The name of the sync PV this node publishes for state replication.
 */
void ClusterController::initAsSoleNode(const std::string &node_id, const std::string &sync_pv) {
    members_ = {{node_id, sync_pv, PVACMS_MAJOR_VERSION, PVACMS_MINOR_VERSION, PVACMS_MAINTENANCE_VERSION}};
    postCtrlValue();
    log_info_printf(pvacmscluster, "Bootstrapped sole-node cluster %s (node %s)\n",
                    issuer_id_.c_str(), node_id.c_str());
}

/**
 * @brief Builds the current membership snapshot into a signed CTRL Value and posts it to the SharedPV.
 *
 * On first call the PV is opened with the prototype value; subsequent calls post only the changed fields.
 */
void ClusterController::postCtrlValue() {
    auto val = prototype_ ? prototype_.cloneEmpty() : makeClusterCtrlValue();
    val["version_major"] = static_cast<uint32_t>(PVACMS_MAJOR_VERSION);
    val["version_minor"] = static_cast<uint32_t>(PVACMS_MINOR_VERSION);
    val["version_patch"] = static_cast<uint32_t>(PVACMS_MAINTENANCE_VERSION);
    val["issuer_id"] = issuer_id_;

    shared_array<Value> members_arr(members_.size());
    for (size_t i = 0; i < members_.size(); i++) {
        members_arr[i] = val["members"].allocMember();
        members_arr[i]["node_id"] = members_[i].node_id;
        members_arr[i]["sync_pv"] = members_[i].sync_pv;
        members_arr[i]["version_major"] = members_[i].version_major;
        members_arr[i]["version_minor"] = members_[i].version_minor;
        members_arr[i]["version_patch"] = members_[i].version_patch;
    }
    val["members"] = members_arr.freeze();

    const auto canonical = canonicalizeCtrl(val);
    clusterSign(cert_auth_pkey_, val, canonical);

    if (!opened_) {
        prototype_ = val;
        ctrl_pv_.open(val);
        opened_ = true;
    } else {
        val["version_major"].unmark();
        val["version_minor"].unmark();
        val["version_patch"].unmark();
        val["issuer_id"].unmark();
        ctrl_pv_.post(val);
    }
}

/**
 * @brief Adds a node to the membership list, republishes, and fires the membership-changed callback.
 *
 * @param member  Descriptor of the node to add; ignored if the node is already a member.
 */
void ClusterController::addMember(const ClusterMember &member) {
    bool already_member = false;
    for (const auto &m : members_) {
        if (m.node_id == member.node_id) {
            already_member = true;
            break;
        }
    }
    if (!already_member) {
        members_.push_back(member);
        postCtrlValue();
        sync_publisher_.publishSnapshot(members_);
    }
    if (on_membership_changed)
        on_membership_changed(members_);
}

/**
 * @brief Removes a node from the membership list, republishes, and fires the membership-changed callback.
 *
 * @param node_id  Identifier of the node to remove; no-op if not found.
 */
void ClusterController::removeMember(const std::string &node_id) {
    const auto it = std::remove_if(members_.begin(), members_.end(),
        [&](const ClusterMember &m) { return m.node_id == node_id; });
    if (it == members_.end())
        return;
    members_.erase(it, members_.end());
    postCtrlValue();
    log_info_printf(pvacmscluster, "Removed node %s from cluster %s\n",
                    node_id.c_str(), issuer_id_.c_str());
    if (on_membership_changed)
        on_membership_changed(members_);
}

/**
 * @brief Atomically replaces the membership list and republishes the CTRL PV.
 *
 * @param members  Authoritative set of cluster members to replace the current list.
 */
void ClusterController::updateMembership(const std::vector<ClusterMember> &members) {
    members_ = members;
    postCtrlValue();
}

/**
 * @brief Returns a copy of the current cluster membership list.
 *
 * @return Vector of ClusterMember descriptors representing the current members.
 */
std::vector<ClusterMember> ClusterController::getMembers() const {
    return members_;
}

/**
 * @brief Returns the fully-qualified PV name of the CTRL process variable.
 *
 * @return The CTRL PV name string.
 */
std::string ClusterController::getCtrlPvName() const {
    return ctrl_pv_name_;
}

}  // namespace certs
}  // namespace pvxs
