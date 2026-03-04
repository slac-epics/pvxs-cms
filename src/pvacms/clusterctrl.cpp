/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clusterctrl.h"

#include <algorithm>

#include <pvxs/log.h>

#include "clustersync.h"

DEFINE_LOGGER(pvacmscluster, "pvxs.certs.cluster");

namespace pvxs {
namespace certs {

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

void ClusterController::setupRpcHandler() {
    ctrl_pv_.onRPC([this](server::SharedPV &, std::unique_ptr<server::ExecOp> &&op, Value &&args) {
        try {
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

            addMember({joiner_node_id, joiner_sync_pv});

            auto resp = makeJoinResponseValue();
            resp["version"] = static_cast<uint32_t>(1);
            resp["issuer_id"] = issuer_id_;
            resp["timestamp"] = static_cast<int64_t>(std::time(nullptr));

            shared_array<Value> members_arr(members_.size());
            for (size_t i = 0; i < members_.size(); i++) {
                members_arr[i] = resp["members"].allocMember();
                members_arr[i]["node_id"] = members_[i].node_id;
                members_arr[i]["sync_pv"] = members_[i].sync_pv;
            }
            resp["members"] = members_arr.freeze();

            resp["nonce"] = nonce;

            auto resp_canonical = canonicalizeJoinResponse(resp);
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

void ClusterController::initAsSoleNode(const std::string &node_id, const std::string &sync_pv) {
    members_ = {{node_id, sync_pv}};
    postCtrlValue();
    log_info_printf(pvacmscluster, "Bootstrapped sole-node cluster %s (node %s)\n",
                    issuer_id_.c_str(), node_id.c_str());
}

void ClusterController::postCtrlValue() {
    auto val = prototype_ ? prototype_.cloneEmpty() : makeClusterCtrlValue();
    val["version"] = static_cast<uint32_t>(1);
    val["issuer_id"] = issuer_id_;

    shared_array<Value> members_arr(members_.size());
    for (size_t i = 0; i < members_.size(); i++) {
        members_arr[i] = val["members"].allocMember();
        members_arr[i]["node_id"] = members_[i].node_id;
        members_arr[i]["sync_pv"] = members_[i].sync_pv;
    }
    val["members"] = members_arr.freeze();

    auto canonical = canonicalizeCtrl(val);
    clusterSign(cert_auth_pkey_, val, canonical);

    if (!opened_) {
        prototype_ = val;
        ctrl_pv_.open(val);
        opened_ = true;
    } else {
        ctrl_pv_.post(val);
    }
}

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

void ClusterController::removeMember(const std::string &node_id) {
    auto it = std::remove_if(members_.begin(), members_.end(),
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

void ClusterController::updateMembership(const std::vector<ClusterMember> &members) {
    members_ = members;
    postCtrlValue();
}

std::vector<ClusterMember> ClusterController::getMembers() const {
    return members_;
}

std::string ClusterController::getCtrlPvName() const {
    return ctrl_pv_name_;
}

}  // namespace certs
}  // namespace pvxs
