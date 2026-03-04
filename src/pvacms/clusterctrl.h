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

#include <pvxs/sharedpv.h>

#include "clustersync.h"
#include "ownedptr.h"

namespace pvxs {
namespace certs {

class ClusterSyncPublisher;

class ClusterController {
public:
    ClusterController(const std::string &issuer_id,
                      const std::string &pv_prefix,
                      const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                      const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                      ClusterSyncPublisher &sync_publisher);

    void initAsSoleNode(const std::string &node_id, const std::string &sync_pv);

    void updateMembership(const std::vector<ClusterMember> &members);
    void removeMember(const std::string &node_id);
    void addMember(const ClusterMember &member);

    std::vector<ClusterMember> getMembers() const;

    std::string getCtrlPvName() const;
    server::SharedPV &getPV() { return ctrl_pv_; }

    std::function<void(const std::vector<ClusterMember>&)> on_membership_changed;

private:
    std::string issuer_id_;
    std::string ctrl_pv_name_;
    const ossl_ptr<EVP_PKEY> &cert_auth_pkey_;
    const ossl_ptr<EVP_PKEY> &cert_auth_pub_key_;
    ClusterSyncPublisher &sync_publisher_;
    server::SharedPV ctrl_pv_;
    bool opened_{false};
    Value prototype_;  // Type prototype from first open() — post() requires matching type
    std::vector<ClusterMember> members_;

    void postCtrlValue();
    void setupRpcHandler();
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERCTRL_H_
