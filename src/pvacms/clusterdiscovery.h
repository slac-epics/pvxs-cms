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

class ClusterDiscovery {
public:
    ClusterDiscovery(const std::string &node_id,
                     const std::string &issuer_id,
                     const std::string &pv_prefix,
                     uint32_t discovery_timeout_secs,
                     sqlite3 *certs_db,
                     const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                     const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                     epicsMutex &status_update_lock,
                     ClusterSyncPublisher &sync_publisher,
                     ClusterController &controller,
                     client::Context client_ctx);

    bool joinCluster();
    void subscribeToMember(const std::string &node_id, const std::string &sync_pv);
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
    static constexpr int64_t kClockSkewTolerance = 5;
    static constexpr int64_t kJoinTimestampTolerance = 30;

    void handleSyncUpdate(const std::string &peer_node_id, Value &&val);
    void handleDisconnect(const std::string &peer_node_id);
};

void applySyncSnapshot(sqlite3 *certs_db,
                       epicsMutex &status_update_lock,
                       const Value &snapshot);

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERDISCOVERY_H_
