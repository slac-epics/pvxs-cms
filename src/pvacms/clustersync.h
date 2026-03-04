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

// Forward declarations
struct sqlite3;

namespace pvxs {
namespace certs {

struct ClusterMember {
    std::string node_id;
    std::string sync_pv;
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t version_patch;

    bool operator==(const ClusterMember &o) const {
        return node_id == o.node_id && sync_pv == o.sync_pv &&
               version_major == o.version_major &&
               version_minor == o.version_minor &&
               version_patch == o.version_patch;
    }
    bool operator!=(const ClusterMember &o) const {
        return !(*this == o);
    }
};

class ClusterSyncPublisher {
public:
    ClusterSyncPublisher(const std::string &node_id,
                         const std::string &issuer_id,
                         const std::string &pv_prefix,
                         sqlite3 *certs_db,
                         const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                         epicsMutex &status_update_lock);

    void publishSnapshot();
    void publishSnapshot(const std::vector<ClusterMember> &members);

    std::string getSyncPvName() const;

    server::SharedPV &getPV() { return sync_pv_; }

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

    void doPublish(const std::vector<ClusterMember> &members,
                   bool members_changed,
                   bool certs_changed);
};

Value serializeCertsTable(sqlite3 *certs_db,
                          const std::string &node_id,
                          const std::vector<ClusterMember> &members,
                          const Value &prototype = Value());

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CLUSTERSYNC_H_
