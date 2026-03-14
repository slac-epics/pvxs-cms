/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clusterdiscovery.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include <epicsMutex.h>
#include <epicsGuard.h>
#include <epicsTime.h>

#include <pvxs/log.h>

#include <openssl/rand.h>
#include <sqlite3.h>

#include "pvacmsVersion.h"

DEFINE_LOGGER(pvacmscluster, "pvxs.certs.cluster");

namespace pvxs {
namespace certs {

typedef epicsGuard<epicsMutex> Guard;

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
ClusterDiscovery::ClusterDiscovery(std::string node_id,
                                   std::string issuer_id,
                                   std::string pv_prefix,
                                   const uint32_t discovery_timeout_secs,
                                   sqlite3 *certs_db,
                                   const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                   const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                                   epicsMutex &status_update_lock,
                                   ClusterSyncPublisher &sync_publisher,
                                   ClusterController &controller,
                                   const client::Context& client_ctx)
    : node_id_(std::move(node_id))
    , issuer_id_(std::move(issuer_id))
    , pv_prefix_(std::move(pv_prefix))
    , discovery_timeout_secs_(discovery_timeout_secs)
    , certs_db_(certs_db)
    , cert_auth_pkey_(cert_auth_pkey)
    , cert_auth_pub_key_(cert_auth_pub_key)
    , status_update_lock_(status_update_lock)
    , sync_publisher_(sync_publisher)
    , controller_(controller)
    , client_ctx_(client_ctx)
{
    controller_.on_membership_changed = [this](const std::vector<ClusterMember> &members) {
        reconcileMembers(members);
    };
}

/**
 * @brief Merges a peer's certificate snapshot into the local SQLite database.
 * @param certs_db SQLite database handle to update.
 * @param status_update_lock Mutex that must be held during database writes.
 * @param snapshot PVAccess Value containing the array of certificate records to merge.
 */
void applySyncSnapshot(sqlite3 *certs_db,
                       epicsMutex &status_update_lock,
                       const Value &snapshot) {
    Guard G(status_update_lock);

    const auto certs_arr = snapshot["certs"].as<shared_array<const Value>>();
    for (const auto & row : certs_arr) {
        const auto serial = row["serial"].as<int64_t>();
        const auto remote_status = static_cast<certstatus_t>(row["status"].as<int32_t>());

        sqlite3_stmt *check_stmt;
        if (sqlite3_prepare_v2(certs_db, SQL_SYNC_CHECK_CERT_STATUS, -1, &check_stmt, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_int64(check_stmt, sqlite3_bind_parameter_index(check_stmt, ":serial"), serial);

        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const auto local_status = static_cast<certstatus_t>(sqlite3_column_int(check_stmt, 0));
            sqlite3_finalize(check_stmt);

            if (!isValidStatusTransition(local_status, remote_status))
                continue;

            sqlite3_stmt *upd_stmt;
            if (sqlite3_prepare_v2(certs_db, SQL_SYNC_UPDATE_CERT, -1, &upd_stmt, nullptr) != SQLITE_OK)
                continue;

            auto bind_text = [&](const char *param, const char *field) {
                const auto s = row[field].as<std::string>();
                sqlite3_bind_text(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, param), s.c_str(), -1, SQLITE_TRANSIENT);
            };
            bind_text(":skid", "skid");
            bind_text(":CN", "cn");
            bind_text(":O", "o");
            bind_text(":OU", "ou");
            bind_text(":C", "c");
            sqlite3_bind_int(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":approved"), row["approved"].as<int32_t>());
            sqlite3_bind_int64(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":not_before"), row["not_before"].as<int64_t>());
            sqlite3_bind_int64(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":not_after"), row["not_after"].as<int64_t>());
            sqlite3_bind_int64(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":renew_by"), row["renew_by"].as<int64_t>());
            sqlite3_bind_int(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":renewal_due"), row["renewal_due"].as<int32_t>());
            sqlite3_bind_int(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":status"), row["status"].as<int32_t>());
            sqlite3_bind_int64(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":status_date"), row["status_date"].as<int64_t>());
            sqlite3_bind_int64(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":serial"), serial);
            sqlite3_step(upd_stmt);
            sqlite3_finalize(upd_stmt);
        } else {
            sqlite3_finalize(check_stmt);
            sqlite3_stmt *ins_stmt;
            if (sqlite3_prepare_v2(certs_db, SQL_SYNC_INSERT_CERT, -1, &ins_stmt, nullptr) != SQLITE_OK)
                continue;

            sqlite3_bind_int64(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":serial"), serial);
            auto bind_text = [&](const char *param, const char *field) {
                const auto s = row[field].as<std::string>();
                sqlite3_bind_text(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, param), s.c_str(), -1, SQLITE_TRANSIENT);
            };
            bind_text(":skid", "skid");
            bind_text(":CN", "cn");
            bind_text(":O", "o");
            bind_text(":OU", "ou");
            bind_text(":C", "c");
            sqlite3_bind_int(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":approved"), row["approved"].as<int32_t>());
            sqlite3_bind_int64(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":not_before"), row["not_before"].as<int64_t>());
            sqlite3_bind_int64(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":not_after"), row["not_after"].as<int64_t>());
            sqlite3_bind_int64(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":renew_by"), row["renew_by"].as<int64_t>());
            sqlite3_bind_int(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":renewal_due"), row["renewal_due"].as<int32_t>());
            sqlite3_bind_int(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":status"), row["status"].as<int32_t>());
            sqlite3_bind_int64(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":status_date"), row["status_date"].as<int64_t>());
            sqlite3_step(ins_stmt);
            sqlite3_finalize(ins_stmt);
        }
    }
}

/**
 * @brief Verifies and applies an incoming sync snapshot from a peer node.
 * @param peer_node_id Unique identifier of the node that sent the update.
 * @param val Incoming PVAccess Value containing the signed sync snapshot.
 */
void ClusterDiscovery::handleSyncUpdate(const std::string &peer_node_id, Value &&val) {
    if (peer_cert_ids_.find(peer_node_id) == peer_cert_ids_.end()) {
        log_warn_printf(pvacmscluster,
            "Received snapshot from %s before peer identity was verified, rejecting\n",
            peer_node_id.c_str());
        return;
    }

    const auto snapshot_node_id = val["node_id"].as<std::string>();
    if (snapshot_node_id != peer_node_id) {
        log_warn_printf(pvacmscluster,
            "Snapshot node_id mismatch from %s: expected %s, got %s\n",
            peer_node_id.c_str(), peer_node_id.c_str(), snapshot_node_id.c_str());
        handleDisconnect(peer_node_id);
        return;
    }

    if (!clusterVerify(cert_auth_pub_key_, val)) {
        log_warn_printf(pvacmscluster, "Sync signature verification failed from node %s\n",
                        peer_node_id.c_str());
        return;
    }

    // Anti-replay: reject timestamps older than high-water mark minus clock skew tolerance
    const auto incoming_ts = getTimeStamp(val);
    const auto hwm = global_high_water_mark_.load();
    if (hwm > 0 && incoming_ts < hwm - kClockSkewTolerance) {
        log_warn_printf(pvacmscluster, "Stale/replayed sync snapshot from %s (ts=%lld, hwm=%lld)\n",
                        peer_node_id.c_str(), static_cast<long long>(incoming_ts), static_cast<long long>(hwm));
        return;
    }

    int64_t expected = hwm;
    while (incoming_ts > expected &&
           !global_high_water_mark_.compare_exchange_weak(expected, incoming_ts)) {}

    sync_publisher_.sync_ingestion_in_progress.store(true);
    try {
        applySyncSnapshot(certs_db_, status_update_lock_, val);
    } catch (...) {
        sync_publisher_.sync_ingestion_in_progress.store(false);
        throw;
    }
    sync_publisher_.sync_ingestion_in_progress.store(false);

    const auto members_arr = val["members"].as<shared_array<const Value>>();
    std::vector<ClusterMember> remote_members;
    for (const auto & m : members_arr) {
        remote_members.push_back({
            m["node_id"].as<std::string>(),
            m["sync_pv"].as<std::string>(),
            m["version_major"].as<uint32_t>(),
            m["version_minor"].as<uint32_t>(),
            m["version_patch"].as<uint32_t>()
        });
    }
    reconcileMembers(remote_members);

    log_debug_printf(pvacmscluster, "Applied sync snapshot from %s (%zu certs)\n",
                     peer_node_id.c_str(), static_cast<size_t>(val["certs"].as<shared_array<const Value> >().size()));
}

/**
 * @brief Creates a monitor subscription to a peer node's sync PV.
 * @param node_id Unique identifier of the peer node to subscribe to.
 * @param sync_pv PVAccess name of the peer's sync PV.
 */
void ClusterDiscovery::subscribeToMember(const std::string &node_id, const std::string &sync_pv) {
    if (node_id == node_id_) return;
    if (subscriptions_.count(node_id)) return;

    auto sub = client_ctx_.monitor(sync_pv)
        .maskConnected(false)
        .maskDisconnected(false)
        .event([this, node_id, sync_pv](client::Subscription &sub) {
            while (true) {
                try {
                    while (auto val = sub.pop()) {
                        handleSyncUpdate(node_id, std::move(val));
                    }
                    break;
                } catch (client::Connected &conn) {
                    if (conn.cred && conn.cred->isTLS && conn.cred->method == "x509") {
                        const auto peer_cert_id = conn.cred->issuer_id + ":" + conn.cred->serial;

                        if (conn.cred->issuer_id != issuer_id_) {
                            log_warn_printf(pvacmscluster,
                                "Peer issuer_id mismatch on SYNC PV %s: expected %s, got %s\n",
                                sync_pv.c_str(), issuer_id_.c_str(), conn.cred->issuer_id.c_str());
                            handleDisconnect(node_id);
                            break;
                        }

                        peer_cert_ids_[node_id] = peer_cert_id;
                        log_debug_printf(pvacmscluster, "Cached peer cert identity %s for node %s\n",
                                         peer_cert_id.c_str(), node_id.c_str());
                    }
                    // continue loop to drain any data queued after Connected
                } catch (client::Disconnect &) {
                    peer_cert_ids_.erase(node_id);
                    handleDisconnect(node_id);
                    break;
                } catch (const std::exception &e) {
                    log_warn_printf(pvacmscluster, "Sync subscription error from %s: %s\n",
                                    node_id.c_str(), e.what());
                    break;
                }
            }
        })
        .exec();

    subscriptions_[node_id] = std::move(sub);
    log_debug_printf(pvacmscluster, "Subscribed to sync PV %s (node %s)\n",
                     sync_pv.c_str(), node_id.c_str());
}

/**
 * @brief Removes all state for a peer node after its sync subscription disconnects.
 * @param peer_node_id Unique identifier of the node that disconnected.
 */
void ClusterDiscovery::handleDisconnect(const std::string &peer_node_id) {
    peer_cert_ids_.erase(peer_node_id);
    subscriptions_.erase(peer_node_id);
    controller_.removeMember(peer_node_id);
    log_info_printf(pvacmscluster, "Removed disconnected member %s\n", peer_node_id.c_str());
}

/**
 * @brief Subscribes to any remote cluster members not yet tracked locally.
 * @param remote_members List of cluster members advertised by a peer in a sync snapshot.
 */
void ClusterDiscovery::reconcileMembers(const std::vector<ClusterMember> &remote_members) {
    for (const auto &m : remote_members) {
        if (m.node_id == node_id_) continue;
        if (subscriptions_.count(m.node_id) == 0) {
            subscribeToMember(m.node_id, m.sync_pv);
            controller_.addMember(m);
        }
    }
}

/**
 * @brief Sends a signed join request to the cluster control PV and subscribes to member sync PVs.
 * @return true if the join handshake succeeded and the cluster was joined; false otherwise.
 */
bool ClusterDiscovery::joinCluster() {
    auto ctrl_pv_name = pv_prefix_ + ":CTRL:" + issuer_id_;
    auto sync_pv_name = sync_publisher_.getSyncPvName();

    // Generate cryptographic nonce for replay protection
    shared_array<uint8_t> nonce(16);
    if (RAND_bytes(nonce.data(), 16) != 1)
        throw std::runtime_error("Failed to generate nonce");
    auto frozen_nonce = nonce.freeze();

    auto req = makeJoinRequestValue();
    req["version_major"] = static_cast<uint32_t>(PVACMS_MAJOR_VERSION);
    req["version_minor"] = static_cast<uint32_t>(PVACMS_MINOR_VERSION);
    req["version_patch"] = static_cast<uint32_t>(PVACMS_MAINTENANCE_VERSION);
    req["node_id"] = node_id_;
    req["sync_pv"] = sync_pv_name;
    req["nonce"] = frozen_nonce;

    clusterSign(cert_auth_pkey_, req);

    try {
        auto resp = client_ctx_.rpc(ctrl_pv_name, req)
            .exec()
            ->wait(discovery_timeout_secs_);

        if (!clusterVerify(cert_auth_pub_key_, resp)) {
            log_warn_printf(pvacmscluster, "Join response signature verification failed%s\n", "");
            return false;
        }

        auto resp_issuer = resp["issuer_id"].as<std::string>();
        if (resp_issuer != issuer_id_) {
            log_warn_printf(pvacmscluster, "Join response issuer_id mismatch: expected %s, got %s\n",
                            issuer_id_.c_str(), resp_issuer.c_str());
            return false;
        }

        auto resp_nonce = resp["nonce"].as<shared_array<const uint8_t>>();
        if (resp_nonce.size() != frozen_nonce.size() ||
            std::memcmp(resp_nonce.data(), frozen_nonce.data(), frozen_nonce.size()) != 0) {
            log_warn_printf(pvacmscluster, "Join response nonce mismatch - possible replay/relay attack%s\n", "");
            return false;
        }

        auto resp_ts = getTimeStamp(resp);
        epicsTimeStamp now_ts = epicsTime::getCurrent();
        auto now = static_cast<int64_t>(now_ts.secPastEpoch);
        if (std::abs(now - resp_ts) > kJoinTimestampTolerance) {
            log_warn_printf(pvacmscluster, "Join response stale timestamp (ts=%lld, now=%lld)\n",
                            static_cast<long long>(resp_ts), static_cast<long long>(now));
            return false;
        }

        log_info_printf(pvacmscluster, "Joined cluster %s (version %u.%u.%u)\n",
                        issuer_id_.c_str(),
                        resp["version_major"].as<uint32_t>(),
                        resp["version_minor"].as<uint32_t>(),
                        resp["version_patch"].as<uint32_t>());

        auto members_arr = resp["members"].as<shared_array<const Value>>();
        std::vector<ClusterMember> members;
        for (const auto & m : members_arr) {
            members.push_back({
                m["node_id"].as<std::string>(),
                m["sync_pv"].as<std::string>(),
                m["version_major"].as<uint32_t>(),
                m["version_minor"].as<uint32_t>(),
                m["version_patch"].as<uint32_t>()
            });
        }

        controller_.updateMembership(members);

        for (const auto &m : members) {
            subscribeToMember(m.node_id, m.sync_pv);
        }

        return true;
    } catch (const std::exception &e) {
        log_warn_printf(pvacmscluster, "Join RPC failed: %s\n", e.what());
        return false;
    }
}

}  // namespace certs
}  // namespace pvxs
