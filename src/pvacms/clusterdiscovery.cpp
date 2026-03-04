/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clusterdiscovery.h"

#include <cstring>
#include <ctime>
#include <algorithm>

#include <epicsMutex.h>
#include <epicsGuard.h>

#include <pvxs/log.h>

#include <openssl/rand.h>
#include <sqlite3.h>

DEFINE_LOGGER(pvacmscluster, "pvxs.certs.cluster");

namespace pvxs {
namespace certs {

typedef epicsGuard<epicsMutex> Guard;

ClusterDiscovery::ClusterDiscovery(const std::string &node_id,
                                   const std::string &issuer_id,
                                   const std::string &pv_prefix,
                                   uint32_t discovery_timeout_secs,
                                   uint32_t removal_timeout_secs,
                                   sqlite3 *certs_db,
                                   const ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                   const ossl_ptr<EVP_PKEY> &cert_auth_pub_key,
                                   epicsMutex &status_update_lock,
                                   ClusterSyncPublisher &sync_publisher,
                                   ClusterController &controller,
                                   client::Context client_ctx)
    : node_id_(node_id)
    , issuer_id_(issuer_id)
    , pv_prefix_(pv_prefix)
    , discovery_timeout_secs_(discovery_timeout_secs)
    , removal_timeout_secs_(removal_timeout_secs)
    , certs_db_(certs_db)
    , cert_auth_pkey_(cert_auth_pkey)
    , cert_auth_pub_key_(cert_auth_pub_key)
    , status_update_lock_(status_update_lock)
    , sync_publisher_(sync_publisher)
    , controller_(controller)
    , client_ctx_(std::move(client_ctx))
{
    controller_.on_membership_changed = [this](const std::vector<ClusterMember> &members) {
        reconcileMembers(members);
    };
}

void applySyncSnapshot(sqlite3 *certs_db,
                       epicsMutex &status_update_lock,
                       const Value &snapshot) {
    Guard G(status_update_lock);

    auto certs_arr = snapshot["certs"].as<shared_array<const Value>>();
    for (size_t i = 0; i < certs_arr.size(); i++) {
        auto &row = certs_arr[i];
        auto serial = row["serial"].as<int64_t>();
        auto remote_status = static_cast<certstatus_t>(row["status"].as<int32_t>());

        sqlite3_stmt *check_stmt;
        const char *check_sql = "SELECT status FROM certs WHERE serial = ?";
        if (sqlite3_prepare_v2(certs_db, check_sql, -1, &check_stmt, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_int64(check_stmt, 1, serial);

        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            auto local_status = static_cast<certstatus_t>(sqlite3_column_int(check_stmt, 0));
            sqlite3_finalize(check_stmt);

            if (!isValidStatusTransition(local_status, remote_status))
                continue;

            const char *update_sql = "UPDATE certs SET skid=?, CN=?, O=?, OU=?, C=?, "
                                     "approved=?, not_before=?, not_after=?, renew_by=?, "
                                     "renewal_due=?, status=?, status_date=? WHERE serial=?";
            sqlite3_stmt *upd_stmt;
            if (sqlite3_prepare_v2(certs_db, update_sql, -1, &upd_stmt, nullptr) != SQLITE_OK)
                continue;

            auto bind_text = [&](int idx, const char *field) {
                auto s = row[field].as<std::string>();
                sqlite3_bind_text(upd_stmt, idx, s.c_str(), -1, SQLITE_TRANSIENT);
            };
            bind_text(1, "skid");
            bind_text(2, "cn");
            bind_text(3, "o");
            bind_text(4, "ou");
            bind_text(5, "c");
            sqlite3_bind_int(upd_stmt, 6, row["approved"].as<int32_t>());
            sqlite3_bind_int64(upd_stmt, 7, row["not_before"].as<int64_t>());
            sqlite3_bind_int64(upd_stmt, 8, row["not_after"].as<int64_t>());
            sqlite3_bind_int64(upd_stmt, 9, row["renew_by"].as<int64_t>());
            sqlite3_bind_int(upd_stmt, 10, row["renewal_due"].as<int32_t>());
            sqlite3_bind_int(upd_stmt, 11, row["status"].as<int32_t>());
            sqlite3_bind_int64(upd_stmt, 12, row["status_date"].as<int64_t>());
            sqlite3_bind_int64(upd_stmt, 13, serial);
            sqlite3_step(upd_stmt);
            sqlite3_finalize(upd_stmt);
        } else {
            sqlite3_finalize(check_stmt);
            const char *insert_sql = "INSERT INTO certs (serial, skid, CN, O, OU, C, approved, "
                                     "not_before, not_after, renew_by, renewal_due, status, status_date) "
                                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            sqlite3_stmt *ins_stmt;
            if (sqlite3_prepare_v2(certs_db, insert_sql, -1, &ins_stmt, nullptr) != SQLITE_OK)
                continue;

            sqlite3_bind_int64(ins_stmt, 1, serial);
            auto bind_text = [&](int idx, const char *field) {
                auto s = row[field].as<std::string>();
                sqlite3_bind_text(ins_stmt, idx, s.c_str(), -1, SQLITE_TRANSIENT);
            };
            bind_text(2, "skid");
            bind_text(3, "cn");
            bind_text(4, "o");
            bind_text(5, "ou");
            bind_text(6, "c");
            sqlite3_bind_int(ins_stmt, 7, row["approved"].as<int32_t>());
            sqlite3_bind_int64(ins_stmt, 8, row["not_before"].as<int64_t>());
            sqlite3_bind_int64(ins_stmt, 9, row["not_after"].as<int64_t>());
            sqlite3_bind_int64(ins_stmt, 10, row["renew_by"].as<int64_t>());
            sqlite3_bind_int(ins_stmt, 11, row["renewal_due"].as<int32_t>());
            sqlite3_bind_int(ins_stmt, 12, row["status"].as<int32_t>());
            sqlite3_bind_int64(ins_stmt, 13, row["status_date"].as<int64_t>());
            sqlite3_step(ins_stmt);
            sqlite3_finalize(ins_stmt);
        }
    }
}

void ClusterDiscovery::handleSyncUpdate(const std::string &peer_node_id, Value &&val) {
    auto canonical = canonicalizeSync(val);
    if (!clusterVerify(cert_auth_pub_key_, val, canonical)) {
        log_warn_printf(pvacmscluster, "Sync signature verification failed from node %s\n",
                        peer_node_id.c_str());
        return;
    }

    // Anti-replay: reject timestamps older than high-water mark minus clock skew tolerance
    auto incoming_ts = val["timestamp"].as<int64_t>();
    auto hwm = global_high_water_mark_.load();
    if (hwm > 0 && incoming_ts < hwm - kClockSkewTolerance) {
        log_warn_printf(pvacmscluster, "Stale/replayed sync snapshot from %s (ts=%lld, hwm=%lld)\n",
                        peer_node_id.c_str(), (long long)incoming_ts, (long long)hwm);
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

    auto members_arr = val["members"].as<shared_array<const Value>>();
    std::vector<ClusterMember> remote_members;
    for (size_t i = 0; i < members_arr.size(); i++) {
        remote_members.push_back({
            members_arr[i]["node_id"].as<std::string>(),
            members_arr[i]["sync_pv"].as<std::string>()
        });
    }
    reconcileMembers(remote_members);

    purgeExpiredDisconnects();

    log_debug_printf(pvacmscluster, "Applied sync snapshot from %s (%zu certs)\n",
                     peer_node_id.c_str(), (size_t)val["certs"].as<shared_array<const Value>>().size());
}

void ClusterDiscovery::subscribeToMember(const std::string &node_id, const std::string &sync_pv) {
    if (node_id == node_id_)
        return;
    if (subscriptions_.count(node_id))
        return;

    disconnected_peers_.erase(node_id);

    auto sub = client_ctx_.monitor(sync_pv)
        .maskConnected(false)
        .maskDisconnected(false)
        .event([this, node_id](client::Subscription &sub) {
            while (true) {
                try {
                    while (auto val = sub.pop()) {
                        handleSyncUpdate(node_id, std::move(val));
                    }
                    break;  // pop() returned empty — queue drained
                } catch (client::Connected &) {
                    handleReconnect(node_id);
                    // continue loop to drain any data queued after Connected
                } catch (client::Disconnect &) {
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

void ClusterDiscovery::handleDisconnect(const std::string &peer_node_id) {
    log_debug_printf(pvacmscluster, "Sync subscription disconnected for node %s, "
                     "starting removal timer (%u secs)\n",
                     peer_node_id.c_str(), removal_timeout_secs_);

    auto it = subscriptions_.find(peer_node_id);
    std::string sync_pv;
    if (it != subscriptions_.end()) {
        subscriptions_.erase(it);
    }

    disconnected_peers_[peer_node_id] = {sync_pv, static_cast<int64_t>(std::time(nullptr))};
}

void ClusterDiscovery::handleReconnect(const std::string &peer_node_id) {
    disconnected_peers_.erase(peer_node_id);
}

void ClusterDiscovery::removeExpiredMember(const std::string &peer_node_id) {
    controller_.removeMember(peer_node_id);
    log_info_printf(pvacmscluster, "Removed expired member %s after disconnect timeout\n",
                    peer_node_id.c_str());
}

void ClusterDiscovery::purgeExpiredDisconnects() {
    auto now = static_cast<int64_t>(std::time(nullptr));
    for (auto it = disconnected_peers_.begin(); it != disconnected_peers_.end(); ) {
        if (now - it->second.disconnect_time > static_cast<int64_t>(removal_timeout_secs_)) {
            removeExpiredMember(it->first);
            it = disconnected_peers_.erase(it);
        } else {
            ++it;
        }
    }
}

void ClusterDiscovery::reconcileMembers(const std::vector<ClusterMember> &remote_members) {
    for (const auto &m : remote_members) {
        if (m.node_id == node_id_)
            continue;
        if (subscriptions_.count(m.node_id) == 0 && disconnected_peers_.count(m.node_id) == 0) {
            subscribeToMember(m.node_id, m.sync_pv);
            controller_.addMember(m);
        }
    }
}

bool ClusterDiscovery::discoverCluster() {
    auto ctrl_pv_name = pv_prefix_ + ":CTRL:" + issuer_id_;
    try {
        client_ctx_.get(ctrl_pv_name)
            .exec()
            ->wait(static_cast<double>(discovery_timeout_secs_));
        return true;
    } catch (const client::Timeout &) {
        return false;
    }
}

bool ClusterDiscovery::joinCluster() {
    auto ctrl_pv_name = pv_prefix_ + ":CTRL:" + issuer_id_;
    auto sync_pv_name = sync_publisher_.getSyncPvName();

    // Generate cryptographic nonce for replay protection
    shared_array<uint8_t> nonce(16);
    if (RAND_bytes(nonce.data(), 16) != 1)
        throw std::runtime_error("Failed to generate nonce");
    auto frozen_nonce = nonce.freeze();

    auto req = makeJoinRequestValue();
    req["node_id"] = node_id_;
    req["sync_pv"] = sync_pv_name;
    req["nonce"] = frozen_nonce;

    auto req_canonical = canonicalizeJoinRequest(req);
    clusterSign(cert_auth_pkey_, req, req_canonical);

    try {
        auto resp = client_ctx_.rpc(ctrl_pv_name, req)
            .exec()
            ->wait(static_cast<double>(discovery_timeout_secs_));

        auto resp_canonical = canonicalizeJoinResponse(resp);
        if (!clusterVerify(cert_auth_pub_key_, resp, resp_canonical)) {
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
            log_warn_printf(pvacmscluster, "Join response nonce mismatch — possible replay/relay attack%s\n", "");
            return false;
        }

        auto resp_ts = resp["timestamp"].as<int64_t>();
        auto now = static_cast<int64_t>(std::time(nullptr));
        if (std::abs(now - resp_ts) > kJoinTimestampTolerance) {
            log_warn_printf(pvacmscluster, "Join response stale timestamp (ts=%lld, now=%lld)\n",
                            (long long)resp_ts, (long long)now);
            return false;
        }

        log_info_printf(pvacmscluster, "Joined cluster %s (version %u)\n",
                        issuer_id_.c_str(), resp["version"].as<uint32_t>());

        auto members_arr = resp["members"].as<shared_array<const Value>>();
        std::vector<ClusterMember> members;
        for (size_t i = 0; i < members_arr.size(); i++) {
            members.push_back({
                members_arr[i]["node_id"].as<std::string>(),
                members_arr[i]["sync_pv"].as<std::string>()
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
