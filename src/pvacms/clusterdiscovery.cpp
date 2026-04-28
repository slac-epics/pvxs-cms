/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clusterdiscovery.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <utility>

#include <epicsMutex.h>
#include <epicsGuard.h>

#include <epicsThread.h>
#include <epicsTime.h>
#include <iostream>

#include <pvxs/log.h>

#include <openssl/rand.h>
#include <sqlite3.h>

#include "pvacmsVersion.h"

DEFINE_LOGGER(pvacmscluster, "cms.certs.cluster");

namespace cms {
namespace cluster {

namespace client = ::pvxs::client;

using ::pvxs::shared_array;
using ::cms::detail::SB;
using ::pvxs::TypeCode;
using ::pvxs::TypeDef;
using ::pvxs::Value;
using ::cms::SYNC_FULL_SNAPSHOT;
using ::cms::SYNC_INCREMENTAL;
using ::cms::clusterSign;
using ::cms::clusterVerify;
using ::cms::getTimeStamp;
using ::cms::isValidStatusTransition;
using ::cms::makeJoinRequestValue;
using ::cms::setTimeStamp;
using ::cms::detail::ossl_ptr;

namespace members = ::pvxs::members;

namespace {

static const char AUDIT_ACTION_SYNC[] = "SYNC";

void insertSyncAuditRecord(sqlite3 *db, const std::string &action,
                           const std::string &operator_id, uint64_t serial,
                           const std::string &detail) {
    static const char SQL_INSERT_AUDIT[] =
        "INSERT INTO audit(timestamp, action, operator, serial, detail) "
        "VALUES(:timestamp, :action, :operator, :serial, :detail)";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_AUDIT, -1, &stmt, nullptr) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":timestamp"),
                       static_cast<sqlite3_int64>(time(nullptr)));
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":action"),
                      action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":operator"),
                      operator_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":serial"),
                       static_cast<sqlite3_int64>(serial));
    sqlite3_bind_text(stmt, sqlite3_bind_parameter_index(stmt, ":detail"),
                      detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

}  // namespace

typedef epicsGuard<epicsMutex> Guard;

struct ConnTimerCtx {
    ClusterDiscovery *discovery;
    std::string node_id;
    std::shared_ptr<ClusterDiscovery::PeerConnectivity> state;
    uint32_t timeout_secs;
};

void connTimerEntry(void *arg) {
    auto ctx = std::unique_ptr<ConnTimerCtx>(static_cast<ConnTimerCtx *>(arg));
    epicsThreadSleep(static_cast<double>(ctx->timeout_secs));
    if (ctx->state->cancelled.load()) return;
    int expected = ClusterDiscovery::CONN_PENDING;
    if (!ctx->state->state.compare_exchange_strong(expected, ClusterDiscovery::CONN_UNREACHABLE))
        return;
    if (ctx->state->cancelled.load()) return;
    ctx->discovery->onConnectivityTimeout(ctx->node_id);
}

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
        reconcileMembers(std::string(), members);
    };
}

ClusterDiscovery::~ClusterDiscovery() {
    shutting_down_.store(true);

    // Join rejoin threads first.  A rejoin thread may be in
    // joinCluster()->client_ctx_.rpc().wait(timeout) and only sees
    // shutting_down_ when that wait returns; we cannot bail it out earlier.
    {
        std::vector<std::thread> threads_to_join;
        {
            std::lock_guard<std::mutex> lk(rejoin_thread_mutex_);
            threads_to_join.swap(old_rejoin_threads_);
            if (rejoin_thread_.joinable()) {
                threads_to_join.push_back(std::move(rejoin_thread_));
            }
        }
        for (auto &t : threads_to_join) {
            if (t.joinable()) t.join();
        }
    }

    // Detach the maps under the lock, then destroy the shared_ptr<Subscription>
    // entries OUTSIDE the lock.  ~Subscription dispatches cancel() to the
    // tcp_loop and waits; if the tcp_loop is concurrently running our event
    // callback, that callback will try to acquire state_lock_ on its own
    // shutting_down_-check path, which would deadlock if we still held it.
    std::map<std::string, std::shared_ptr<client::Subscription>> subs_to_destroy;
    {
        Guard G(state_lock_);
        subs_to_destroy.swap(subscriptions_);
        acknowledged_by_.clear();
        for (auto &kv : peer_connectivity_) kv.second->cancelled.store(true);
        peer_connectivity_.clear();
        active_forwarding_.clear();
        peer_sync_members_.clear();
        peer_last_sequence_.clear();
    }
    subs_to_destroy.clear();
    drainDeadSubscriptions();
}

SyncMergeResult applySyncSnapshot(sqlite3 *certs_db,
                                  epicsMutex &status_update_lock,
                                  const Value &snapshot,
                                  const std::string &peer_node_id) {
    Guard G(status_update_lock);
    SyncMergeResult result;

    const auto certs_arr = snapshot["certs"].as<shared_array<const Value>>();
    for (const auto & row : certs_arr) {
        auto serial = row["serial"].as<uint64_t>();
        const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
        const auto remote_status = static_cast<cms::cert::certstatus_t>(row["status"].as<int32_t>());

        sqlite3_stmt *check_stmt;
        if (sqlite3_prepare_v2(certs_db, SQL_SYNC_CHECK_CERT_STATUS, -1, &check_stmt, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_int64(check_stmt, sqlite3_bind_parameter_index(check_stmt, ":serial"), db_serial);

        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const auto local_status = static_cast<cms::cert::certstatus_t>(sqlite3_column_int(check_stmt, 0));
            sqlite3_finalize(check_stmt);

            log_debug_printf(pvacmscluster, "Sync merge: serial=%llu local_status=%d remote_status=%d\n",
                             static_cast<unsigned long long>(serial), static_cast<int>(local_status), static_cast<int>(remote_status));

            if (!isValidStatusTransition(local_status, remote_status)) {
                log_debug_printf(pvacmscluster, "Sync merge: skipping serial=%llu — invalid transition %d -> %d\n",
                                 static_cast<unsigned long long>(serial), static_cast<int>(local_status), static_cast<int>(remote_status));
                continue;
            }

            if (local_status == remote_status) {
                log_debug_printf(pvacmscluster, "Sync merge: skipping serial=%llu — same status %d\n",
                                 static_cast<unsigned long long>(serial), static_cast<int>(local_status));
                continue;
            }

            if (remote_status == cms::cert::REVOKED && local_status != cms::cert::REVOKED) {
                result.revoked_skids.push_back(row["skid"].as<std::string>());
            }

            sqlite3_stmt *upd_stmt;
            if (sqlite3_prepare_v2(certs_db, SQL_SYNC_UPDATE_CERT, -1, &upd_stmt, nullptr) != SQLITE_OK) {
                log_debug_printf(pvacmscluster, "Sync merge: SQL_SYNC_UPDATE_CERT prepare failed for serial=%llu: %s\n",
                                 static_cast<unsigned long long>(serial), sqlite3_errmsg(certs_db));
                continue;
            }

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
            {
                auto san_field = row["san"];
                if (san_field) {
                    auto san_str = san_field.as<std::string>();
                    if (!san_str.empty()) {
                        sqlite3_bind_text(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":san"), san_str.c_str(), -1, SQLITE_TRANSIENT);
                    } else {
                        sqlite3_bind_null(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":san"));
                    }
                } else {
                    sqlite3_bind_null(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":san"));
                }
            }
            sqlite3_bind_int64(upd_stmt, sqlite3_bind_parameter_index(upd_stmt, ":serial"), db_serial);
            auto rc = sqlite3_step(upd_stmt);
            log_debug_printf(pvacmscluster, "Sync merge: UPDATE serial=%llu rc=%d changes=%d\n",
                             static_cast<unsigned long long>(serial), rc, sqlite3_changes(certs_db));
            insertSyncAuditRecord(certs_db, AUDIT_ACTION_SYNC, peer_node_id,
                                  static_cast<uint64_t>(serial), SB() << "status=" << remote_status);
            sqlite3_finalize(upd_stmt);
            result.had_changes = true;
        } else {
            sqlite3_finalize(check_stmt);
            sqlite3_stmt *ins_stmt;
            if (sqlite3_prepare_v2(certs_db, SQL_SYNC_INSERT_CERT, -1, &ins_stmt, nullptr) != SQLITE_OK)
                continue;

            sqlite3_bind_int64(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":serial"), db_serial);
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
            {
                auto san_field = row["san"];
                if (san_field) {
                    auto san_str = san_field.as<std::string>();
                    if (!san_str.empty()) {
                        sqlite3_bind_text(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":san"), san_str.c_str(), -1, SQLITE_TRANSIENT);
                    } else {
                        sqlite3_bind_null(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":san"));
                    }
                } else {
                    sqlite3_bind_null(ins_stmt, sqlite3_bind_parameter_index(ins_stmt, ":san"));
                }
            }
            sqlite3_step(ins_stmt);
            insertSyncAuditRecord(certs_db, AUDIT_ACTION_SYNC, peer_node_id, serial, SB() << "status=" << remote_status);
            sqlite3_finalize(ins_stmt);
            result.had_changes = true;

            if (remote_status == REVOKED) {
                result.revoked_skids.push_back(row["skid"].as<std::string>());
            }
        }
    }

    auto sched_field = snapshot["cert_schedules"];
    if (sched_field) {
        auto sched_arr = sched_field.as<shared_array<const Value>>();
        std::set<uint64_t> synced_serials;
        for (const auto &row : sched_arr) {
            synced_serials.insert(row["serial"].as<uint64_t>());
        }
        for (auto serial : synced_serials) {
            const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
            sqlite3_stmt *del_stmt = nullptr;
            if (sqlite3_prepare_v2(certs_db, "DELETE FROM cert_schedules WHERE serial = ?", -1, &del_stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int64(del_stmt, 1, db_serial);
                sqlite3_step(del_stmt);
                sqlite3_finalize(del_stmt);
            }
        }
        for (const auto &row : sched_arr) {
            auto serial = row["serial"].as<uint64_t>();
            const int64_t db_serial = *reinterpret_cast<int64_t *>(&serial);
            sqlite3_stmt *ins_stmt = nullptr;
            if (sqlite3_prepare_v2(certs_db,
                                   "INSERT INTO cert_schedules(serial, day_of_week, start_time, end_time) VALUES(?, ?, ?, ?)",
                                   -1,
                                   &ins_stmt,
                                   nullptr) == SQLITE_OK) {
                sqlite3_bind_int64(ins_stmt, 1, db_serial);
                auto txt = [&](const char *field) { return row[field].as<std::string>(); };
                const auto day_of_week = txt("day_of_week");
                const auto start_time = txt("start_time");
                const auto end_time = txt("end_time");
                sqlite3_bind_text(ins_stmt, 2, day_of_week.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins_stmt, 3, start_time.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins_stmt, 4, end_time.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(ins_stmt);
                sqlite3_finalize(ins_stmt);
                insertSyncAuditRecord(certs_db, "SCHEDULE", peer_node_id,
                                      static_cast<uint64_t>(serial), "synced schedule");
            }
        }
        if (!sched_arr.empty()) {
            result.had_changes = true;
        }
    }

    return result;
}

/**
 * @brief Verifies and applies an incoming sync snapshot from a peer node.
 * @param peer_node_id Unique identifier of the node that sent the update.
 * @param val Incoming PVAccess Value containing the signed sync snapshot.
 */
void ClusterDiscovery::handleSyncUpdate(const std::string &peer_node_id, Value &&val) {
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

    const auto update_type = val["update_type"].as<int32_t>();
    const auto sequence = val["sequence"].as<int64_t>();

    auto peer_seq_it = peer_last_sequence_.find(peer_node_id);
    if (update_type == SYNC_INCREMENTAL && peer_seq_it != peer_last_sequence_.end()) {
        if (sequence != peer_seq_it->second + 1) {
            log_warn_printf(pvacmscluster,
                "Sequence gap from %s: expected %lld, got %lld — requesting resync\n",
                peer_node_id.c_str(),
                static_cast<long long>(peer_seq_it->second + 1),
                static_cast<long long>(sequence));

            auto peer_sync_pv = pv_prefix_ + ":SYNC:" + issuer_id_ + ":" + peer_node_id;
            try {
                auto req = TypeDef(TypeCode::Struct, {
                    members::String("operation"),
                }).create();
                req["operation"] = "resync";
                client_ctx_.rpc(peer_sync_pv, req).exec()->wait(5.0);
            } catch (const std::exception &e) {
                log_warn_printf(pvacmscluster, "Resync request to %s failed: %s\n",
                                peer_node_id.c_str(), e.what());
            }
        }
    }
    peer_last_sequence_[peer_node_id] = sequence;

    sync_publisher_.sync_ingestion_in_progress.store(true);
    SyncMergeResult merge_result;
    try {
        merge_result = applySyncSnapshot(certs_db_, status_update_lock_, val, peer_node_id);
    } catch (...) {
        sync_publisher_.sync_ingestion_in_progress.store(false);
        throw;
    }
    sync_publisher_.sync_ingestion_in_progress.store(false);

    auto certs_arr = val["certs"].as<shared_array<const Value>>();
    log_debug_printf(pvacmscluster, "Ingested sync %s from node %s (seq=%lld, %zu certs, changes=%d)\n",
                     update_type == SYNC_INCREMENTAL ? "incremental" : "snapshot",
                     peer_node_id.c_str(), static_cast<long long>(sequence), certs_arr.size(),
                     merge_result.had_changes);

    if (merge_result.had_changes && sync_publisher_.isForwarding(peer_node_id)) {
        log_debug_printf(pvacmscluster, "Forwarding: republishing after merge changes from %s\n",
                         peer_node_id.c_str());
        sync_publisher_.publishSnapshot();
    }

    if (on_node_cert_revoked) {
        for (const auto &skid : merge_result.revoked_skids) {
            on_node_cert_revoked(skid);
        }
    }

    const auto members_arr = val["members"].as<shared_array<const Value>>();
    std::vector<ClusterMember> remote_members;
    for (const auto & m : members_arr) {
        ClusterMember member;
        member.node_id = m["node_id"].as<std::string>();
        member.sync_pv = m["sync_pv"].as<std::string>();
        member.version_major = m["version_major"].as<uint32_t>();
        member.version_minor = m["version_minor"].as<uint32_t>();
        member.version_patch = m["version_patch"].as<uint32_t>();
        auto connected_field = m["connected"];
        member.connected = connected_field.valid() ? connected_field.as<bool>() : true;
        remote_members.push_back(std::move(member));
    }
    reconcileMembers(peer_node_id, remote_members);
    peer_sync_members_[peer_node_id] = remote_members;
    rescanForwarders();

    log_debug_printf(pvacmscluster, "Applied sync snapshot from %s (%zu certs)\n",
                     peer_node_id.c_str(), static_cast<size_t>(val["certs"].as<shared_array<const Value> >().size()));
}

/**
 * @brief Creates a monitor subscription to a peer node's sync PV.
 * @param node_id Unique identifier of the peer node to subscribe to.
 * @param sync_pv PVAccess name of the peer's sync PV.
 */
void ClusterDiscovery::subscribeToMember(const std::string &node_id, const std::string &sync_pv) {
    drainDeadSubscriptions();
    if (shutting_down_.load()) return;
    if (node_id == node_id_) return;

    std::shared_ptr<PeerConnectivity> conn_state;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        if (subscriptions_.count(node_id)) return;
        conn_state = std::make_shared<PeerConnectivity>();
        peer_connectivity_[node_id] = conn_state;
    }

    auto sub = client_ctx_.monitor(sync_pv)
        .maskConnected(false)
        .maskDisconnected(false)
        .event([this, node_id, sync_pv](client::Subscription &sub) {
            if (shutting_down_.load()) return;
            while (true) {
                try {
                    while (auto val = sub.pop()) {
                        if (shutting_down_.load()) return;
                        handleSyncUpdate(node_id, std::move(val));
                    }
                    break;
                } catch (client::Connected &) {
                    if (shutting_down_.load()) return;
                    Guard G(state_lock_);
                    if (shutting_down_.load()) return;
                    auto it = peer_connectivity_.find(node_id);
                    if (it != peer_connectivity_.end()) {
                        int prev = it->second->state.exchange(CONN_CONNECTED);
                        if (prev == CONN_UNREACHABLE) {
                            log_info_printf(pvacmscluster, "Peer %s now reachable (was unreachable)\n",
                                            node_id.c_str());
                            cancelForwarding(node_id);
                            publishMemberConnectivity();
                        }
                    }
                    // continue loop to drain any data queued after Connected
                } catch (client::Disconnect &) {
                    if (shutting_down_.load()) return;
                    handleDisconnect(node_id);
                    break;
                } catch (const std::exception &e) {
                    log_warn_printf(pvacmscluster, "Sync subscription error from %s: %s\n", node_id.c_str(), e.what());
                    break;
                }
            }
        })
        .exec();

    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        subscriptions_[node_id] = std::move(sub);
    }
    log_debug_printf(pvacmscluster, "Subscribed to sync PV %s (node %s)\n",
                     sync_pv.c_str(), node_id.c_str());

    if (shutting_down_.load()) return;
    auto *timer_ctx = new ConnTimerCtx{this, node_id, conn_state, discovery_timeout_secs_};
    epicsThreadCreate("pvacms-conn",
        epicsThreadPriorityLow,
        epicsThreadGetStackSize(epicsThreadStackSmall),
        connTimerEntry,
        timer_ctx);
}

/**
 * @brief Removes all state for a peer node after its sync subscription disconnects.
 * @param peer_node_id Unique identifier of the node that disconnected.
 */
void ClusterDiscovery::drainDeadSubscriptions() {
    std::vector<std::shared_ptr<client::Subscription>> to_destroy;
    {
        Guard G(dead_subscriptions_lock_);
        to_destroy.swap(dead_subscriptions_);
    }
}

void ClusterDiscovery::handleDisconnect(const std::string &peer_node_id) {
    if (shutting_down_.load()) return;

    bool was_forwarding = false;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;

        peer_last_sequence_.erase(peer_node_id);
        auto it = subscriptions_.find(peer_node_id);
        if (it != subscriptions_.end()) {
            Guard DG(dead_subscriptions_lock_);
            dead_subscriptions_.push_back(std::move(it->second));
            subscriptions_.erase(it);
        }

        auto conn_it = peer_connectivity_.find(peer_node_id);
        if (conn_it != peer_connectivity_.end()) {
            conn_it->second->cancelled.store(true);
            peer_connectivity_.erase(conn_it);
        }

        was_forwarding = sync_publisher_.isForwarding(peer_node_id);
    }

    if (was_forwarding) {
        log_info_printf(pvacmscluster, "Forwardee %s disconnected, stopping forwarding\n",
                        peer_node_id.c_str());
        sync_publisher_.removeForwardingRelationship(peer_node_id);
        publishMemberConnectivity();
    }

    if (shutting_down_.load()) return;
    controller_.removeMember(peer_node_id);
    log_info_printf(pvacmscluster, "Removed disconnected member %s\n", peer_node_id.c_str());

    rejoinCluster();
}

/**
 * @brief Subscribes to any remote cluster members not yet tracked locally.
 * @param remote_members List of cluster members advertised by a peer in a sync snapshot.
 */
void ClusterDiscovery::reconcileMembers(const std::string &sender_node_id,
                                        const std::vector<ClusterMember> &remote_members) {
    if (shutting_down_.load()) return;

    // Detect self-eviction per peer: only trigger if THIS specific peer
    // previously included us in its membership and now does not.  Stale
    // snapshots from peers that haven't processed our join yet are ignored.
    if (!sender_node_id.empty() && remote_members.size() > 1) {
        bool self_present = false;
        for (const auto &m : remote_members) {
            if (m.node_id == node_id_) {
                self_present = true;
                break;
            }
        }
        if (self_present) {
            acknowledged_by_.insert(sender_node_id);
        } else if (acknowledged_by_.count(sender_node_id)) {
            log_warn_printf(pvacmscluster,
                "This node (%s) is absent from %s's membership list — evicted, rejoining%s\n",
                node_id_.c_str(), sender_node_id.c_str(), "");
            acknowledged_by_.clear();
            rejoinCluster();
            return;
        }
    }

    for (const auto &m : remote_members) {
        if (shutting_down_.load()) return;
        if (m.node_id == node_id_) continue;
        bool already_subscribed;
        {
            Guard G(state_lock_);
            already_subscribed = subscriptions_.count(m.node_id) > 0;
        }
        if (!already_subscribed) {
            log_info_printf(pvacmscluster, "Discovered new member %s via peer sync\n", m.node_id.c_str());
            subscribeToMember(m.node_id, m.sync_pv);
            // Only add to membership if subscribe actually succeeded -
            // otherwise we'd recurse via on_membership_changed forever
            // (subscriptions_.count(m.node_id) stays 0, addMember fires
            // on_membership_changed, which calls back into us).
            bool subscribed_now;
            {
                Guard G(state_lock_);
                subscribed_now = subscriptions_.count(m.node_id) > 0;
            }
            if (subscribed_now) {
                controller_.addMember(m);
            }
        }
    }
}

void ClusterDiscovery::rejoinCluster() {
    if (shutting_down_.load()) return;
    if (rejoin_in_progress_.exchange(true)) {
        return;
    }

    log_info_printf(pvacmscluster, "Membership changed — re-establishing cluster for node %s\n", node_id_.c_str());

    // Hand the previous (now-finished, since rejoin_in_progress_ was false)
    // thread off to a side-vector so we never block the caller (which may
    // be running on the client tcp_loop) on join().  The destructor joins
    // both the side-vector entries and the live thread.
    std::lock_guard<std::mutex> lk(rejoin_thread_mutex_);
    if (shutting_down_.load()) {
        rejoin_in_progress_.store(false);
        return;
    }
    if (rejoin_thread_.joinable()) {
        old_rejoin_threads_.push_back(std::move(rejoin_thread_));
    }
    rejoin_thread_ = std::thread([this]() { doRejoin(); });
}

void ClusterDiscovery::doRejoin() {
    if (shutting_down_.load()) {
        rejoin_in_progress_.store(false);
        return;
    }

    {
        Guard G(state_lock_);
        if (shutting_down_.load()) {
            rejoin_in_progress_.store(false);
            return;
        }
        acknowledged_by_.clear();
        peer_last_sequence_.clear();
        subscriptions_.clear();

        for (auto &kv : peer_connectivity_)
            kv.second->cancelled.store(true);
        peer_connectivity_.clear();
        active_forwarding_.clear();
        peer_sync_members_.clear();
    }

    if (shutting_down_.load()) {
        rejoin_in_progress_.store(false);
        return;
    }

    controller_.initAsSoleNode(node_id_, sync_publisher_.getSyncPvName());
    sync_publisher_.publishSnapshot();

    if (shutting_down_.load()) {
        rejoin_in_progress_.store(false);
        return;
    }

    auto result = joinCluster();
    if (result == JoinResult::Joined) {
        sync_publisher_.publishSnapshot();
    }

    if (controller_.getMembers().size() > 1) {
        log_info_printf(pvacmscluster, "Cluster membership re-established%s\n", "");
    } else {
        log_info_printf(pvacmscluster,
            "No peers found — continuing as sole node%s\n", "");
    }

    rejoin_in_progress_.store(false);
}

/**
 * @brief Sends a signed join request to the cluster control PV and subscribes to member sync PVs.
 * @return true if the join handshake succeeded and the cluster was joined; false otherwise.
 */
ClusterDiscovery::JoinResult ClusterDiscovery::joinCluster() {
    if (shutting_down_.load()) return JoinResult::NotFound;
    drainDeadSubscriptions();
    static constexpr int kMaxBidiRetries = 3;
    auto ctrl_pv_name = pv_prefix_ + ":CTRL:" + issuer_id_ + ":" + node_id_;
    auto sync_pv_name = sync_publisher_.getSyncPvName();

    for (int bidi_attempt = 0; bidi_attempt <= kMaxBidiRetries; bidi_attempt++) {
    if (shutting_down_.load()) return JoinResult::NotFound;
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
        // Short-circuit RPC on shutdown so destructor join can complete fast.
        double rpc_timeout = shutting_down_.load() ? 0.5 : double(discovery_timeout_secs_);
        auto resp = client_ctx_.rpc(ctrl_pv_name, req)
            .exec()
            ->wait(rpc_timeout);

        if (!clusterVerify(cert_auth_pub_key_, resp)) {
            log_warn_printf(pvacmscluster, "Join response signature verification failed%s\n", "");
            return JoinResult::NotFound;
        }

        auto resp_issuer = resp["issuer_id"].as<std::string>();
        if (resp_issuer != issuer_id_) {
            log_warn_printf(pvacmscluster, "Join response issuer_id mismatch: expected %s, got %s\n",
                            issuer_id_.c_str(), resp_issuer.c_str());
            return JoinResult::NotFound;
        }

        auto resp_nonce = resp["nonce"].as<shared_array<const uint8_t>>();
        if (resp_nonce.size() != frozen_nonce.size() ||
            std::memcmp(resp_nonce.data(), frozen_nonce.data(), frozen_nonce.size()) != 0) {
            log_warn_printf(pvacmscluster, "Join response nonce mismatch - possible replay/relay attack%s\n", "");
            return JoinResult::NotFound;
        }

        auto resp_ts = getTimeStamp(resp);
        epicsTimeStamp now_ts = epicsTime::getCurrent();
        auto now = static_cast<int64_t>(now_ts.secPastEpoch);
        if (std::abs(now - resp_ts) > kJoinTimestampTolerance) {
            log_warn_printf(pvacmscluster, "Join response stale timestamp (ts=%lld, now=%lld)\n",
                            static_cast<long long>(resp_ts), static_cast<long long>(now));
            return JoinResult::NotFound;
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
                m["version_patch"].as<uint32_t>(),
                true
            });
        }

        controller_.updateMembership(members);

        for (const auto &m : members) {
            subscribeToMember(m.node_id, m.sync_pv);
        }

        return JoinResult::Joined;
    } catch (const std::exception &e) {
        std::string msg(e.what());
        if (msg.find("REVOKED:") == 0) {
            log_err_printf(pvacmscluster, "Join rejected: %s\n", msg.c_str());
            return JoinResult::Revoked;
        }
        if (msg.find("Bidirectional connectivity") != std::string::npos &&
            bidi_attempt < kMaxBidiRetries) {
            log_info_printf(pvacmscluster,
                "Join rejected (bidi check), retry %d/%d for alternate responder...\n",
                bidi_attempt + 1, kMaxBidiRetries);
            epicsThreadSleep(1.0);
            continue;
        }
        log_warn_printf(pvacmscluster, "Join RPC failed: %s\n", e.what());
        return JoinResult::NotFound;
    }
    }
    return JoinResult::NotFound;
}

void ClusterDiscovery::onConnectivityTimeout(const std::string &node_id) {
    if (shutting_down_.load()) return;
    log_warn_printf(pvacmscluster, "Peer %s unreachable after %u second timeout\n",
                    node_id.c_str(), discovery_timeout_secs_);
    publishMemberConnectivity();
    if (shutting_down_.load()) return;
    seekForwarder(node_id);
}

void ClusterDiscovery::seekForwarder(const std::string &unreachable_node_id) {
    if (active_forwarding_.count(unreachable_node_id))
        return;

    for (const auto &peer : peer_sync_members_) {
        if (peer.first == unreachable_node_id)
            continue;
        auto conn_it = peer_connectivity_.find(peer.first);
        if (conn_it == peer_connectivity_.end() || conn_it->second->state.load() != CONN_CONNECTED)
            continue;

        for (const auto &m : peer.second) {
            if (m.node_id == unreachable_node_id && m.connected) {
                log_info_printf(pvacmscluster,
                    "Requesting forwarding of %s via intermediary %s\n",
                    unreachable_node_id.c_str(), peer.first.c_str());

                auto req = TypeDef(TypeCode::Struct, {
                    members::String("operation"),
                    members::String("node_id"),
                }).create();
                req["operation"] = "forward";
                req["node_id"] = unreachable_node_id;

                std::string intermediary_sync_pv;
                for (const auto &pm : peer.second) {
                    if (pm.node_id == peer.first) {
                        intermediary_sync_pv = pm.sync_pv;
                        break;
                    }
                }
                if (intermediary_sync_pv.empty()) {
                    auto subs_it = subscriptions_.find(peer.first);
                    if (subs_it == subscriptions_.end())
                        continue;
                    auto members = controller_.getMembers();
                    for (const auto &cm : members) {
                        if (cm.node_id == peer.first) {
                            intermediary_sync_pv = cm.sync_pv;
                            break;
                        }
                    }
                }
                if (intermediary_sync_pv.empty())
                    continue;

                try {
                    client_ctx_.rpc(intermediary_sync_pv, req)
                        .exec()
                        ->wait(double(discovery_timeout_secs_));
                    active_forwarding_[unreachable_node_id] = {peer.first, intermediary_sync_pv};
                    log_info_printf(pvacmscluster,
                        "Forwarding of %s via %s established\n",
                        unreachable_node_id.c_str(), peer.first.c_str());
                    return;
                } catch (const std::exception &e) {
                    log_warn_printf(pvacmscluster,
                        "Forward request to %s for %s failed: %s\n",
                        peer.first.c_str(), unreachable_node_id.c_str(), e.what());
                }
            }
        }
    }

    log_warn_printf(pvacmscluster, "No intermediary available for unreachable peer %s\n",
                    unreachable_node_id.c_str());
}

void ClusterDiscovery::cancelForwarding(const std::string &node_id) {
    auto it = active_forwarding_.find(node_id);
    if (it == active_forwarding_.end())
        return;

    log_info_printf(pvacmscluster, "Cancelling forwarding of %s via %s (direct connectivity restored)\n",
                    node_id.c_str(), it->second.intermediary_node_id.c_str());

    auto req = TypeDef(TypeCode::Struct, {
        members::String("operation"),
        members::String("node_id"),
    }).create();
    req["operation"] = "cancel-forward";
    req["node_id"] = node_id;

    try {
        client_ctx_.rpc(it->second.intermediary_sync_pv, req)
            .exec()
            ->wait(double(discovery_timeout_secs_));
    } catch (const std::exception &e) {
        log_warn_printf(pvacmscluster, "Cancel-forward RPC to %s failed: %s\n",
                        it->second.intermediary_node_id.c_str(), e.what());
    }
    active_forwarding_.erase(it);
}

void ClusterDiscovery::rescanForwarders() {
    for (auto &conn_kv : peer_connectivity_) {
        if (conn_kv.second->state.load() != CONN_UNREACHABLE)
            continue;
        if (active_forwarding_.count(conn_kv.first))
            continue;
        seekForwarder(conn_kv.first);
    }
}

bool ClusterDiscovery::isPeerConnected(const std::string &node_id) const {
    auto it = peer_connectivity_.find(node_id);
    return it != peer_connectivity_.end() && it->second->state.load() == CONN_CONNECTED;
}

void ClusterDiscovery::publishMemberConnectivity() {
    auto members = controller_.getMembers();
    for (auto &m : members) {
        if (m.node_id == node_id_) {
            m.connected = true;
        } else {
            auto it = peer_connectivity_.find(m.node_id);
            m.connected = (it != peer_connectivity_.end() &&
                           it->second->state.load() == CONN_CONNECTED);
        }
    }
    sync_publisher_.publishSnapshot(members);
}

}  // namespace cluster
}  // namespace cms
