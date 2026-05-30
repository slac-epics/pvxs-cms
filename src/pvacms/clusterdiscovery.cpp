/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clusterdiscovery.h"

#include <algorithm>
#include <cinttypes>
#include <chrono>
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
#include "sqlitestmtguard.h"

DEFINE_LOGGER(pvacmscluster, "cms.certs.cluster");

namespace cms {
namespace cluster {

using ::cms::detail::SqliteStmtGuard;

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

    sqlite3_stmt *stmt_raw = nullptr;
    if (sqlite3_prepare_v2(db, SQL_INSERT_AUDIT, -1, &stmt_raw, nullptr) != SQLITE_OK) {
        return;
    }
    SqliteStmtGuard stmt_guard(stmt_raw);
    sqlite3_stmt *stmt = stmt_guard.get();
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
}

}  // namespace

typedef epicsGuard<epicsMutex> Guard;

constexpr int64_t ClusterDiscovery::kBeaconRefreshCooldownSecs;

struct ConnTimerCtx {
    ClusterDiscovery *discovery;
    std::string node_id;
    std::shared_ptr<ClusterDiscovery::PeerConnectivity> state;
    uint32_t timeout_secs;
};

void connTimerEntry(void *arg) {
    auto ctx = std::unique_ptr<ConnTimerCtx>(static_cast<ConnTimerCtx *>(arg));
    // Balance the increment done before epicsThreadCreate so the destructor
    // can wait this detached thread out before destroying the peer maps.
    struct TimerGuard {
        std::atomic<int> &count;
        ~TimerGuard() { count.fetch_sub(1); }
    } timer_guard{ctx->discovery->outstanding_conn_timers_};

    // Sleep the timeout in short slices so ~ClusterDiscovery (which waits this
    // detached thread out) is not blocked for the full timeout during teardown.
    const double slice = 0.1;
    double remaining = static_cast<double>(ctx->timeout_secs);
    while (remaining > 0.0) {
        if (ctx->discovery->shutting_down_.load() || ctx->state->cancelled.load()) return;
        const double s = remaining < slice ? remaining : slice;
        epicsThreadSleep(s);
        remaining -= s;
    }
    if (ctx->discovery->shutting_down_.load()) return;
    if (ctx->state->cancelled.load()) return;
    int expected = ClusterDiscovery::CONN_PENDING;
    if (!ctx->state->state.compare_exchange_strong(expected, ClusterDiscovery::CONN_UNREACHABLE))
        return;
    if (ctx->state->cancelled.load()) return;
    if (ctx->discovery->shutting_down_.load()) return;
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
    join_worker_thread_.reset(new epicsThread( join_worker_runnable_, "pvacms-cluster-join", epicsThreadGetStackSize(epicsThreadStackSmall), epicsThreadPriorityLow));
    join_worker_thread_->start();
    rejoin_watchdog_thread_.reset(new epicsThread( rejoin_watchdog_runnable_, "pvacms-rejoin-wd", epicsThreadGetStackSize(epicsThreadStackSmall), epicsThreadPriorityLow));
    rejoin_watchdog_thread_->start();
    deferred_worker_thread_.reset(new epicsThread(deferred_worker_runnable_, "pvacms-deferred", epicsThreadGetStackSize(epicsThreadStackSmall), epicsThreadPriorityLow));
    deferred_worker_thread_->start();
    startBeaconDiscovery();
}

ClusterDiscovery::~ClusterDiscovery() {
    shutting_down_.store(true);
    join_worker_wakeup_.signal();
    rejoin_watchdog_wakeup_.signal();
    deferred_wakeup_.signal();
    beacon_discovery_.reset();
    if (join_worker_thread_) {
        join_worker_thread_->exitWait();
        join_worker_thread_.reset();
    }
    if (rejoin_watchdog_thread_) {
        rejoin_watchdog_thread_->exitWait();
        rejoin_watchdog_thread_.reset();
    }
    if (deferred_worker_thread_) {
        deferred_worker_thread_->exitWait();
        deferred_worker_thread_.reset();
    }
    {
        Guard G(deferred_lock_);
        deferred_resubscribes_.clear();
        deferred_rescan_pending_ = false;
    }

    // Cancel every peer's connectivity timer under the lock so any detached
    // "pvacms-conn" thread that wakes from its sleep observes cancelled/
    // shutting_down_ and returns without touching state.
    {
        Guard G(state_lock_);
        for (auto &kv : peer_connectivity_) kv.second->cancelled.store(true);
    }
    // The named worker threads are exitWait-joined above, but the conn-timers
    // are detached and not joinable.  Wait them out before destroying the maps
    // they iterate (peer_connectivity_/peer_sync_members_/active_forwarding_/
    // relayed_via_/subscriptions_) — otherwise a timer mid-iteration crashes in
    // std::_Rb_tree_increment when the map is cleared underneath it.  Each
    // timer rechecks shutting_down_ on wake, so this drains within one sleep.
    while (outstanding_conn_timers_.load() > 0) {
        epicsThreadSleep(0.01);
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
        peer_connectivity_.clear();
        active_forwarding_.clear();
        peer_sync_members_.clear();
        peer_last_sequence_.clear();
        relayed_via_.clear();
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
        const auto remote_status = static_cast<certstatus_t>(row["status"].as<int32_t>());

        sqlite3_stmt *check_stmt;
        if (sqlite3_prepare_v2(certs_db, SQL_SYNC_CHECK_CERT_STATUS, -1, &check_stmt, nullptr) != SQLITE_OK)
            continue;
        sqlite3_bind_int64(check_stmt, sqlite3_bind_parameter_index(check_stmt, ":serial"), db_serial);

        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const auto local_status = static_cast<certstatus_t>(sqlite3_column_int(check_stmt, 0));
            sqlite3_finalize(check_stmt);

            log_debug_printf(pvacmscluster, "Sync merge: serial=%" PRIu64 " local_status=%d remote_status=%d\n",
                             serial, static_cast<int>(local_status), static_cast<int>(remote_status));

            if (!isValidStatusTransition(local_status, remote_status)) {
                log_debug_printf(pvacmscluster, "Sync merge: skipping serial=%" PRIu64 " — invalid transition %d -> %d\n",
                                 serial, static_cast<int>(local_status), static_cast<int>(remote_status));
                continue;
            }

            if (local_status == remote_status) {
                log_debug_printf(pvacmscluster, "Sync merge: skipping serial=%" PRIu64 " — same status %d\n", serial, static_cast<int>(local_status));
                continue;
            }

            if (remote_status == cms::cert::REVOKED && local_status != cms::cert::REVOKED) {
                result.revoked_skids.push_back(row["skid"].as<std::string>());
            }

            sqlite3_stmt *upd_stmt_raw = nullptr;
            if (sqlite3_prepare_v2(certs_db, SQL_SYNC_UPDATE_CERT, -1, &upd_stmt_raw, nullptr) != SQLITE_OK) {
                log_debug_printf(pvacmscluster, "Sync merge: SQL_SYNC_UPDATE_CERT prepare failed for serial=%" PRIu64 ": %s\n",
                                 serial, sqlite3_errmsg(certs_db));
                continue;
            }
            SqliteStmtGuard upd_guard(upd_stmt_raw);
            sqlite3_stmt *upd_stmt = upd_guard.get();

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
            log_debug_printf(pvacmscluster, "Sync merge: UPDATE serial=%" PRIu64 " rc=%d changes=%d\n", serial, rc, sqlite3_changes(certs_db));
            insertSyncAuditRecord(certs_db, AUDIT_ACTION_SYNC, peer_node_id, serial, SB() << "status=" << remote_status);
            result.had_changes = true;
        } else {
            sqlite3_finalize(check_stmt);
            sqlite3_stmt *ins_stmt_raw = nullptr;
            if (sqlite3_prepare_v2(certs_db, SQL_SYNC_INSERT_CERT, -1, &ins_stmt_raw, nullptr) != SQLITE_OK)
                continue;
            SqliteStmtGuard ins_guard(ins_stmt_raw);
            sqlite3_stmt *ins_stmt = ins_guard.get();

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
            sqlite3_stmt *ins_stmt_raw = nullptr;
            if (sqlite3_prepare_v2(certs_db,
                                   "INSERT INTO cert_schedules(serial, day_of_week, start_time, end_time) VALUES(?, ?, ?, ?)",
                                   -1,
                                   &ins_stmt_raw,
                                   nullptr) == SQLITE_OK) {
                SqliteStmtGuard sched_guard(ins_stmt_raw);
                sqlite3_stmt *ins_stmt = sched_guard.get();
                sqlite3_bind_int64(ins_stmt, 1, db_serial);
                auto txt = [&](const char *field) { return row[field].as<std::string>(); };
                const auto day_of_week = txt("day_of_week");
                const auto start_time = txt("start_time");
                const auto end_time = txt("end_time");
                sqlite3_bind_text(ins_stmt, 2, day_of_week.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins_stmt, 3, start_time.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(ins_stmt, 4, end_time.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(ins_stmt);
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
        log_warn_printf(pvacmscluster, "Stale/replayed sync snapshot from %s (ts=%" PRId64 ", hwm=%" PRId64 ")\n",
                        peer_node_id.c_str(), incoming_ts, hwm);
        return;
    }

    int64_t expected = hwm;
    while (incoming_ts > expected &&
           !global_high_water_mark_.compare_exchange_weak(expected, incoming_ts)) {}

    const auto update_type = val["update_type"].as<int32_t>();
    const auto sequence = val["sequence"].as<int64_t>();

    // Read the last-seen sequence and record this one under state_lock_; the
    // peer_last_sequence_ map is also torn down by ~ClusterDiscovery.
    bool needs_resync = false;
    int64_t last_sequence = 0;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        auto peer_seq_it = peer_last_sequence_.find(peer_node_id);
        if (update_type == SYNC_INCREMENTAL && peer_seq_it != peer_last_sequence_.end()) {
            last_sequence = peer_seq_it->second;
            needs_resync = (sequence <= last_sequence);
        }
        peer_last_sequence_[peer_node_id] = sequence;
    }

    if (needs_resync) {
        // ClusterSyncPublisher::sendToSubscriber batches every update_log_
        // entry since the subscriber's last sequence into one incremental
        // message and stamps it with updates.back().sequence — so a forward
        // jump (sequence > last+1) is normal: the message carries every
        // missed cert row. Only resync on a backwards/duplicate sequence,
        // which indicates the publisher restarted or our state is stale.
        log_warn_printf(pvacmscluster,
            "Stale sequence from %s: got %" PRId64 ", already at %" PRId64 " — requesting resync\n",
            peer_node_id.c_str(), sequence, last_sequence);

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
    log_debug_printf(pvacmscluster, "Ingested sync %s from node %s (seq=%" PRId64 ", %zu certs, changes=%d)\n",
                     update_type == SYNC_INCREMENTAL ? "incremental" : "snapshot",
                     peer_node_id.c_str(), sequence, certs_arr.size(),
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
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        peer_sync_members_[peer_node_id] = std::move(remote_members);
    }

    scheduleRescanForwarders();

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
                    bool reachable_restored = false;
                    {
                        Guard G(state_lock_);
                        if (shutting_down_.load()) return;
                        auto it = peer_connectivity_.find(node_id);
                        if (it != peer_connectivity_.end()) {
                            int prev = it->second->state.exchange(CONN_CONNECTED);
                            // We now hold a live subscription to this peer, so it
                            // is no longer merely relayed via a middle node.
                            relayed_via_.erase(node_id);
                            reachable_restored = (prev == CONN_UNREACHABLE);
                        }
                    }
                    // cancelForwarding/publishMemberConnectivity take state_lock_
                    // and issue blocking RPCs, so call them outside the lock.
                    if (reachable_restored) {
                        log_info_printf(pvacmscluster, "Peer %s now reachable (was unreachable)\n",
                                        node_id.c_str());
                        cancelForwarding(node_id);
                        publishMemberConnectivity();
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
    // Register the timer before creating it so ~ClusterDiscovery cannot finish
    // clearing the peer maps while this detached thread is still in flight.
    outstanding_conn_timers_.fetch_add(1);
    if (!epicsThreadCreate("pvacms-conn",
            epicsThreadPriorityLow,
            epicsThreadGetStackSize(epicsThreadStackSmall),
            connTimerEntry,
            timer_ctx)) {
        // Thread never started: connTimerEntry will not run, so undo the
        // registration and reclaim the context here.
        outstanding_conn_timers_.fetch_sub(1);
        delete timer_ctx;
    }
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

void ClusterDiscovery::scheduleRescanForwarders() {
    {
        Guard G(deferred_lock_);
        if (deferred_rescan_pending_) return;
        deferred_rescan_pending_ = true;
    }
    deferred_wakeup_.signal();
}

void ClusterDiscovery::scheduleResubscribe(const std::string &node_id,
                                           const std::string &sync_pv,
                                           double holdoff_secs) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(static_cast<int64_t>(holdoff_secs * 1000.0));
    {
        Guard G(deferred_lock_);
        deferred_resubscribes_.push_back({node_id, sync_pv, deadline});
    }
    deferred_wakeup_.signal();
}

void ClusterDiscovery::deferredWorkerLoop() {
    while (!shutting_down_.load()) {
        bool do_rescan = false;
        std::vector<DeferredResubscribe> ready;
        std::chrono::steady_clock::time_point next_deadline =
            std::chrono::steady_clock::time_point::max();
        const auto now = std::chrono::steady_clock::now();

        {
            Guard G(deferred_lock_);
            if (deferred_rescan_pending_) {
                deferred_rescan_pending_ = false;
                do_rescan = true;
            }
            auto it = deferred_resubscribes_.begin();
            while (it != deferred_resubscribes_.end()) {
                if (it->not_before <= now) {
                    ready.push_back(std::move(*it));
                    it = deferred_resubscribes_.erase(it);
                } else {
                    if (it->not_before < next_deadline) next_deadline = it->not_before;
                    ++it;
                }
            }
        }

        if (do_rescan && !shutting_down_.load()) {
            try {
                rescanForwarders();
            } catch (const std::exception &e) {
                log_warn_printf(pvacmscluster, "Deferred rescanForwarders failed: %s\n", e.what());
            }
        }
        for (auto &work : ready) {
            if (shutting_down_.load()) break;
            try {
                resubscribeIfStillUnreachable(work.node_id, work.sync_pv);
            } catch (const std::exception &e) {
                log_warn_printf(pvacmscluster,
                                "Deferred resubscribe of %s failed: %s\n",
                                work.node_id.c_str(), e.what());
            }
        }

        if (shutting_down_.load()) return;

        if (next_deadline == std::chrono::steady_clock::time_point::max()) {
            deferred_wakeup_.wait();
        } else {
            const auto wait_secs = std::chrono::duration<double>(next_deadline - now).count();
            if (wait_secs > 0.0) deferred_wakeup_.wait(wait_secs);
        }
    }
}

void ClusterDiscovery::resubscribeIfStillUnreachable(const std::string &peer_node_id,
                                                     const std::string &sync_pv) {
    if (shutting_down_.load()) return;

    std::shared_ptr<client::Subscription> stale;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        auto conn_it = peer_connectivity_.find(peer_node_id);
        if (conn_it == peer_connectivity_.end()) return;
        if (conn_it->second->state.load() != CONN_UNREACHABLE) return;

        auto sub_it = subscriptions_.find(peer_node_id);
        if (sub_it == subscriptions_.end()) return;
        stale = std::move(sub_it->second);
        subscriptions_.erase(sub_it);
        peer_connectivity_.erase(peer_node_id);
    }

    {
        Guard G(dead_subscriptions_lock_);
        dead_subscriptions_.push_back(std::move(stale));
    }

    log_info_printf(pvacmscluster,
                    "Peer %s still unreachable after pvxs reconnect window; recreating subscription\n",
                    peer_node_id.c_str());
    subscribeToMember(peer_node_id, sync_pv);
}

void ClusterDiscovery::handleDisconnect(const std::string &peer_node_id) {
    if (shutting_down_.load()) return;

    bool was_forwarding = false;
    bool transitioned_to_unreachable = false;
    std::vector<std::pair<std::string, std::shared_ptr<client::Subscription>>> orphaned_relayed;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;

        peer_last_sequence_.erase(peer_node_id);

        auto conn_it = peer_connectivity_.find(peer_node_id);
        if (conn_it != peer_connectivity_.end()) {
            int prev = conn_it->second->state.exchange(CONN_UNREACHABLE);
            transitioned_to_unreachable = (prev == CONN_CONNECTED);
        }

        was_forwarding = sync_publisher_.isForwarding(peer_node_id);

        // Teardown the relay: members we counted only because peer_node_id (the
        // middle node) advertised and forwarded them lose their data path now
        // that the middle node is gone.  Collect them for removal so membership
        // does not retain ghosts; detach their (never-connected) subscription
        // handles under the lock and destroy them outside it.
        for (auto it = relayed_via_.begin(); it != relayed_via_.end();) {
            if (it->second == peer_node_id) {
                const std::string relayed_id = it->first;
                std::shared_ptr<client::Subscription> sub;
                auto sub_it = subscriptions_.find(relayed_id);
                if (sub_it != subscriptions_.end()) {
                    sub = std::move(sub_it->second);
                    subscriptions_.erase(sub_it);
                }
                // Cancel the relayed peer's connectivity timer before dropping
                // the map entry: the detached conn-timer thread holds its own
                // ref to PeerConnectivity and would otherwise dereference a
                // freed ClusterDiscovery after teardown (use-after-free).
                auto conn_it = peer_connectivity_.find(relayed_id);
                if (conn_it != peer_connectivity_.end()) {
                    conn_it->second->cancelled.store(true);
                    peer_connectivity_.erase(conn_it);
                }
                orphaned_relayed.emplace_back(relayed_id, std::move(sub));
                it = relayed_via_.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto &entry : orphaned_relayed) {
        log_info_printf(pvacmscluster,
                        "Relay via %s lost; dropping relayed member %s\n",
                        peer_node_id.c_str(), entry.first.c_str());
        controller_.removeMember(entry.first);
    }
    if (!orphaned_relayed.empty()) {
        Guard G(dead_subscriptions_lock_);
        for (auto &entry : orphaned_relayed) {
            if (entry.second) dead_subscriptions_.push_back(std::move(entry.second));
        }
    }

    if (was_forwarding) {
        log_info_printf(pvacmscluster, "Forwardee %s disconnected, stopping forwarding\n",
                        peer_node_id.c_str());
        sync_publisher_.removeForwardingRelationship(peer_node_id);
    }

    if (transitioned_to_unreachable) {
        log_info_printf(pvacmscluster,
                        "Peer %s TCP lost; awaiting auto-reconnect (membership preserved)\n",
                        peer_node_id.c_str());
        publishMemberConnectivity();

        auto sync_pv = pv_prefix_ + ":SYNC:" + issuer_id_ + ":" + peer_node_id;
        scheduleResubscribe(peer_node_id, sync_pv, 30.0);
    }
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

    // A member learned from a directly-connected peer that we cannot reach
    // ourselves is a RELAYED member: the middle node (sender_node_id) forwards
    // its sync data to us, so we count it as a member without holding our own
    // live subscription.  Record the relay so handleDisconnect can drop it if
    // the middle node goes away (no membership ghosts).
    bool sender_is_connected = false;
    if (!sender_node_id.empty() && sender_node_id != node_id_) {
        Guard G(state_lock_);
        sender_is_connected = isPeerConnected(sender_node_id);
    }

    for (const auto &m : remote_members) {
        if (shutting_down_.load()) return;
        if (m.node_id == node_id_) continue;
        bool already_subscribed;
        bool directly_connected;
        {
            Guard G(state_lock_);
            already_subscribed = subscriptions_.count(m.node_id) > 0;
            directly_connected = isPeerConnected(m.node_id);
        }

        // Maintain the relay bookkeeping for members we don't directly reach.
        if (sender_is_connected && m.node_id != sender_node_id && !directly_connected) {
            Guard G(state_lock_);
            relayed_via_[m.node_id] = sender_node_id;
        }

        if (!already_subscribed) {
            log_info_printf(pvacmscluster, "Discovered new member %s via peer sync\n", m.node_id.c_str());
            subscribeToMember(m.node_id, m.sync_pv);
            // subscribeToMember stores the subscription handle even before it
            // connects, so subscriptions_.count(m.node_id) is now >0 whether or
            // not the peer is directly reachable.  Adding the member here is the
            // relay-membership path: a transitively-reachable node still counts.
            // Re-checking the count keeps the "add once" discipline that stops
            // the on_membership_changed -> reconcileMembers recursion from
            // looping (the recursive call sees already_subscribed and skips).
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

void ClusterDiscovery::rejoinWatchdogLoop() {
    // Wake up periodically; if we are still a sole-node cluster (e.g.
    // because startup raced peer-readiness — gateway not yet TLS-ready
    // when we first attempted to join), trigger another rejoin.  Once
    // we have peers, the watchdog stays cheap (it just re-checks).
    constexpr double kWatchdogIntervalSecs = 30.0;
    while (!shutting_down_.load()) {
        rejoin_watchdog_wakeup_.wait(kWatchdogIntervalSecs);
        if (shutting_down_.load()) return;
        if (controller_.getMembers().size() <= 1) {
            log_info_printf(pvacmscluster,
                            "Watchdog: still sole-node, attempting rejoin\n%s", "");
            rejoinCluster();
        }
    }
}

void ClusterDiscovery::rejoinCluster() {
    if (shutting_down_.load()) return;
    log_info_printf(pvacmscluster, "Membership changed — re-establishing cluster for node %s\n", node_id_.c_str());
    pending_full_rejoin_.store(true);
    join_worker_wakeup_.signal();
}

void ClusterDiscovery::doRejoin() {
    if (shutting_down_.load()) return;

    // Detach subscriptions under the lock, destroy them OUTSIDE.  Same
    // deadlock-avoidance pattern as ~ClusterDiscovery: ~Subscription cancel()
    // dispatches to the tcp_loop and waits, but the tcp_loop is concurrently
    // running our event callback which (on Disconnect) tries to acquire
    // state_lock_ via handleDisconnect.  Holding state_lock_ across the
    // clear() deadlocks against that.
    std::map<std::string, std::shared_ptr<client::Subscription>> subs_to_destroy;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        acknowledged_by_.clear();
        peer_last_sequence_.clear();
        subs_to_destroy.swap(subscriptions_);

        for (auto &kv : peer_connectivity_)
            kv.second->cancelled.store(true);
        peer_connectivity_.clear();
        active_forwarding_.clear();
        peer_sync_members_.clear();
        relayed_via_.clear();
    }
    subs_to_destroy.clear();

    if (shutting_down_.load()) {
        return;
    }

    controller_.initAsSoleNode(node_id_, sync_publisher_.getSyncPvName());
    sync_publisher_.publishSnapshot();

    if (shutting_down_.load()) {
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
}

void ClusterDiscovery::doDiscoveryRefresh() {
    if (shutting_down_.load()) return;

    const auto members_before = controller_.getMembers().size();
    if (joinCluster() == JoinResult::Joined) {
        if (controller_.getMembers().size() > members_before) {
            log_info_printf(pvacmscluster,
                            "Beacon-triggered discovery added cluster members%s\n",
                            "");
        }
        sync_publisher_.publishSnapshot();
    }
}

void ClusterDiscovery::joinWorkerLoop() {
    while (!shutting_down_.load()) {
        join_worker_wakeup_.wait();
        if (shutting_down_.load()) return;

        while (!shutting_down_.load()) {
            if (pending_full_rejoin_.exchange(false)) {
                pending_discovery_refresh_.store(false);
                doRejoin();
                continue;
            }
            if (pending_discovery_refresh_.exchange(false)) {
                doDiscoveryRefresh();
                continue;
            }
            break;
        }
    }
}

void ClusterDiscovery::startBeaconDiscovery() {
    beacon_discovery_ = client_ctx_.discover([this](const client::Discovered &evt) {
            handleBeaconEvent(evt);
        })
        .exec();
}

void ClusterDiscovery::scheduleDiscoveryRefresh(const std::string &reason) {
    if (shutting_down_.load()) return;
    pending_discovery_refresh_.store(true);
    log_info_printf(pvacmscluster, "%s\n", reason.c_str());
    join_worker_wakeup_.signal();
}

void ClusterDiscovery::handleBeaconEvent(const client::Discovered &evt) {
    if (shutting_down_.load()) return;
    if (evt.event != client::Discovered::Online) return;

    const auto now = std::chrono::steady_clock::now();
    bool should_refresh = false;
    {
        Guard G(beacon_refresh_lock_);
        if (last_beacon_refresh_.time_since_epoch().count() == 0 ||
            now - last_beacon_refresh_ >= std::chrono::seconds(kBeaconRefreshCooldownSecs)) {
            last_beacon_refresh_ = now;
            should_refresh = true;
        }
    }
    if (!should_refresh) return;

    scheduleDiscoveryRefresh(SB() << "Beacon discovered server " << evt.server
                                  << " (proto=" << evt.proto
                                  << ") - refreshing cluster discovery");
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
            log_warn_printf(pvacmscluster, "Join response stale timestamp (ts=%" PRId64 ", now=%" PRId64 ")\n",
                            resp_ts, now);
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

        // Merge response members with any locally-discovered ones rather
        // than overwriting: a node we found via peer sync before joining
        // (e.g. a 3rd member that was already in our table from a prior
        // sync snapshot) must not be erased by a join response that the
        // responder constructed before learning about that 3rd member.
        for (const auto &existing : controller_.getMembers()) {
            bool present = false;
            for (const auto &m : members) {
                if (m.node_id == existing.node_id) { present = true; break; }
            }
            if (!present) members.push_back(existing);
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

// Forward-RPC blocks the calling thread until accept/reject. When invoked
// from handleSyncUpdate (which runs on the pvxs client monitor callback
// thread), a long blocking wait freezes the monitor for that entire window
// and any sync notifies published in the gap go unprocessed. 5s is the
// intermediary's accept-RPC budget; longer than that means the path is
// dead and forwarding wouldn't have worked anyway.
static constexpr double kForwardRpcTimeoutSecs = 5.0;

// Caller must NOT hold state_lock_.  The discovery maps are read under
// state_lock_ to assemble an ordered list of candidate intermediaries; the
// (blocking) forward RPCs then run outside the lock, and a success is recorded
// back into active_forwarding_ under the lock.  Early-returns on shutting_down_
// so a worker/timer thread never walks the maps while ~ClusterDiscovery is
// destroying them.
void ClusterDiscovery::seekForwarder(const std::string &unreachable_node_id) {
    if (shutting_down_.load()) return;

    // A candidate intermediary: the node we ask to forward, and its sync PV.
    struct Candidate {
        std::string intermediary_node_id;
        std::string intermediary_sync_pv;
    };
    std::vector<Candidate> candidates;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        if (active_forwarding_.count(unreachable_node_id))
            return;

        const auto members = controller_.getMembers();
        auto sync_pv_for = [&](const std::vector<ClusterMember> &advertised,
                               const std::string &node) -> std::string {
            for (const auto &pm : advertised) {
                if (pm.node_id == node) return pm.sync_pv;
            }
            for (const auto &cm : members) {
                if (cm.node_id == node) return cm.sync_pv;
            }
            return std::string();
        };

        for (const auto &peer : peer_sync_members_) {
            if (peer.first == unreachable_node_id)
                continue;
            auto conn_it = peer_connectivity_.find(peer.first);
            if (conn_it == peer_connectivity_.end() || conn_it->second->state.load() != CONN_CONNECTED)
                continue;

            for (const auto &m : peer.second) {
                if (m.node_id == unreachable_node_id && m.connected) {
                    std::string sync_pv = sync_pv_for(peer.second, peer.first);
                    if (sync_pv.empty() && !subscriptions_.count(peer.first))
                        continue;
                    if (!sync_pv.empty())
                        candidates.push_back({peer.first, sync_pv});
                    break;
                }
            }
        }

        // Fallback: the peer_sync_members_ scan above can transiently fail to
        // name an intermediary when the would-be middle node momentarily
        // reports the unreachable peer as disconnected in the snapshot we hold.
        // We already recorded which directly-connected node relays this member
        // in relayed_via_ (set by reconcileMembers); use it so data forwarding
        // still establishes instead of being abandoned until the next
        // connectivity event.  Without this, a single stale snapshot can leave
        // relayed sync DATA permanently undelivered even though membership
        // relay succeeded.
        auto relay_it = relayed_via_.find(unreachable_node_id);
        if (relay_it != relayed_via_.end()) {
            const std::string &middle = relay_it->second;
            auto conn_it = peer_connectivity_.find(middle);
            if (conn_it != peer_connectivity_.end() &&
                conn_it->second->state.load() == CONN_CONNECTED) {
                std::string middle_sync_pv;
                for (const auto &cm : members) {
                    if (cm.node_id == middle) { middle_sync_pv = cm.sync_pv; break; }
                }
                if (!middle_sync_pv.empty())
                    candidates.push_back({middle, middle_sync_pv});
            }
        }
    }

    auto req = TypeDef(TypeCode::Struct, {
        members::String("operation"),
        members::String("node_id"),
    }).create();
    req["operation"] = "forward";
    req["node_id"] = unreachable_node_id;

    for (const auto &cand : candidates) {
        if (shutting_down_.load()) return;
        log_info_printf(pvacmscluster,
            "Requesting forwarding of %s via intermediary %s\n",
            unreachable_node_id.c_str(), cand.intermediary_node_id.c_str());
        try {
            client_ctx_.rpc(cand.intermediary_sync_pv, req)
                .exec()
                ->wait(kForwardRpcTimeoutSecs);
        } catch (const std::exception &e) {
            log_warn_printf(pvacmscluster,
                "Forward request to %s for %s failed: %s\n",
                cand.intermediary_node_id.c_str(), unreachable_node_id.c_str(), e.what());
            continue;
        }
        {
            Guard G(state_lock_);
            if (shutting_down_.load()) return;
            active_forwarding_[unreachable_node_id] = {cand.intermediary_node_id, cand.intermediary_sync_pv};
        }
        log_info_printf(pvacmscluster,
            "Forwarding of %s via %s established\n",
            unreachable_node_id.c_str(), cand.intermediary_node_id.c_str());
        return;
    }

    log_warn_printf(pvacmscluster, "No intermediary available for unreachable peer %s\n",
                    unreachable_node_id.c_str());
}

// Caller must NOT hold state_lock_.  Removes the active_forwarding_ entry under
// the lock, then issues the (blocking) cancel-forward RPC outside the lock so
// state_lock_ is never held across a blocking RPC.
void ClusterDiscovery::cancelForwarding(const std::string &node_id) {
    ActiveForwarding fwd;
    {
        Guard G(state_lock_);
        auto it = active_forwarding_.find(node_id);
        if (it == active_forwarding_.end())
            return;
        fwd = it->second;
        active_forwarding_.erase(it);
    }

    log_info_printf(pvacmscluster, "Cancelling forwarding of %s via %s (direct connectivity restored)\n",
                    node_id.c_str(), fwd.intermediary_node_id.c_str());

    auto req = TypeDef(TypeCode::Struct, {
        members::String("operation"),
        members::String("node_id"),
    }).create();
    req["operation"] = "cancel-forward";
    req["node_id"] = node_id;

    try {
        client_ctx_.rpc(fwd.intermediary_sync_pv, req)
            .exec()
            ->wait(double(discovery_timeout_secs_));
    } catch (const std::exception &e) {
        log_warn_printf(pvacmscluster, "Cancel-forward RPC to %s failed: %s\n",
                        fwd.intermediary_node_id.c_str(), e.what());
    }
}

// Caller must NOT hold state_lock_.  Collects the set of peers that still need
// a data forwarder under the lock, then calls seekForwarder (which re-takes the
// lock and issues blocking RPCs) for each outside the lock.  Early-returns on
// shutting_down_ so the deferred worker never walks the maps during teardown.
void ClusterDiscovery::rescanForwarders() {
    if (shutting_down_.load()) return;

    std::vector<std::string> targets;
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        for (auto &conn_kv : peer_connectivity_) {
            if (conn_kv.second->state.load() != CONN_UNREACHABLE)
                continue;
            if (active_forwarding_.count(conn_kv.first))
                continue;
            targets.push_back(conn_kv.first);
        }

        // Also seek a forwarder for every relayed member that does not yet have
        // an active one, even if its own connectivity timer has not
        // transitioned it to UNREACHABLE.  A relayed member (recorded in
        // relayed_via_) is by definition one we cannot reach directly, so it
        // needs a data forwarder; relying solely on the connectivity-timeout
        // path leaves a window where a relayed member's sync DATA is never
        // forwarded if the timeout's single seekForwarder attempt raced cluster
        // settling.
        for (const auto &kv : relayed_via_) {
            if (active_forwarding_.count(kv.first))
                continue;
            targets.push_back(kv.first);
        }
    }

    for (const auto &target : targets) {
        if (shutting_down_.load()) return;
        seekForwarder(target);
    }
}

// Caller MUST hold state_lock_: reads the peer_connectivity_ map.
bool ClusterDiscovery::isPeerConnected(const std::string &node_id) const {
    auto it = peer_connectivity_.find(node_id);
    return it != peer_connectivity_.end() && it->second->state.load() == CONN_CONNECTED;
}

// Caller must NOT hold state_lock_ (this acquires it to read peer_connectivity_,
// then publishes outside the lock).  Early-returns once shutting_down_ so it
// never reads peer_connectivity_ while ~ClusterDiscovery destroys it.
void ClusterDiscovery::publishMemberConnectivity() {
    if (shutting_down_.load()) return;
    auto members = controller_.getMembers();
    {
        Guard G(state_lock_);
        if (shutting_down_.load()) return;
        for (auto &m : members) {
            if (m.node_id == node_id_) {
                m.connected = true;
            } else {
                auto it = peer_connectivity_.find(m.node_id);
                m.connected = (it != peer_connectivity_.end() &&
                               it->second->state.load() == CONN_CONNECTED);
            }
        }
    }
    sync_publisher_.publishSnapshot(members);
}

}  // namespace cluster
}  // namespace cms
