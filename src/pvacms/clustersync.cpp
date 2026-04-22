/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "clustersync.h"

#include <stdexcept>
#include <string>
#include <vector>

#include <epicsMutex.h>
#include <epicsGuard.h>

#include <pvxs/log.h>

#include <sqlite3.h>

#include "pvacmsVersion.h"

DEFINE_LOGGER(pvacmscluster, "cms.certs.cluster");

namespace cms {
namespace cluster {

namespace members = ::pvxs::members;
namespace server = ::pvxs::server;

using ::pvxs::shared_array;
using ::pvxs::TypeCode;
using ::pvxs::TypeDef;
using ::pvxs::Value;
using ::cms::SYNC_FULL_SNAPSHOT;
using ::cms::SYNC_INCREMENTAL;
using ::cms::clusterSign;
using ::cms::makeClusterSyncValue;
using ::cms::setTimeStamp;

typedef epicsGuard<epicsMutex> Guard;

SyncSource::SyncSource(const std::string &pv_name, ClusterSyncPublisher &publisher)
    : names_(std::make_shared<std::set<std::string>>(std::initializer_list<std::string>{pv_name}))
    , publisher_(publisher)
{}

void SyncSource::onSearch(SyncSource::Search &op) {
    for (auto &pv : op) {
        if (names_->count(pv.name()))
            pv.claim();
    }
}

void SyncSource::onCreate(std::unique_ptr<server::ChannelControl> &&chan) {
    if (!names_->count(chan->name()))
        return;

    chan->onOp([this](std::unique_ptr<server::ConnectOp> &&cop) {
        cop->onGet([](std::unique_ptr<server::ExecOp> &&op) {
            op->error("Only monitor implemented");
        });
        if (prototype_)
            cop->connect(prototype_);
        else
            cop->error("Sync PV not yet initialised");
    });

    chan->onRPC([this](std::unique_ptr<server::ExecOp> &&op, Value &&args) {
        auto operation = args["operation"].as<std::string>();
        if (operation == "forward") {
            publisher_.handleForwardRpc(std::move(op), std::move(args));
        } else if (operation == "cancel-forward") {
            publisher_.handleCancelForwardRpc(std::move(op), std::move(args));
        } else if (operation == "resync") {
            publisher_.handleResyncRpc(std::move(op));
        } else {
            op->error("Unknown operation: " + operation);
        }
    });

    chan->onSubscribe([this](std::unique_ptr<server::MonitorSetupOp> &&setup) {
        Guard G(lock_);

        if (!prototype_) {
            setup->error("Sync PV not yet initialised");
            return;
        }

        auto sub = setup->connect(prototype_);
        const auto sub_id = next_sub_id_++;

        auto sub_ptr = sub.get();

        SubscriberState state;
        state.op = std::move(sub);
        state.sequence = 0;
        state.needs_full_snapshot = true;

        server::MonitorStat stats{};
        sub_ptr->stats(stats);
        sub_ptr->setWatermarks(0, stats.limitQueue);

        sub_ptr->onHighMark([this, sub_id]() {
            Guard G(lock_);
            auto it = subscribers_.find(sub_id);
            if (it == subscribers_.end())
                return;
            auto &s = it->second;
            while (!s.pending.empty()) {
                if (!s.op->tryPost(s.pending.front()))
                    break;
                s.pending.pop_front();
            }
        });

        sub_ptr->onStart([this, sub_id](bool start) {
            if (!start)
                return;
            Guard G(lock_);
            auto it = subscribers_.find(sub_id);
            if (it == subscribers_.end())
                return;
            publisher_.sendToSubscriber(it->second);
        });

        setup->onClose([this, sub_id](const std::string &) {
            Guard G(lock_);
            subscribers_.erase(sub_id);
            log_debug_printf(pvacmscluster, "Sync subscriber %llu disconnected\n",
                             static_cast<unsigned long long>(sub_id));
        });

        subscribers_.emplace(sub_id, std::move(state));

        log_debug_printf(pvacmscluster, "New sync subscriber %llu from %s\n",
                         static_cast<unsigned long long>(sub_id), sub_ptr->peerName().c_str());
    });
}

server::Source::List SyncSource::onList() {
    return List{names_, false};
}

Value serializeCertsTable(sqlite3 *certs_db,
                          const std::string &node_id,
                          const std::vector<ClusterMember> &members,
                          const Value &prototype) {
    auto val = prototype ? prototype.cloneEmpty() : makeClusterSyncValue();
    val["node_id"] = node_id;
    setTimeStamp(val);

    shared_array<Value> members_arr(members.size());
    for (size_t i = 0; i < members.size(); i++) {
        members_arr[i] = val["members"].allocMember();
        members_arr[i]["node_id"] = members[i].node_id;
        members_arr[i]["sync_pv"] = members[i].sync_pv;
        members_arr[i]["version_major"] = members[i].version_major;
        members_arr[i]["version_minor"] = members[i].version_minor;
        members_arr[i]["version_patch"] = members[i].version_patch;
        members_arr[i]["connected"] = members[i].connected;
    }
    val["members"] = members_arr.freeze();

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(certs_db, SQL_SYNC_SELECT_ALL_CERTS, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("Failed to query certs: ") + sqlite3_errmsg(certs_db));
    }

    std::vector<Value> cert_rows;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto row = val["certs"].allocMember();
        row["serial"] = sqlite3_column_int64(stmt, 0);
        auto col_text = [&](const int col) -> std::string {
            const auto txt = sqlite3_column_text(stmt, col);
            return txt ? reinterpret_cast<const char*>(txt) : "";
        };
        row["skid"] = col_text(1);
        row["cn"] = col_text(2);
        row["o"] = col_text(3);
        row["ou"] = col_text(4);
        row["c"] = col_text(5);
        row["approved"] = sqlite3_column_int(stmt, 6);
        row["not_before"] = sqlite3_column_int64(stmt, 7);
        row["not_after"] = sqlite3_column_int64(stmt, 8);
        row["renew_by"] = sqlite3_column_int64(stmt, 9);
        row["renewal_due"] = sqlite3_column_int(stmt, 10);
        row["status"] = sqlite3_column_int(stmt, 11);
        row["status_date"] = sqlite3_column_int64(stmt, 12);
        row["san"] = col_text(13);
        cert_rows.push_back(std::move(row));
    }
    sqlite3_finalize(stmt);

    shared_array<Value> certs_arr(cert_rows.size());
    for (size_t i = 0; i < cert_rows.size(); i++) certs_arr[i] = std::move(cert_rows[i]);
    val["certs"] = certs_arr.freeze();

    sqlite3_stmt *sched_stmt;
    if (sqlite3_prepare_v2(certs_db, SQL_SYNC_SELECT_ALL_SCHEDULES, -1, &sched_stmt, nullptr) == SQLITE_OK) {
        std::vector<Value> sched_rows;
        while (sqlite3_step(sched_stmt) == SQLITE_ROW) {
            auto row = val["cert_schedules"].allocMember();
            row["serial"] = sqlite3_column_int64(sched_stmt, 0);
            auto txt = [&](int c) -> std::string {
                auto t = sqlite3_column_text(sched_stmt, c);
                return t ? reinterpret_cast<const char*>(t) : "";
            };
            row["day_of_week"] = txt(1);
            row["start_time"] = txt(2);
            row["end_time"] = txt(3);
            sched_rows.push_back(std::move(row));
        }
        sqlite3_finalize(sched_stmt);
        shared_array<Value> sched_arr(sched_rows.size());
        for (size_t i = 0; i < sched_rows.size(); i++) sched_arr[i] = std::move(sched_rows[i]);
        val["cert_schedules"] = sched_arr.freeze();
    }

    return val;
}

ClusterSyncPublisher::ClusterSyncPublisher(const std::string &node_id,
                                           const std::string &issuer_id,
                                           const std::string &pv_prefix,
                                           sqlite3 *certs_db,
                                           const ::pvxs::ossl_ptr<EVP_PKEY> &cert_auth_pkey,
                                           epicsMutex &status_update_lock)
    : node_id_(node_id)
    , issuer_id_(issuer_id)
    , sync_pv_name_(pv_prefix + ":SYNC:" + issuer_id + ":" + node_id)
    , certs_db_(certs_db)
    , cert_auth_pkey_(cert_auth_pkey)
    , status_update_lock_(status_update_lock)
    , sync_source_(std::make_shared<SyncSource>(sync_pv_name_, *this))
    , members_({{node_id, sync_pv_name_, PVACMS_MAJOR_VERSION, PVACMS_MINOR_VERSION, PVACMS_MAINTENANCE_VERSION, true}})
{}

void ClusterSyncPublisher::appendToLog(CertUpdate update) {
    Guard G(sync_source_->lock_);

    update.sequence = next_sequence_++;
    update_log_.push_back(std::move(update));

    while (update_log_.size() > max_log_size_) {
        const auto evicted_seq = update_log_.front().sequence;
        update_log_.pop_front();

        // Mark fallen-behind subscribers for full resync
        for (auto &kv : sync_source_->subscribers_) {
            if (kv.second.sequence < evicted_seq) {
                kv.second.needs_full_snapshot = true;
                kv.second.pending.clear();
            }
        }
    }

    dispatchToSubscribers();
}

void ClusterSyncPublisher::dispatchToSubscribers() {
    // Caller must hold sync_source_->lock_
    for (auto &kv : sync_source_->subscribers_) {
        sendToSubscriber(kv.second);
    }
}

void ClusterSyncPublisher::sendToSubscriber(SubscriberState &sub) {
    // Caller must hold sync_source_->lock_
    if (!sub.op)
        return;

    // If there are pending back-pressure retries, don't add more
    if (!sub.pending.empty())
        return;

    auto proto = sync_source_->prototype_;
    if (!proto)
        return;

    if (sub.needs_full_snapshot) {
        auto val = serializeCertsTable(certs_db_, node_id_, members_, proto);
        auto seq = update_log_.empty() ? next_sequence_ - 1 : update_log_.back().sequence;
        val["sequence"] = seq;
        val["update_type"] = static_cast<int32_t>(SYNC_FULL_SNAPSHOT);
        clusterSign(cert_auth_pkey_, val);

        if (sub.op->tryPost(val)) {
            sub.needs_full_snapshot = false;
            sub.sequence = seq;
        } else {
            sub.pending.push_back(std::move(val));
        }
        return;
    }

    // Find updates since subscriber's last sequence
    std::vector<const CertUpdate *> updates;
    for (const auto &entry : update_log_) {
        if (entry.sequence > sub.sequence) {
            updates.push_back(&entry);
        }
    }

    if (updates.empty())
        return;

    // Build incremental Value with only changed certs
    auto val = proto.cloneEmpty();
    val["node_id"] = node_id_;
    setTimeStamp(val);
    val["sequence"] = updates.back()->sequence;
    val["update_type"] = static_cast<int32_t>(SYNC_INCREMENTAL);

    shared_array<Value> members_arr(members_.size());
    for (size_t i = 0; i < members_.size(); i++) {
        members_arr[i] = val["members"].allocMember();
        members_arr[i]["node_id"] = members_[i].node_id;
        members_arr[i]["sync_pv"] = members_[i].sync_pv;
        members_arr[i]["version_major"] = members_[i].version_major;
        members_arr[i]["version_minor"] = members_[i].version_minor;
        members_arr[i]["version_patch"] = members_[i].version_patch;
        members_arr[i]["connected"] = members_[i].connected;
    }
    val["members"] = members_arr.freeze();

    shared_array<Value> certs_arr(updates.size());
    for (size_t i = 0; i < updates.size(); i++) {
        auto row = val["certs"].allocMember();
        row["serial"] = updates[i]->serial;
        row["skid"] = updates[i]->skid;
        row["cn"] = updates[i]->cn;
        row["o"] = updates[i]->o;
        row["ou"] = updates[i]->ou;
        row["c"] = updates[i]->c;
        row["approved"] = updates[i]->approved;
        row["not_before"] = updates[i]->not_before;
        row["not_after"] = updates[i]->not_after;
        row["renew_by"] = updates[i]->renew_by;
        row["renewal_due"] = updates[i]->renewal_due;
        row["status"] = updates[i]->status;
        row["status_date"] = updates[i]->status_date;
        row["san"] = updates[i]->san;
        certs_arr[i] = std::move(row);
    }
    val["certs"] = certs_arr.freeze();

    clusterSign(cert_auth_pkey_, val);

    if (sub.op->tryPost(val)) {
        sub.sequence = updates.back()->sequence;
    } else {
        sub.pending.push_back(std::move(val));
    }
}

void ClusterSyncPublisher::publishCertChange(int64_t serial) {
    if (!enabled_ || sync_ingestion_in_progress.load())
        return;

    Guard G(status_update_lock_);

    if (!sync_source_->prototype_) {
        sync_source_->prototype_ = makeClusterSyncValue();
    }

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(certs_db_, SQL_SYNC_SELECT_CERT_BY_SERIAL, -1, &stmt, nullptr) != SQLITE_OK) {
        log_err_printf(pvacmscluster, "Failed to query cert %lld: %s\n",
                       static_cast<long long>(serial), sqlite3_errmsg(certs_db_));
        return;
    }
    sqlite3_bind_int64(stmt, 1, serial);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        log_warn_printf(pvacmscluster, "Cert %lld not found for incremental publish\n",
                        static_cast<long long>(serial));
        return;
    }

    auto col_text = [&](int col) -> std::string {
        const auto txt = sqlite3_column_text(stmt, col);
        return txt ? reinterpret_cast<const char*>(txt) : "";
    };

    CertUpdate update;
    update.serial      = sqlite3_column_int64(stmt, 0);
    update.skid        = col_text(1);
    update.cn          = col_text(2);
    update.o           = col_text(3);
    update.ou          = col_text(4);
    update.c           = col_text(5);
    update.approved    = sqlite3_column_int(stmt, 6);
    update.not_before  = sqlite3_column_int64(stmt, 7);
    update.not_after   = sqlite3_column_int64(stmt, 8);
    update.renew_by    = sqlite3_column_int64(stmt, 9);
    update.renewal_due = sqlite3_column_int(stmt, 10);
    update.status      = sqlite3_column_int(stmt, 11);
    update.status_date = sqlite3_column_int64(stmt, 12);
    update.san        = col_text(13);
    sqlite3_finalize(stmt);

    appendToLog(std::move(update));

    log_debug_printf(pvacmscluster, "Published incremental cert change (serial=%lld, seq=%lld) to %zu subscribers\n",
                     static_cast<long long>(serial),
                     static_cast<long long>(next_sequence_ - 1),
                     sync_source_->subscribers_.size());
}

void ClusterSyncPublisher::publishSnapshot() {
    doPublish(members_, false, true);
}

void ClusterSyncPublisher::publishSnapshot(const std::vector<ClusterMember> &members) {
    const bool members_changed = (members != members_);
    members_ = members;
    doPublish(members_, members_changed, false);
}

void ClusterSyncPublisher::doPublish(const std::vector<ClusterMember> &members, const bool members_changed, const bool certs_changed) {
    if (!enabled_ || sync_ingestion_in_progress.load())
        return;

    Guard G(status_update_lock_);

    if (!sync_source_->prototype_) {
        sync_source_->prototype_ = makeClusterSyncValue();
    }

    auto seq = next_sequence_++;

    Guard G2(sync_source_->lock_);
    for (auto &kv : sync_source_->subscribers_) {
        kv.second.needs_full_snapshot = true;
        kv.second.pending.clear();
    }
    dispatchToSubscribers();

    log_debug_printf(pvacmscluster, "Dispatched sync update (seq=%lld) to %zu subscribers (members_changed=%d, certs_changed=%d)\n",
                     static_cast<long long>(seq), sync_source_->subscribers_.size(), members_changed, certs_changed);
}

std::string ClusterSyncPublisher::getSyncPvName() const {
    return sync_pv_name_;
}

void ClusterSyncPublisher::handleForwardRpc(std::unique_ptr<server::ExecOp> &&op, Value &&args) {
    try {
        const auto creds = op->credentials();
        bool is_tls_cluster_member = creds->isTLS && creds->method == "x509" && creds->issuer_id == issuer_id_;
        if (!is_tls_cluster_member && !skip_peer_identity_check) {
            op->error("Not authenticated as cluster member");
            return;
        }

        auto target_node_id = args["node_id"].as<std::string>();
        if (target_node_id.empty()) {
            op->error("Missing node_id");
            return;
        }

        if (is_peer_connected && !is_peer_connected(target_node_id)) {
            op->error("Not connected to target node " + target_node_id);
            return;
        }

        auto requester = creds->account;
        log_info_printf(pvacmscluster, "Accepted forwarding request for node %s from %s\n",
                        target_node_id.c_str(), requester.c_str());

        forwarding_[target_node_id] = requester;

        auto resp = TypeDef(TypeCode::Struct, {
            members::String("status"),
        }).create();
        resp["status"] = "accepted";
        op->reply(resp);

        publishSnapshot();
    } catch (const std::exception &e) {
        op->error(std::string("Forward request failed: ") + e.what());
    }
}

void ClusterSyncPublisher::handleCancelForwardRpc(std::unique_ptr<server::ExecOp> &&op, Value &&args) {
    try {
        const auto creds = op->credentials();
        bool is_tls_cluster_member = creds->isTLS && creds->method == "x509" && creds->issuer_id == issuer_id_;
        if (!is_tls_cluster_member && !skip_peer_identity_check) {
            op->error("Not authenticated as cluster member");
            return;
        }

        auto target_node_id = args["node_id"].as<std::string>();
        if (target_node_id.empty()) {
            op->error("Missing node_id");
            return;
        }

        auto it = forwarding_.find(target_node_id);
        if (it != forwarding_.end()) {
            log_info_printf(pvacmscluster, "Cancelled forwarding for node %s\n",
                            target_node_id.c_str());
            forwarding_.erase(it);
        }

        auto resp = TypeDef(TypeCode::Struct, {
            members::String("status"),
        }).create();
        resp["status"] = "cancelled";
        op->reply(resp);
    } catch (const std::exception &e) {
        op->error(std::string("Cancel-forward request failed: ") + e.what());
    }
}

void ClusterSyncPublisher::addForwardingRelationship(const std::string &forwardee_node_id,
                                                      const std::string &requester_node_id) {
    forwarding_[forwardee_node_id] = requester_node_id;
}

void ClusterSyncPublisher::removeForwardingRelationship(const std::string &forwardee_node_id) {
    forwarding_.erase(forwardee_node_id);
}

bool ClusterSyncPublisher::isForwarding(const std::string &forwardee_node_id) const {
    return forwarding_.count(forwardee_node_id) > 0;
}

void ClusterSyncPublisher::handleResyncRpc(std::unique_ptr<server::ExecOp> &&op) {
    try {
        Guard G(sync_source_->lock_);
        for (auto &kv : sync_source_->subscribers_) {
            kv.second.needs_full_snapshot = true;
            kv.second.pending.clear();
        }
        dispatchToSubscribers();

        auto resp = TypeDef(TypeCode::Struct, {
            members::String("status"),
        }).create();
        resp["status"] = "resync dispatched";
        op->reply(resp);

        log_info_printf(pvacmscluster, "Resync requested — dispatched full snapshot to %zu subscribers\n",
                        sync_source_->subscribers_.size());
    } catch (const std::exception &e) {
        op->error(std::string("Resync failed: ") + e.what());
    }
}

std::map<std::string, std::string> ClusterSyncPublisher::getForwardingRelationships() const {
    return forwarding_;
}

}  // namespace cluster
}  // namespace cms
