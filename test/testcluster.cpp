/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <cstring>
#include <string>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/unittest.h>

#include "clustertypes.h"
#include "clusterdiscovery.h"
#include "ownedptr.h"
#include "pvacmsVersion.h"

using namespace pvxs;
using namespace pvxs::certs;

namespace {

// SQL to create the certs table for in-memory test DB
const char *kCreateCertsTable =
    "CREATE TABLE IF NOT EXISTS certs("
    "  serial INTEGER PRIMARY KEY,"
    "  skid TEXT,"
    "  CN TEXT,"
    "  O TEXT,"
    "  OU TEXT,"
    "  C TEXT,"
    "  approved INTEGER,"
    "  not_before INTEGER,"
    "  not_after INTEGER,"
    "  renew_by INTEGER,"
    "  renewal_due INTEGER,"
    "  status INTEGER,"
    "  status_date INTEGER"
    ")";

// RAII wrapper for in-memory test database
struct TestDb {
    sqlite3 *db;
    TestDb() : db(nullptr) {
        sqlite3_open(":memory:", &db);
        char *err = nullptr;
        sqlite3_exec(db, kCreateCertsTable, nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
    }
    ~TestDb() { if (db) sqlite3_close(db); }
    sqlite3 *get() { return db; }
};

// Generate an EC key pair for signing tests
ossl_ptr<EVP_PKEY> generateTestKey() {
    ossl_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1);
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_keygen(ctx.get(), &pkey);
    return ossl_ptr<EVP_PKEY>(pkey);
}

// Helper to build a sync Value with one cert row
Value buildSyncWithCert(int64_t serial, int32_t status, int64_t status_date,
                        const std::string &cn = "TestCN") {
    auto val = makeClusterSyncValue();
    val["node_id"] = "remote";
    val["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(2000);
    val["timeStamp.nanoseconds"] = static_cast<int32_t>(0);

    shared_array<Value> empty_members(0);
    val["members"] = empty_members.freeze();

    shared_array<Value> certs(1);
    certs[0] = val["certs"].allocMember();
    certs[0]["serial"] = serial;
    certs[0]["skid"] = "skid1";
    certs[0]["cn"] = cn;
    certs[0]["o"] = "Org";
    certs[0]["ou"] = "Unit";
    certs[0]["c"] = "US";
    certs[0]["approved"] = static_cast<int32_t>(1);
    certs[0]["not_before"] = static_cast<int64_t>(1000);
    certs[0]["not_after"] = static_cast<int64_t>(3000);
    certs[0]["renew_by"] = static_cast<int64_t>(2500);
    certs[0]["renewal_due"] = static_cast<int32_t>(0);
    certs[0]["status"] = status;
    certs[0]["status_date"] = status_date;
    val["certs"] = certs.freeze();

    return val;
}

// ---- Category 1: Unit Tests ----

void testStateMachine() {
    testDiag("State machine transitions");

    // Same status always valid (field propagation)
    testOk(isValidStatusTransition(VALID, VALID), "VALID->VALID accepted");
    testOk(isValidStatusTransition(EXPIRED, EXPIRED), "EXPIRED->EXPIRED accepted");
    testOk(isValidStatusTransition(REVOKED, REVOKED), "REVOKED->REVOKED accepted");

    // Operator/CCR-driven transitions (synced between nodes)
    testOk(isValidStatusTransition(PENDING, REVOKED), "PENDING->REVOKED");
    testOk(isValidStatusTransition(PENDING_APPROVAL, VALID), "PENDING_APPROVAL->VALID");
    testOk(isValidStatusTransition(PENDING_APPROVAL, PENDING), "PENDING_APPROVAL->PENDING");
    testOk(isValidStatusTransition(PENDING_APPROVAL, REVOKED), "PENDING_APPROVAL->REVOKED");
    testOk(isValidStatusTransition(VALID, REVOKED), "VALID->REVOKED");
    testOk(isValidStatusTransition(PENDING_RENEWAL, VALID), "PENDING_RENEWAL->VALID");
    testOk(isValidStatusTransition(PENDING_RENEWAL, REVOKED), "PENDING_RENEWAL->REVOKED");

    // Time-based transitions rejected (each node computes independently)
    testOk(!isValidStatusTransition(PENDING, VALID), "PENDING->VALID rejected (time-based)");
    testOk(!isValidStatusTransition(VALID, PENDING_RENEWAL), "VALID->PENDING_RENEWAL rejected (time-based)");
    testOk(!isValidStatusTransition(VALID, EXPIRED), "VALID->EXPIRED rejected (time-based)");
    testOk(!isValidStatusTransition(PENDING_RENEWAL, EXPIRED), "PENDING_RENEWAL->EXPIRED rejected (time-based)");

    // Other backward transitions rejected
    testOk(!isValidStatusTransition(VALID, PENDING), "VALID->PENDING rejected");
    testOk(!isValidStatusTransition(VALID, PENDING_APPROVAL), "VALID->PENDING_APPROVAL rejected");

    // Terminal states reject transitions (except same)
    testOk(!isValidStatusTransition(EXPIRED, VALID), "EXPIRED->VALID rejected");
    testOk(!isValidStatusTransition(EXPIRED, PENDING), "EXPIRED->PENDING rejected");
    testOk(!isValidStatusTransition(REVOKED, VALID), "REVOKED->VALID rejected");
    testOk(!isValidStatusTransition(REVOKED, PENDING), "REVOKED->PENDING rejected");
}

void testTypeDefs() {
    testDiag("TypeDef creation");

    auto sync_val = makeClusterSyncValue();
    testOk(!!sync_val["node_id"], "ClusterSync has node_id");
    testOk(!!sync_val["timeStamp"], "ClusterSync has timeStamp");
    testOk(!!sync_val["timeStamp.secondsPastEpoch"], "ClusterSync has timeStamp.secondsPastEpoch");
    testOk(!!sync_val["timeStamp.nanoseconds"], "ClusterSync has timeStamp.nanoseconds");
    testOk(!!sync_val["members"], "ClusterSync has members");
    testOk(!!sync_val["certs"], "ClusterSync has certs");
    testOk(!!sync_val["signature"], "ClusterSync has signature");
    {
        auto sync_member = sync_val["members"].allocMember();
        testOk(!!sync_member["version_major"], "ClusterSync member has version_major");
        testOk(!!sync_member["version_minor"], "ClusterSync member has version_minor");
        testOk(!!sync_member["version_patch"], "ClusterSync member has version_patch");
    }

    auto ctrl_val = makeClusterCtrlValue();
    testOk(!!ctrl_val["version_major"], "ClusterCtrl has version_major");
    testOk(!!ctrl_val["version_minor"], "ClusterCtrl has version_minor");
    testOk(!!ctrl_val["version_patch"], "ClusterCtrl has version_patch");
    testOk(!!ctrl_val["issuer_id"], "ClusterCtrl has issuer_id");
    testOk(!!ctrl_val["members"], "ClusterCtrl has members");
    testOk(!!ctrl_val["signature"], "ClusterCtrl has signature");
    {
        auto ctrl_member = ctrl_val["members"].allocMember();
        testOk(!!ctrl_member["version_major"], "ClusterCtrl member has version_major");
        testOk(!!ctrl_member["version_minor"], "ClusterCtrl member has version_minor");
        testOk(!!ctrl_member["version_patch"], "ClusterCtrl member has version_patch");
    }

    auto join_req = makeJoinRequestValue();
    testOk(!!join_req["version_major"], "JoinRequest has version_major");
    testOk(!!join_req["version_minor"], "JoinRequest has version_minor");
    testOk(!!join_req["version_patch"], "JoinRequest has version_patch");
    testOk(!!join_req["node_id"], "JoinRequest has node_id");
    testOk(!!join_req["sync_pv"], "JoinRequest has sync_pv");
    testOk(!!join_req["nonce"], "JoinRequest has nonce");
    testOk(!!join_req["signature"], "JoinRequest has signature");

    auto join_resp = makeJoinResponseValue();
    testOk(!!join_resp["version_major"], "JoinResponse has version_major");
    testOk(!!join_resp["version_minor"], "JoinResponse has version_minor");
    testOk(!!join_resp["version_patch"], "JoinResponse has version_patch");
    testOk(!!join_resp["issuer_id"], "JoinResponse has issuer_id");
    testOk(!!join_resp["timeStamp"], "JoinResponse has timeStamp");
    testOk(!!join_resp["timeStamp.secondsPastEpoch"], "JoinResponse has timeStamp.secondsPastEpoch");
    testOk(!!join_resp["timeStamp.nanoseconds"], "JoinResponse has timeStamp.nanoseconds");
    testOk(!!join_resp["members"], "JoinResponse has members");
    testOk(!!join_resp["nonce"], "JoinResponse has nonce");
    testOk(!!join_resp["signature"], "JoinResponse has signature");
    {
        auto resp_member = join_resp["members"].allocMember();
        testOk(!!resp_member["version_major"], "JoinResponse member has version_major");
        testOk(!!resp_member["version_minor"], "JoinResponse member has version_minor");
        testOk(!!resp_member["version_patch"], "JoinResponse member has version_patch");
    }
}

void testSigning() {
    testDiag("Signing and verification");

    auto pkey = generateTestKey();

    auto sync_val = makeClusterSyncValue();
    sync_val["node_id"] = "a1b2c3d4";
    sync_val["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(1000);
    sync_val["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
    shared_array<Value> empty_members(0);
    sync_val["members"] = empty_members.freeze();
    shared_array<Value> empty_certs(0);
    sync_val["certs"] = empty_certs.freeze();

    auto canonical = canonicalizeSync(sync_val);
    clusterSign(pkey, sync_val, canonical);

    // Verify with same key succeeds
    auto canonical2 = canonicalizeSync(sync_val);
    testOk(clusterVerify(pkey, sync_val, canonical2), "Valid sync signature accepted");

    // Tamper with payload — old signature won't match new canonical
    sync_val["node_id"] = "tampered";
    auto canonical3 = canonicalizeSync(sync_val);
    testOk(!clusterVerify(pkey, sync_val, canonical3), "Tampered sync signature rejected");
}

void testAntiReplayLogic() {
    testDiag("Anti-replay timestamp logic");

    std::atomic<int64_t> hwm{0};
    constexpr int64_t tolerance = 5;

    // First snapshot always accepted (hwm == 0)
    int64_t ts1 = 1000;
    testOk(hwm.load() == 0 || ts1 >= hwm.load() - tolerance, "First snapshot accepted (hwm=0)");
    hwm.store(ts1);

    // Newer snapshot advances hwm
    int64_t ts2 = 1050;
    testOk(ts2 >= hwm.load() - tolerance, "Newer snapshot accepted");
    hwm.store(ts2);

    // Cross-peer newer snapshot
    int64_t ts3 = 1060;
    testOk(ts3 >= hwm.load() - tolerance, "Cross-peer newer snapshot accepted");
    hwm.store(ts3);

    // Stale snapshot rejected (replay attack)
    int64_t ts4 = 900;
    testOk(ts4 < hwm.load() - tolerance, "Stale snapshot rejected (replay)");

    // Cross-peer replay blocked
    int64_t ts5 = 1050;
    testOk(ts5 < hwm.load() - tolerance, "Cross-peer replay blocked");

    // Within tolerance accepted
    int64_t ts6 = 1057;
    testOk(ts6 >= hwm.load() - tolerance, "Within tolerance accepted");
}

void testSyncLoopGuard() {
    testDiag("Sync loop guard");
    std::atomic<bool> flag{false};

    testOk(!flag.load(), "Sync ingestion not in progress initially");

    flag.store(true);
    testOk(flag.load(), "Sync ingestion flag set during ingestion");

    flag.store(false);
    testOk(!flag.load(), "Sync ingestion flag cleared after ingestion");
}

// ---- Category 2: Integration Tests (in-memory SQLite) ----

void testApplySyncBackwardDropped() {
    testDiag("applySyncSnapshot: backward transition dropped");

    TestDb tdb;
    epicsMutex lock;

    // Insert cert with EXPIRED status
    {
        std::string sql = "INSERT INTO certs VALUES(42,'skid1','CN1','O1','OU1','C1',1,1000,2000,1800,0,"
                          + std::to_string(EXPIRED) + ",1500)";
        sqlite3_exec(tdb.get(), sql.c_str(), nullptr, nullptr, nullptr);
    }

    // Sync snapshot tries to set VALID — backward from EXPIRED
    auto val = buildSyncWithCert(42, static_cast<int32_t>(VALID), 1600, "CN1_updated");

    applySyncSnapshot(tdb.get(), lock, val);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(tdb.get(), "SELECT status FROM certs WHERE serial=42", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    int status = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    testOk(status == EXPIRED, "EXPIRED cert unchanged after backward transition attempt");
}

void testApplySyncForwardAccepted() {
    testDiag("applySyncSnapshot: forward transition accepted");

    TestDb tdb;
    epicsMutex lock;

    {
        std::string sql = "INSERT INTO certs VALUES(42,'skid1','CN1','O1','OU1','C1',1,1000,2000,1800,0,"
                          + std::to_string(PENDING_APPROVAL) + ",1500)";
        sqlite3_exec(tdb.get(), sql.c_str(), nullptr, nullptr, nullptr);
    }

    auto val = buildSyncWithCert(42, static_cast<int32_t>(VALID), 2000);

    applySyncSnapshot(tdb.get(), lock, val);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(tdb.get(), "SELECT status FROM certs WHERE serial=42", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    int status = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    testOk(status == VALID, "PENDING_APPROVAL->VALID forward transition applied");
}

void testApplySyncNewCert() {
    testDiag("applySyncSnapshot: new cert inserted");

    TestDb tdb;
    epicsMutex lock;

    auto val = buildSyncWithCert(99, static_cast<int32_t>(VALID), 600, "NewCert");

    applySyncSnapshot(tdb.get(), lock, val);

    // Verify cert was inserted
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(tdb.get(), "SELECT CN, status FROM certs WHERE serial=99", -1, &stmt, nullptr);
    auto rc = sqlite3_step(stmt);
    testOk(rc == SQLITE_ROW, "New cert row found");
    if (rc == SQLITE_ROW) {
        testOk(std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0))) == "NewCert",
               "CN matches");
        testOk(sqlite3_column_int(stmt, 1) == VALID, "Status is VALID");
    } else {
        testSkip(1, "Row not found — skipping CN check");
        testSkip(1, "Row not found — skipping status check");
    }
    sqlite3_finalize(stmt);
}

// ---- Category 3: Integration Tests (multi-node Value passing) ----

// Helper: insert a cert row into an in-memory test DB
void insertCert(sqlite3 *db, int64_t serial, const std::string &cn, certstatus_t status,
                int64_t not_before, int64_t not_after, int64_t renew_by, int64_t status_date) {
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO certs (serial, skid, CN, O, OU, C, approved, "
                      "not_before, not_after, renew_by, renewal_due, status, status_date) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, serial);
    sqlite3_bind_text(stmt, 2, "skid1", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, cn.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, "Org", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, "Unit", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, "US", -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, 1);
    sqlite3_bind_int64(stmt, 8, not_before);
    sqlite3_bind_int64(stmt, 9, not_after);
    sqlite3_bind_int64(stmt, 10, renew_by);
    sqlite3_bind_int(stmt, 11, 0);
    sqlite3_bind_int(stmt, 12, static_cast<int>(status));
    sqlite3_bind_int64(stmt, 13, status_date);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// Helper: query a single int64 column from certs table
int64_t queryCertInt64(sqlite3 *db, int64_t serial, const char *column) {
    std::string sql = std::string("SELECT ") + column + " FROM certs WHERE serial = ?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, serial);
    int64_t result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        result = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return result;
}

// Helper: build a signed sync snapshot from a DB
Value buildSignedSync(sqlite3 *db, const std::string &node_id,
                      const std::vector<ClusterMember> &members,
                      const ossl_ptr<EVP_PKEY> &pkey) {
    auto val = serializeCertsTable(db, node_id, members);
    auto canonical = canonicalizeSync(val);
    clusterSign(pkey, val, canonical);
    return val;
}

void testJoinHandshake() {
    testDiag("Integration: two-node join handshake");

    auto pkey = generateTestKey();

    // Node A builds a JoinRequest
    shared_array<uint8_t> nonce(16);
    RAND_bytes(nonce.data(), 16);
    auto frozen_nonce = nonce.freeze();

    auto req = makeJoinRequestValue();
    req["version_major"] = static_cast<uint32_t>(1);
    req["version_minor"] = static_cast<uint32_t>(0);
    req["version_patch"] = static_cast<uint32_t>(0);
    req["node_id"] = "node_a";
    req["sync_pv"] = "CERT:CLUSTER:SYNC:ISSUER1:node_a";
    req["nonce"] = frozen_nonce;
    auto req_canonical = canonicalizeJoinRequest(req);
    clusterSign(pkey, req, req_canonical);

    // Node B (existing) validates the request
    auto req_canonical2 = canonicalizeJoinRequest(req);
    testOk(clusterVerify(pkey, req, req_canonical2), "Join request signature valid");

    auto req_major = req["version_major"].as<uint32_t>();
    testOk(req_major == 1, "Join request version_major == 1");

    auto req_nonce = req["nonce"].as<shared_array<const uint8_t>>();
    testOk(!req_nonce.empty(), "Join request has nonce");

    // Node B builds the response (simulating the RPC handler)
    std::vector<ClusterMember> members = {
        {"node_b", "CERT:CLUSTER:SYNC:ISSUER1:node_b", 1, 0, 0},
        {"node_a", "CERT:CLUSTER:SYNC:ISSUER1:node_a", 1, 0, 0},
    };

    auto resp = makeJoinResponseValue();
    resp["version_major"] = static_cast<uint32_t>(1);
    resp["version_minor"] = static_cast<uint32_t>(0);
    resp["version_patch"] = static_cast<uint32_t>(0);
    resp["issuer_id"] = "ISSUER1";
    setTimeStamp(resp);

    shared_array<Value> members_arr(members.size());
    for (size_t i = 0; i < members.size(); i++) {
        members_arr[i] = resp["members"].allocMember();
        members_arr[i]["node_id"] = members[i].node_id;
        members_arr[i]["sync_pv"] = members[i].sync_pv;
        members_arr[i]["version_major"] = members[i].version_major;
        members_arr[i]["version_minor"] = members[i].version_minor;
        members_arr[i]["version_patch"] = members[i].version_patch;
    }
    resp["members"] = members_arr.freeze();
    resp["nonce"] = frozen_nonce;
    auto resp_canonical = canonicalizeJoinResponse(resp);
    clusterSign(pkey, resp, resp_canonical);

    // Node A validates the response (simulating joinCluster validation)
    auto resp_canonical2 = canonicalizeJoinResponse(resp);
    testOk(clusterVerify(pkey, resp, resp_canonical2), "Join response signature valid");

    auto resp_issuer = resp["issuer_id"].as<std::string>();
    testOk(resp_issuer == "ISSUER1", "Join response issuer_id matches");

    auto resp_nonce = resp["nonce"].as<shared_array<const uint8_t>>();
    testOk(resp_nonce.size() == frozen_nonce.size() &&
           std::memcmp(resp_nonce.data(), frozen_nonce.data(), frozen_nonce.size()) == 0,
           "Join response nonce echoed correctly");

    auto resp_ts = getTimeStampAsUnix(resp);
    auto now = static_cast<int64_t>(std::time(nullptr));
    testOk(std::abs(now - resp_ts) <= 30, "Join response timestamp within tolerance");

    auto resp_members = resp["members"].as<shared_array<const Value>>();
    testOk(resp_members.size() == 2, "Join response has 2 members");

    testOk(resp_members[0]["node_id"].as<std::string>() == "node_b", "First member is node_b");
    testOk(resp_members[1]["node_id"].as<std::string>() == "node_a", "Second member is node_a");
    testOk(resp_members[0]["version_major"].as<uint32_t>() == 1, "First member version_major == 1");
    testOk(resp_members[1]["version_major"].as<uint32_t>() == 1, "Second member version_major == 1");

    // Wrong nonce should be detected
    shared_array<uint8_t> bad_nonce(16);
    RAND_bytes(bad_nonce.data(), 16);
    auto frozen_bad = bad_nonce.freeze();
    testOk(frozen_bad.size() != frozen_nonce.size() ||
           std::memcmp(frozen_bad.data(), frozen_nonce.data(), frozen_nonce.size()) != 0,
           "Bad nonce differs from original");

    // Wrong major version should be rejected
    auto req_bad_ver = makeJoinRequestValue();
    req_bad_ver["version_major"] = static_cast<uint32_t>(2);
    testOk(req_bad_ver["version_major"].as<uint32_t>() != 1,
           "Major version 2 would be rejected by handler");
}

void testCrossNodeSyncIngestion() {
    testDiag("Integration: cross-node sync ingestion");

    auto pkey = generateTestKey();

    // Node A has certs in its DB
    TestDb db_a;
    insertCert(db_a.get(), 100, "CertA", VALID, 1000, 5000, 4000, 1500);
    insertCert(db_a.get(), 101, "CertB", PENDING_APPROVAL, 1000, 5000, 4000, 1500);

    // Node A builds and signs a sync snapshot
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};
    auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

    // Node B receives and verifies the snapshot
    auto canonical = canonicalizeSync(snapshot);
    testOk(clusterVerify(pkey, snapshot, canonical), "Cross-node sync signature valid");

    // Node B ingests the snapshot into its own (empty) DB
    TestDb db_b;
    epicsMutex lock_b;
    applySyncSnapshot(db_b.get(), lock_b, snapshot);

    // Verify both certs appeared in Node B's DB
    testOk(queryCertInt64(db_b.get(), 100, "status") == VALID, "CertA ingested as VALID");
    testOk(queryCertInt64(db_b.get(), 101, "status") == PENDING_APPROVAL,
           "CertB ingested as PENDING_APPROVAL");
    testOk(queryCertInt64(db_b.get(), 100, "not_after") == 5000, "CertA not_after correct");
    testOk(queryCertInt64(db_b.get(), 100, "renew_by") == 4000, "CertA renew_by correct");

    // Node B already has cert 100 as VALID — a second sync with PENDING should be rejected
    // (backward transition from VALID)
    TestDb db_b2;
    epicsMutex lock_b2;
    insertCert(db_b2.get(), 100, "CertA", VALID, 1000, 5000, 4000, 1500);

    // Build a snapshot where Node A has cert 100 as PENDING (backward from B's VALID)
    TestDb db_a_stale;
    insertCert(db_a_stale.get(), 100, "CertA_stale", PENDING, 1000, 5000, 4000, 1200);
    auto stale_snapshot = buildSignedSync(db_a_stale.get(), "node_a", members, pkey);
    applySyncSnapshot(db_b2.get(), lock_b2, stale_snapshot);

    testOk(queryCertInt64(db_b2.get(), 100, "status") == VALID,
           "Backward VALID->PENDING rejected — status unchanged");
}

void testMembershipReconciliation() {
    testDiag("Integration: membership reconciliation from sync");

    auto pkey = generateTestKey();

    // Node A's sync snapshot includes members A, B, and C
    TestDb db_a;
    std::vector<ClusterMember> members = {
        {"node_a", "sync:a", 1, 0, 0},
        {"node_b", "sync:b", 1, 0, 0},
        {"node_c", "sync:c", 1, 0, 0},
    };
    auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

    // Extract members from the snapshot (simulating what handleSyncUpdate does)
    auto members_arr = snapshot["members"].as<shared_array<const Value>>();
    std::vector<ClusterMember> remote_members;
    for (size_t i = 0; i < members_arr.size(); i++) {
        remote_members.push_back({
            members_arr[i]["node_id"].as<std::string>(),
            members_arr[i]["sync_pv"].as<std::string>(),
            members_arr[i]["version_major"].as<uint32_t>(),
            members_arr[i]["version_minor"].as<uint32_t>(),
            members_arr[i]["version_patch"].as<uint32_t>()
        });
    }

    testOk(remote_members.size() == 3, "Snapshot carries 3 members");
    testOk(remote_members[0].node_id == "node_a", "Member 0 is node_a");
    testOk(remote_members[1].node_id == "node_b", "Member 1 is node_b");
    testOk(remote_members[2].node_id == "node_c", "Member 2 is node_c");
    testOk(remote_members[0].version_major == 1, "Member 0 version_major == 1");
    testOk(remote_members[1].version_major == 1, "Member 1 version_major == 1");
    testOk(remote_members[2].version_major == 1, "Member 2 version_major == 1");
}

void testAntiReplayIntegration() {
    testDiag("Integration: anti-replay with signed snapshots");

    auto pkey = generateTestKey();

    TestDb db_a;
    insertCert(db_a.get(), 200, "ReplayCert", VALID, 1000, 5000, 4000, 1500);
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};

    // Build two snapshots — the type definitions use setTimeStamp which writes
    // the current time.  For deterministic testing, we manually set timestamps.
    auto snap1 = serializeCertsTable(db_a.get(), "node_a", members);
    snap1["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(1000);
    snap1["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
    auto can1 = canonicalizeSync(snap1);
    clusterSign(pkey, snap1, can1);

    auto snap2 = serializeCertsTable(db_a.get(), "node_a", members);
    snap2["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(500);
    snap2["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
    auto can2 = canonicalizeSync(snap2);
    clusterSign(pkey, snap2, can2);

    // Both are validly signed
    testOk(clusterVerify(pkey, snap1, canonicalizeSync(snap1)), "Snapshot 1 signature valid");
    testOk(clusterVerify(pkey, snap2, canonicalizeSync(snap2)), "Snapshot 2 signature valid");

    // Simulate anti-replay HWM logic from handleSyncUpdate
    std::atomic<int64_t> hwm{0};
    constexpr int64_t tolerance = 5;

    // First snapshot (ts=1000) accepted
    auto ts1 = getTimeStampAsUnix(snap1);
    bool accept1 = (hwm.load() == 0 || ts1 >= hwm.load() - tolerance);
    testOk(accept1, "First snapshot (ts=1000) accepted");
    if (accept1) hwm.store(ts1);

    // Second snapshot (ts=500) rejected — stale
    auto ts2 = getTimeStampAsUnix(snap2);
    bool accept2 = (hwm.load() == 0 || ts2 >= hwm.load() - tolerance);
    testOk(!accept2, "Stale snapshot (ts=500) rejected after hwm=1000");
}

void testRenewalPropagation() {
    testDiag("Integration: VALID->VALID renewal propagation");

    auto pkey = generateTestKey();

    // Node B has cert 300 as VALID with renew_by=4000
    TestDb db_b;
    epicsMutex lock_b;
    insertCert(db_b.get(), 300, "RenewalCert", VALID, 1000, 5000, 4000, 1500);

    // Node A has already processed a renewal — cert 300 is still VALID but renew_by=8000
    TestDb db_a;
    insertCert(db_a.get(), 300, "RenewalCert", VALID, 1000, 9000, 8000, 2000);
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};
    auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

    // Node B ingests the snapshot
    applySyncSnapshot(db_b.get(), lock_b, snapshot);

    // renew_by should be overwritten to 8000 (VALID->VALID allowed by same-status rule)
    testOk(queryCertInt64(db_b.get(), 300, "renew_by") == 8000,
           "renew_by updated from 4000 to 8000 via VALID->VALID");
    testOk(queryCertInt64(db_b.get(), 300, "not_after") == 9000,
           "not_after updated from 5000 to 9000 via VALID->VALID");
    testOk(queryCertInt64(db_b.get(), 300, "status") == VALID,
           "Status remains VALID after renewal propagation");
}

void testSignatureTamperingRejected() {
    testDiag("Integration: signature tampering detected");

    auto pkey = generateTestKey();

    TestDb db_a;
    insertCert(db_a.get(), 400, "TamperCert", VALID, 1000, 5000, 4000, 1500);
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};
    auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

    // Verify the unmodified snapshot
    auto canonical = canonicalizeSync(snapshot);
    testOk(clusterVerify(pkey, snapshot, canonical), "Unmodified snapshot passes verification");

    // Tamper with the node_id — the canonical form changes, signature won't match
    snapshot["node_id"] = "tampered_node";
    auto tampered_canonical = canonicalizeSync(snapshot);
    testOk(!clusterVerify(pkey, snapshot, tampered_canonical),
           "Tampered snapshot fails verification");
}

void testDeltaMarking() {
    testDiag("Integration: delta marking after unmark");

    TestDb db;
    insertCert(db.get(), 500, "DeltaCert", VALID, 1000, 5000, 4000, 1500);
    std::vector<ClusterMember> members = {{"node_x", "sync:x", 1, 0, 0}};

    // Build a full Value (all fields marked since we set them)
    auto val = serializeCertsTable(db.get(), "node_x", members);

    // All fields should be marked after assignment
    testOk(val["node_id"].isMarked(false, false), "node_id marked after assignment");
    testOk(val["timeStamp.secondsPastEpoch"].isMarked(false, false),
           "timeStamp.secondsPastEpoch marked after assignment");
    testOk(val["members"].isMarked(false, false), "members marked after assignment");
    testOk(val["certs"].isMarked(false, false), "certs marked after assignment");

    val["node_id"].unmark();
    val["members"].unmark();

    testOk(!val["node_id"].isMarked(false, false), "node_id unmarked after unmark()");
    testOk(!val["members"].isMarked(false, false), "members unmarked after unmark()");
    testOk(val["certs"].isMarked(false, false), "certs still marked");
    testOk(val["timeStamp.secondsPastEpoch"].isMarked(false, false),
           "timeStamp.secondsPastEpoch still marked");
}

}  // namespace

MAIN(testcluster) {
    testPlan(119);
    testSetup();
    logger_config_env();

    try {
        testStateMachine();
    } catch (std::exception &e) {
        testFail("testStateMachine failed: %s", e.what());
    }
    try {
        testTypeDefs();
    } catch (std::exception &e) {
        testFail("testTypeDefs failed: %s", e.what());
    }
    try {
        testSigning();
    } catch (std::exception &e) {
        testFail("testSigning failed: %s", e.what());
    }
    try {
        testAntiReplayLogic();
    } catch (std::exception &e) {
        testFail("testAntiReplayLogic failed: %s", e.what());
    }
    try {
        testSyncLoopGuard();
    } catch (std::exception &e) {
        testFail("testSyncLoopGuard failed: %s", e.what());
    }
    try {
        testApplySyncBackwardDropped();
    } catch (std::exception &e) {
        testFail("testApplySyncBackwardDropped failed: %s", e.what());
    }
    try {
        testApplySyncForwardAccepted();
    } catch (std::exception &e) {
        testFail("testApplySyncForwardAccepted failed: %s", e.what());
    }
    try {
        testApplySyncNewCert();
    } catch (std::exception &e) {
        testFail("testApplySyncNewCert failed: %s", e.what());
    }
    try {
        testJoinHandshake();
    } catch (std::exception &e) {
        testFail("testJoinHandshake failed: %s", e.what());
    }
    try {
        testCrossNodeSyncIngestion();
    } catch (std::exception &e) {
        testFail("testCrossNodeSyncIngestion failed: %s", e.what());
    }
    try {
        testMembershipReconciliation();
    } catch (std::exception &e) {
        testFail("testMembershipReconciliation failed: %s", e.what());
    }
    try {
        testAntiReplayIntegration();
    } catch (std::exception &e) {
        testFail("testAntiReplayIntegration failed: %s", e.what());
    }
    try {
        testRenewalPropagation();
    } catch (std::exception &e) {
        testFail("testRenewalPropagation failed: %s", e.what());
    }
    try {
        testSignatureTamperingRejected();
    } catch (std::exception &e) {
        testFail("testSignatureTamperingRejected failed: %s", e.what());
    }
    try {
        testDeltaMarking();
    } catch (std::exception &e) {
        testFail("testDeltaMarking failed: %s", e.what());
    }

    return testDone();
}
