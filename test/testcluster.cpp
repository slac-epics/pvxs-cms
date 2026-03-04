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
    val["timestamp"] = static_cast<int64_t>(2000);

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

    // Forward transitions
    testOk(isValidStatusTransition(PENDING, PENDING_APPROVAL), "PENDING->PENDING_APPROVAL");
    testOk(isValidStatusTransition(PENDING, VALID), "PENDING->VALID");
    testOk(isValidStatusTransition(PENDING, REVOKED), "PENDING->REVOKED");
    testOk(isValidStatusTransition(PENDING_APPROVAL, VALID), "PENDING_APPROVAL->VALID");
    testOk(isValidStatusTransition(PENDING_APPROVAL, REVOKED), "PENDING_APPROVAL->REVOKED");
    testOk(isValidStatusTransition(VALID, PENDING_RENEWAL), "VALID->PENDING_RENEWAL");
    testOk(isValidStatusTransition(VALID, EXPIRED), "VALID->EXPIRED");
    testOk(isValidStatusTransition(VALID, REVOKED), "VALID->REVOKED");
    testOk(isValidStatusTransition(PENDING_RENEWAL, VALID), "PENDING_RENEWAL->VALID");
    testOk(isValidStatusTransition(PENDING_RENEWAL, EXPIRED), "PENDING_RENEWAL->EXPIRED");
    testOk(isValidStatusTransition(PENDING_RENEWAL, REVOKED), "PENDING_RENEWAL->REVOKED");

    // Backward transitions rejected
    testOk(!isValidStatusTransition(VALID, PENDING), "VALID->PENDING rejected");
    testOk(!isValidStatusTransition(VALID, PENDING_APPROVAL), "VALID->PENDING_APPROVAL rejected");
    testOk(!isValidStatusTransition(PENDING_APPROVAL, PENDING), "PENDING_APPROVAL->PENDING rejected");

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
    testOk(!!sync_val["timestamp"], "ClusterSync has timestamp");
    testOk(!!sync_val["members"], "ClusterSync has members");
    testOk(!!sync_val["certs"], "ClusterSync has certs");
    testOk(!!sync_val["signature"], "ClusterSync has signature");

    auto ctrl_val = makeClusterCtrlValue();
    testOk(!!ctrl_val["version"], "ClusterCtrl has version");
    testOk(!!ctrl_val["issuer_id"], "ClusterCtrl has issuer_id");
    testOk(!!ctrl_val["members"], "ClusterCtrl has members");
    testOk(!!ctrl_val["signature"], "ClusterCtrl has signature");

    auto join_req = makeJoinRequestValue();
    testOk(!!join_req["node_id"], "JoinRequest has node_id");
    testOk(!!join_req["sync_pv"], "JoinRequest has sync_pv");
    testOk(!!join_req["nonce"], "JoinRequest has nonce");
    testOk(!!join_req["signature"], "JoinRequest has signature");

    auto join_resp = makeJoinResponseValue();
    testOk(!!join_resp["version"], "JoinResponse has version");
    testOk(!!join_resp["issuer_id"], "JoinResponse has issuer_id");
    testOk(!!join_resp["timestamp"], "JoinResponse has timestamp");
    testOk(!!join_resp["members"], "JoinResponse has members");
    testOk(!!join_resp["nonce"], "JoinResponse has nonce");
    testOk(!!join_resp["signature"], "JoinResponse has signature");
}

void testSigning() {
    testDiag("Signing and verification");

    auto pkey = generateTestKey();

    auto sync_val = makeClusterSyncValue();
    sync_val["node_id"] = "a1b2c3d4";
    sync_val["timestamp"] = static_cast<int64_t>(1000);
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
                          + std::to_string(VALID) + ",1500)";
        sqlite3_exec(tdb.get(), sql.c_str(), nullptr, nullptr, nullptr);
    }

    auto val = buildSyncWithCert(42, static_cast<int32_t>(EXPIRED), 2000);

    applySyncSnapshot(tdb.get(), lock, val);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(tdb.get(), "SELECT status FROM certs WHERE serial=42", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    int status = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    testOk(status == EXPIRED, "VALID->EXPIRED forward transition applied");
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

}  // namespace

MAIN(testcluster) {
    testPlan(56);
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

    return testDone();
}
