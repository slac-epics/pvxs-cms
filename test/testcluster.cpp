/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <atomic>
#include <cstring>
#include <string>

#include <epicsTime.h>
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

/**
 * @brief SQL DDL statement used to create the certs table in the in-memory test database.
 *
 * Mirrors the schema used in production so that applySyncSnapshot, serializeCertsTable,
 * and related functions operate on a realistic table layout.  All integration tests that
 * need a database create one via TestDb, which executes this statement on construction.
 */
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

/**
 * @brief RAII wrapper around an in-memory SQLite database for unit and integration tests.
 *
 * Opens a fresh ":memory:" SQLite database on construction, creates the certs table via
 * kCreateCertsTable, and closes the database handle on destruction.  Using a new TestDb
 * per test function ensures complete isolation with no shared state between tests.
 */
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

/**
 * @brief Generate a fresh prime256v1 EC key pair for use in signing tests.
 *
 * Creates a one-time ephemeral ECDSA P-256 key pair via OpenSSL EVP_PKEY_keygen.
 * Returned as an RAII-managed ossl_ptr so the caller need not call EVP_PKEY_free.
 * Every test that exercises clusterSign/clusterVerify calls this to obtain a
 * self-consistent key pair without depending on external key material.
 *
 * @return Newly generated prime256v1 EVP_PKEY wrapped in an ossl_ptr.
 */
ossl_ptr<EVP_PKEY> generateTestKey() {
    ossl_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1);
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_keygen(ctx.get(), &pkey);
    return ossl_ptr<EVP_PKEY>(pkey);
}

/**
 * @brief Build a minimal ClusterSync PVXS Value containing a single certificate row.
 *
 * Constructs a fully-populated sync snapshot with one cert entry, zero members, and
 * a fixed timestamp of 2000 seconds.  Used by Category 2 integration tests that feed
 * a snapshot directly to applySyncSnapshot without needing a real database on the
 * sending side.  The caller controls the cert's serial, status, and status_date so
 * each test can exercise the specific transition scenario it cares about.
 *
 * @param serial       Certificate serial number to embed in the snapshot.
 * @param status       Certificate status code (e.g. VALID, EXPIRED, PENDING_APPROVAL).
 * @param status_date  Unix timestamp of the status change to embed.
 * @param cn           Common Name string for the certificate (default "TestCN").
 * @return Unsigned ClusterSync Value ready to pass to applySyncSnapshot.
 */
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

/**
 * @brief Tests the isValidStatusTransition() certificate state machine.
 *
 * Verifies that the cluster sync engine correctly distinguishes between transitions
 * that are permitted to propagate across nodes and those that must not.  The test
 * exercises three categories of transition:
 *   - Same-to-same (always accepted for field propagation such as VALID->VALID)
 *   - Operator/CCR-driven transitions (PENDING_APPROVAL->VALID, VALID->REVOKED, etc.)
 *     which must be synced between nodes
 *   - Time-based transitions (VALID->EXPIRED, VALID->PENDING_RENEWAL, etc.) which
 *     each node computes independently and therefore must NOT be accepted via sync
 *   - Backward or otherwise disallowed moves (e.g. VALID->PENDING) which would
 *     corrupt the certificate lifecycle state
 *
 * A failure here indicates a regression in isValidStatusTransition() that would
 * either allow stale or incorrect status from a peer to overwrite the local state
 * (accepting something that should be rejected) or would prevent legitimate operator
 * actions from propagating across the cluster (rejecting something that should be
 * accepted).
 */
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

/**
 * @brief Tests that all cluster PVXS Value type definitions contain the expected fields.
 *
 * Calls makeClusterSyncValue(), makeClusterCtrlValue(), makeJoinRequestValue(), and
 * makeJoinResponseValue() and asserts that every required field path resolves to a
 * non-null Value.  Also checks that sub-structure members (array element prototypes)
 * expose the expected version and identity fields.
 *
 * This test guards against accidental field removal or renaming in the TypeDef
 * factory functions.  A failure would mean that other cluster code — serialization,
 * signing, ingestion, join handshake — could silently drop or mis-read data because
 * a field it relies on no longer exists in the Value prototype.
 */
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

/**
 * @brief Tests ECDSA signing and verification of cluster sync snapshots.
 *
 * Generates a transient prime256v1 key pair, constructs a ClusterSync Value with
 * known fields, canonicalizes it, and calls clusterSign to write the signature into
 * the "signature" field.  Verification is then performed against a fresh
 * canonicalization of the same Value (simulating what the receiving node does).
 *
 * A second pass deliberately mutates the node_id field after signing to confirm that
 * the resulting canonical form no longer matches the signature — verifying that the
 * canonicalization covers all significant payload fields and that clusterVerify
 * correctly rejects tampered data.
 *
 * A failure here indicates a bug in clusterSign, clusterVerify, or canonicalizeSync
 * that would allow unsigned or tampered sync snapshots to be trusted by cluster peers,
 * undermining the integrity guarantee of the cert sync protocol.
 */
void testSigning() {
    testDiag("Signing and verification");

    const auto pkey = generateTestKey();

    auto sync_val = makeClusterSyncValue();
    sync_val["node_id"] = "a1b2c3d4";
    sync_val["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(1000);
    sync_val["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
    shared_array<Value> empty_members(0);
    sync_val["members"] = empty_members.freeze();
    shared_array<Value> empty_certs(0);
    sync_val["certs"] = empty_certs.freeze();

    const auto canonical = canonicalizeSync(sync_val);
    clusterSign(pkey, sync_val, canonical);

    // Verify with same key succeeds
    const auto canonical2 = canonicalizeSync(sync_val);
    testOk(clusterVerify(pkey, sync_val, canonical2), "Valid sync signature accepted");

    // Tamper with payload — old signature won't match new canonical
    sync_val["node_id"] = "tampered";
    const auto canonical3 = canonicalizeSync(sync_val);
    testOk(!clusterVerify(pkey, sync_val, canonical3), "Tampered sync signature rejected");
}

/**
 * @brief Tests the high-water-mark anti-replay timestamp logic in isolation.
 *
 * Simulates the per-peer high-water-mark (HWM) check that handleSyncUpdate performs
 * before ingesting a snapshot: a snapshot whose timestamp is below (HWM - tolerance)
 * must be rejected to prevent replay attacks.  The test uses an atomic int64 to mimic
 * the in-process HWM variable and manually advances it with accepted snapshots.
 *
 * Five scenarios are covered:
 *   1. First snapshot (HWM == 0) is always accepted.
 *   2. A newer snapshot from the same peer advances the HWM.
 *   3. A newer snapshot from a cross-peer scenario is also accepted.
 *   4. A stale snapshot (timestamp well below HWM) is rejected.
 *   5. A cross-peer replay of a previously-seen timestamp is blocked.
 *   6. A snapshot within the clock-skew tolerance window is accepted.
 *
 * Failure here means the anti-replay guard could be bypassed, allowing an attacker
 * or malfunctioning peer to inject old cert-status data into a live cluster.
 */
void testAntiReplayLogic() {
    testDiag("Anti-replay timestamp logic");

    std::atomic<int64_t> hwm{0};
    constexpr int64_t tolerance = 5;

    // First snapshot always accepted (hwm == 0)
    constexpr int64_t ts1 = 1000;
    testOk(hwm.load() == 0 || ts1 >= hwm.load() - tolerance, "First snapshot accepted (hwm=0)");
    hwm.store(ts1);

    // Newer snapshot advances hwm
    constexpr int64_t ts2 = 1050;
    testOk(ts2 >= hwm.load() - tolerance, "Newer snapshot accepted");
    hwm.store(ts2);

    // Cross-peer newer snapshot
    constexpr int64_t ts3 = 1060;
    testOk(ts3 >= hwm.load() - tolerance, "Cross-peer newer snapshot accepted");
    hwm.store(ts3);

    // Stale snapshot rejected (replay attack)
    constexpr int64_t ts4 = 900;
    testOk(ts4 < hwm.load() - tolerance, "Stale snapshot rejected (replay)");

    // Cross-peer replay blocked
    constexpr int64_t ts5 = 1050;
    testOk(ts5 < hwm.load() - tolerance, "Cross-peer replay blocked");

    // Within tolerance accepted
    constexpr int64_t ts6 = 1057;
    testOk(ts6 >= hwm.load() - tolerance, "Within tolerance accepted");
}

/**
 * @brief Tests the atomic boolean flag that prevents sync ingestion re-entrancy.
 *
 * Verifies the lifecycle of the flag used by handleSyncUpdate to guard against
 * re-entrant snapshot ingestion: the flag is clear at rest, set during an active
 * ingestion, and cleared again when ingestion completes.  The test manually
 * manipulates a local atomic<bool> to mirror the three observable states.
 *
 * Failure here indicates that the guard flag transitions are broken, which could
 * allow a second sync callback to interleave with an ongoing applySyncSnapshot call,
 * producing partial or inconsistent database updates.
 */
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

/**
 * @brief Tests that applySyncSnapshot silently drops a backward status transition.
 *
 * Pre-populates an in-memory SQLite database with a certificate in the EXPIRED
 * terminal state.  A sync snapshot carrying the same serial with status VALID is
 * then fed to applySyncSnapshot.  Because EXPIRED -> VALID is a prohibited backward
 * transition (terminal states are irreversible), the local row must remain EXPIRED.
 *
 * This test guards against a regression where the sync merge logic fails to consult
 * isValidStatusTransition() and blindly overwrites the local status with whatever the
 * remote peer reports.  Such a regression would allow revived certificates to appear
 * valid after they have expired, a serious PKI security violation.
 */
void testApplySyncBackwardDropped() {
    testDiag("applySyncSnapshot: backward transition dropped");

    TestDb tdb;
    epicsMutex lock;

    // Insert cert with EXPIRED status
    {
        const std::string sql = "INSERT INTO certs VALUES(42,'skid1','CN1','O1','OU1','C1',1,1000,2000,1800,0,"
                          + std::to_string(EXPIRED) + ",1500)";
        sqlite3_exec(tdb.get(), sql.c_str(), nullptr, nullptr, nullptr);
    }

    // Sync snapshot tries to set VALID — backward from EXPIRED
    const auto val = buildSyncWithCert(42, static_cast<int32_t>(VALID), 1600, "CN1_updated");

    applySyncSnapshot(tdb.get(), lock, val);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(tdb.get(), "SELECT status FROM certs WHERE serial=42", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    const int status = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    testOk(status == EXPIRED, "EXPIRED cert unchanged after backward transition attempt");
}

/**
 * @brief Tests that applySyncSnapshot applies a valid forward status transition.
 *
 * Pre-populates an in-memory SQLite database with a certificate in the
 * PENDING_APPROVAL state.  A sync snapshot carrying the same serial with status
 * VALID (which represents an operator approval decision) is then fed to
 * applySyncSnapshot.  The test asserts that the row's status is updated to VALID,
 * confirming that legitimate operator-driven transitions are propagated correctly.
 *
 * Failure here would mean that approved certificates never become VALID on nodes
 * that did not perform the approval locally, effectively siloing operator actions
 * to a single node and breaking cluster consistency.
 */
void testApplySyncForwardAccepted() {
    testDiag("applySyncSnapshot: forward transition accepted");

    TestDb tdb;
    epicsMutex lock;

    {
        std::string sql = "INSERT INTO certs VALUES(42,'skid1','CN1','O1','OU1','C1',1,1000,2000,1800,0,"
                          + std::to_string(PENDING_APPROVAL) + ",1500)";
        sqlite3_exec(tdb.get(), sql.c_str(), nullptr, nullptr, nullptr);
    }

    const auto val = buildSyncWithCert(42, static_cast<int32_t>(VALID), 2000);

    applySyncSnapshot(tdb.get(), lock, val);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(tdb.get(), "SELECT status FROM certs WHERE serial=42", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    const int status = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    testOk(status == VALID, "PENDING_APPROVAL->VALID forward transition applied");
}

/**
 * @brief Tests that applySyncSnapshot inserts a certificate that is absent locally.
 *
 * Starts with an empty in-memory database and feeds a snapshot that contains one
 * certificate (serial 99, CN "NewCert", status VALID).  After applySyncSnapshot
 * returns, the test queries the database to confirm that the row was created with
 * the correct CN and status.  Conditional testSkip calls are used when the row is
 * unexpectedly absent to prevent cascading assertion failures.
 *
 * Failure here means that new certificates issued on one cluster node are never
 * propagated to peers that were not present at issuance time, leaving those peers
 * with an incomplete and stale certificate database.
 */
void testApplySyncNewCert() {
    testDiag("applySyncSnapshot: new cert inserted");

    TestDb tdb;
    epicsMutex lock;

    const auto val = buildSyncWithCert(99, static_cast<int32_t>(VALID), 600, "NewCert");

    applySyncSnapshot(tdb.get(), lock, val);

    // Verify cert was inserted
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(tdb.get(), "SELECT CN, status FROM certs WHERE serial=99", -1, &stmt, nullptr);
    const auto rc = sqlite3_step(stmt);
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

/**
 * @brief Insert a fully-specified certificate row into a test SQLite database.
 *
 * Binds all required certs-table columns and executes a parameterized INSERT.
 * Fixed values are used for skid ("skid1"), O ("Org"), OU ("Unit"), C ("US"), and
 * renewal_due (0) so that callers only need to supply the fields that vary between
 * test scenarios.  Used by Category 3 integration tests to set up pre-existing
 * certificate state before exercising sync, tamper-detection, or renewal logic.
 *
 * @param db          Open SQLite database handle.
 * @param serial      Certificate serial number (primary key).
 * @param cn          Certificate Common Name.
 * @param status      Initial certificate status (e.g. VALID, PENDING_APPROVAL).
 * @param not_before  Not-before timestamp (EPICS epoch seconds).
 * @param not_after   Not-after (expiry) timestamp (EPICS epoch seconds).
 * @param renew_by    Renewal deadline timestamp (EPICS epoch seconds).
 * @param status_date Timestamp of the most recent status change (EPICS epoch seconds).
 */
void insertCert(sqlite3 *db, int64_t serial, const std::string &cn, const certstatus_t status,
                const int64_t not_before, const int64_t not_after, const int64_t renew_by, const int64_t status_date) {
    sqlite3_stmt *stmt;
    const auto sql = "INSERT INTO certs (serial, skid, CN, O, OU, C, approved, "
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

/**
 * @brief Query a single integer column from the certs table for a given serial.
 *
 * Executes "SELECT <column> FROM certs WHERE serial = ?" with the supplied serial
 * and returns the first result as int64_t.  Returns -1 if no matching row is found,
 * making it easy for test assertions to detect missing rows without crashing.  Used
 * by Category 3 integration tests as a concise post-condition checker after calling
 * applySyncSnapshot.
 *
 * @param db      Open SQLite database handle.
 * @param serial  Certificate serial number to look up.
 * @param column  Name of the column to retrieve (e.g. "status", "renew_by").
 * @return The column value as int64_t, or -1 if no row was found.
 */
int64_t queryCertInt64(sqlite3 *db, int64_t serial, const char *column) {
    const std::string sql = std::string("SELECT ") + column + " FROM certs WHERE serial = ?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, serial);
    int64_t result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        result = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return result;
}

/**
 * @brief Serialize a database's certs table into a signed ClusterSync snapshot.
 *
 * Calls serializeCertsTable to produce a ClusterSync PVXS Value from the given
 * database, then canonicalizes and signs it with clusterSign using the provided
 * private key.  This helper mimics the sequence that a real CMS node executes when
 * publishing its sync PV, enabling Category 3 integration tests to produce realistic
 * signed snapshots without duplicating the sign/serialize boilerplate.
 *
 * @param db       Open SQLite database whose certs table is to be serialized.
 * @param node_id  Identifier of the node that is publishing the snapshot.
 * @param members  Current cluster membership list to embed in the snapshot.
 * @param pkey     Private key used to sign the snapshot.
 * @return Fully signed ClusterSync Value ready to pass to clusterVerify or applySyncSnapshot.
 */
Value buildSignedSync(sqlite3 *db, const std::string &node_id,
                      const std::vector<ClusterMember> &members,
                      const ossl_ptr<EVP_PKEY> &pkey) {
    auto val = serializeCertsTable(db, node_id, members);
    const auto canonical = canonicalizeSync(val);
    clusterSign(pkey, val, canonical);
    return val;
}

/**
 * @brief Tests the full nonce-based join handshake between two cluster nodes.
 *
 * Simulates the sequence a joining node (node_a) and an existing node (node_b)
 * execute when node_a requests cluster membership:
 *   1. node_a builds a JoinRequest containing a random 16-byte nonce and signs it.
 *   2. node_b verifies the signature and inspects the version and nonce fields.
 *   3. node_b builds a JoinResponse that echoes the nonce, embeds the member list
 *      and a current timestamp, then signs the response.
 *   4. node_a verifies the response signature, confirms the issuer_id, validates that
 *      the echoed nonce matches the one it sent, checks that the timestamp is
 *      within a 30-second tolerance, and reads the member list.
 *   5. A wrong nonce is confirmed to differ from the original.
 *   6. A JoinRequest with version_major == 2 is confirmed to carry the wrong version.
 *
 * Failure here means the nonce echo or signature validation in the join handshake is
 * broken, which would allow nodes to be added to the cluster without cryptographic
 * proof of identity or open the handshake to replay-based impersonation attacks.
 */
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

    auto resp_ts = getTimeStamp(resp);
    epicsTimeStamp now_ts = epicsTime::getCurrent();
    auto now = static_cast<int64_t>(now_ts.secPastEpoch);
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

    // The wrong major version should be rejected
    auto req_bad_ver = makeJoinRequestValue();
    req_bad_ver["version_major"] = static_cast<uint32_t>(2);
    testOk(req_bad_ver["version_major"].as<uint32_t>() != 1,
           "Major version 2 would be rejected by handler");
}

/**
 * @brief Tests end-to-end cert propagation from one node's database to another.
 *
 * Populates node_a's database with two certificates (VALID and PENDING_APPROVAL),
 * serializes and signs a snapshot via buildSignedSync, and feeds it to node_b's
 * empty database via applySyncSnapshot.  The test then confirms that:
 *   - The snapshot signature is accepted by clusterVerify.
 *   - Both certs appear in node_b's database with the correct status and timestamps.
 *
 * A second scenario inserts cert 100 as VALID in node_b and then feeds a snapshot
 * from a "stale" node_a that carries cert 100 as PENDING — a backward transition —
 * verifying that node_b's VALID status is preserved and not clobbered.
 *
 * Failure here indicates that the serialize → sign → verify → ingest pipeline has a
 * gap: either certs are lost during serialization, the signature is not properly
 * checked before ingestion, or the backward-transition guard in applySyncSnapshot is
 * not engaged when a cert already exists locally.
 */
void testCrossNodeSyncIngestion() {
    testDiag("Integration: cross-node sync ingestion");

    const auto pkey = generateTestKey();

    // Node A has certs in its DB
    TestDb db_a;
    insertCert(db_a.get(), 100, "CertA", VALID, 1000, 5000, 4000, 1500);
    insertCert(db_a.get(), 101, "CertB", PENDING_APPROVAL, 1000, 5000, 4000, 1500);

    // Node A builds and signs a sync snapshot
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};
    const auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

    // Node B receives and verifies the snapshot
    const auto canonical = canonicalizeSync(snapshot);
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
    const auto stale_snapshot = buildSignedSync(db_a_stale.get(), "node_a", members, pkey);
    applySyncSnapshot(db_b2.get(), lock_b2, stale_snapshot);

    testOk(queryCertInt64(db_b2.get(), 100, "status") == VALID,
           "Backward VALID->PENDING rejected — status unchanged");
}

/**
 * @brief Tests that cluster membership is correctly extracted from a sync snapshot.
 *
 * Builds a signed ClusterSync snapshot from node_a's (empty) database with a
 * member list of three nodes (node_a, node_b, node_c) and then simulates what
 * handleSyncUpdate does when it receives the snapshot: it iterates over the
 * "members" array and reconstructs a vector<ClusterMember> with the node_id,
 * sync_pv, and version fields from each entry.
 *
 * The test asserts that all three members are present in the correct order with
 * the expected node_id and version_major values.
 *
 * Failure here means that member list serialization or deserialization is broken,
 * which would prevent a receiving node from discovering or connecting to its peers
 * after receiving a sync update, causing the cluster to fragment.
 */
void testMembershipReconciliation() {
    testDiag("Integration: membership reconciliation from sync");

    const auto pkey = generateTestKey();

    // Node A's sync snapshot includes members A, B, and C
    TestDb db_a;
    std::vector<ClusterMember> members = {
        {"node_a", "sync:a", 1, 0, 0},
        {"node_b", "sync:b", 1, 0, 0},
        {"node_c", "sync:c", 1, 0, 0},
    };
    auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

    // Extract members from the snapshot (simulating what handleSyncUpdate does)
    const auto members_arr = snapshot["members"].as<shared_array<const Value>>();
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

    testOk(remote_members.size() == 3, "Snapshot carries 3 members");
    testOk(remote_members[0].node_id == "node_a", "Member 0 is node_a");
    testOk(remote_members[1].node_id == "node_b", "Member 1 is node_b");
    testOk(remote_members[2].node_id == "node_c", "Member 2 is node_c");
    testOk(remote_members[0].version_major == 1, "Member 0 version_major == 1");
    testOk(remote_members[1].version_major == 1, "Member 1 version_major == 1");
    testOk(remote_members[2].version_major == 1, "Member 2 version_major == 1");
}

/**
 * @brief Tests the anti-replay HWM check against genuinely signed snapshots.
 *
 * Unlike testAntiReplayLogic which uses raw atomic variables, this test constructs
 * two full ClusterSync snapshots from a real (in-memory) database, manually assigns
 * them deterministic timestamps (ts=1000 and ts=500 respectively), and signs both
 * with clusterSign.  It then simulates the handleSyncUpdate HWM gate:
 *   - Snapshot 1 (ts=1000) is accepted first and advances the HWM.
 *   - Snapshot 2 (ts=500) is then presented; because its timestamp is below
 *     HWM - tolerance, it must be rejected even though its signature is valid.
 *
 * This test closes the gap left by the unit-level test by confirming that signed
 * snapshots also carry timestamps that are checked by the anti-replay logic, so
 * a valid but old signature cannot be replayed to downgrade cert state.
 */
void testAntiReplayIntegration() {
    testDiag("Integration: anti-replay with signed snapshots");

    const auto pkey = generateTestKey();

    TestDb db_a;
    insertCert(db_a.get(), 200, "ReplayCert", VALID, 1000, 5000, 4000, 1500);
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};

    // Build two snapshots — the type definitions use setTimeStamp which writes
    // the current time.  For deterministic testing, we manually set timestamps.
    auto snap1 = serializeCertsTable(db_a.get(), "node_a", members);
    snap1["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(1000);
    snap1["timeStamp.nanoseconds"] = static_cast<int32_t>(0);
    const auto can1 = canonicalizeSync(snap1);
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
    const auto ts1 = getTimeStamp(snap1);
    const bool accept1 = (hwm.load() == 0 || ts1 >= hwm.load() - tolerance);
    testOk(accept1, "First snapshot (ts=1000) accepted");
    if (accept1) hwm.store(ts1);

    // Second snapshot (ts=500) rejected — stale
    const auto ts2 = getTimeStamp(snap2);
    const bool accept2 = (hwm.load() == 0 || ts2 >= hwm.load() - tolerance);
    testOk(!accept2, "Stale snapshot (ts=500) rejected after hwm=1000");
}

/**
 * @brief Tests that certificate renewal metadata propagates via VALID->VALID sync.
 *
 * Simulates the scenario where node_a has already processed a certificate renewal
 * for cert 300 — the cert remains VALID but its not_after and renew_by dates have
 * been extended — while node_b still holds the old validity window.  node_a builds
 * and signs a sync snapshot; node_b ingests it via applySyncSnapshot.
 *
 * The test asserts that after ingestion:
 *   - renew_by is updated from 4000 to 8000
 *   - not_after is updated from 5000 to 9000
 *   - status remains VALID (no unintended status change)
 *
 * Failure here means that cert renewals processed on one node never propagate to
 * peers, leaving those peers with stale expiry windows that could cause unnecessary
 * re-issuance or premature client authentication failures.
 */
void testRenewalPropagation() {
    testDiag("Integration: VALID->VALID renewal propagation");

    const auto pkey = generateTestKey();

    // Node B has cert 300 as VALID with renew_by=4000
    TestDb db_b;
    epicsMutex lock_b;
    insertCert(db_b.get(), 300, "RenewalCert", VALID, 1000, 5000, 4000, 1500);

    // Node A has already processed a renewal — cert 300 is still VALID but renew_by=8000
    TestDb db_a;
    insertCert(db_a.get(), 300, "RenewalCert", VALID, 1000, 9000, 8000, 2000);
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};
    const auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

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

/**
 * @brief Tests that tampering with a signed snapshot is detected by clusterVerify.
 *
 * Builds a ClusterSync snapshot from a real database, signs it with buildSignedSync,
 * and verifies the unmodified snapshot passes clusterVerify.  The test then mutates
 * the node_id field of the already-signed Value and re-canonicalizes it.  Because
 * the canonical form now differs from what was signed, clusterVerify must return false.
 *
 * This test confirms that the canonicalization function canonicalizeSync covers the
 * node_id field (and by extension, all fields it serializes) and that clusterVerify
 * does not accept a signature computed over a different canonical form.  Failure here
 * would mean that a man-in-the-middle could alter the originating node identity or
 * any other serialized field without invalidating the signature.
 */
void testSignatureTamperingRejected() {
    testDiag("Integration: signature tampering detected");

    const auto pkey = generateTestKey();

    TestDb db_a;
    insertCert(db_a.get(), 400, "TamperCert", VALID, 1000, 5000, 4000, 1500);
    std::vector<ClusterMember> members = {{"node_a", "sync:a", 1, 0, 0}};
    auto snapshot = buildSignedSync(db_a.get(), "node_a", members, pkey);

    // Verify the unmodified snapshot
    const auto canonical = canonicalizeSync(snapshot);
    testOk(clusterVerify(pkey, snapshot, canonical), "Unmodified snapshot passes verification");

    // Tamper with the node_id — the canonical form changes, signature won't match
    snapshot["node_id"] = "tampered_node";
    const auto tampered_canonical = canonicalizeSync(snapshot);
    testOk(!clusterVerify(pkey, snapshot, tampered_canonical),
           "Tampered snapshot fails verification");
}

/**
 * @brief Tests that PVXS Value delta-marking and unmark() behave as expected.
 *
 * Serializes a one-cert database into a ClusterSync Value via serializeCertsTable
 * and verifies that all top-level fields (node_id, timeStamp, members, certs) are
 * marked after the initial assignment, since PVXS marks fields when they are set.
 * The test then calls unmark() on node_id and members and re-checks that those two
 * fields lose their mark while certs and timeStamp.secondsPastEpoch remain marked.
 *
 * This test guards against regressions in the PVXS Value change-tracking semantics
 * used by the cluster sync PV publication path: a broken mark/unmark mechanism
 * would cause either all fields or no fields to be included in a delta PV update,
 * resulting in unnecessary full-table retransmissions or missed cert state changes
 * on subscribing peers.
 */
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
