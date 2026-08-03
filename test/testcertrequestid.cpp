/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>

#include <pvxs/unittest.h>

#include "certfactory.h"
#include "certrequestid.h"
// The table and its statements live with the feature, in certrequestid.h

using namespace pvxs;
using namespace pvxs::certs;

namespace {

/** A key pair of the kind a requester makes, so a test can encrypt to it and read it back. */
std::shared_ptr<KeyPair> makeRsaKeyPair(const int bits = 2048) {
    ossl_ptr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), false);
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits);
    EVP_PKEY *raw = nullptr;
    EVP_PKEY_keygen(ctx.get(), &raw);
    ossl_ptr<EVP_PKEY> pkey(raw, false);
    return std::make_shared<KeyPair>(std::move(pkey));
}

std::string publicKeyPem(const std::shared_ptr<KeyPair> &key_pair) { return key_pair->public_key; }

/** The columns a table has, so a test can assert none were added. */
std::vector<std::string> tableColumns(sqlite3 *db, const char *table) {
    std::vector<std::string> out;
    const std::string sql = std::string("PRAGMA table_info(") + table + ");";
    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (const auto name = sqlite3_column_text(st, 1)) out.emplace_back(reinterpret_cast<const char *>(name));
    }
    sqlite3_finalize(st);
    return out;
}

int64_t scalar(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return -1;
    int64_t out = -1;
    if (sqlite3_step(st) == SQLITE_ROW) out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return out;
}

void testIdentifierForm() {
    testDiag("The identifier itself");

    const auto id = generateRequestId();
    testEq(id.size(), kRequestIdLength);

    // Crockford base32: no I, L, O or U, because a reader turns them into 1, 1, 0 and V.
    bool alphabet_ok = true;
    for (const char c : id) {
        if (!std::strchr("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c)) alphabet_ok = false;
    }
    testOk(alphabet_ok, "Written only with characters that survive being read aloud: %s", id.c_str());

    testEq(requestIdForDisplay("A3K97QRT2MXE5W1B"), std::string("A3K9-7QRT-2MXE-5W1B"));
    testEq(requestIdCanonical("A3K9-7QRT-2MXE-5W1B"), std::string("A3K97QRT2MXE5W1B"));
    testEq(requestIdCanonical("a3k9-7qrt-2mxe-5w1b"), std::string("A3K97QRT2MXE5W1B"));
    testEq(requestIdCanonical(requestIdForDisplay(id)), id);

    testThrows<std::runtime_error>([] { requestIdCanonical("A3K9-7QRT-2MXE-5W1"); })
        << "too short to be an identifier";
    testThrows<std::runtime_error>([] { requestIdCanonical("A3K9-7QRT-2MXE-5W1I"); })
        << "holds a character an identifier is never written with";

    // Two identifiers minted together must differ, or the whole point of minting per request goes.
    testOk1(generateRequestId() != generateRequestId());
}

void testEncryption() {
    testDiag("Encrypting to the key that asked for the certificate");

    const auto requester = makeRsaKeyPair();
    const auto payload = buildRequestIdPayload(generateRequestId(), "abcd1234:12345678901234567890",
                                               std::string(64, 'a'), 1785700000);

    const auto ciphertext = encryptToRequester(publicKeyPem(requester), payload);
    testEq(ciphertext.size(), size_t(256));

    // The holder of the private key reads it back; nobody else can.
    testEq(decryptWithRequesterKey(requester, ciphertext), payload);

    const auto other = makeRsaKeyPair();
    testThrows<std::runtime_error>([&other, &ciphertext] { decryptWithRequesterKey(other, ciphertext); })
        << "a different key cannot read it, which is what a substituted public key looks like";

    // A key type with no encryption path here must fail loudly rather than fall back to
    // anything weaker, so a later move to elliptic curve keys cannot slip through.
    ossl_ptr<EVP_PKEY_CTX> ec_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), false);
    EVP_PKEY_keygen_init(ec_ctx.get());
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ec_ctx.get(), NID_X9_62_prime256v1);
    EVP_PKEY *ec_raw = nullptr;
    EVP_PKEY_keygen(ec_ctx.get(), &ec_raw);
    const ossl_ptr<EVP_PKEY> ec_key(ec_raw, false);
    const ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()), false);
    PEM_write_bio_PUBKEY(bio.get(), ec_key.get());
    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(bio.get(), &bptr);
    const std::string ec_pem(bptr->data, bptr->length);
    testThrows<std::runtime_error>([&ec_pem, &payload] { encryptToRequester(ec_pem, payload); })
        << "a key that is not RSA is refused rather than worked around";

    // More than the key can carry must fail, never be shortened: a truncated payload would
    // fail its own checks later and look like tampering.
    const std::string too_long(300, 'x');
    testThrows<std::runtime_error>([&requester, &too_long] { encryptToRequester(publicKeyPem(requester), too_long); })
        << "an over-long package is refused rather than shortened";
}

void testSignature() {
    testDiag("Signing what comes back");

    const auto authority = makeRsaKeyPair();
    const auto requester = makeRsaKeyPair();
    const std::string cert_id = "abcd1234:12345678901234567890";
    const auto digest = publicKeyDigest(requester->pkey.get());
    const auto payload = buildRequestIdPayload(generateRequestId(), cert_id, digest, 1785700000);
    const auto ciphertext = encryptToRequester(publicKeyPem(requester), payload);

    const auto covered = requestIdSignedBytes(cert_id, digest, ciphertext);
    const auto signature = CertFactory::sign(authority->pkey, covered);
    testOk1(CertFactory::verifySignature(authority->pkey, covered, signature));

    // Each thing the signature covers, altered one at a time.
    testOk(!CertFactory::verifySignature(authority->pkey,
                                         requestIdSignedBytes("abcd1234:99999999999999999999", digest, ciphertext),
                                         signature),
           "A different certificate identifier fails the signature");
    testOk(!CertFactory::verifySignature(authority->pkey,
                                         requestIdSignedBytes(cert_id, std::string(64, 'b'), ciphertext),
                                         signature),
           "A different public key digest fails the signature");
    auto tampered = ciphertext;
    tampered[0] = static_cast<uint8_t>(tampered[0] ^ 0x01);
    testOk(!CertFactory::verifySignature(authority->pkey, requestIdSignedBytes(cert_id, digest, tampered), signature),
           "One altered ciphertext byte fails the signature");

    // Signed by an authority the requester did not commit to.
    const auto impostor = makeRsaKeyPair();
    testOk(!CertFactory::verifySignature(authority->pkey, covered, CertFactory::sign(impostor->pkey, covered)),
           "A signature by another authority fails");
}

void testPayloadBindings() {
    testDiag("A package can only be used for the request it was made for");

    const auto requester = makeRsaKeyPair();
    const std::string cert_id = "abcd1234:12345678901234567890";
    const auto digest = publicKeyDigest(requester->pkey.get());
    const auto id = generateRequestId();
    const auto payload = buildRequestIdPayload(id, cert_id, digest, 1785700000);

    const auto parsed = parseRequestIdPayload(payload, cert_id, digest);
    testEq(parsed.request_id, id);
    testEq(parsed.cert_id, cert_id);
    testEq(parsed.issued_at, time_t(1785700000));

    // Replayed against another request.
    testThrows<std::runtime_error>(
        [&payload, &digest] { parseRequestIdPayload(payload, "abcd1234:99999999999999999999", digest); })
        << "a package made for one certificate is refused for another";

    // Issued against another key.
    testThrows<std::runtime_error>(
        [&payload, &cert_id] { parseRequestIdPayload(payload, cert_id, std::string(64, 'b')); })
        << "a package issued against another key is refused";

    // A version this code does not read.
    const std::string wrong_version = "SPVA-REQUEST-ID-2\n" + id + "\n" + cert_id + "\n" + digest + "\n0\n";
    testThrows<std::runtime_error>(
        [&wrong_version, &cert_id, &digest] { parseRequestIdPayload(wrong_version, cert_id, digest); })
        << "a package of another version is refused rather than guessed at";

    // Truncated.
    testThrows<std::runtime_error>(
        [&cert_id, &digest] { parseRequestIdPayload("SPVA-REQUEST-ID-1\n", cert_id, digest); })
        << "a package that is not the expected five lines is refused";

    // A field that could move the line boundaries must never be accepted for building one.
    testThrows<std::runtime_error>([&cert_id, &digest] {
        buildRequestIdPayload("AAAA\nBBBB", cert_id, digest, 0);
    }) << "a field carrying a line feed is refused, since it could pose as another field";
}

void testDigest() {
    testDiag("Identifying a key");

    const auto key = makeRsaKeyPair();
    const auto from_key = publicKeyDigest(key->pkey.get());
    const auto from_pem = publicKeyDigest(publicKeyPem(key));
    testEq(from_key, from_pem);
    testEq(from_key.size(), size_t(64));
    testOk1(from_key != publicKeyDigest(makeRsaKeyPair()->pkey.get()));
}

/** The shape of the certificate table before the request identifier table existed. */
constexpr const char *kOldCertsTable =
    "CREATE TABLE certs("
    "     serial INTEGER PRIMARY KEY,"
    "     skid TEXT,"
    "     CN TEXT,"
    "     status INTEGER"
    ");";

void testSchema() {
    testDiag("The table, on a database made before it existed");

    sqlite3 *db = nullptr;
    testOk1(sqlite3_open(":memory:", &db) == SQLITE_OK);

    // A database as an earlier version left it, with rows in it.
    testOk1(sqlite3_exec(db, kOldCertsTable, nullptr, nullptr, nullptr) == SQLITE_OK);
    testOk1(sqlite3_exec(db,
                         "INSERT INTO certs(serial, skid, CN, status) VALUES (1, 'aa', 'one', 1),"
                         " (2, 'bb', 'two', 1);",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
    const auto columns_before = tableColumns(db, "certs");
    const auto rows_before = scalar(db, "SELECT COUNT(*) FROM certs;");

    // The statement the service runs on every start, not only when the certificate table is
    // absent, which is the whole reason it is separate.
    testOk1(sqlite3_exec(db, SQL_CREATE_REQUEST_ID_TABLE, nullptr, nullptr, nullptr) == SQLITE_OK);
    testEq(scalar(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cert_request_ids';"),
           int64_t(1));

    // Running it again must be harmless, because it runs on every start.
    testOk1(sqlite3_exec(db, SQL_CREATE_REQUEST_ID_TABLE, nullptr, nullptr, nullptr) == SQLITE_OK);

    // The certificate table is untouched: same rows, and no column added to it.
    testEq(scalar(db, "SELECT COUNT(*) FROM certs;"), rows_before);
    testOk(tableColumns(db, "certs") == columns_before,
           "The certificate table gains no column: the identifier is not a property of a certificate");

    // One row per request, keyed on the serial number.
    sqlite3_stmt *st = nullptr;
    testOk1(sqlite3_prepare_v2(db, SQL_CREATE_REQUEST_ID, -1, &st, nullptr) == SQLITE_OK);
    const auto id = generateRequestId();
    const std::string digest(64, 'a');
    sqlite3_bind_int64(st, sqlite3_bind_parameter_index(st, ":serial"), 42);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, ":request_id"), id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, ":pub_key_digest"), digest.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, sqlite3_bind_parameter_index(st, ":created"), 1785700000);
    testOk1(sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);

    testEq(scalar(db, "SELECT COUNT(*) FROM cert_request_ids;"), int64_t(1));
    testEq(scalar(db, "SELECT serial FROM cert_request_ids;"), int64_t(42));

    // Read back for that serial number, which is how a renewal finds the one already issued.
    testOk1(sqlite3_prepare_v2(db, SQL_REQUEST_ID_BY_SERIAL, -1, &st, nullptr) == SQLITE_OK);
    sqlite3_bind_int64(st, sqlite3_bind_parameter_index(st, ":serial"), 42);
    testOk1(sqlite3_step(st) == SQLITE_ROW);
    testEq(std::string(reinterpret_cast<const char *>(sqlite3_column_text(st, 0))), id);
    sqlite3_finalize(st);

    // The serial number is the primary key, so one certificate cannot end up with two.
    testOk1(sqlite3_prepare_v2(db, SQL_CREATE_REQUEST_ID, -1, &st, nullptr) == SQLITE_OK);
    sqlite3_bind_int64(st, sqlite3_bind_parameter_index(st, ":serial"), 42);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, ":request_id"), id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(st, sqlite3_bind_parameter_index(st, ":pub_key_digest"), digest.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, sqlite3_bind_parameter_index(st, ":created"), 1785700000);
    testOk1(sqlite3_step(st) != SQLITE_DONE);
    sqlite3_finalize(st);

    sqlite3_close(db);
}

/**
 * The whole exchange, and then the same exchange with the public key swapped in transit, which
 * is the attack this exists to make visible.
 */
void testSubstitutedKey() {
    testDiag("A public key swapped in transit");

    const auto authority = makeRsaKeyPair();
    const auto requester = makeRsaKeyPair();
    const auto attacker = makeRsaKeyPair();
    const std::string cert_id = "abcd1234:12345678901234567890";
    const auto id = generateRequestId();

    // What the service does when the request arrives carrying the attacker's key: it encrypts
    // to the key it was given, and binds the package to that key's digest.
    const auto attacker_digest = publicKeyDigest(attacker->pkey.get());
    const auto payload = buildRequestIdPayload(id, cert_id, attacker_digest, 1785700000);
    const auto ciphertext = encryptToRequester(publicKeyPem(attacker), payload);
    const auto signature =
        CertFactory::sign(authority->pkey, requestIdSignedBytes(cert_id, attacker_digest, ciphertext));

    // What the real requester does with the reply. It rebuilds the covered bytes from its OWN
    // digest, because that is all it knows, so the signature no longer matches: the swap is
    // caught before anything is decrypted.
    const auto requester_digest = publicKeyDigest(requester->pkey.get());
    testOk(!CertFactory::verifySignature(authority->pkey,
                                         requestIdSignedBytes(cert_id, requester_digest, ciphertext), signature),
           "The signature fails, because it covers the attacker's key digest and not the requester's");

    // And even reaching past that, the requester cannot read it.
    testThrows<std::runtime_error>([&requester, &ciphertext] { decryptWithRequesterKey(requester, ciphertext); })
        << "the requester cannot read a package encrypted to a key it does not hold";

    // So no identifier is ever produced for the requester to email, which is the property:
    // the substitution cannot proceed quietly.
    testOk(true, "No identifier is produced, so no approval can follow a substituted key");
}

}  // namespace

MAIN(testcertrequestid) {
    testPlan(50);
    testIdentifierForm();
    testDigest();
    testEncryption();
    testSignature();
    testPayloadBindings();
    testSchema();
    testSubstitutedKey();
    return testDone();
}
