/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "pvxs/cms/testHarness.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "certfactory.h"
#include "certfilefactory.h"
#include "certstatus.h"
#include "openssl.h"
#include "ownedptr.h"

namespace pvxs {
namespace cms {
namespace test {

namespace {

constexpr time_t kFourYearsSecs = static_cast<time_t>(4) * 365 * 24 * 60 * 60;

uint64_t randomSerial() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    return dist(gen);
}

int unlinkTreeCallback(const char *path, const struct stat *, int typeflag, struct FTW *) noexcept {
    if (typeflag == FTW_DP) {
        ::rmdir(path);
    } else {
        ::unlink(path);
    }
    return 0;
}

void removeTree(const std::string &path) noexcept {
    if (path.empty()) return;
    ::nftw(path.c_str(), unlinkTreeCallback, 8, FTW_DEPTH | FTW_PHYS);
}

std::string makeTempDir() {
    std::string templ;
    if (const char *tmpdir = std::getenv("TMPDIR")) {
        templ = tmpdir;
        if (!templ.empty() && templ.back() != '/') templ.push_back('/');
    } else {
        templ = "/tmp/";
    }
    templ += "pvxs-cms-pki.XXXXXX";
    std::vector<char> buf(templ.begin(), templ.end());
    buf.push_back('\0');
    if (!::mkdtemp(buf.data())) {
        throw std::runtime_error(std::string("mkdtemp failed: ") + std::strerror(errno));
    }
    return std::string(buf.data());
}

void writePemChain(const std::string &path, const ::cms::cert::CertData &caData) {
    pvxs::ossl_ptr<BIO> bio(BIO_new_file(path.c_str(), "w"));
    if (!bio) {
        throw std::runtime_error("Cannot open " + path + " for writing");
    }
    if (!PEM_write_bio_X509(bio.get(), caData.cert.get())) {
        throw std::runtime_error("PEM_write_bio_X509 failed for " + path);
    }
    if (caData.cert_auth_chain) {
        const int n = sk_X509_num(caData.cert_auth_chain.get());
        for (int i = 0; i < n; ++i) {
            X509 *x = sk_X509_value(caData.cert_auth_chain.get(), i);
            if (!PEM_write_bio_X509(bio.get(), x)) {
                throw std::runtime_error("PEM_write_bio_X509 chain entry failed for " + path);
            }
        }
    }
}

::cms::cert::CertData makeCa(const std::string &p12_path) {
    auto key_pair = ::cms::cert::IdFileFactory::createKeyPair();
    const time_t not_before = std::time(nullptr);
    const time_t not_after = not_before + kFourYearsSecs;

    ::cms::cert::CertFactory factory(
        randomSerial(),
        key_pair,
        "PVXS CMS Test CA",
        "US",
        "pvxs-cms-test",
        "PkiFixture CA",
        not_before,
        not_after,
        0,
        ::cms::ssl::kForCertAuth,
        std::string{},
        ::cms::cert::DEFAULT,
        true,
        false);

    auto cert = factory.create();
    auto pem = ::cms::cert::CertFactory::certAndCasToPemString(cert, factory.certificate_chain_.get());

    auto writer = ::cms::cert::IdFileFactory::create(p12_path, "", key_pair, nullptr, nullptr, pem);
    writer->writeIdentityFile();
    return writer->getCertData(key_pair);
}

void issueEE(const std::string &p12_path,
             const ::cms::cert::CertData &ca,
             const SubjectSpec &subject,
             uint16_t usage_mask) {
    auto key_pair = ::cms::cert::IdFileFactory::createKeyPair();
    const time_t not_before = std::time(nullptr);
    const time_t not_after = not_before + kFourYearsSecs;

    ::cms::cert::CertFactory factory(
        randomSerial(),
        key_pair,
        subject.common_name,
        subject.country.empty() ? "US" : subject.country,
        subject.organization.empty() ? "pvxs-cms-test" : subject.organization,
        subject.organizational_unit.empty() ? "PkiFixture EE" : subject.organizational_unit,
        not_before,
        not_after,
        0,
        usage_mask,
        std::string{},
        ::cms::cert::NO,
        true,
        true,
        ca.cert.get(),
        ca.key_pair ? ca.key_pair->pkey.get() : nullptr,
        ca.cert_auth_chain.get());

    auto cert = factory.create();
    auto pem = ::cms::cert::CertFactory::certAndCasToPemString(cert, factory.certificate_chain_.get());

    auto writer = ::cms::cert::IdFileFactory::create(p12_path, "", key_pair, nullptr, nullptr, pem);
    writer->writeIdentityFile();
}

std::string sha256HexOfPubkey(X509 *cert) {
    pvxs::ossl_ptr<EVP_PKEY> pkey(X509_get_pubkey(cert));
    if (!pkey) throw std::runtime_error("X509_get_pubkey failed");
    int len = i2d_PUBKEY(pkey.get(), nullptr);
    if (len <= 0) throw std::runtime_error("i2d_PUBKEY size query failed");
    std::vector<unsigned char> der(static_cast<size_t>(len));
    unsigned char *p = der.data();
    if (i2d_PUBKEY(pkey.get(), &p) != len) throw std::runtime_error("i2d_PUBKEY failed");
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der.data(), der.size(), digest);
    std::ostringstream out;
    static const char *hex = "0123456789abcdef";
    for (auto b : digest) {
        out << hex[(b >> 4) & 0x0f] << hex[b & 0x0f];
    }
    return out.str();
}

}  // namespace

struct PkiFixture::Impl {
    std::string dir;
    std::string ca_p12;
    std::string ca_chain_pem;
    std::string server_p12;
    std::string admin_p12;
    ::cms::cert::CertData ca;
    std::atomic<uint64_t> ee_counter{0};
};

PkiFixture::PkiFixture() : impl_(new Impl{}) {
    impl_->dir = makeTempDir();
    impl_->ca_p12 = impl_->dir + "/ca.p12";
    impl_->ca_chain_pem = impl_->dir + "/ca-chain.pem";
    impl_->server_p12 = impl_->dir + "/pvacms-server.p12";
    impl_->admin_p12 = impl_->dir + "/admin.p12";

    try {
        impl_->ca = makeCa(impl_->ca_p12);
        writePemChain(impl_->ca_chain_pem, impl_->ca);
        issueEE(impl_->server_p12, impl_->ca, {"PVACMS Test Server", {}, {}, {}}, ::cms::ssl::kForCMS);
        issueEE(impl_->admin_p12, impl_->ca, {"PVACMS Test Admin", {}, {}, {}}, ::cms::ssl::kForClient);
    } catch (...) {
        removeTree(impl_->dir);
        throw;
    }
}

PkiFixture::PkiFixture(PkiFixture &&) noexcept = default;
PkiFixture &PkiFixture::operator=(PkiFixture &&) noexcept = default;

PkiFixture::~PkiFixture() {
    if (impl_) removeTree(impl_->dir);
}

const std::string &PkiFixture::dir() const noexcept { return impl_->dir; }
const std::string &PkiFixture::caP12Path() const noexcept { return impl_->ca_p12; }
const std::string &PkiFixture::caChainPemPath() const noexcept { return impl_->ca_chain_pem; }
const std::string &PkiFixture::serverP12Path() const noexcept { return impl_->server_p12; }
const std::string &PkiFixture::adminP12Path() const noexcept { return impl_->admin_p12; }

std::string PkiFixture::caFingerprintSha256() const {
    return sha256HexOfPubkey(impl_->ca.cert.get());
}

std::string PkiFixture::issueServerEE(const SubjectSpec &subject) {
    auto path = impl_->dir + "/server-ee-" + std::to_string(impl_->ee_counter.fetch_add(1)) + ".p12";
    issueEE(path, impl_->ca, subject, ::cms::ssl::kForServer);
    return path;
}

std::string PkiFixture::issueClientEE(const SubjectSpec &subject) {
    auto path = impl_->dir + "/client-ee-" + std::to_string(impl_->ee_counter.fetch_add(1)) + ".p12";
    issueEE(path, impl_->ca, subject, ::cms::ssl::kForClient);
    return path;
}

}  // namespace test
}  // namespace cms
}  // namespace pvxs
