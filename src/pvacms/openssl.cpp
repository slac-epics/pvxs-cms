/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "openssl.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif
#include <cassert>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include <epicsExit.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusmanager.h"
#include "evhelper.h"
#include "opensslgbl.h"
#include "ownedptr.h"

#ifndef TLS1_3_VERSION
#error TLS 1.3 support required.  Upgrade to openssl >= 1.1.0
#endif

namespace pvxs {
namespace ossl {

SSLError::SSLError(const std::string &msg)
    : std::runtime_error([&msg]() -> std::string {
          std::ostringstream strm;
          const char *file = nullptr;
          int line = 0;
          const char *data = nullptr;
          int flags = 0;
          while (const auto err = ERR_get_error_all(&file, &line, nullptr, &data, &flags)) {
              strm << file << ':' << line << ':' << ERR_reason_error_string(err);
              if (data && (flags & ERR_TXT_STRING)) strm << ':' << data;
              strm << ", ";
          }
          strm << msg;
          return strm.str();
      }()) {}

SSLError::~SSLError() = default;

std::ostream &operator<<(std::ostream &strm, const ShowX509 &cert) {
    if (cert.cert) {
        const auto name = X509_get_subject_name(cert.cert);
        const auto issuer = X509_get_issuer_name(cert.cert);
        assert(name);
        const ossl_ptr<BIO> io(__FILE__, __LINE__, BIO_new(BIO_s_mem()));
        {
            try {
                const auto cert_id = certs::CmsStatusManager::getCertIdFromCert(cert.cert);
                (void)BIO_printf(io.get(), "\nCertificate ID : ");
                (void)BIO_printf(io.get(), cert_id.c_str());
            } catch (...) {}
        }
        (void)BIO_printf(io.get(), "\nEntity Subject : ");
        (void)X509_NAME_print(io.get(), name, 1024);
        (void)BIO_printf(io.get(), "\nIssuer Subject : ");
        (void)X509_NAME_print(io.get(), issuer, 1024);
        if (const auto atm = X509_get0_notBefore(cert.cert)) {
            const certs::CertDate the_date(atm);
            (void)BIO_printf(io.get(), "\nValid From     : ");
            (void)BIO_printf(io.get(), the_date.s.c_str());
        }
        if (const auto atm = X509_get0_notAfter(cert.cert)) {
            const certs::CertDate the_date(atm);
            (void)BIO_printf(io.get(), "\nExpires On     : ");
            (void)BIO_printf(io.get(), the_date.s.c_str());
        }
        {
            const ossl_ptr<BIO> san_bio(BIO_new(BIO_s_mem()));
            bool first = true;
            for (int ext_idx = X509_get_ext_by_NID(cert.cert, NID_subject_alt_name, -1);
                 ext_idx >= 0;
                 ext_idx = X509_get_ext_by_NID(cert.cert, NID_subject_alt_name, ext_idx)) {
                X509_EXTENSION *ext = X509_get_ext(cert.cert, ext_idx);
                if (!ext) break;
                const ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ext);
                const unsigned char *p = data->data;
                auto *gens = d2i_GENERAL_NAMES(nullptr, &p,
                                               static_cast<long>(data->length));
                if (!gens) break;
                for (int i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
                    const GENERAL_NAME *gen = sk_GENERAL_NAME_value(gens, i);
                    std::string entry;
                    if (gen->type == GEN_DNS) {
                        const auto *dns = reinterpret_cast<const ASN1_IA5STRING *>(gen->d.dNSName);
                        entry = "dns=" + std::string(reinterpret_cast<const char *>(dns->data),
                                                     static_cast<size_t>(dns->length));
                    } else if (gen->type == GEN_IPADD) {
                        const auto *ip = gen->d.iPAddress;
                        if (ip->length == 4) {
                            char buf[32];
                            snprintf(buf, sizeof(buf), "ip=%d.%d.%d.%d",
                                     ip->data[0], ip->data[1], ip->data[2], ip->data[3]);
                            entry = buf;
                        }
                    } else if (gen->type == GEN_URI) {
                        const auto *uri = reinterpret_cast<const ASN1_IA5STRING *>(gen->d.uniformResourceIdentifier);
                        entry = "uri=" + std::string(reinterpret_cast<const char *>(uri->data),
                                                     static_cast<size_t>(uri->length));
                    }
                    if (!entry.empty()) {
                        if (!first) BIO_printf(san_bio.get(), ", ");
                        BIO_printf(san_bio.get(), "%s", entry.c_str());
                        first = false;
                    }
                }
                GENERAL_NAMES_free(gens);
                break;
            }
            char *san_str = nullptr;
            const auto san_len = BIO_get_mem_data(san_bio.get(), &san_str);
            if (san_len > 0) {
                (void)BIO_printf(io.get(), "\nSAN            : ");
                (void)BIO_write(io.get(), san_str, static_cast<int>(san_len));
            }
        }
        {
            char *str = nullptr;
            if (const auto len = BIO_get_mem_data(io.get(), &str)) {
                strm.write(str, len);
            }
        }
    } else {
        strm << "NULL";
    }
    return strm;
}

// ---------------------------------------------------------------------------
// Helpers shared by ShowX509Verbose
// ---------------------------------------------------------------------------

namespace {

// All dump output uses a fixed column for the colon so every value aligns
// regardless of nesting depth. 32-char prefix => colon at column 33.
constexpr int kColonCol = 32;

// Emit "  LABEL" padded so the next character is at kColonCol, then " : ".
// indent: number of leading spaces (2 for top-level, 4 for sub-block item).
void writeLabel(std::ostream& strm, const char* label, int indent = 2) {
    std::string s(indent, ' ');
    s += label;
    if (static_cast<int>(s.size()) < kColonCol) s.append(kColonCol - s.size(), ' ');
    strm << s << " : ";
}

// Emit a section header line (no colon) at indent 2, e.g. "  Validity Period".
void writeSubHeader(std::ostream& strm, const char* header) {
    strm << "  " << header << "\n";
}

// Write a colon-separated uppercase hex string of raw bytes to strm.
void writeHexColon(std::ostream& strm, const unsigned char* data, int len) {
    for (int i = 0; i < len; ++i) {
        if (i) strm << ':';
        char buf[3];
        snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(data[i]));
        strm << buf;
    }
}

// Resolve an ASN1_OBJECT to its long name; fall back to dotted OID.
std::string oidLongName(const ASN1_OBJECT* obj) {
    if (!obj) return "(null)";
    const int nid = OBJ_obj2nid(obj);
    if (nid != NID_undef) {
        const char* ln = OBJ_nid2ln(nid);
        if (ln && std::string(ln) != "undefined") return ln;
    }
    char buf[128];
    OBJ_obj2txt(buf, sizeof(buf), obj, 1);  // 1 = always dotted OID
    return buf;
}

// Get a single NID attribute from an X509_NAME as UTF-8 string, or "".
std::string nameAttr(const X509_NAME* name, int nid) {
    const int idx = X509_NAME_get_index_by_NID(const_cast<X509_NAME*>(name), nid, -1);
    if (idx < 0) return {};
    const X509_NAME_ENTRY* entry = X509_NAME_get_entry(const_cast<X509_NAME*>(name), idx);
    if (!entry) return {};
    const ASN1_STRING* str = X509_NAME_ENTRY_get_data(entry);
    if (!str) return {};
    unsigned char* utf8 = nullptr;
    const int len = ASN1_STRING_to_UTF8(&utf8, const_cast<ASN1_STRING*>(str));
    if (len < 0 || !utf8) return {};
    std::string result(reinterpret_cast<char*>(utf8), static_cast<size_t>(len));
    OPENSSL_free(utf8);
    return result;
}

void writeDnFields(std::ostream& strm, const X509_NAME* name, const char* header) {
    static const std::pair<int, const char*> kAttrs[] = {
        {NID_commonName,             "Common Name (CN)"},
        {NID_organizationName,       "Organization (O)"},
        {NID_organizationalUnitName, "Org Unit (OU)"},
        {NID_countryName,            "Country (C)"},
        {NID_stateOrProvinceName,    "State/Province (ST)"},
        {NID_localityName,           "Locality (L)"},
        {NID_pkcs9_emailAddress,     "Email"},
    };
    writeSubHeader(strm, header);
    for (const auto& a : kAttrs) {
        const std::string v = nameAttr(name, a.first);
        if (!v.empty()) {
            writeLabel(strm, a.second, 4);
            strm << v << "\n";
        }
    }
}

// NIST common name table for EC curves.
std::string ecCurveName(int nid) {
    static const std::pair<int, const char*> kNist[] = {
        {NID_X9_62_prime256v1, "P-256"},
        {NID_secp384r1,        "P-384"},
        {NID_secp521r1,        "P-521"},
        {NID_secp224r1,        "P-224"},
        {NID_secp192k1,        "secp192k1"},
        {NID_secp256k1,        "secp256k1"},
    };
    for (const auto& p : kNist) {
        if (p.first == nid) return p.second;
    }
    // Fall back to OpenSSL long name, then dotted OID
    const char* ln = OBJ_nid2ln(nid);
    if (ln && std::string(ln) != "undefined") return ln;
    char buf[64];
    OBJ_obj2txt(buf, sizeof(buf), OBJ_nid2obj(nid), 1);
    return buf;
}

void writeSanEntry(std::ostream& strm, const char* type_label, const std::string& value) {
    writeLabel(strm, type_label, 6);
    strm << value << "\n";
}

void writeSans(std::ostream& strm, const X509* cert) {
    const char* kEmpty = "      (none)\n";
    const int ext_idx = X509_get_ext_by_NID(const_cast<X509*>(cert), NID_subject_alt_name, -1);
    if (ext_idx < 0) { strm << kEmpty; return; }
    X509_EXTENSION* ext = X509_get_ext(const_cast<X509*>(cert), ext_idx);
    if (!ext) { strm << kEmpty; return; }
    const ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    const unsigned char* p = data->data;
    GENERAL_NAMES* gens = d2i_GENERAL_NAMES(nullptr, &p, static_cast<long>(data->length));
    if (!gens) { strm << kEmpty; return; }

    const int n = sk_GENERAL_NAME_num(gens);
    if (n == 0) { strm << kEmpty; }
    for (int i = 0; i < n; ++i) {
        const GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens, i);
        if (gen->type == GEN_DNS) {
            const auto* s = reinterpret_cast<const ASN1_IA5STRING*>(gen->d.dNSName);
            writeSanEntry(strm, "DNS", std::string(reinterpret_cast<const char*>(s->data), static_cast<size_t>(s->length)));
        } else if (gen->type == GEN_IPADD) {
            const auto* ip = gen->d.iPAddress;
            char buf[INET6_ADDRSTRLEN] = {};
            if (ip->length == 4) {
                inet_ntop(AF_INET, ip->data, buf, sizeof(buf));
                writeSanEntry(strm, "IP", buf);
            } else if (ip->length == 16) {
                inet_ntop(AF_INET6, ip->data, buf, sizeof(buf));
                writeSanEntry(strm, "IP", buf);
            } else {
                writeSanEntry(strm, "IP", "[" + std::to_string(ip->length) + " bytes]");
            }
        } else if (gen->type == GEN_URI) {
            const auto* s = reinterpret_cast<const ASN1_IA5STRING*>(gen->d.uniformResourceIdentifier);
            writeSanEntry(strm, "URI", std::string(reinterpret_cast<const char*>(s->data), static_cast<size_t>(s->length)));
        } else if (gen->type == GEN_EMAIL) {
            const auto* s = reinterpret_cast<const ASN1_IA5STRING*>(gen->d.rfc822Name);
            writeSanEntry(strm, "Email", std::string(reinterpret_cast<const char*>(s->data), static_cast<size_t>(s->length)));
        } else if (gen->type == GEN_RID) {
            writeSanEntry(strm, "Registered ID", oidLongName(gen->d.registeredID));
        } else if (gen->type == GEN_OTHERNAME) {
            writeSanEntry(strm, "Other Name", oidLongName(gen->d.otherName->type_id) + " [value: hex]");
        } else if (gen->type == GEN_X400) {
            writeSanEntry(strm, "X.400 Address", "[hex]");
        } else if (gen->type == GEN_DIRNAME) {
            ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()));
            X509_NAME_print_ex(bio.get(), gen->d.directoryName, 0, XN_FLAG_RFC2253);
            char* s = nullptr;
            const long len = BIO_get_mem_data(bio.get(), &s);
            writeSanEntry(strm, "Directory Name", std::string(s, static_cast<size_t>(len)));
        } else if (gen->type == GEN_EDIPARTY) {
            writeSanEntry(strm, "EDI Party", "[hex]");
        } else {
            writeSanEntry(strm, "Unknown", "[type " + std::to_string(gen->type) + " hex]");
        }
    }
    GENERAL_NAMES_free(gens);
}

// Track which extension NIDs have already been emitted so the generic
// catch-all loop can skip them.
static const int kHandledNids[] = {
    NID_subject_alt_name,
    NID_subject_key_identifier,
    NID_authority_key_identifier,
    NID_key_usage,
    NID_ext_key_usage,
    NID_basic_constraints,
    NID_crl_distribution_points,
    NID_info_access,
    NID_certificate_policies,
};

bool isHandledNid(int nid) {
    for (int h : kHandledNids) if (h == nid) return true;
    // Also skip the two PVXS custom NIDs (registered at runtime)
    if (nid == ossl::NID_SPvaCertStatusURI) return true;
    if (nid == ossl::NID_SPvaCertConfigURI) return true;
    return false;
}

void writeExtension(std::ostream& strm, X509_EXTENSION* ext) {
    ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
    std::string label = oidLongName(obj);
    if (X509_EXTENSION_get_critical(ext)) label += " [critical]";
    writeLabel(strm, label.c_str());

    ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()));
    if (X509V3_EXT_print(bio.get(), ext, 0, 0)) {
        char* s = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &s);
        if (len > 0) strm << std::string(s, static_cast<size_t>(len));
    } else {
        const ASN1_OCTET_STRING* raw = X509_EXTENSION_get_data(ext);
        for (int i = 0; i < raw->length; ++i) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(raw->data[i]));
            strm << buf;
        }
    }
    strm << "\n";
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// ShowX509Verbose::operator<<
// ---------------------------------------------------------------------------

std::ostream& operator<<(std::ostream& strm, const ShowX509Verbose& show) {
    const X509* cert = show.cert;
    if (!cert) { strm << "NULL\n"; return strm; }

    try {
        writeLabel(strm, "PVXS Cert ID");
        strm << certs::CmsStatusManager::getCertIdFromCert(cert) << "\n";
    } catch (...) {}

    writeLabel(strm, "Version");
    strm << (X509_get_version(cert) + 1) << "\n";
    {
        const ASN1_INTEGER* serial_asn1 = X509_get_serialNumber(const_cast<X509*>(cert));
        const ossl_ptr<BIGNUM> bn(ASN1_INTEGER_to_BN(serial_asn1, nullptr), false);
        if (bn) {
            char* dec = BN_bn2dec(bn.get());
            if (dec) { writeLabel(strm, "Serial Number"); strm << dec << "\n"; OPENSSL_free(dec); }
        }
    }

    writeDnFields(strm, X509_get_subject_name(cert), "Subject");
    writeDnFields(strm, X509_get_issuer_name(cert), "Issuer");

    writeSubHeader(strm, "Validity Period");
    if (const ASN1_TIME* t = X509_get0_notBefore(cert)) {
        writeLabel(strm, "Not Before", 4);
        strm << certs::CertDate(t).s << "\n";
    }
    if (const ASN1_TIME* t = X509_get0_notAfter(cert)) {
        writeLabel(strm, "Not After", 4);
        strm << certs::CertDate(t).s << "\n";
    }

    {
        EVP_PKEY* pkey = X509_get0_pubkey(const_cast<X509*>(cert));
        if (pkey) {
            writeSubHeader(strm, "Public Key");
            const int base_id = EVP_PKEY_base_id(pkey);
            const char* alg_name = OBJ_nid2ln(base_id);
            writeLabel(strm, "Algorithm", 4);
            strm << (alg_name ? alg_name : "unknown");
            const int bits = EVP_PKEY_bits(pkey);
            if (bits > 0) strm << " (" << bits << " bit)";
            strm << "\n";
            if (base_id == EVP_PKEY_EC) {
                char curve_name[64] = {};
                EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                               curve_name, sizeof(curve_name), nullptr);
                const int cnid = OBJ_sn2nid(curve_name);
                if (cnid != NID_undef) {
                    writeLabel(strm, "Curve", 4);
                    strm << ecCurveName(cnid) << "\n";
                }
            }
        }
    }

    writeSubHeader(strm, "Signature");
    {
        const int sig_nid = X509_get_signature_nid(cert);
        const char* ln = OBJ_nid2ln(sig_nid);
        writeLabel(strm, "Algorithm", 4);
        strm << (ln ? ln : "unknown") << "\n";
    }
    {
        static const struct { int nid; const char* label; } kFp[] = {
            {NID_sha1,   "SHA-1 Fingerprint"},
            {NID_sha256, "SHA-256 Fingerprint"},
        };
        for (const auto& fp : kFp) {
            unsigned char md[EVP_MAX_MD_SIZE];
            unsigned int md_len = 0;
            if (X509_digest(cert, EVP_get_digestbynid(fp.nid), md, &md_len)) {
                writeLabel(strm, fp.label, 4);
                writeHexColon(strm, md, static_cast<int>(md_len));
                strm << "\n";
            }
        }
    }

    writeSubHeader(strm, "Extensions");

    {
        auto* skid = static_cast<ASN1_OCTET_STRING*>(
            X509_get_ext_d2i(const_cast<X509*>(cert), NID_subject_key_identifier, nullptr, nullptr));
        if (skid) {
            writeLabel(strm, "Subject Key Identifier", 4);
            writeHexColon(strm, skid->data, skid->length);
            strm << "\n";
            ASN1_OCTET_STRING_free(skid);
        }
    }

    {
        auto* akid = static_cast<AUTHORITY_KEYID*>(
            X509_get_ext_d2i(const_cast<X509*>(cert), NID_authority_key_identifier, nullptr, nullptr));
        if (akid) {
            if (akid->keyid) {
                writeLabel(strm, "Authority Key Identifier", 4);
                writeHexColon(strm, akid->keyid->data, akid->keyid->length);
                strm << "\n";
            }
            AUTHORITY_KEYID_free(akid);
        }
    }

    {
        const int ku_idx = X509_get_ext_by_NID(const_cast<X509*>(cert), NID_key_usage, -1);
        if (ku_idx >= 0) {
            X509_EXTENSION* ku_ext = X509_get_ext(const_cast<X509*>(cert), ku_idx);
            const bool critical = ku_ext && X509_EXTENSION_get_critical(ku_ext);
            const uint32_t ku = X509_get_key_usage(const_cast<X509*>(cert));
            static const std::pair<uint32_t, const char*> kBits[] = {
                {KU_DIGITAL_SIGNATURE,  "Digital Signature"},
                {KU_NON_REPUDIATION,    "Non-Repudiation"},
                {KU_KEY_ENCIPHERMENT,   "Key Encipherment"},
                {KU_DATA_ENCIPHERMENT,  "Data Encipherment"},
                {KU_KEY_AGREEMENT,      "Key Agreement"},
                {KU_KEY_CERT_SIGN,      "Certificate Sign"},
                {KU_CRL_SIGN,           "CRL Sign"},
                {KU_ENCIPHER_ONLY,      "Encipher Only"},
                {KU_DECIPHER_ONLY,      "Decipher Only"},
            };
            std::string usage;
            for (const auto& b : kBits) {
                if (ku & b.first) {
                    if (!usage.empty()) usage += ", ";
                    usage += b.second;
                }
            }
            std::string label = "Key Usage";
            if (critical) label += " [critical]";
            writeLabel(strm, label.c_str(), 4);
            strm << (usage.empty() ? "(none)" : usage) << "\n";
        }
    }

    {
        auto* eku = static_cast<EXTENDED_KEY_USAGE*>(
            X509_get_ext_d2i(const_cast<X509*>(cert), NID_ext_key_usage, nullptr, nullptr));
        if (eku) {
            const int eku_idx = X509_get_ext_by_NID(const_cast<X509*>(cert), NID_ext_key_usage, -1);
            const bool critical = (eku_idx >= 0) && X509_EXTENSION_get_critical(X509_get_ext(const_cast<X509*>(cert), eku_idx));
            std::string usages;
            for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
                if (!usages.empty()) usages += ", ";
                usages += oidLongName(sk_ASN1_OBJECT_value(eku, i));
            }
            std::string label = "Extended Key Usage";
            if (critical) label += " [critical]";
            writeLabel(strm, label.c_str(), 4);
            strm << (usages.empty() ? "(none)" : usages) << "\n";
            EXTENDED_KEY_USAGE_free(eku);
        }
    }

    {
        auto* bc = static_cast<BASIC_CONSTRAINTS*>(
            X509_get_ext_d2i(const_cast<X509*>(cert), NID_basic_constraints, nullptr, nullptr));
        if (bc) {
            const int bc_idx = X509_get_ext_by_NID(const_cast<X509*>(cert), NID_basic_constraints, -1);
            const bool critical = (bc_idx >= 0) && X509_EXTENSION_get_critical(X509_get_ext(const_cast<X509*>(cert), bc_idx));
            std::string label = "Basic Constraints";
            if (critical) label += " [critical]";
            writeLabel(strm, label.c_str(), 4);
            strm << "CA: " << (bc->ca ? "TRUE" : "FALSE");
            if (bc->ca && bc->pathlen) {
                strm << ", Path Length: " << ASN1_INTEGER_get(bc->pathlen);
            }
            strm << "\n";
            BASIC_CONSTRAINTS_free(bc);
        }
    }

    {
        auto* crldp = static_cast<CRL_DIST_POINTS*>(
            X509_get_ext_d2i(const_cast<X509*>(cert), NID_crl_distribution_points, nullptr, nullptr));
        if (crldp) {
            writeLabel(strm, "CRL Distribution Points", 4);
            strm << "\n";
            for (int i = 0; i < sk_DIST_POINT_num(crldp); ++i) {
                const DIST_POINT* dp = sk_DIST_POINT_value(crldp, i);
                if (dp->distpoint && dp->distpoint->type == 0) {
                    const GENERAL_NAMES* gns = dp->distpoint->name.fullname;
                    for (int j = 0; j < sk_GENERAL_NAME_num(gns); ++j) {
                        const GENERAL_NAME* gn = sk_GENERAL_NAME_value(gns, j);
                        if (gn->type == GEN_URI) {
                            const auto* uri = reinterpret_cast<const ASN1_IA5STRING*>(gn->d.uniformResourceIdentifier);
                            strm << std::string(kColonCol + 3, ' ')
                                 << std::string(reinterpret_cast<const char*>(uri->data), static_cast<size_t>(uri->length))
                                 << "\n";
                        }
                    }
                }
            }
            CRL_DIST_POINTS_free(crldp);
        }
    }

    {
        auto* aia = static_cast<AUTHORITY_INFO_ACCESS*>(
            X509_get_ext_d2i(const_cast<X509*>(cert), NID_info_access, nullptr, nullptr));
        if (aia) {
            writeLabel(strm, "Authority Information Access", 4);
            strm << "\n";
            for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); ++i) {
                const ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
                const std::string method = oidLongName(ad->method);
                if (ad->location->type == GEN_URI) {
                    const auto* uri = reinterpret_cast<const ASN1_IA5STRING*>(ad->location->d.uniformResourceIdentifier);
                    strm << std::string(kColonCol + 3, ' ') << method << " : "
                         << std::string(reinterpret_cast<const char*>(uri->data), static_cast<size_t>(uri->length))
                         << "\n";
                }
            }
            AUTHORITY_INFO_ACCESS_free(aia);
        }
    }

    {
        auto* policies = static_cast<CERTIFICATEPOLICIES*>(
            X509_get_ext_d2i(const_cast<X509*>(cert), NID_certificate_policies, nullptr, nullptr));
        if (policies) {
            writeLabel(strm, "Certificate Policies", 4);
            strm << "\n";
            for (int i = 0; i < sk_POLICYINFO_num(policies); ++i) {
                const POLICYINFO* pi = sk_POLICYINFO_value(policies, i);
                strm << std::string(kColonCol + 3, ' ') << oidLongName(pi->policyid) << "\n";
            }
            CERTIFICATEPOLICIES_free(policies);
        }
    }

    strm << "    Subject Alternative Names\n";
    writeSans(strm, cert);

    try {
        const std::string status_pv = certs::CmsStatusManager::getStatusPvFromCert(cert);
        if (!status_pv.empty()) { writeLabel(strm, "PVXS Status PV URI", 4); strm << status_pv << "\n"; }
    } catch (...) {}
    try {
        const std::string config_uri = certs::CmsStatusManager::getConfigPvFromCert(cert);
        if (!config_uri.empty()) { writeLabel(strm, "PVXS Config URI", 4); strm << config_uri << "\n"; }
    } catch (...) {}

    const int ext_count = X509_get_ext_count(cert);
    for (int i = 0; i < ext_count; ++i) {
        X509_EXTENSION* ext = X509_get_ext(const_cast<X509*>(cert), i);
        if (!ext) continue;
        const int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
        if (isHandledNid(nid)) continue;
        writeExtension(strm, ext);
    }

    return strm;
}

// ---------------------------------------------------------------------------
// ShowX509Chain::operator<<
// ---------------------------------------------------------------------------

std::ostream& operator<<(std::ostream& strm, const ShowX509Chain& show) {
    strm << ShowX509Verbose{show.cert};

    const int n = (show.chain && sk_X509_num(show.chain) > 0) ? sk_X509_num(show.chain) : 0;
    if (n == 0) {
        strm << "\nCertificate Chain: (none)\n";
        return strm;
    }

    for (int i = 0; i < n; ++i) {
        const X509* ca = sk_X509_value(show.chain, i);
        if (!ca) continue;

        // Extract CN for the section header
        const X509_NAME* subj = X509_get_subject_name(const_cast<X509*>(ca));
        const std::string cn = subj ? nameAttr(subj, NID_commonName) : "";

        strm << "\nCertificate Chain [" << (i + 1) << "]: " << (cn.empty() ? "(unknown)" : cn) << "\n";
        strm << "--------------------------------------------\n";
        strm << ShowX509Verbose{ca};
    }
    return strm;
}


}  // namespace ossl
}  // namespace pvxs
