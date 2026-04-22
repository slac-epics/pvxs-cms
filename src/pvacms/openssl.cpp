/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "openssl.h"

#include <fstream>
#include <stdexcept>

#include <epicsExit.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "certfilefactory.h"
#include "certstatus.h"
#include "certstatusmanager.h"
#include "evhelper.h"
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

}  // namespace ossl
}  // namespace pvxs
