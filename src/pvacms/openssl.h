/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_OPENSSL_H
#define PVXS_OPENSSL_H

#include <list>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#else
#endif

#include <epicsMutex.h>

#include <openssl/ssl.h>

#include <pvxs/server.h>

#include "ownedptr.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;
typedef uint64_t serial_number_t;

namespace pvxs {

namespace client {
struct Config;
}
namespace server {
struct Config;
}
namespace certs {
struct PVACertificateStatus;
struct CertificateStatus;
class CertStatusManager;
struct CertData;
template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = ossl_shared_ptr<T, cert_status_delete<T>>;
}  // namespace certs

namespace ssl {
constexpr uint16_t kForClient = 0x01;
constexpr uint16_t kForServer = 0x02;
constexpr uint16_t kForIntermediateCertAuth = 0x04;
constexpr uint16_t kForCMS = 0x08;
constexpr uint16_t kForCertAuth = 0x10;

constexpr uint16_t kForClientAndServer = kForClient | kForServer;
constexpr uint16_t kAnyServer = kForCMS | kForServer;

#define IS_USED_FOR_(USED, USAGE) (((USED) & (USAGE)) == USAGE)
#define IS_FOR_A_SERVER_(USED) (((USED) & (pvxs::ssl::kAnyServer)) != 0x00)
}  // namespace ssl

struct PeerCredentials;
namespace ossl {

struct SSLError : std::runtime_error {
    explicit SSLError(const std::string& msg);
    virtual ~SSLError();
};

struct ShowX509 {
    const X509* cert;
};

std::ostream& operator<<(std::ostream& strm, const ShowX509& cert);


}  // namespace ossl
}  // namespace pvxs

#endif  // PVXS_OPENSSL_H
