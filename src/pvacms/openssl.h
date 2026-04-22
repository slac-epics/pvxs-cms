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
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#else
#endif

#include <epicsMutex.h>

#include <openssl/ssl.h>

#include "ownedptr.h"

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;
typedef uint64_t serial_number_t;

namespace pvxs {

namespace client {
struct Config;
}
namespace ossl {
struct SSLError : std::runtime_error {
    explicit SSLError(const std::string& msg);
    virtual ~SSLError();
};
}
namespace server {
struct Config;
}
struct PeerCredentials;
}  // namespace pvxs

namespace cms {
namespace cert {
struct PVACertificateStatus;
struct CertificateStatus;
class CmsStatusManager;
struct CertData;
template <typename T>
struct cert_status_delete;

template <typename T>
using cert_status_ptr = pvxs::ossl_shared_ptr<T, cert_status_delete<T>>;
}  // namespace cert

namespace ssl {
constexpr uint16_t kForClient = 0x01;
constexpr uint16_t kForServer = 0x02;
constexpr uint16_t kForIntermediateCertAuth = 0x04;
constexpr uint16_t kForCMS = 0x08;
constexpr uint16_t kForCertAuth = 0x10;

constexpr uint16_t kForClientAndServer = kForClient | kForServer;
constexpr uint16_t kAnyServer = kForCMS | kForServer;

#define IS_USED_FOR_(USED, USAGE) (((USED) & (USAGE)) == USAGE)
#define IS_FOR_A_SERVER_(USED) (((USED) & (cms::ssl::kAnyServer)) != 0x00)

using SSLError = pvxs::ossl::SSLError;

struct ShowX509 {
    const X509* cert;
};

std::ostream& operator<<(std::ostream& strm, const ShowX509& cert);

/// Exhaustive single-certificate dump — every extractable X.509 field,
/// all extensions decoded, all SANs with type labels.
struct ShowX509Verbose {
    const X509* cert;
};

std::ostream& operator<<(std::ostream& strm, const ShowX509Verbose& cert);

/// Full chain dump — end-entity via ShowX509Verbose, then each CA cert in
/// cert_auth_chain (index 0 = nearest issuer, last = root) also via ShowX509Verbose.
struct ShowX509Chain {
    const X509*          cert;
    const STACK_OF(X509)* chain;
};

std::ostream& operator<<(std::ostream& strm, const ShowX509Chain& chain);


}  // namespace ssl
}  // namespace cms

#endif  // PVXS_OPENSSL_H
