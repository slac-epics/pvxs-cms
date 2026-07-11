/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CMS_ASAUTH_H
#define PVXS_CMS_ASAUTH_H

#include <cstddef>
#include <string>
#include <vector>

#include <asLib.h>

#include <pvxs/srvcommon.h>

#include "utilpvt.h"

namespace pvxs {
namespace certs {

/**
 * @brief Check whether a client is authorized to PUT against an access-security
 * member, using the client's certificate/credential identity.
 *
 * This performs the same access-security check the IOC layer does, but built
 * directly on the epics-base asLib primitives so PVACMS does not depend on the
 * IOC's internal credentials header.
 *
 * @param mem the access-security member to check against
 * @param asl the access-security level
 * @param cred the client credentials for the operation
 * @return true if the client is permitted to PUT
 */
inline bool clientCanPut(ASMEMBERPVT mem, int asl, const server::ClientCredentials &cred) {
    // Access security wants the peer host without the port.  cred.peer is a
    // numeric "address:port"; strip the trailing ":port" (the last colon, which
    // also leaves bracketed IPv6 literals like "[::1]" intact).
    std::string host = cred.peer;
    const auto colon = host.find_last_of(':');
    if (colon != std::string::npos) {
        host.resize(colon);
    }

    std::vector<std::string> accounts;
    accounts.push_back(cred.account);
    for (const auto &role : cred.roles()) {
        accounts.push_back(SB() << "role/" << role);
    }

    std::vector<ASCLIENTPVT> clients(accounts.size(), nullptr);
    for (std::size_t i = 0; i < accounts.size(); i++) {
        // asAddClientIdentity()/asAddClient() fail secure to no-permission
#ifndef EPICS_ASLIB_HAS_IDENTITY
        // Old access-security: no method/authority fields, so append "x509/" to
        // a TLS x509 account to distinguish it.
        std::string user = accounts[i];
        if (cred.method == "x509") {
            user = cred.method + "/" + user;
        }
        (void)asAddClient(&clients[i], mem, asl, user.c_str(), const_cast<char *>(host.data()));
#else
        (void)asAddClientIdentity(&clients[i], mem, asl,
                                  {.user = accounts[i].c_str(),
                                   .host = const_cast<char *>(host.data()),
                                   .method = cred.method.c_str(),
                                   .authority = cred.authority.c_str(),
                                   .protocol = cred.isTLS ? AS_PROTOCOL_TLS : AS_PROTOCOL_TCP});
#endif
    }

    bool can_put = false;
    for (const auto client : clients) {
        if (asCheckPut(client)) {
            can_put = true;
            break;
        }
    }

    for (auto client : clients) {
        asRemoveClient(&client);
    }

    return can_put;
}

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_CMS_ASAUTH_H
