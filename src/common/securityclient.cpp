/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <dbCommon.h>
#include <asLib.h>

#include <utilpvt.h>

#include "securityclient.h"

namespace pvxs {
namespace certs {

/**
 * eg.
 * "username"  implies "ca/" prefix
 * "krb/principle"
 * "role/groupname"
 *
 * @param clientCredentials The client credentials to be used for the credentials object
 */

AsCredentials::AsCredentials(const server::ClientCredentials& clientCredentials) {
    SockAddr addr(clientCredentials.peer);
    addr.setPort(0);
    host = std::string(SB()<<addr.map6to4());
    method = clientCredentials.method;
    authority = clientCredentials.authority;
    issuer_id = clientCredentials.issuer_id;
    serial = clientCredentials.serial;
    cred.emplace_back(clientCredentials.account);

    for (const auto& role: clientCredentials.roles()) {
        cred.emplace_back(SB() << "role/" << role);
    }
}

void SecurityClient::update(ASMEMBERPVT mem, int asl, AsCredentials& cred) {
    SecurityClient temp;
    temp.cli.resize(cred.cred.size(), nullptr);

    for (size_t i = 0, N = temp.cli.size(); i < N; i++) {
        /* asAddClientIdentity() fails secure to no-permission */
#ifndef EPICS_ASLIB_HAS_IDENTITY
        // Append "x509/" to any account that is isTLS
        std::string user = cred.cred[i];
        if (cred.method == "x509") {
            user = cred.method +  "/" + user;
        }

        /* asAddClient() fails secure to no-permission */
        (void)asAddClient(&temp.cli[i],
                mem, asl,
                user.c_str(),
                // TODO switch to vector of char to accommodate inplace modifications to string
                const_cast<char*>(cred.host.data()));
#else
        (void)asAddClientIdentity(&temp.cli[i], mem, asl, {
               .user = cred.cred[i].c_str(),
               .host = const_cast<char*>(cred.host.data()),
               .method = cred.method.c_str(),
               .authority = cred.authority.c_str(),
               .protocol = AS_PROTOCOL_TLS });
#endif
    }

    cli.swap(temp.cli);
}

void SecurityClient::update(dbChannel* ch, AsCredentials& cred) {
    update(dbChannelRecord(ch)->asp, dbChannelFldDes(ch)->as_level, cred);
}

SecurityClient::~SecurityClient() {
    for (auto asc: cli) {
        asRemoveClient(&asc);
    }
}

bool SecurityClient::canWrite() const {
    return std::any_of(cli.begin(), cli.end(), [](ASCLIENTPVT asc) {
        return asCheckPut(asc);
    });
}
} // certs
} // pvxs
