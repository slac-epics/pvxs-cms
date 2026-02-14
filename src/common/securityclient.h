/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_SECURITYCLIENT_H
#define PVXS_SECURITYCLIENT_H

#include <vector>

#include <asLib.h>
#include <dbBase.h>
#include <dbChannel.h>
#include <dbNotify.h>

#include <pvxs/source.h>

namespace pvxs {
namespace certs {

/**
 * eg.
 * "username"  implies "ca/" prefix
 * "krb/principle"
 * "role/groupname"
 */
class AsCredentials {
	public:
		std::vector<std::string> cred;
		std::string method;
		std::string authority;
		std::string host;
		std::string issuer_id;
		std::string serial;
		explicit AsCredentials(const server::ClientCredentials& clientCredentials);
		AsCredentials(const AsCredentials&) = delete;
		AsCredentials(AsCredentials&&) = default;
};

class SecurityClient {
public:
	std::vector<ASCLIENTPVT> cli;
	~SecurityClient();
	void update(dbChannel* ch, AsCredentials& cred);
	void update(ASMEMBERPVT mem, int asl, AsCredentials& cred);
	bool canWrite() const;
};

} // certs
} // pvxs

#endif //PVXS_SECURITYCLIENT_H
