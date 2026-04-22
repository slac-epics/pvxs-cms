/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_CONFIGCERTS_H_
#define PVXS_CONFIGCERTS_H_

#include <pvxs/server.h>

#include "serverev.h"

namespace cms {
namespace auth {
    namespace server = ::pvxs::server;
    using ::cms::detail::CustomServerCallback;
    using ::cms::detail::ServerEv;

class Config : public server::Config {
   public:
    Config& applyCertsEnv() {
        server::Config::applyEnv();
        return *this;
    }

    /**
     * @brief Create configuration from environment variables
     *
     * @return ConfigCerts
     */
    static Config fromEnv() {
        // Get default config
        auto config = Config{};
        config.applyEnv();
        config.disableStatusCheck();

        return config;
    }

    ServerEv build(const CustomServerCallback &cert_file_event_callback = {}) const;
};

}  // namespace auth
}  // namespace cms
#endif  // PVXS_CONFIGCERTS_H_
