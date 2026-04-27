/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CMS_PVACMS_H
#define PVXS_CMS_PVACMS_H

#include <memory>
#include <string>
#include <vector>

#include <pvxs/server.h>

namespace cms {
class ConfigCms;
}

namespace pvxs {
namespace cms {

class ServerHandle;

namespace detail {
struct PreparedCmsState;
ServerHandle prepareServerFromState(const ::cms::ConfigCms &config,
                                    PreparedCmsState &&state);
}

/** Programmatic PVACMS startup handle.
 *
 * Owns the prepared PVACMS server state, including the bound PVA server,
 * certificate database, loaded certificate authority material, registered PVs,
 * and cluster runtime state.
 *
 * @since UNRELEASED
 */
class ServerHandle
{
public:
    ServerHandle(ServerHandle&&) noexcept;
    ServerHandle& operator=(ServerHandle&&) noexcept;
    ~ServerHandle();

    ServerHandle(const ServerHandle&) = delete;
    ServerHandle& operator=(const ServerHandle&) = delete;

    /** Effective underlying PVA server configuration.
     *
     * Useful for inspecting resolved listener ports after prepareServer()
     * returns.
     *
     * @since UNRELEASED
     */
    const server::Server& pvaServer() const;

private:
    friend ServerHandle prepareServer(const ::cms::ConfigCms &config);
    friend void startCluster(ServerHandle& handle);
    friend void startCluster(ServerHandle& handle,
                             const std::vector<std::string>& peers);
    friend void stopServer(ServerHandle& handle);
    friend ServerHandle detail::prepareServerFromState(
        const ::cms::ConfigCms &config,
        detail::PreparedCmsState &&state);

    struct Pvt;
    std::unique_ptr<Pvt> pvt_;

    ServerHandle();
};

/** Prepare a PVACMS instance for later startup.
 *
 * Opens the certificate database, loads or creates the certificate authority
 * material, ensures the PVACMS server certificate exists, binds the PVA server,
 * and registers the production PV set.  The accept loop is not running when
 * this call returns.
 *
 * Access-security initialization is intentionally left to the caller; the
 * standalone pvacms binary performs that work in main() before calling here.
 *
 * @since UNRELEASED
 */
ServerHandle prepareServer(const ::cms::ConfigCms &config);

/** Start the cluster runtime using environment-provided peers.
 *
 * Reads `EPICS_PVACMS_CLUSTER_NAME_SERVERS` exactly as the standalone pvacms
 * binary does today, starts the prepared cluster runtime, then blocks in the
 * PVACMS run loop until shutdown.
 *
 * @since UNRELEASED
 */
void startCluster(ServerHandle& handle);

/** Start the cluster runtime using an explicit peer list.
 *
 * Uses @p peers to populate the cluster client's `nameServers` instead of
 * reading `EPICS_PVACMS_CLUSTER_NAME_SERVERS`, then blocks in the PVACMS run
 * loop until shutdown.
 *
 * @since UNRELEASED
 */
void startCluster(ServerHandle& handle,
                  const std::vector<std::string>& peers);

/** Stop the cluster runtime and prepared server.
 *
 * Safe to call more than once on the same handle.  After stopServer(), the
 * handle remains owned by the caller but is not restartable.
 *
 * @since UNRELEASED
 */
void stopServer(ServerHandle& handle);

} // namespace cms
} // namespace pvxs

#endif // PVXS_CMS_PVACMS_H
