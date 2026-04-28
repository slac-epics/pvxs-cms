/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CMS_CMS_H
#define PVXS_CMS_CMS_H

#include <memory>
#include <string>
#include <vector>

#include <pvxs/server.h>

namespace cms {

class ConfigCms;
class ServerHandle;

namespace server = pvxs::server;

namespace detail {
struct PreparedCmsState;
ServerHandle prepareServerFromState(const ConfigCms &config,
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

    /** Whether the PVACMS server's accept loop is running.
     *
     * True after `startCluster()` returns. False before that and after
     * `stopServer()`. Thread-safe.
     *
     * @since UNRELEASED
     */
    bool isStarted() const;

    /** Register a P12-borne Entity Certificate in the running PVACMS DB so its
     * `CERT:STATUS:<issuer>:<serial>` PV resolves with status VALID.
     *
     * Intended for in-process test harnesses that mint Entity Certs after
     * PVACMS startup (when `cfg.preload_cert_files` cannot be used).
     * Idempotent: re-registering an already-known cert is a no-op.
     * Thread-safe: serialised on the same lock production status updates use.
     *
     * @param p12_path Filesystem path to a PKCS#12 file containing the
     *                 Entity Certificate to register, plus its issuing chain.
     *
     * @since UNRELEASED
     */
    void registerCertFromP12(const std::string &p12_path);

private:
    friend ServerHandle prepareServer(const ConfigCms &config);
    friend void startCluster(ServerHandle& handle);
    friend void startCluster(ServerHandle& handle,
                             const std::vector<std::string>& peers);
    friend void stopServer(ServerHandle& handle);
    friend ServerHandle detail::prepareServerFromState(const ConfigCms &config, detail::PreparedCmsState &&state);

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
ServerHandle prepareServer(const ConfigCms &config);

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
void startCluster(ServerHandle& handle, const std::vector<std::string>& peers);

/** Stop the cluster runtime and prepared server.
 *
 * Safe to call more than once on the same handle.  After stopServer(), the
 * handle remains owned by the caller but is not restartable.
 *
 * @since UNRELEASED
 */
void stopServer(ServerHandle& handle);

} // namespace cms

#endif // PVXS_CMS_CMS_H
