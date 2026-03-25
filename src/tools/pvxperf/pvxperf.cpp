/**
 * pvxperf - GET-based performance benchmarking tool for CA, EPICS_PVA, PVXS_PVA, SPVA, and SPVA+CERTMON.
 *
 * Measures GET throughput (gets/second) across five protocol modes using
 * sequential and parallel GET operations with configurable array sizes.
 *
 * WARNING: Run on a network with no other active PVACMS to avoid interference
 * with benchmark results.
 *
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <epicsEvent.h>
#include <epicsThread.h>
#include <epicsTime.h>
#include <errlog.h>

#include <cadef.h>

#include <pv/pvAccess.h>
#include <pv/pvData.h>
#include <pv/createRequest.h>
#include <pv/clientFactory.h>
#include <pv/event.h>

#include <pvxs/client.h>
#include <pvxs/data.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>
#include <pvxs/util.h>

#include <CLI/CLI.hpp>

#ifndef PVXPERF_EPICS_HOST_ARCH
#define PVXPERF_EPICS_HOST_ARCH "linux-x86_64"
#endif


using namespace pvxs;

/** @brief Global flag set by SIGTERM/SIGINT handler to signal server mode shutdown. */
volatile sig_atomic_t g_server_stop = 0;

/**
 * @brief POSIX signal handler that sets the global server stop flag.
 * @note Must have external linkage for use with signal(2). Writes volatile g_server_stop.
 */
extern "C" void serverSignalHandler(int) {
    g_server_stop = 1;
}

namespace {

DEFINE_LOGGER(perflog, "pvxs.perf");

/**
 * @brief Fixed ports for the PVACMS child process launched by --setup-cms.
 *
 * These are deliberately non-default (not 5075/5076) to avoid collisions with
 * any production PVACMS or other PVA servers on the same machine.  The benchmark
 * server's inner cert-status client must search on this UDP port to discover
 * PVACMS for certificate status monitoring in SPVA_CERTMON mode.
 */
constexpr uint16_t kPvacmsUdpPort = 15076u;
constexpr uint16_t kPvacmsTcpPort = 15075u;
constexpr uint16_t kPvacmsTlsPort = 15076u;

/**
 * @brief Create a server config on loopback with ephemeral ports.
 *
 * Like Config::isolated() but does NOT disable status checking or stapling,
 * so SPVA_CERTMON can still reach PVACMS for certificate status monitoring.
 *
 * @param pvacms_udp_port  If non-zero, add 127.0.0.1:<port> to the beacon
 *                         destinations so that the server's inner cert-status
 *                         client can discover PVACMS via UDP search.
 */
server::Config loopbackServerConfig(const uint16_t pvacms_udp_port = 0u) {
    server::Config ret;
    ret.udp_port = 0u;
    ret.tcp_port = 0u;
    ret.auto_beacon = false;
    ret.interfaces.emplace_back("127.0.0.1");
    ret.beaconDestinations.emplace_back("127.0.0.1");
    if (pvacms_udp_port) {
        ret.beaconDestinations.emplace_back("127.0.0.1:" + std::to_string(pvacms_udp_port));
    }
    return ret;
}

/**
 * @brief Build the benchmark NTScalar type with custom fields for server timestamping.
 *
 * Extends NTScalar{Float64A} with:
 * - benchCounter (UInt64): monotonically incrementing counter per GET
 * - benchTimestampNs (Int64): steady_clock nanoseconds at the moment the server handles GET
 *
 * @param array_size  Number of doubles in the value array.
 * @return A Value instance of the benchmark type with the value array pre-filled.
 */
Value buildBenchType(const uint32_t array_size) {
    auto def = nt::NTScalar{TypeCode::Float64A}.build();
    def += {
        Member(TypeCode::UInt64, "benchCounter"),
        Member(TypeCode::Int64, "benchTimestampNs"),
    };
    auto val = def.create();
    shared_array<double> arr(array_size, 1.0);
    val["value"] = arr.freeze().castTo<const void>();
    return val;
}

/**
 * @brief Custom PVA Source that stamps each GET response with a steady_clock timestamp
 *        and incrementing counter.
 *
 * Unlike SharedPV::buildReadonly() which clones a cached value, this Source creates
 * a fresh response for every GET with the current timestamp. This allows the client
 * to measure the true propagation latency: recv_time - embedded_timestamp.
 */
class BenchmarkSource final : public server::Source {
public:
    /**
     * @brief Construct a BenchmarkSource for a given PV name and array size.
     * @param pvname      PV name to serve (e.g. "PVXPERF:BENCH").
     * @param array_size  Number of doubles in the response array.
     */
    BenchmarkSource(std::string  pvname, const uint32_t array_size)
        : pvname_(std::move(pvname))
        , prototype_(buildBenchType(array_size))
        , counter_(0)
    {}

    void onSearch(Search& op) override {
        for (auto& name : op) {
            if (name.name() == pvname_)
                name.claim();
        }
    }

    void onCreate(std::unique_ptr<server::ChannelControl>&& chan) override {
        if (chan->name() != pvname_)
            return;

        auto self = this;
        chan->onOp([self](std::unique_ptr<server::ConnectOp>&& op) {
            op->onGet([self](std::unique_ptr<server::ExecOp>&& eop) {
                auto response = self->prototype_.cloneEmpty();
                response["value"] = self->prototype_["value"];
                response["benchCounter"] = self->counter_.fetch_add(1, std::memory_order_relaxed);
                response["benchTimestampNs"] = static_cast<int64_t>(
                    std::chrono::steady_clock::now().time_since_epoch().count());
                eop->reply(response);
            });
            op->connect(self->prototype_);
        });
    }

    List onList() override {
        auto names = std::make_shared<std::set<std::string>>();
        names->insert(pvname_);
        return {names, false};
    }

private:
    const std::string pvname_;
    const Value prototype_;
    std::atomic<uint64_t> counter_;
};

/** @brief Protocol modes supported by pvxperf benchmarks. */
enum class ProtocolMode { CA, EPICS_PVA, PVXS_PVA, SPVA, SPVA_CERTMON };

/**
 * @brief Convert a ProtocolMode value to its canonical string name.
 * @param m  Protocol mode to convert.
 * @return   Null-terminated string: "CA", "EPICS_PVA", "PVXS_PVA", "SPVA", "SPVA_CERTMON", or "UNKNOWN".
 */
const char* protocolModeStr(const ProtocolMode m) {
    switch (m) {
    case ProtocolMode::CA:             return "CA";
    case ProtocolMode::EPICS_PVA:      return "EPICS_PVA";
    case ProtocolMode::PVXS_PVA:       return "PVXS_PVA";
    case ProtocolMode::SPVA:           return "SPVA";
    case ProtocolMode::SPVA_CERTMON:   return "SPVA_CERTMON";
    }
    return "UNKNOWN";
}

/**
 * @brief Parse a case-insensitive protocol mode name into a ProtocolMode value.
 * @param s  Mode name string (e.g. "ca", "PVA", "spva_certmon").
 * @return   Corresponding ProtocolMode enum value.
 * @throws std::runtime_error if @p s does not match any known mode.
 */
ProtocolMode parseProtocolMode(const std::string& s) {
    if (s == "ca" || s == "CA")                               return ProtocolMode::CA;
    if (s == "epics_pva" || s == "EPICS_PVA")                 return ProtocolMode::EPICS_PVA;
    if (s == "pvxs_pva" || s == "PVXS_PVA")                   return ProtocolMode::PVXS_PVA;
    if (s == "spva" || s == "SPVA")                           return ProtocolMode::SPVA;
    if (s == "spva_certmon" || s == "SPVA_CERTMON")           return ProtocolMode::SPVA_CERTMON;
    throw std::runtime_error(std::string("Unknown protocol mode: ") + s);
}

/**
 * @brief Parse a comma-separated list of protocol mode names.
 * @param csv  Comma-separated mode names (e.g. "pva,spva,spva_certmon").
 * @return     Vector of parsed ProtocolMode values in the order supplied.
 */
std::vector<ProtocolMode> parseModes(const std::string& csv) {
    std::vector<ProtocolMode> modes;
    std::istringstream ss(csv);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (!token.empty())
            modes.push_back(parseProtocolMode(token));
    }
    return modes;
}

/**
 * @brief Parse a comma-separated list of array sizes (number of doubles).
 * @param csv  Comma-separated counts (e.g. "1,10,100,1000").
 * @return     Vector of array sizes.
 */
std::vector<size_t> parseSizes(const std::string& csv) {
    std::vector<size_t> sizes;
    std::istringstream ss(csv);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (!token.empty())
            sizes.push_back(std::stoul(token));
    }
    return sizes;
}

/**
 * @brief Parse a comma-separated list of parallelism values.
 * @param csv  Comma-separated count values (e.g. "1,10,100,1000").
 * @return     Vector of parallelism counts.
 */
std::vector<uint32_t> parseParallelism(const std::string& csv) {
    std::vector<uint32_t> counts;
    std::istringstream ss(csv);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (!token.empty())
            counts.push_back(static_cast<uint32_t>(std::stoul(token)));
    }
    return counts;
}

/** @brief Compute median of a vector (sorts in place). */
double computeMedian(std::vector<double>& v) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    if (n % 2 == 0)
        return (v[n/2 - 1] + v[n/2]) / 2.0;
    return v[n/2];
}

/** @brief Compute percentile (0-100) of a vector (sorts in place). */
double computePercentile(std::vector<double>& v, double pct) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double rank = (pct / 100.0) * static_cast<double>(v.size() - 1);
    const auto lo = static_cast<size_t>(rank);
    const size_t hi = std::min(lo + 1, v.size() - 1);
    const double frac = rank - static_cast<double>(lo);
    return v[lo] + frac * (v[hi] - v[lo]);
}

/** @brief Compute coefficient of variation (stddev/mean * 100). Returns 0 if fewer than 2 values. */
double computeCV(const std::vector<double>& v) {
    if (v.size() < 2) return 0.0;
    const double sum = std::accumulate(v.begin(), v.end(), 0.0);
    const double mean = sum / static_cast<double>(v.size());
    if (mean == 0.0) return 0.0;
    double sq_sum = 0.0;
    for (const auto x : v) {
        const double diff = x - mean;
        sq_sum += diff * diff;
    }
    const double stddev = std::sqrt(sq_sum / static_cast<double>(v.size() - 1));
    return (stddev / mean) * 100.0;
}

/** @brief Holds the outcome of a single GET benchmark run. */
struct GetResult {
    std::string protocol;
    uint32_t array_size{0};
    uint32_t parallelism{0};
    uint32_t num_samples{0};
    double median_get_us{0.0};
    double mean_get_us{0.0};
    double p25_get_us{0.0};
    double p75_get_us{0.0};
    double p99_get_us{0.0};
    double min_get_us{0.0};
    double max_get_us{0.0};
    double cv_pct{0.0};
    double gets_per_sec{0.0};
    // Raw per-sample latencies (µs per GET) for CSV iteration output
    std::vector<double> raw_get_times;
};

/**
 * @brief RAII manager for a pvacms child process launched during SPVA_CERTMON benchmarks.
 */
class PvacmsProcess {
public:
    PvacmsProcess() = default;
    ~PvacmsProcess() { stop(); }

    PvacmsProcess(const PvacmsProcess&) = delete;
    PvacmsProcess& operator=(const PvacmsProcess&) = delete;

    /**
     * @brief Fork and exec pvacms with all state isolated to the given temporary directory.
     * @param tmp_dir      Temporary directory that will hold all PVACMS state files.
     * @param override_db  The override path for the SQLite database (empty = use tmp_dir default).
     * @param override_kc  The override path for the PVACMS server keychain (empty = use tmp_dir default).
     * @param override_acf The override path for the ACF file (empty = use tmp_dir default).
     * @throws std::runtime_error if fork() fails.
     */
    void start(const std::string& tmp_dir,
               const std::string& override_db = {},
               const std::string& override_kc = {},
               const std::string& override_acf = {}) {
        const std::string cert_auth = tmp_dir + "/cert_auth.p12";
        const std::string certs_db  = override_db.empty()  ? (tmp_dir + "/certs.db")   : override_db;
        const std::string pvacms_kc = override_kc.empty()   ? (tmp_dir + "/pvacms.p12") : override_kc;
        const std::string acf_file  = override_acf.empty()  ? (tmp_dir + "/pvacms.acf") : override_acf;
        const std::string admin_kc  = tmp_dir + "/admin.p12";

        pid_ = fork();
        if (pid_ < 0) {
            throw std::runtime_error("fork() failed for pvacms");
        }
        if (pid_ == 0) {
            setenv("EPICS_PVAS_INTF_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);
            setenv("EPICS_PVAS_AUTO_BEACON_ADDR_LIST", "NO", 1);
            setenv("EPICS_PVAS_BROADCAST_PORT",
                   std::to_string(kPvacmsUdpPort).c_str(), 1);
            setenv("EPICS_PVAS_SERVER_PORT",
                   std::to_string(kPvacmsTcpPort).c_str(), 1);
            setenv("EPICS_PVAS_TLS_PORT",
                   std::to_string(kPvacmsTlsPort).c_str(), 1);

            execlp("pvacms", "pvacms",
                   "--certs-dont-require-approval",
                   "-c", cert_auth.c_str(),
                   "-d", certs_db.c_str(),
                   "-p", pvacms_kc.c_str(),
                   "--acf", acf_file.c_str(),
                   "-a", admin_kc.c_str(),
                   nullptr);
            _exit(127);
        }
        log_info_printf(perflog, "Launched pvacms as PID %d\n", pid_);
    }

    /**
     * @brief Send SIGTERM to the pvacms child process and wait for it to exit.
     */
    void stop() {
        if (pid_ > 0) {
            log_info_printf(perflog, "Stopping pvacms PID %d\n", pid_);
            kill(pid_, SIGTERM);
            int status = 0;
            waitpid(pid_, &status, 0);
            pid_ = -1;
        }
    }

    /**
     * @brief Check whether the pvacms child process is currently running.
     * @return true if the process has been started and not yet stopped.
     */
    bool is_running() const { return pid_ > 0; }

private:
    pid_t pid_{-1};
};

/**
 * @brief Poll for PVACMS readiness by probing the CERT:ROOT PV over plain PVA.
 * @param timeout_sec   Maximum seconds to wait before returning false.
 * @param cms_udp_port  PVACMS UDP port for --setup-cms (e.g., 15076); 0 means external PVACMS
 *                      reachable via standard EPICS_PVA_* environment variables.
 * @return true if PVACMS responded successfully within the timeout; false otherwise.
 */
bool waitForPvacms(const double timeout_sec = 30.0,
                   const uint16_t cms_udp_port = 0u) {
    log_info_printf(perflog, "Waiting for PVACMS readiness (timeout %.0fs)...\n", timeout_sec);

    auto conf = client::Config::fromEnv();
    conf.tls_disabled = true;
    if (cms_udp_port != 0u) {
        conf.udp_port = cms_udp_port;
        conf.addressList.clear();
        conf.addressList.emplace_back("127.0.0.1");
        conf.autoAddrList = false;
    }
    auto ctxt = conf.build();

    const auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(static_cast<int>(timeout_sec * 1000));

    while (std::chrono::steady_clock::now() < deadline) {
        try {
            const auto result = ctxt.get("CERT:ROOT").exec()->wait(3.0);
            if (result) {
                log_info_printf(perflog, "%s\n", "PVACMS is ready");
                return true;
            }
        } catch (std::exception& e) {
            log_debug_printf(perflog, "PVACMS probe: %s\n", e.what());
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    log_warn_printf(perflog, "%s\n", "PVACMS readiness probe timed out");
    return false;
}

/**
 * @brief Fork and exec authnstd to provision a TLS keychain from PVACMS.
 * @param name          Common name for the certificate (e.g. "pvxperf-server").
 * @param usage         Certificate usage role: "server" or "client".
 * @param keychain_path Destination path for the provisioned .p12 keychain file.
 * @return true if authnstd exited with status 0; false on fork failure or non-zero exit.
 */
bool runAuthnstd(const std::string& name, const std::string& usage,
                  const std::string& keychain_path) {
    const pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        if (usage == "server") {
            setenv("EPICS_PVAS_TLS_KEYCHAIN", keychain_path.c_str(), 1);
        } else {
            setenv("EPICS_PVA_TLS_KEYCHAIN", keychain_path.c_str(), 1);
        }
        setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
        setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);
        setenv("EPICS_PVA_BROADCAST_PORT",
               std::to_string(kPvacmsUdpPort).c_str(), 1);

        execlp("authnstd", "authnstd",
               "-n", name.c_str(),
               "-u", usage.c_str(),
               nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/**
 * @brief Create a unique temporary directory for PVACMS state isolation.
 * @return Absolute path to the newly created directory (e.g. /tmp/pvxperf-cms-XXXXXX).
 * @throws std::runtime_error if mkdtemp() fails.
 */
std::string createTempDir() {
    char tmpl[] = "/tmp/pvxperf-cms-XXXXXX";
    const char* dir = mkdtemp(tmpl);
    if (!dir)
        throw std::runtime_error("mkdtemp() failed");
    return {dir};
}

/**
 * @brief Recursively remove a temporary directory created by createTempDir().
 * @param dir  Path to the directory to remove; no-op if empty or "/".
 */
void removeTempDir(const std::string& dir) {
    if (dir.empty() || dir == "/")
        return;
    const std::string cmd = "rm -rf " + dir;
    if (system(cmd.c_str()) != 0) {
        log_warn_printf(perflog, "Failed to remove temp dir: %s\n", dir.c_str());
    }
}

/**
 * @brief Manages a softIoc child process for CA benchmarks.
 *
 * Runs the IOC as a separate process, so CA client access goes through real TCP
 * loopback (not the in-process direct-memory shortcut via dbChannelIO).
 */
enum class IocType { CA_ONLY, EPICS_PVA, PVXS };

class CaIocProcess {
public:
    CaIocProcess() = default;
    ~CaIocProcess() { stop(); }

    CaIocProcess(const CaIocProcess&) = delete;
    CaIocProcess& operator=(const CaIocProcess&) = delete;

    bool start(const size_t max_array_size, const IocType ioc_type,
               const std::string& server_keychain = {},
               const std::string& pvname = "PVXPERF:CA:BENCH") {
        const size_t nelm = std::max(max_array_size, static_cast<size_t>(1));
        pvname_ = pvname;

        tmp_db_path_ = (ioc_type == IocType::PVXS)
            ? "/tmp/pvxperf_pvxs_bench.db" : "/tmp/pvxperf_bench.db";
        {
            std::ofstream ofs(tmp_db_path_);
            ofs << "record(waveform, \"" << pvname << "\") {\n"
                << "  field(FTVL, \"DOUBLE\")\n"
                << "  field(NELM, \"" << nelm << "\")\n"
                << "}\n";
        }

        int pipefd[2];
        if (pipe(pipefd) != 0) {
            log_warn_printf(perflog, "%s\n", "IOC: pipe() failed");
            return false;
        }
        stdin_write_fd_ = pipefd[1];

        pid_ = fork();
        if (pid_ < 0) {
            log_warn_printf(perflog, "%s\n", "IOC: fork() failed");
            close(pipefd[0]);
            close(pipefd[1]);
            stdin_write_fd_ = -1;
            return false;
        }
        if (pid_ == 0) {
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);

            setenv("EPICS_CAS_INTF_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_CAS_AUTO_BEACON_ADDR_LIST", "NO", 1);
            setenv("EPICS_CAS_BEACON_ADDR_LIST", "127.0.0.1", 1);

            if (ioc_type == IocType::PVXS) {
                setenv("EPICS_PVAS_INTF_ADDR_LIST", "127.0.0.1", 1);
                setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
                setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);
                setenv("EPICS_PVAS_AUTO_BEACON_ADDR_LIST", "NO", 1);
                setenv("EPICS_PVAS_BEACON_ADDR_LIST", "127.0.0.1", 1);
                if (!server_keychain.empty())
                    setenv("PVXS_TLS_KEYCHAIN", server_keychain.c_str(), 1);
                const std::string bin = std::string(PVXPERF_PVXS) +
                    "/bin/" + PVXPERF_EPICS_HOST_ARCH + "/softIocPVX";
                execl(bin.c_str(), "softIocPVX", "-d", tmp_db_path_.c_str(), nullptr);
            } else if (ioc_type == IocType::EPICS_PVA) {
                setenv("EPICS_PVAS_INTF_ADDR_LIST", "127.0.0.1", 1);
                setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
                setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);
                const std::string bin = std::string(PVXPERF_EPICS_BASE) +
                    "/bin/" + PVXPERF_EPICS_HOST_ARCH + "/softIocPVA";
                execl(bin.c_str(), "softIocPVA", "-d", tmp_db_path_.c_str(), nullptr);
            } else {
                const std::string bin = std::string(PVXPERF_EPICS_BASE) +
                    "/bin/" + PVXPERF_EPICS_HOST_ARCH + "/softIoc";
                execl(bin.c_str(), "softIoc", "-d", tmp_db_path_.c_str(), nullptr);
            }
            _exit(127);
        }
        close(pipefd[0]);

        const char* ioc_name = (ioc_type == IocType::PVXS) ? "softIocPVX" :
                               (ioc_type == IocType::EPICS_PVA) ? "softIocPVA" : "softIoc";
        log_info_printf(perflog, "Launched %s as PID %d\n", ioc_name, pid_);

        std::this_thread::sleep_for(std::chrono::seconds(3));

        int wstatus = 0;
        const pid_t result = waitpid(pid_, &wstatus, WNOHANG);
        if (result != 0) {
            log_warn_printf(perflog, "CA: softIoc exited prematurely (status=%d)\n", wstatus);
            pid_ = -1;
            return false;
        }

        log_info_printf(perflog, "%s\n", "CA softIoc is ready");

        if (!seedWaveform(nelm)) {
            log_warn_printf(perflog, "%s\n", "IOC: failed to seed waveform via ca_array_put");
            stop();
            return false;
        }

        return true;
    }

    void stop() {
        if (stdin_write_fd_ >= 0) {
            close(stdin_write_fd_);
            stdin_write_fd_ = -1;
        }
        if (pid_ > 0) {
            log_info_printf(perflog, "Stopping softIoc PID %d\n", pid_);
            kill(pid_, SIGTERM);
            int status = 0;
            waitpid(pid_, &status, 0);
            pid_ = -1;
        }
        if (!tmp_db_path_.empty()) {
            unlink(tmp_db_path_.c_str());
            tmp_db_path_.clear();
        }
    }

    bool is_running() const { return pid_ > 0; }

private:
    bool seedWaveform(const size_t nelm) const {
        const int st = ca_context_create(ca_enable_preemptive_callback);
        if (st != ECA_NORMAL) {
            log_warn_printf(perflog, "IOC seed: ca_context_create failed (%d)\n", st);
            return false;
        }

        chid ch = nullptr;
        if (ca_create_channel(pvname_.c_str(), nullptr, nullptr, 0, &ch) != ECA_NORMAL ||
            ca_pend_io(5.0) != ECA_NORMAL || !ch) {
            log_warn_printf(perflog, "%s\n", "IOC seed: channel connect failed");
            ca_context_destroy();
            return false;
        }

        std::vector<double> data(nelm, 1.0);
        if (ca_array_put(DBR_DOUBLE, nelm, ch, data.data()) != ECA_NORMAL ||
            ca_pend_io(5.0) != ECA_NORMAL) {
            log_warn_printf(perflog, "%s\n", "IOC seed: ca_array_put failed");
            ca_clear_channel(ch);
            ca_context_destroy();
            return false;
        }

        ca_clear_channel(ch);
        ca_context_destroy();
        log_info_printf(perflog, "Seeded PVXPERF:CA:BENCH with %zu doubles\n", nelm);
        return true;
    }

    pid_t pid_{-1};
    int stdin_write_fd_{-1};
    std::string tmp_db_path_;
    std::string pvname_;
};

GetResult computeGetStats(std::vector<double>& get_times,
                          const std::string& protocol,
                          const uint32_t array_size,
                          const uint32_t parallelism) {
    GetResult r;
    r.protocol = protocol;
    r.array_size = array_size;
    r.parallelism = parallelism;
    r.num_samples = static_cast<uint32_t>(get_times.size());

    if (get_times.empty())
        return r;

    r.median_get_us = computeMedian(get_times);
    r.p25_get_us = computePercentile(get_times, 25.0);
    r.p75_get_us = computePercentile(get_times, 75.0);
    r.p99_get_us = computePercentile(get_times, 99.0);
    r.cv_pct = computeCV(get_times);

    const double sum = std::accumulate(get_times.begin(), get_times.end(), 0.0);
    r.mean_get_us = sum / static_cast<double>(get_times.size());
    r.min_get_us = *std::min_element(get_times.begin(), get_times.end());
    r.max_get_us = *std::max_element(get_times.begin(), get_times.end());

    if (r.median_get_us > 0.0) {
        r.gets_per_sec = 1000000.0 / r.median_get_us;
    }

    r.raw_get_times = get_times;

    return r;
}

GetResult runPvaGetBenchmarkWithContext(
    client::Context& ctxt,
    const std::string& label,
    const std::string& pvname,
    const uint32_t array_size,
    const uint32_t parallelism,
    const uint32_t num_samples,
    const uint32_t warmup)
{
    std::vector<double> get_times;
    get_times.reserve(num_samples);

    // reExecGet(): INIT once per Operation, then single-round-trip EXEC per call
    // (vs get().exec() which does INIT+EXEC = 2 round-trips every time)

    if (parallelism <= 1) {
        epicsEvent initDone;
        auto op = ctxt.get(pvname)
                      .autoExec(false)
                      .onInit([&initDone](const Value&) {
                          initDone.signal();
                      })
                      .result([&initDone](client::Result&& result) {
                          try { result(); } catch (...) {}
                          initDone.signal();
                      })
                      .exec();

        if (!initDone.wait(10.0))
            throw std::runtime_error("pvxs GET INIT timeout for " + pvname);

        for (uint32_t w = 0; w < warmup; w++) {
            epicsEvent done;
            op->reExecGet([&done](client::Result&& result) {
                result();
                done.signal();
            });
            if (!done.wait(5.0))
                throw std::runtime_error("pvxs GET warmup timeout");
        }
        {
            epicsEvent done;
            Value val;
            op->reExecGet([&val, &done](client::Result&& r) {
                val = r();
                done.signal();
            });
            if (done.wait(5.0) && val) {
                const auto arr = val["value"].as<shared_array<const double>>();
                if (!arr.empty() && arr[arr.size() - 1] != 1.0)
                    log_warn_printf(perflog, "%s smoke test failed: last element = %f\n",
                                    label.c_str(), arr[arr.size() - 1]);
            }
        }

        for (uint32_t s = 0; s < num_samples; s++) {
            epicsEvent done;
            const auto start = std::chrono::steady_clock::now();
            op->reExecGet([&done](client::Result&& result) {
                result();
                done.signal();
            });
            if (!done.wait(5.0))
                throw std::runtime_error("pvxs GET sample timeout");
            const auto end = std::chrono::steady_clock::now();
            get_times.push_back(
                std::chrono::duration<double, std::micro>(end - start).count());
        }

    } else {
        std::vector<std::shared_ptr<client::Operation>> ops(parallelism);
        std::atomic<uint32_t> initCount{0};
        epicsEvent initDone;

        for (uint32_t i = 0; i < parallelism; i++) {
            ops[i] = ctxt.get(pvname)
                         .autoExec(false)
                         .onInit([&initCount, &initDone, parallelism](const Value&) {
                             if (initCount.fetch_add(1, std::memory_order_acq_rel) + 1 >= parallelism)
                                 initDone.signal();
                         })
                         .result([&initCount, &initDone, parallelism](client::Result&& result) {
                             try { result(); } catch (...) {}
                             if (initCount.fetch_add(1, std::memory_order_acq_rel) + 1 >= parallelism)
                                 initDone.signal();
                         })
                         .exec();
        }

        if (!initDone.wait(30.0))
            throw std::runtime_error("pvxs parallel GET INIT timeout");

        std::atomic<uint32_t> batchDone{0};
        epicsEvent batchEvent;

        const uint32_t warmup_batches = std::max(warmup / parallelism, static_cast<uint32_t>(5));
        for (uint32_t w = 0; w < warmup_batches; w++) {
            batchDone.store(0, std::memory_order_release);
            for (uint32_t i = 0; i < parallelism; i++) {
                ops[i]->reExecGet([&batchDone, &batchEvent, parallelism](client::Result&& result) {
                    result();
                    if (batchDone.fetch_add(1, std::memory_order_acq_rel) + 1 >= parallelism)
                        batchEvent.signal();
                });
            }
            batchEvent.wait(5.0);
        }
        {
            epicsEvent done;
            Value val;
            ops[0]->reExecGet([&val, &done](client::Result&& r) {
                val = r();
                done.signal();
            });
            if (done.wait(5.0) && val) {
                auto arr = val["value"].as<shared_array<const double>>();
                if (!arr.empty() && arr[arr.size() - 1] != 1.0)
                    log_warn_printf(perflog, "%s smoke test failed: last element = %f\n", label.c_str(), arr[arr.size() - 1]);
            }
        }

        for (uint32_t s = 0; s < num_samples; s++) {
            batchDone.store(0, std::memory_order_release);

            const auto batch_start = std::chrono::steady_clock::now();

            for (uint32_t i = 0; i < parallelism; i++) {
                ops[i]->reExecGet([&batchDone, &batchEvent, parallelism](client::Result&& result) {
                    result();
                    if (batchDone.fetch_add(1, std::memory_order_acq_rel) + 1 >= parallelism)
                        batchEvent.signal();
                });
            }
            batchEvent.wait(5.0);

            const auto batch_end = std::chrono::steady_clock::now();
            const double batch_us = std::chrono::duration<double, std::micro>(
                batch_end - batch_start).count();
            get_times.push_back(batch_us / parallelism);
        }
    }

    return computeGetStats(get_times, label, array_size, parallelism);
}

GetResult runCaGetBenchmark(
    const uint32_t array_size,
    const uint32_t parallelism,
    const uint32_t num_samples = 1000,
    const uint32_t warmup = 100)
{
    GetResult empty_result;
    empty_result.protocol = "CA";
    empty_result.array_size = array_size;
    empty_result.parallelism = parallelism;

    if (parallelism <= 1) {
        const int st = ca_context_create(ca_enable_preemptive_callback);
        if (st != ECA_NORMAL) return empty_result;

        chid ch = nullptr;
        if (ca_create_channel("PVXPERF:CA:BENCH", nullptr, nullptr, 0, &ch) != ECA_NORMAL ||
            ca_pend_io(5.0) != ECA_NORMAL || !ch) {
            ca_context_destroy();
            return empty_result;
        }

        std::vector<double> buffer(array_size);
        for (uint32_t w = 0; w < warmup; w++) {
            ca_array_get(DBR_DOUBLE, array_size, ch, buffer.data());
            ca_pend_io(5.0);
        }
        if (array_size > 0 && buffer[array_size - 1] != 1.0)
            log_warn_printf(perflog, "CA smoke test failed: last element = %f\n", buffer[array_size - 1]);

        std::vector<double> get_times;
        get_times.reserve(num_samples);
        for (uint32_t s = 0; s < num_samples; s++) {
            const auto start = std::chrono::steady_clock::now();
            ca_array_get(DBR_DOUBLE, array_size, ch, buffer.data());
            ca_pend_io(5.0);
            const auto end = std::chrono::steady_clock::now();
            get_times.push_back(
                std::chrono::duration<double, std::micro>(end - start).count());
        }

        ca_clear_channel(ch);
        ca_context_destroy();
        return computeGetStats(get_times, "CA", array_size, parallelism);
    }

    // Single context, N channels, N concurrent ca_array_get_callback - mirrors
    // PVA's single-connection multiplexed async GET pattern.
    const int st = ca_context_create(ca_enable_preemptive_callback);
    if (st != ECA_NORMAL) return empty_result;

    std::vector<chid> channels(parallelism, nullptr);
    for (uint32_t i = 0; i < parallelism; i++) {
        if (ca_create_channel("PVXPERF:CA:BENCH", nullptr, nullptr, 0, &channels[i]) != ECA_NORMAL) {
            ca_context_destroy();
            return empty_result;
        }
    }
    if (ca_pend_io(10.0) != ECA_NORMAL) {
        ca_context_destroy();
        return empty_result;
    }

    struct CbState {
        std::chrono::steady_clock::time_point recv_time;
        std::atomic<bool> done{false};
    };
    std::vector<CbState> cb_states(parallelism);

    auto get_callback = [](struct event_handler_args args) {
        auto* state = static_cast<CbState*>(args.usr);
        state->recv_time = std::chrono::steady_clock::now();
        state->done.store(true, std::memory_order_release);
    };

    for (uint32_t w = 0; w < warmup; w++) {
        for (uint32_t i = 0; i < parallelism; i++) {
            cb_states[i].done.store(false, std::memory_order_relaxed);
            ca_array_get_callback(DBR_DOUBLE, array_size, channels[i],
                                  get_callback, &cb_states[i]);
        }
        ca_flush_io();
        bool warmup_done = false;
        while (!warmup_done) {
            ca_pend_event(0.001);
            warmup_done = true;
            for (uint32_t i = 0; i < parallelism; i++) {
                if (!cb_states[i].done.load(std::memory_order_acquire)) {
                    warmup_done = false;
                    break;
                }
            }
        }
    }
    {
        std::vector<double> check(array_size);
        ca_array_get(DBR_DOUBLE, array_size, channels[0], check.data());
        ca_pend_io(5.0);
        if (array_size > 0 && check[array_size - 1] != 1.0)
            log_warn_printf(perflog, "CA smoke test failed: last element = %f\n", check[array_size - 1]);
    }

    std::vector<double> get_times;
    get_times.reserve(num_samples);

    for (uint32_t s = 0; s < num_samples; s++) {
        for (uint32_t i = 0; i < parallelism; i++) {
            cb_states[i].done.store(false, std::memory_order_release);
        }

        const auto batch_send = std::chrono::steady_clock::now();

        for (uint32_t i = 0; i < parallelism; i++) {
            ca_array_get_callback(DBR_DOUBLE, array_size, channels[i],
                                  get_callback, &cb_states[i]);
        }
        ca_flush_io();

        bool all_done = false;
        while (!all_done) {
            ca_pend_event(0.001);
            all_done = true;
            for (uint32_t i = 0; i < parallelism; i++) {
                if (!cb_states[i].done.load(std::memory_order_acquire)) {
                    all_done = false;
                    break;
                }
            }
        }

        std::vector<double> batch_latencies;
        batch_latencies.reserve(parallelism);
        for (uint32_t i = 0; i < parallelism; i++) {
            batch_latencies.push_back(
                std::chrono::duration<double, std::micro>(
                    cb_states[i].recv_time - batch_send).count());
        }
        get_times.push_back(computeMedian(batch_latencies));
    }

    for (auto& ch : channels) {
        if (ch) ca_clear_channel(ch);
    }
    ca_context_destroy();

    return computeGetStats(get_times, "CA", array_size, parallelism);
}

/**
 * @brief ChannelRequester implementation for EPICS_PVA benchmark.
 *
 * Signals an Event when the channel becomes CONNECTED so the caller
 * can wait synchronously.
 */
class BenchChannelRequester : public epics::pvAccess::ChannelRequester,
    public std::tr1::enable_shared_from_this<BenchChannelRequester>
{
public:
    BenchChannelRequester() = default;

    std::string getRequesterName() override { return "pvxperf"; }

    void message(std::string const &msg, epics::pvData::MessageType) override {
        (void)msg;
    }

    void channelCreated(const epics::pvData::Status &status,
                        epics::pvAccess::Channel::shared_pointer const &) override
    {
        if (!status.isSuccess())
            log_err_printf(perflog, "EPICS_PVA channelCreated: %s\n",
                           status.getMessage().c_str());
    }

    void channelStateChange(
        epics::pvAccess::Channel::shared_pointer const &,
        epics::pvAccess::Channel::ConnectionState state) override
    {
        if (state == epics::pvAccess::Channel::CONNECTED)
            connected_.signal();
    }

    bool waitConnected(double timeout) { return connected_.wait(timeout); }

private:
    epics::pvData::Event connected_;
};

/**
 * @brief ChannelGetRequester that signals an Event on each getDone() callback,
 *        ensuring a true wire round-trip per get().
 */
class BenchGetRequester : public epics::pvAccess::ChannelGetRequester,
    public std::tr1::enable_shared_from_this<BenchGetRequester>
{
public:
    BenchGetRequester() = default;

    std::string getRequesterName() override { return "pvxperf"; }

    void message(std::string const &msg, epics::pvData::MessageType) override {
        (void)msg;
    }

    void channelGetConnect(
        const epics::pvData::Status &status,
        epics::pvAccess::ChannelGet::shared_pointer const &,
        epics::pvData::Structure::const_shared_pointer const &) override
    {
        if (status.isSuccess())
            connectEvent_.signal();
        else
            log_err_printf(perflog, "EPICS_PVA channelGetConnect: %s\n",
                           status.getMessage().c_str());
    }

    void getDone(
        const epics::pvData::Status &status,
        epics::pvAccess::ChannelGet::shared_pointer const &,
        epics::pvData::PVStructure::shared_pointer const &pvStructure,
        epics::pvData::BitSet::shared_pointer const &) override
    {
        if (!status.isSuccess())
            log_err_printf(perflog, "EPICS_PVA getDone: %s\n",
                           status.getMessage().c_str());
        else if (!smokeChecked_)
            lastValue_ = pvStructure;
        doneEvent_.signal();
    }

    bool waitConnect(double timeout) { return connectEvent_.wait(timeout); }
    bool waitDone(double timeout) { return doneEvent_.wait(timeout); }

    epics::pvData::PVStructure::shared_pointer consumeSmokeValue() {
        smokeChecked_ = true;
        return std::move(lastValue_);
    }

private:
    epics::pvData::Event connectEvent_;
    epics::pvData::Event doneEvent_;
    epics::pvData::PVStructure::shared_pointer lastValue_;
    bool smokeChecked_{false};
};

GetResult runEpicsPvaGetBenchmark(
    const std::string& label,
    const std::string& pvname,
    const uint32_t array_size,
    const uint32_t parallelism,
    const uint32_t num_samples = 1000,
    const uint32_t warmup = 100)
{
    namespace pva = epics::pvAccess;
    namespace pvd = epics::pvData;

    pva::ClientFactory::start();

    auto provider = pva::ChannelProviderRegistry::clients()->getProvider("pva");
    if (!provider)
        throw std::runtime_error("EPICS_PVA: cannot get 'pva' provider");

    auto pvRequest = pvd::CreateRequest::create()->createRequest("field(value)");

    if (parallelism <= 1) {
        auto chReq = std::make_shared<BenchChannelRequester>();
        auto channel = provider->createChannel(pvname, chReq);
        if (!chReq->waitConnected(10.0))
            throw std::runtime_error(label + ": channel connect timeout");

        auto getReq = std::make_shared<BenchGetRequester>();
        auto channelGet = channel->createChannelGet(getReq, pvRequest);
        if (!getReq->waitConnect(10.0))
            throw std::runtime_error(label + ": channelGet connect timeout");

        for (uint32_t w = 0; w < warmup; w++) {
            channelGet->get();
            getReq->waitDone(5.0);
        }
        if (auto pv = getReq->consumeSmokeValue()) {
            auto field = pv->getSubField<pvd::PVDoubleArray>("value");
            if (field) {
                pvd::PVDoubleArray::const_svector data;
                field->getAs(data);
                if (!data.empty() && data.back() != 1.0)
                    log_warn_printf(perflog, "%s smoke test failed: last element = %f\n", label.c_str(), data.back());
            }
        }

        std::vector<double> get_times;
        get_times.reserve(num_samples);
        for (uint32_t s = 0; s < num_samples; s++) {
            const auto start = std::chrono::steady_clock::now();
            channelGet->get();
            getReq->waitDone(5.0);
            const auto end = std::chrono::steady_clock::now();
            get_times.push_back(
                std::chrono::duration<double, std::micro>(end - start).count());
        }

        return computeGetStats(get_times, label, array_size, parallelism);
    }

    struct GetSlot {
        std::tr1::shared_ptr<BenchChannelRequester> chReq;
        pva::Channel::shared_pointer channel;
        std::tr1::shared_ptr<BenchGetRequester> getReq;
        pva::ChannelGet::shared_pointer getter;
    };

    std::vector<GetSlot> slots(parallelism);
    for (uint32_t i = 0; i < parallelism; i++) {
        slots[i].chReq = std::make_shared<BenchChannelRequester>();
        slots[i].channel = provider->createChannel(pvname, slots[i].chReq);
    }
    for (uint32_t i = 0; i < parallelism; i++) {
        if (!slots[i].chReq->waitConnected(10.0))
            throw std::runtime_error(label + ": parallel channel connect timeout");
        slots[i].getReq = std::make_shared<BenchGetRequester>();
        slots[i].getter = slots[i].channel->createChannelGet(slots[i].getReq, pvRequest);
        if (!slots[i].getReq->waitConnect(10.0))
            throw std::runtime_error(label + ": parallel channelGet connect timeout");
    }

    for (uint32_t w = 0; w < warmup; w++) {
        for (uint32_t i = 0; i < parallelism; i++)
            slots[i].getter->get();
        for (uint32_t i = 0; i < parallelism; i++)
            slots[i].getReq->waitDone(5.0);
    }
    if (auto pv = slots[0].getReq->consumeSmokeValue()) {
        auto field = pv->getSubField<pvd::PVDoubleArray>("value");
        if (field) {
            pvd::PVDoubleArray::const_svector data;
            field->getAs(data);
            if (!data.empty() && data.back() != 1.0)
                log_warn_printf(perflog, "%s smoke test failed: last element = %f\n",
                                label.c_str(), data.back());
        }
    }

    std::vector<double> get_times;
    get_times.reserve(num_samples);

    for (uint32_t s = 0; s < num_samples; s++) {
        const auto batch_start = std::chrono::steady_clock::now();

        for (uint32_t i = 0; i < parallelism; i++)
            slots[i].getter->get();
        for (uint32_t i = 0; i < parallelism; i++)
            slots[i].getReq->waitDone(5.0);

        const auto batch_end = std::chrono::steady_clock::now();
        const double batch_us = std::chrono::duration<double, std::micro>(
            batch_end - batch_start).count();
        get_times.push_back(batch_us / parallelism);
    }

    return computeGetStats(get_times, label, array_size, parallelism);
}

void printGetSummary(const GetResult& r) {
    fprintf(stderr,
        "\n=== GET: %s array_size=%u parallelism=%u ===\n"
        "  Samples:    %u\n"
        "  Per-GET latency:\n"
        "    Median:   %.2f us\n"
        "    Mean:     %.2f us\n"
        "    P25:      %.2f us\n"
        "    P75:      %.2f us\n"
        "    P99:      %.2f us\n"
        "    Min:      %.2f us\n"
        "    Max:      %.2f us\n"
        "  CV:         %.1f%%\n"
        "  Throughput: %.0f gets/sec\n",
        r.protocol.c_str(), r.array_size, r.parallelism,
        r.num_samples,
        r.median_get_us, r.mean_get_us,
        r.p25_get_us, r.p75_get_us, r.p99_get_us,
        r.min_get_us, r.max_get_us,
        r.cv_pct, r.gets_per_sec);
}

void writeGetCsvHeader(std::ostream& out) {
    out << "protocol,array_size,parallelism,iteration,"
           "gets_per_second,per_getter_gets_per_second,total_gets,duration_seconds"
        << std::endl;
}

void writeGetCsvRows(std::ostream& out, const GetResult& r) {
    for (uint32_t i = 0; i < r.raw_get_times.size(); i++) {
        const double per_get_us = r.raw_get_times[i];
        if (per_get_us <= 0.0) continue;
        const double agg_gets_per_sec = static_cast<double>(r.parallelism) * 1000000.0 / per_get_us;
        const double per_getter_gps = 1000000.0 / per_get_us;
        const double duration_sec = per_get_us * static_cast<double>(r.parallelism) / 1000000.0;
        out << r.protocol
            << "," << r.array_size
            << "," << r.parallelism
            << "," << (i + 1)
            << "," << std::fixed << std::setprecision(1) << agg_gets_per_sec
            << "," << std::fixed << std::setprecision(1) << per_getter_gps
            << "," << r.parallelism
            << "," << std::fixed << std::setprecision(6) << duration_sec
            << std::endl;
    }
}

void printGetSummaryTable(const std::vector<GetResult>& results) {
    if (results.empty())
        return;

    fprintf(stderr,
        "\n=== GET Throughput Summary ===\n"
        "%-14s  %10s  %11s  %12s  %6s\n",
        "Protocol", "ArraySize", "Parallelism", "Gets/sec", "CV%");
    fprintf(stderr,
        "%-14s  %10s  %11s  %12s  %6s\n",
        "----------", "----------", "-----------", "----------", "------");

    for (const auto& r : results) {
        fprintf(stderr,
            "%-14s  %10u  %11u  %12.0f  %5.1f%%\n",
            r.protocol.c_str(), r.array_size, r.parallelism,
            r.gets_per_sec, r.cv_pct);
    }
    fprintf(stderr, "\n");
}

/** @brief Holds the duration of one connection phase for one benchmark iteration. */
struct PhaseTimingResult {
    std::string protocol;
    uint32_t iteration{0};
    std::string phase;
    double duration_us{0.0};
};

/**
 * @brief Shared state for capturing pvxs debug-log timestamps during connection phase timing.
 */
struct PhaseTimingCapture {
    std::mutex mtx;
    // Phase boundary timestamps in nanoseconds since epoch
    // Keys: "searching", "connecting", "connected", "connection_validation", "validated", "active"
    std::map<std::string, int64_t> timestamps;
    // Track if capture is complete (all mandatory markers seen)
    bool complete{false};

    // Port suffix strings for the benchmark server (e.g. ":5076", ":52341").
    // ConnBase::state messages whose peerName matches one of these are accepted;
    // all others (e.g., inner cert-status client -> PVACMS) are rejected.
    // Empty strings disable port-based filtering (non-SPVA_CERTMON modes).
    std::string server_tcp_port_str;
    std::string server_tls_port_str;

    /**
     * @brief Clear all captured timestamps and reset the completion flag.
     */
    void reset() {
        std::lock_guard<std::mutex> lk(mtx);
        timestamps.clear();
        complete = false;
    }
};

/**
 * @brief Parse an ISO 8601 nanosecond timestamp from the prefix of a pvxs log message.
 * @param msg  Log message string; expected format: YYYY-MM-DDTHH:MM:SS.nnnnnnnnn ...
 * @param len  Length of @p msg in bytes; must be at least 29 for a valid timestamp.
 * @return     Nanoseconds since the Unix epoch, or -1 if parsing fails.
 */
int64_t parseTimestampNs(const char* msg, const size_t len) {
    // Need at least 29 chars: 2026-03-06T10:30:45.123456789
    if (len < 29)
        return -1;

    // Quick format validation
    if (msg[4] != '-' || msg[7] != '-' || msg[10] != 'T' ||
        msg[13] != ':' || msg[16] != ':' || msg[19] != '.')
        return -1;

    char buf[10];
    char* end = nullptr;

    std::memcpy(buf, msg, 4); buf[4] = '\0';
    const long year = std::strtol(buf, &end, 10);
    if (end != buf + 4) return -1;

    std::memcpy(buf, msg + 5, 2); buf[2] = '\0';
    const long mon = std::strtol(buf, &end, 10);
    if (end != buf + 2) return -1;

    std::memcpy(buf, msg + 8, 2); buf[2] = '\0';
    const long mday = std::strtol(buf, &end, 10);
    if (end != buf + 2) return -1;

    std::memcpy(buf, msg + 11, 2); buf[2] = '\0';
    const long hour = std::strtol(buf, &end, 10);
    if (end != buf + 2) return -1;

    std::memcpy(buf, msg + 14, 2); buf[2] = '\0';
    const long min = std::strtol(buf, &end, 10);
    if (end != buf + 2) return -1;

    std::memcpy(buf, msg + 17, 2); buf[2] = '\0';
    const long sec = std::strtol(buf, &end, 10);
    if (end != buf + 2) return -1;

    std::memcpy(buf, msg + 20, 9); buf[9] = '\0';
    const long nanos = std::strtol(buf, &end, 10);
    if (end != buf + 9) return -1;

    tm tm_val{};
    std::memset(&tm_val, 0, sizeof(tm_val));
    tm_val.tm_year = static_cast<int>(year) - 1900;
    tm_val.tm_mon  = static_cast<int>(mon) - 1;
    tm_val.tm_mday = static_cast<int>(mday);
    tm_val.tm_hour = static_cast<int>(hour);
    tm_val.tm_min  = static_cast<int>(min);
    tm_val.tm_sec  = static_cast<int>(sec);
    tm_val.tm_isdst = -1;

    const time_t epoch_sec = mktime(&tm_val);
    if (epoch_sec == static_cast<time_t>(-1))
        return -1;

    return static_cast<int64_t>(epoch_sec) * 1000000000LL + nanos;
}

/**
 * @brief errlog listener callback that captures pvxs debug-log connection phase transitions.
 * @param pPrivate  Pointer to the PhaseTimingCapture instance to write timestamps into.
 * @param message   Null-terminated errlog message string; may be NULL.
 */
extern "C" void phaseTimingListener(void* pPrivate, const char* message) {
    auto* capture = static_cast<PhaseTimingCapture*>(pPrivate);
    if (!message)
        return;

    const std::string msg(message);
    const size_t msg_len = msg.size();

    // Parse timestamp from the log line prefix
    const int64_t ts = parseTimestampNs(msg.c_str(), msg_len);
    if (ts < 0)
        return;

    // For SPVA_CERTMON, inner cert-status clients produce ConnBase/Channel
    // state transitions for CERT:* PVs on PVACMS.  Filter ConnBase messages
    // by whitelisting the benchmark server's port (set after server.start()).
    // When server_tcp_port_str is empty, port filtering is disabled (PVA/SPVA).
    const bool has_port_filter = !capture->server_tcp_port_str.empty();
    const bool is_bench_server = !has_port_filter ||
        msg.find(capture->server_tcp_port_str) != std::string::npos ||
        msg.find(capture->server_tls_port_str) != std::string::npos;

    std::string phase;

    if (msg.find("Search tick") != std::string::npos) {
        phase = "searching";
    } else if (msg.find("Channel::state = Connecting") != std::string::npos &&
               msg.find("PVXPERF:") != std::string::npos) {
        phase = "connecting";
    } else if (msg.find("ConnBase::state = Connected") != std::string::npos &&
               msg.find("Connection::bevEvent") != std::string::npos &&
               is_bench_server) {
        phase = "connected";
    } else if (msg.find("ConnBase::state = Validated") != std::string::npos &&
               is_bench_server) {
        phase = "validated";
    } else if (msg.find("Channel::state = Active") != std::string::npos &&
               msg.find("PVXPERF:") != std::string::npos) {
        phase = "active";
    } else if (msg.find("==> CONNECTION_VALIDATION") != std::string::npos &&
               is_bench_server) {
        phase = "connection_validation";
    }

    if (msg.find("error") != std::string::npos || msg.find("Error") != std::string::npos) {
        fprintf(stderr, "[pvxperf] %s", message);
    }
    if (msg.find("<<TRUNCATED>>") != std::string::npos) {
        fprintf(stderr, "[pvxperf] WARNING: log message truncated — phase timing may be incomplete\n");
    }

    if (!phase.empty()) {
        std::lock_guard<std::mutex> lk(capture->mtx);
        if (phase == "searching") {
            if (!capture->timestamps.count(phase))
                capture->timestamps[phase] = ts;
        } else {
            capture->timestamps[phase] = ts;
        }
        if (capture->timestamps.count("searching") &&
            capture->timestamps.count("connecting") &&
            capture->timestamps.count("connected") &&
            capture->timestamps.count("validated") &&
            capture->timestamps.count("active")) {
            capture->complete = true;
        }
    }
}

/**
 * @brief Enable debug-log capture for connection phase timing.
 * @note Suppresses console errlog output and sets pvxs.st.cli and pvxs.cli.io to Debug level.
 */
void enablePhaseTimingLoggers() {
    eltc(0);
    pvxs::logger_level_set("pvxs.st.cli", pvxs::Level::Debug);
    pvxs::logger_level_set("pvxs.cli.io", pvxs::Level::Debug);
}

void disablePhaseTimingLoggers() {
    pvxs::logger_level_set("pvxs.st.cli", pvxs::Level::Err);
    pvxs::logger_level_set("pvxs.cli.io", pvxs::Level::Err);
    eltc(1);
}

void enablePhaseTimingCapture(PhaseTimingCapture& capture) {
    errlogFlush();
    errlogAddListener(phaseTimingListener, &capture);
}

void disablePhaseTimingCapture(PhaseTimingCapture& capture) {
    errlogRemoveListeners(phaseTimingListener, &capture);
}

/**
 * @brief Compute per-phase durations from captured log timestamps.
 * @param capture  PhaseTimingCapture holding timestamps keyed by phase name.
 * @return         Map of phase name to duration in microseconds (search, tcp_connect,
 *                 validation, create_channel, total), or empty if required timestamps
 *                 are missing.
 */
std::map<std::string, double> computePhaseDurations(PhaseTimingCapture& capture) {
    std::lock_guard<std::mutex> lk(capture.mtx);
    std::map<std::string, double> durations;

    const auto& ts = capture.timestamps;

    // Check for required timestamps
    const char* required[] = {"searching", "connecting", "connected", "validated", "active"};
    bool missing = false;
    for (const char* key : required) {
        if (!ts.count(key)) {
            log_warn_printf(perflog, "Phase timing: missing marker '%s'\n", key);
            missing = true;
        }
    }
    if (missing)
        return durations;

    const int64_t searching_ts = ts.at("searching");
    const int64_t connecting_ts = ts.at("connecting");
    const int64_t connected_ts = ts.at("connected");
    const int64_t validated_ts = ts.at("validated");
    const int64_t active_ts = ts.at("active");

    durations["search"] = static_cast<double>(connecting_ts - searching_ts) / 1000.0;
    durations["tcp_connect"] = static_cast<double>(connected_ts - connecting_ts) / 1000.0;

    // Use connection_validation timestamp if available, and it precedes connected
    if (ts.count("connection_validation")) {
        const int64_t cv_ts = ts.at("connection_validation");
        if (cv_ts < connected_ts) {
            durations["validation"] = static_cast<double>(validated_ts - cv_ts) / 1000.0;
        } else {
            durations["validation"] = static_cast<double>(validated_ts - connected_ts) / 1000.0;
        }
    } else {
        durations["validation"] = static_cast<double>(validated_ts - connected_ts) / 1000.0;
    }

    durations["create_channel"] = static_cast<double>(active_ts - validated_ts) / 1000.0;
    durations["total"] = static_cast<double>(active_ts - searching_ts) / 1000.0;

    return durations;
}

/**
 * @brief Run the connection phase timing benchmark for N connect/disconnect cycles.
 * @param mode              Protocol mode to benchmark (PVXS_PVA, SPVA, or SPVA_CERTMON).
 * @param iterations        Number of independent connect/disconnect cycles to perform.
 * @param server_keychain   Path to TLS keychain for the benchmark server.
 * @param client_keychain_path  Path to TLS keychain for the client (falls back to server_keychain if empty).
 * @param cms_udp_port      PVACMS UDP port for --setup-cms (e.g., 15076); 0 means external PVACMS
 *                          reachable via standard EPICS_PVA_* environment variables.
 * @return                  Vector of PhaseTimingResult, one entry per phase per iteration.
 */
std::vector<PhaseTimingResult> runPvaPhaseTiming(
    const ProtocolMode mode,
    const uint32_t iterations,
    const std::string& server_keychain,
    const std::string& client_keychain_path,
    const uint16_t cms_udp_port = 0u)
{
    std::vector<PhaseTimingResult> results;
    const std::string protocol = protocolModeStr(mode);
    const std::string pvname = "PVXPERF:PHASE";

    enablePhaseTimingLoggers();

    for (uint32_t iter = 1; iter <= iterations; ++iter) {
        PhaseTimingCapture capture;

        // Create a fresh server for each iteration (cold connection).
        // For --setup-cms, inject the known PVACMS port into beaconDestinations.
        // For --external-cms (cms_udp_port==0), use fromEnv() so the inner
        // cert-status client discovers PVACMS via the standard PVA environment.
        server::Config sconfig;
        if (mode == ProtocolMode::SPVA_CERTMON && cms_udp_port == 0u) {
            sconfig = server::Config::fromEnv();
        } else {
            sconfig = loopbackServerConfig(
                (mode == ProtocolMode::SPVA_CERTMON) ? cms_udp_port : 0u);
        }

        if (mode == ProtocolMode::PVXS_PVA) {
            sconfig.tls_disabled = true;
        } else {
            sconfig.tls_disabled = false;
            sconfig.tls_keychain_file = server_keychain;
#ifdef PVXS_ENABLE_EXPERT_API
            if (mode == ProtocolMode::SPVA) {
                sconfig.disableStatusCheck(true);
            } else {
                sconfig.disableStatusCheck(false);
            }
#endif
        }

        auto pv = server::SharedPV::buildReadonly();
        pv.open(buildBenchType(1));

        const auto server = sconfig.build()
                          .addPV(pvname, pv)
                          .start();

        // For SPVA_CERTMON, the server's inner cert-status client connects to
        // PVACMS asynchronously after start().  Wait for those connections to
        // settle so their log messages don't contaminate the phase timing capture.
        if (mode == ProtocolMode::SPVA_CERTMON) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            errlogFlush();
        }

        // Set the port whitelist for ConnBase::state log filtering.
        // Only messages whose peerName matches the benchmark server's port
        // are accepted; inner cert-status client connections are rejected.
        if (mode == ProtocolMode::SPVA_CERTMON) {
            const auto& eff = server.config();
            capture.server_tcp_port_str = ":" + std::to_string(eff.tcp_port);
            capture.server_tls_port_str = ":" + std::to_string(eff.tls_port);
        }

        auto cconfig = server.clientConfig();
        if (mode == ProtocolMode::PVXS_PVA) {
            cconfig.tls_disabled = true;
        } else {
            cconfig.tls_disabled = false;
            cconfig.tls_keychain_file = client_keychain_path.empty() ?
                server_keychain : client_keychain_path;
#ifdef PVXS_ENABLE_EXPERT_API
            if (mode == ProtocolMode::SPVA) {
                cconfig.disableStatusCheck(true);
            } else {
                cconfig.disableStatusCheck(false);
            }
#endif
        }

        enablePhaseTimingCapture(capture);
        eltc(0); // Turn off console logging of log messages but still intercept them

        auto ctxt = cconfig.build();

        // Track connection and TLS verification state from the event callback.
        // With maskConnected(false), the first pop() delivers a Connected exception
        // before any data values, allowing us to inspect the peer credentials.
        const bool expect_tls = (mode == ProtocolMode::SPVA || mode == ProtocolMode::SPVA_CERTMON);
        std::atomic<bool> got_value{false};
        std::atomic<bool> tls_verified{false};
        std::atomic<bool> tls_failed{false};
        auto sub = ctxt.monitor(pvname)
                       .record("pipeline", true)
                       .maskConnected(false)
                       .maskDisconnected(true)
                       .event([&got_value, &tls_verified, &tls_failed, expect_tls](client::Subscription& s) {
                           try {
                               while (true) {
                                   try {
                                       auto val = s.pop();
                                       if (!val)
                                           break;
                                       got_value.store(true, std::memory_order_relaxed);
                                   } catch (client::Connected& e) {
                                       if (expect_tls) {
                                           if (e.cred && e.cred->isTLS) {
                                               tls_verified.store(true, std::memory_order_relaxed);
                                           } else {
                                               tls_failed.store(true, std::memory_order_relaxed);
                                           }
                                       }
                                       // Continue popping - data values follow the Connected event
                                   }
                               }
                           } catch (std::exception&) {
                               // ignore other exceptions (Disconnect, Finished, etc.)
                           }
                       })
                       .exec();

        // Wait for value to arrive via subscription callback
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (!got_value.load(std::memory_order_relaxed) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (expect_tls) {
            if (tls_failed.load(std::memory_order_relaxed)) {
                log_err_printf(perflog,
                    "FATAL: %s iter %u: connection is NOT using TLS - falling back to plain PVA. "
                    "Check keychain configuration.\n",
                    protocol.c_str(), iter);
                throw std::runtime_error(
                    protocol + " phase timing: connection established without TLS. "
                    "Benchmark results would be invalid.");
            }
            if (!tls_verified.load(std::memory_order_relaxed)) {
                log_warn_printf(perflog,
                    "%s iter %u: TLS verification inconclusive - Connected event not received "
                    "within timeout. Results may be unreliable.\n",
                    protocol.c_str(), iter);
            } else {
                log_debug_printf(perflog, "%s iter %u: TLS connection verified\n",
                    protocol.c_str(), iter);
            }
        }

        // Wait for all phase markers to arrive in the errlog listener.
        // Poll capture.complete with errlogFlush() for up to 500ms.
        const auto marker_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (std::chrono::steady_clock::now() < marker_deadline) {
            errlogFlush();
            {
                std::lock_guard<std::mutex> lk(capture.mtx);
                if (capture.complete)
                    break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        // Disable log capture
        disablePhaseTimingCapture(capture);

        // Cancel subscription
        sub->cancel();

        // Compute phase durations
        const auto durations = computePhaseDurations(capture);

        // Store results
        const std::vector<std::string> phases = {
            "search", "tcp_connect", "validation", "create_channel", "total"
        };
        for (const auto& phase : phases) {
            PhaseTimingResult r;
            r.protocol = protocol;
            r.iteration = iter;
            r.phase = phase;
            if (durations.count(phase)) {
                r.duration_us = durations.at(phase);
            }
            results.push_back(r);
        }

        log_debug_printf(perflog, "Phase timing %s iter %u: %s\n",
                        protocol.c_str(), iter,
                        durations.empty() ? "incomplete" : "ok");
    }

    disablePhaseTimingLoggers();
    return results;
}

/**
 * @brief Write the CSV header for phase timing output.
 * @param out  Output stream to write the header to.
 */
void writePhaseCsvHeader(std::ostream& out) {
    out << "test_type,protocol,iteration,phase,duration_us" << std::endl;
}

/**
 * @brief Write one phase timing result as a CSV row.
 * @param out  Output stream to write to.
 * @param r    PhaseTimingResult to serialize.
 */
void writePhaseCsvRow(std::ostream& out, const PhaseTimingResult& r) {
    out << "connection_phase," << r.protocol << "," << r.iteration << ","
        << r.phase << "," << r.duration_us << std::endl;
}

/**
 * @brief Print a phase timing comparison table to stderr with overhead percentages relative to PVXS_PVA.
 * @param results     All phase timing results to aggregate across protocols.
 * @param iterations  Number of iterations used, shown in the table header.
 */
void printComparisonTable(const std::vector<PhaseTimingResult>& results,
                            const uint32_t iterations) {
    if (results.empty())
        return;

    // Collect unique protocols (in order: PVXS_PVA, SPVA, SPVA_CERTMON)
    std::vector<std::string> protocol_order = {"PVXS_PVA", "SPVA", "SPVA_CERTMON"};
    std::vector<std::string> protocols;
    for (const auto& p : protocol_order) {
        for (const auto& r : results) {
            if (r.protocol == p) {
                protocols.push_back(p);
                break;
            }
        }
    }

    if (protocols.empty())
        return;

    // Compute mean per (protocol, phase)
    std::map<std::string, std::map<std::string, double>> means;
    for (const auto& proto : protocols) {
        const std::vector<std::string> phases = {
            "search", "tcp_connect", "validation", "create_channel", "total"
        };
        for (const auto& phase : phases) {
            double sum = 0.0;
            uint32_t count = 0;
            for (const auto& r : results) {
                if (r.protocol == proto && r.phase == phase) {
                    sum += r.duration_us;
                    count++;
                }
            }
            if (count > 0) {
                means[proto][phase] = sum / static_cast<double>(count);
            }
        }
    }

    // Print table
    std::cerr << "\n=== Connection Phase Timing (mean of " << iterations << " iterations) ===" << std::endl;

    // Header
    std::cerr << std::left << std::setw(18) << "Phase";
    for (size_t i = 0; i < protocols.size(); ++i) {
        if (i == 0) {
            std::cerr << std::setw(20) << (protocols[i] + " (baseline)");
        } else {
            std::cerr << std::setw(20) << protocols[i];
        }
    }
    std::cerr << std::endl;

    // Rows
    const std::vector<std::string> phases = {
        "search", "tcp_connect", "validation", "create_channel", "total"
    };

    const std::string& baseline_proto = protocols[0];

    for (const auto& phase : phases) {
        std::cerr << std::left << std::setw(18) << phase;

        const double baseline_val = means.count(baseline_proto) && means[baseline_proto].count(phase)
                                    ? means[baseline_proto][phase] : 0.0;

        for (size_t i = 0; i < protocols.size(); ++i) {
            const double val = means.count(protocols[i]) && means[protocols[i]].count(phase)
                               ? means[protocols[i]][phase] : 0.0;
            const double ms = val / 1000.0;  // convert us to ms

            std::ostringstream cell;
            cell << std::fixed << std::setprecision(1) << ms << " ms";

            if (i > 0 && baseline_val > 0.0) {
                const double pct = ((val - baseline_val) / baseline_val) * 100.0;
                cell << " (";
                if (pct >= 0.0) cell << "+";
                cell << std::fixed << std::setprecision(0) << pct << "%)";
            }

            std::cerr << std::setw(20) << cell.str();
        }
        std::cerr << std::endl;
    }
    std::cerr << std::endl;
}

void showHelp(const char *program_name) {
    std::cout << "pvxperf - GET-based performance benchmarking tool\n"
              << std::endl
              << "Measures GET throughput (gets/second) across five protocol modes (CA, EPICS_PVA,\n"
              << "PVXS_PVA, SPVA, SPVA_CERTMON) using sequential and parallel GET operations.\n"
              << std::endl
              << "usage:\n"
              << "  " << program_name << " [options]                          Run benchmark\n"
              << "  " << program_name << " (-h | --help)                      Show this help message and exit\n"
              << "  " << program_name << " (-V | --version)                   Print version and exit\n"
              << std::endl
              << "options:\n"
              << "  (-h | --help)                              Show this help message and exit\n"
              << "  (-V | --version)                           Print version and exit\n"
              << "  (-v | --verbose)                           Verbose mode\n"
              << "  (-d | --debug)                             Enable PVXS debug logging\n"
              << std::endl
              << "benchmark options:\n"
              << "        --modes <list>                       Comma-separated protocol modes. Default: ca,epics_pva,pvxs_pva,spva,spva_certmon\n"
              << "        --sizes <list>                       Comma-separated array sizes in doubles. Default: 1,10,100,1000,10000,100000\n"
              << "        --parallelism <list>                 Comma-separated parallelism values. Default: 1,1000\n"
              << "        --samples <N>                        Number of measured GETs per data point. Default: 1000\n"
              << "        --warmup <N>                         Number of warmup GETs to discard. Default: 100\n"
              << "        --output <file>                      CSV output file (default: stdout)\n"
              << std::endl
              << "server options:\n"
              << "        --pvxs-server <mode>                 'in-process' (BenchmarkSource, default) or 'external' (softIocPVX child)\n"
              << std::endl
              << "PVACMS options:\n"
              << "        --keychain <path>                    TLS keychain file for SPVA modes\n"
              << "        --setup-cms                          Auto-bootstrap PVACMS with temp certs for SPVA_CERTMON\n"
              << "        --external-cms                       Use already-running PVACMS for SPVA_CERTMON\n"
              << "        --cms-db <path>                      Path to existing PVACMS SQLite database\n"
              << "        --cms-keychain <path>                Path to existing PVACMS server keychain\n"
              << "        --cms-acf <path>                     Path to existing PVACMS ACF file\n"
              << std::endl
              << "phase timing options:\n"
              << "        --benchmark-phases                   After GET benchmark, run connect/disconnect cycles and report phase timing\n"
              << "        --phase-iterations <N>               Number of connect/disconnect cycles for phase timing. Default: 50\n"
              << "        --phase-output <file>                CSV output file for phase timing results (default: stderr table only)\n"
              << std::endl
              << "build-time paths (compiled in via Makefile, not runtime env vars):\n"
              << "  EPICS_BASE = " << PVXPERF_EPICS_BASE << "\n"
              << "  PVXS       = " << PVXPERF_PVXS << "\n"
              << "  HOST_ARCH  = " << PVXPERF_EPICS_HOST_ARCH << "\n"
              << std::endl
              << "  softIoc    = $EPICS_BASE/bin/$HOST_ARCH/softIoc\n"
              << "  softIocPVA = $EPICS_BASE/bin/$HOST_ARCH/softIocPVA\n"
              << "  softIocPVX = $PVXS/bin/$HOST_ARCH/softIocPVX\n"
              << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        errlogInit2(1024 * 1024, 0);
        logger_config_env();

        CLI::App app{
            "pvxperf - GET-based performance benchmarking tool for CA, EPICS_PVA, PVXS_PVA, SPVA, SPVA+CERTMON.\n\n"
            "Measures GET throughput (gets/second) across five protocol modes using\n"
            "sequential and parallel GET operations with configurable array sizes.\n\n"
            "WARNING: Run on a network with no other active PVACMS to avoid\n"
            "interference with benchmark results.\n"
        };

        app.set_help_flag("", "");

        bool help{false};
        bool verbose{false};
        bool debug{false};
        bool show_version{false};
        std::string modes_str = "ca,epics_pva,pvxs_pva,spva,spva_certmon";
        std::string sizes_str = "1,10,100,1000,10000,100000";
        std::string parallelism_str = "1,1000";
        uint32_t samples = 1000;
        uint32_t warmup = 100;
        std::string keychain;
        std::string output_file;
        bool setup_cms = false;
        bool external_cms = false;
        std::string pvxs_server_mode = "in-process";
        std::string cms_db, cms_keychain, cms_acf;
        bool benchmark_phases{false};
        uint32_t phase_iterations{50};
        std::string phase_output;

        app.add_flag("-h,--help", help);
        app.add_flag("-v,--verbose", verbose, "Verbose mode");
        app.add_flag("-d,--debug", debug, "Enable PVXS debug logging");
        app.add_flag("-V,--version", show_version, "Print version and exit");
        app.add_option("--modes", modes_str,
                       "Comma-separated protocol modes: ca,epics_pva,pvxs_pva,spva,spva_certmon");
        app.add_option("--sizes", sizes_str,
                       "Comma-separated array sizes in doubles (e.g. 1,10,100,1000)");
        app.add_option("--parallelism", parallelism_str,
                       "Comma-separated parallelism values (e.g. 1,1000)");
        app.add_option("--samples", samples,
                       "Number of measured GETs per data point");
        app.add_option("--warmup", warmup,
                       "Number of warmup GETs to discard");
        app.add_option("--keychain", keychain,
                       "TLS keychain file for SPVA modes");
        app.add_option("--output", output_file,
                       "CSV output file (default: stdout)");
        app.add_flag("--setup-cms", setup_cms,
                     "Auto-bootstrap PVACMS with temp certs for SPVA_CERTMON");
        app.add_flag("--external-cms", external_cms,
                     "Use already-running PVACMS for SPVA_CERTMON");
        app.add_option("--pvxs-server", pvxs_server_mode,
                       "PVXS server mode: 'in-process' (BenchmarkSource, default) or 'external' (softIocPVX child)");
        app.add_option("--cms-db", cms_db,
                       "Path to existing PVACMS SQLite database");
        app.add_option("--cms-keychain", cms_keychain,
                       "Path to existing PVACMS server keychain");
        app.add_option("--cms-acf", cms_acf,
                       "Path to existing PVACMS ACF file");
        app.add_flag("--benchmark-phases", benchmark_phases,
                     "After GET benchmark, run N connect/disconnect cycles per pvxs mode and report phase timing");
        app.add_option("--phase-iterations", phase_iterations,
                       "Number of connect/disconnect cycles for phase timing (default: 50)");
        app.add_option("--phase-output", phase_output,
                       "CSV output file for phase timing results (default: stderr table only)");

        CLI11_PARSE(app, argc, argv);

        if (help) {
            showHelp(argv[0]);
            return 0;
        }

        if (show_version) {
            version_information(std::cout);
            return 0;
        }

        if (debug) {
            setenv("PVXS_LOG", "pvxs.*=DEBUG", 1);
            logger_config_env();
        }

        const auto modes = parseModes(modes_str);
        const auto sizes = parseSizes(sizes_str);
        const auto parallelisms = parseParallelism(parallelism_str);

        if (pvxs_server_mode != "external" && pvxs_server_mode != "in-process") {
            std::cerr << "Error: --pvxs-server must be 'external' or 'in-process'" << std::endl;
            return 1;
        }
        const bool pvxs_external = (pvxs_server_mode == "external");

        std::ofstream file_out;
        std::ostream* out = &std::cout;
        if (!output_file.empty()) {
            file_out.open(output_file);
            if (!file_out.is_open()) {
                std::cerr << "Error: cannot open output file: " << output_file << std::endl;
                return 1;
            }
            out = &file_out;
        }

        std::string client_keychain;
        bool have_keychain = !keychain.empty();

        std::string tmp_cms_dir;
        std::unique_ptr<PvacmsProcess> pvacms_proc;

        if (setup_cms) {
            tmp_cms_dir = createTempDir();
            log_info_printf(perflog, "PVACMS temp directory: %s\n", tmp_cms_dir.c_str());

            setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);

            pvacms_proc.reset(new PvacmsProcess());
            pvacms_proc->start(tmp_cms_dir, cms_db, cms_keychain, cms_acf);

            if (!waitForPvacms(30.0, kPvacmsUdpPort)) {
                std::cerr << "Error: PVACMS did not become ready within timeout" << std::endl;
                return 1;
            }

            const std::string server_kc = tmp_cms_dir + "/server.p12";
            const std::string client_kc = tmp_cms_dir + "/client.p12";

            if (!runAuthnstd("pvxperf-server", "server", server_kc)) {
                std::cerr << "Error: failed to provision server keychain" << std::endl;
                return 1;
            }
            if (!runAuthnstd("pvxperf-client", "client", client_kc)) {
                std::cerr << "Error: failed to provision client keychain" << std::endl;
                return 1;
            }

            if (keychain.empty()) {
                keychain = server_kc;
                client_keychain = client_kc;
                have_keychain = true;
            }

            log_info_printf(perflog, "%s\n", "PVACMS setup complete, keychains provisioned");
        }

        auto needsMode = [&modes](ProtocolMode m) {
            return std::any_of(modes.begin(), modes.end(),
                [m](const ProtocolMode x) { return x == m; });
        };

        const bool needs_epics_pva_on_ioc = needsMode(ProtocolMode::EPICS_PVA);

        const size_t max_size = sizes.empty() ? static_cast<size_t>(1) :
            *std::max_element(sizes.begin(), sizes.end());

        setenv("EPICS_CA_ADDR_LIST", "127.0.0.1", 1);
        setenv("EPICS_CA_AUTO_ADDR_LIST", "NO", 1);
        setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
        setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);

        CaIocProcess ca_ioc;
        CaIocProcess pvxs_ioc;

        auto requireCaIoc = [&]() -> bool {
            if (ca_ioc.is_running()) return true;
            const IocType t = needs_epics_pva_on_ioc
                ? IocType::EPICS_PVA : IocType::CA_ONLY;
            if (!ca_ioc.start(max_size, t)) {
                std::cerr << "Warning: softIoc failed to start" << std::endl;
                return false;
            }
            return true;
        };

        auto requirePvxsIoc = [&]() -> bool {
            if (pvxs_ioc.is_running()) return true;
            if (!pvxs_ioc.start(max_size, IocType::PVXS, keychain,
                                "PVXPERF:PVXS:BENCH")) {
                std::cerr << "Warning: softIocPVX failed to start" << std::endl;
                return false;
            }
            return true;
        };

        writeGetCsvHeader(*out);

        std::vector<GetResult> all_results;

        for (const auto mode : modes) {
            if ((mode == ProtocolMode::SPVA || mode == ProtocolMode::SPVA_CERTMON) &&
                !have_keychain) {
                std::cerr << "Warning: skipping " << protocolModeStr(mode)
                          << " - no keychain available" << std::endl;
                continue;
            }

            if (mode == ProtocolMode::SPVA_CERTMON && !setup_cms && !external_cms) {
                std::cerr << "Warning: skipping SPVA_CERTMON - no PVACMS configured "
                          << "(use --setup-cms or --external-cms)" << std::endl;
                continue;
            }

            if (mode == ProtocolMode::SPVA_CERTMON && external_cms) {
                if (!waitForPvacms(10.0, 0u)) {
                    std::cerr << "Warning: skipping SPVA_CERTMON - external PVACMS not reachable"
                              << std::endl;
                    continue;
                }
            }

            // Per-mode in-process server setup for pvxs-based modes
            struct PvxsBenchServer {
                std::unique_ptr<server::Server> srv;
                std::unique_ptr<client::Context> ctxt;
                std::string pvname;
            };

            PvxsBenchServer bench_server;

            const bool is_pvxs_mode = (mode == ProtocolMode::PVXS_PVA ||
                                       mode == ProtocolMode::SPVA ||
                                       mode == ProtocolMode::SPVA_CERTMON);
            const bool is_ca_mode = (mode == ProtocolMode::CA ||
                                     mode == ProtocolMode::EPICS_PVA);

            if (is_ca_mode) {
                pvxs_ioc.stop();
                if (!requireCaIoc()) continue;
            } else if (is_pvxs_mode) {
                ca_ioc.stop();
            }

            if (is_pvxs_mode && pvxs_external) {
                if (!requirePvxsIoc()) {
                    std::cerr << "Warning: skipping " << protocolModeStr(mode)
                              << " - softIocPVX not running" << std::endl;
                    continue;
                }
                auto cconfig = client::Config::fromEnv();
                if (mode == ProtocolMode::PVXS_PVA) {
                    cconfig.tls_disabled = true;
                } else {
                    cconfig.tls_disabled = false;
                    cconfig.tls_keychain_file = client_keychain.empty() ? keychain : client_keychain;
#ifdef PVXS_ENABLE_EXPERT_API
                    if (mode == ProtocolMode::SPVA)
                        cconfig.disableStatusCheck(true);
                    else
                        cconfig.disableStatusCheck(false);
#endif
                    if (mode == ProtocolMode::SPVA_CERTMON && setup_cms)
                        cconfig.addressList.push_back(
                            "127.0.0.1:" + std::to_string(kPvacmsUdpPort));
                }
                bench_server.ctxt.reset(new client::Context(cconfig.build()));
                bench_server.pvname = "PVXPERF:PVXS:BENCH";
                if (mode == ProtocolMode::SPVA_CERTMON)
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));

            } else if (mode == ProtocolMode::PVXS_PVA) {
                // In-process mode: BenchmarkSource server
                const size_t pvxs_pva_max_size = sizes.empty() ? static_cast<size_t>(1) :
                    *std::max_element(sizes.begin(), sizes.end());
                auto sconfig = loopbackServerConfig();
                sconfig.tls_disabled = true;
                auto src = std::make_shared<BenchmarkSource>(
                    "PVXPERF:PVXS_PVA:BENCH", static_cast<uint32_t>(pvxs_pva_max_size));
                auto srv = sconfig.build()
                    .addSource("bench", src)
                    .start();
                auto cconfig = srv.clientConfig();
                cconfig.tls_disabled = true;
                bench_server.ctxt.reset(new client::Context(cconfig.build()));
                bench_server.srv.reset(new server::Server(std::move(srv)));
                bench_server.pvname = "PVXPERF:PVXS_PVA:BENCH";

            } else if (mode == ProtocolMode::SPVA) {
                const size_t spva_max_size = sizes.empty() ? static_cast<size_t>(1) :
                    *std::max_element(sizes.begin(), sizes.end());
                auto sconfig = loopbackServerConfig();
                sconfig.tls_disabled = false;
                sconfig.tls_keychain_file = keychain;
#ifdef PVXS_ENABLE_EXPERT_API
                sconfig.disableStatusCheck(true);
#endif
                auto src = std::make_shared<BenchmarkSource>(
                    "PVXPERF:SPVA:BENCH", static_cast<uint32_t>(spva_max_size));
                auto srv = sconfig.build()
                    .addSource("bench", src)
                    .start();
                auto cconfig = srv.clientConfig();
                cconfig.tls_disabled = false;
                cconfig.tls_keychain_file = client_keychain.empty() ? keychain : client_keychain;
#ifdef PVXS_ENABLE_EXPERT_API
                cconfig.disableStatusCheck(true);
#endif
                bench_server.ctxt.reset(new client::Context(cconfig.build()));
                bench_server.srv.reset(new server::Server(std::move(srv)));
                bench_server.pvname = "PVXPERF:SPVA:BENCH";

            } else if (mode == ProtocolMode::SPVA_CERTMON) {
                const size_t spva_certmon_max_size = sizes.empty() ? static_cast<size_t>(1) :
                    *std::max_element(sizes.begin(), sizes.end());
                const uint16_t cms_port = setup_cms ? kPvacmsUdpPort : 0u;
                auto sconfig = loopbackServerConfig(cms_port);
                sconfig.tls_disabled = false;
                sconfig.tls_keychain_file = keychain;
                auto src = std::make_shared<BenchmarkSource>(
                    "PVXPERF:SPVA_CERTMON:BENCH", static_cast<uint32_t>(spva_certmon_max_size));
                auto srv = sconfig.build()
                    .addSource("bench", src)
                    .start();
                auto cconfig = srv.clientConfig();
                cconfig.tls_disabled = false;
                cconfig.tls_keychain_file = client_keychain.empty() ? keychain : client_keychain;
#ifdef PVXS_ENABLE_EXPERT_API
                cconfig.disableStatusCheck(false);
#endif
                bench_server.ctxt.reset(new client::Context(cconfig.build()));
                bench_server.srv.reset(new server::Server(std::move(srv)));
                bench_server.pvname = "PVXPERF:SPVA_CERTMON:BENCH";
                // Wait for the cert-status client to settle
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            for (const auto array_size : sizes) {
                for (const auto par : parallelisms) {
                    log_info_printf(perflog,
                        "Benchmarking %s array_size=%zu parallelism=%u samples=%u...\n",
                        protocolModeStr(mode), array_size, par, samples);

                    GetResult result;
                    if (mode == ProtocolMode::CA) {
                        if (!ca_ioc.is_running()) continue;
                        result = runCaGetBenchmark(
                            static_cast<uint32_t>(array_size), par,
                            samples, warmup);
                    } else if (mode == ProtocolMode::EPICS_PVA) {
                        if (!ca_ioc.is_running()) continue;
                        result = runEpicsPvaGetBenchmark(
                            "EPICS_PVA", "PVXPERF:CA:BENCH",
                            static_cast<uint32_t>(array_size), par,
                            samples, warmup);
                    } else if (mode == ProtocolMode::PVXS_PVA ||
                               mode == ProtocolMode::SPVA ||
                               mode == ProtocolMode::SPVA_CERTMON) {
                        result = runPvaGetBenchmarkWithContext(
                            *bench_server.ctxt, protocolModeStr(mode),
                            bench_server.pvname,
                            static_cast<uint32_t>(array_size), par,
                            samples, warmup);
                    }

                    printGetSummary(result);
                    writeGetCsvRows(*out, result);
                    all_results.push_back(result);
                }
            }
        }

        printGetSummaryTable(all_results);

        if (benchmark_phases) {
            std::ofstream phase_file_out;
            std::ostream* phase_out = &std::cout;
            if (!phase_output.empty()) {
                phase_file_out.open(phase_output);
                if (!phase_file_out.is_open()) {
                    std::cerr << "Error: cannot open phase output file: " << phase_output << std::endl;
                    return 1;
                }
                phase_out = &phase_file_out;
            }
            writePhaseCsvHeader(*phase_out);

            std::vector<PhaseTimingResult> all_phase_results;
            for (const auto mode : modes) {
                if (mode == ProtocolMode::CA || mode == ProtocolMode::EPICS_PVA) {
                    std::cerr << "Note: " << protocolModeStr(mode)
                              << " excluded from phase timing (not a pvxs-based mode)" << std::endl;
                    continue;
                }
                if ((mode == ProtocolMode::SPVA || mode == ProtocolMode::SPVA_CERTMON) &&
                    !have_keychain) {
                    std::cerr << "Warning: skipping " << protocolModeStr(mode)
                              << " phase timing - no keychain" << std::endl;
                    continue;
                }
                if (mode == ProtocolMode::SPVA_CERTMON && !setup_cms && !external_cms) {
                    std::cerr << "Warning: skipping SPVA_CERTMON phase timing - no PVACMS configured"
                              << std::endl;
                    continue;
                }

                log_info_printf(perflog, "Phase timing %s (%u iterations)...\n",
                               protocolModeStr(mode), phase_iterations);

                const uint16_t cms_port = setup_cms ? kPvacmsUdpPort : 0u;
                const auto phase_results = runPvaPhaseTiming(mode, phase_iterations,
                                                              keychain, client_keychain,
                                                              cms_port);
                for (const auto& r : phase_results) {
                    writePhaseCsvRow(*phase_out, r);
                    all_phase_results.push_back(r);
                }
            }

            printComparisonTable(all_phase_results, phase_iterations);
        }

        if (pvacms_proc) {
            pvacms_proc->stop();
        }
        if (!tmp_cms_dir.empty()) {
            removeTempDir(tmp_cms_dir);
        }

        return 0;

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
