/**
 * pvxperf — Performance benchmarking tool for CA, PVA, SPVA, and SPVA+CERTMON.
 *
 * Measures monitor subscription throughput (updates/second) across four protocol
 * modes, with sequential (1 subscription) and parallel (N subscriptions) execution.
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <epicsThread.h>
#include <epicsTime.h>

#include <dbAccess.h>
#include <dbStaticLib.h>
#include <iocInit.h>
#include <iocsh.h>
#include <dbChannel.h>
#include <dbAddr.h>
#include <iocshRegisterCommon.h>

#include <cadef.h>

#include <pvxs/client.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/util.h>

#include <CLI/CLI.hpp>

using namespace pvxs;

namespace {

DEFINE_LOGGER(perflog, "pvxs.perf");

// ============================================================
// 2.2: Protocol mode enum
// ============================================================
enum class ProtocolMode { CA, PVA, SPVA, SPVA_CERTMON };

const char* protocolModeStr(ProtocolMode m) {
    switch (m) {
    case ProtocolMode::CA:           return "CA";
    case ProtocolMode::PVA:          return "PVA";
    case ProtocolMode::SPVA:         return "SPVA";
    case ProtocolMode::SPVA_CERTMON: return "SPVA_CERTMON";
    }
    return "UNKNOWN";
}

ProtocolMode parseProtocolMode(const std::string& s) {
    if (s == "ca" || s == "CA")                       return ProtocolMode::CA;
    if (s == "pva" || s == "PVA")                     return ProtocolMode::PVA;
    if (s == "spva" || s == "SPVA")                   return ProtocolMode::SPVA;
    if (s == "spva_certmon" || s == "SPVA_CERTMON")   return ProtocolMode::SPVA_CERTMON;
    throw std::runtime_error(std::string("Unknown protocol mode: ") + s);
}

std::vector<ProtocolMode> parseModes(const std::string& csv) {
    std::vector<ProtocolMode> modes;
    std::istringstream ss(csv);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // trim whitespace
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (!token.empty())
            modes.push_back(parseProtocolMode(token));
    }
    return modes;
}

// ============================================================
// 2.3: Execution style enum
// ============================================================
enum class ExecutionStyle { Sequential, Parallel };

const char* executionStyleStr(ExecutionStyle s) {
    return s == ExecutionStyle::Sequential ? "sequential" : "parallel";
}

// ============================================================
// Parse comma-separated sizes
// ============================================================
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

// ============================================================
// 5.1: Payload header encoding/decoding
// 16-byte header: [8-byte counter (NBO)][8-byte timestamp_us (NBO)]
// Minimum payload = 16 bytes; smaller payloads get counter-only (8 bytes min)
// ============================================================
constexpr size_t kHeaderSize = 16;
constexpr size_t kCounterSize = 8;

uint64_t toNetworkOrder64(uint64_t val) {
    uint32_t hi = htonl(static_cast<uint32_t>(val >> 32));
    uint32_t lo = htonl(static_cast<uint32_t>(val & 0xFFFFFFFF));
    uint64_t result;
    std::memcpy(&result, &hi, 4);
    std::memcpy(reinterpret_cast<char*>(&result) + 4, &lo, 4);
    return result;
}

uint64_t fromNetworkOrder64(uint64_t val) {
    return toNetworkOrder64(val);
}

void encodePayload(uint8_t* buf, size_t size, uint64_t counter, uint64_t timestamp_us) {
    if (size >= kCounterSize) {
        uint64_t net_counter = toNetworkOrder64(counter);
        std::memcpy(buf, &net_counter, kCounterSize);
    }
    if (size >= kHeaderSize) {
        uint64_t net_ts = toNetworkOrder64(timestamp_us);
        std::memcpy(buf + kCounterSize, &net_ts, kCounterSize);
    }
    // Fill remainder with deterministic pattern
    uint8_t fill = static_cast<uint8_t>(counter & 0xFF);
    size_t start = (size >= kHeaderSize) ? kHeaderSize : (size >= kCounterSize ? kCounterSize : 0);
    std::memset(buf + start, fill, size - start);
}

uint64_t decodeCounter(const uint8_t* buf, size_t size) {
    if (size < kCounterSize)
        return 0;
    uint64_t net_counter;
    std::memcpy(&net_counter, buf, kCounterSize);
    return fromNetworkOrder64(net_counter);
}

uint64_t currentTimestampUs() {
    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    return static_cast<uint64_t>(us);
}

// ============================================================
// Benchmark result structure
// ============================================================
struct BenchmarkResult {
    std::string protocol;
    std::string mode;
    size_t payloadBytes{0};
    double updatesPerSecond{0.0};
    uint64_t totalUpdates{0};
    uint64_t drops{0};
    uint64_t errors{0};
    double durationSeconds{0.0};
};

// ============================================================
// Per-subscription state for counter verification
// ============================================================
struct SubscriptionState {
    std::mutex mtx;
    bool firstUpdateSeen{false};
    bool warmupDone{false};
    uint64_t warmupRemaining{0};
    uint64_t expectedCounter{0};
    uint64_t successCount{0};
    uint64_t dropCount{0};
    uint64_t errorCount{0};
};

// ============================================================
// 7.1-7.8: PVACMS child process management (RAII)
// ============================================================
class PvacmsProcess {
public:
    PvacmsProcess() = default;
    ~PvacmsProcess() { stop(); }

    PvacmsProcess(const PvacmsProcess&) = delete;
    PvacmsProcess& operator=(const PvacmsProcess&) = delete;

    void start(const std::string& tmpDir,
               const std::string& overrideDb = {},
               const std::string& overrideKeychain = {},
               const std::string& overrideAcf = {}) {
        std::string certAuth = tmpDir + "/cert_auth.p12";
        std::string certsDb  = overrideDb.empty()       ? (tmpDir + "/certs.db")   : overrideDb;
        std::string pvacmsKc = overrideKeychain.empty()  ? (tmpDir + "/pvacms.p12") : overrideKeychain;
        std::string acfFile  = overrideAcf.empty()       ? (tmpDir + "/pvacms.acf") : overrideAcf;
        std::string adminKc  = tmpDir + "/admin.p12";

        pid_ = fork();
        if (pid_ < 0) {
            throw std::runtime_error("fork() failed for pvacms");
        }
        if (pid_ == 0) {
            setenv("EPICS_PVAS_INTF_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);
            setenv("EPICS_PVAS_AUTO_BEACON_ADDR_LIST", "NO", 1);

            execlp("pvacms", "pvacms",
                   "--certs-dont-require-approval",
                   "-c", certAuth.c_str(),
                   "-d", certsDb.c_str(),
                   "-p", pvacmsKc.c_str(),
                   "--acf", acfFile.c_str(),
                   "-a", adminKc.c_str(),
                   nullptr);
            _exit(127);
        }
        log_info_printf(perflog, "Launched pvacms as PID %d\n", pid_);
    }

    void stop() {
        if (pid_ > 0) {
            log_info_printf(perflog, "Stopping pvacms PID %d\n", pid_);
            kill(pid_, SIGTERM);
            int status = 0;
            waitpid(pid_, &status, 0);
            pid_ = -1;
        }
    }

    bool isRunning() const { return pid_ > 0; }

private:
    pid_t pid_{-1};
};

// ============================================================
// Wait for PVACMS readiness by probing CERT:ROOT:* PV
// ============================================================
bool waitForPvacms(double timeoutSec = 30.0) {
    log_info_printf(perflog, "Waiting for PVACMS readiness (timeout %.0fs)...\n", timeoutSec);

    // Use plain PVA (no TLS) for the probe — we don't have a keychain yet.
    // PVACMS serves CERT:ROOT on both plain PVA and TLS.
    auto conf = client::Config::fromEnv();
    conf.tls_disabled = true;
    auto ctxt = conf.build();

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(static_cast<int>(timeoutSec * 1000));

    while (std::chrono::steady_clock::now() < deadline) {
        try {
            auto result = ctxt.get("CERT:ROOT").exec()->wait(3.0);
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

// ============================================================
// Run authnstd to provision a keychain
// ============================================================
bool runAuthnstd(const std::string& name, const std::string& usage,
                 const std::string& keychainPath) {
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        // Child
        if (usage == "server") {
            setenv("EPICS_PVAS_TLS_KEYCHAIN", keychainPath.c_str(), 1);
        } else {
            setenv("EPICS_PVA_TLS_KEYCHAIN", keychainPath.c_str(), 1);
        }
        setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
        setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);

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

// ============================================================
// Create temp directory
// ============================================================
std::string createTempDir() {
    char tmpl[] = "/tmp/pvxperf-cms-XXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir)
        throw std::runtime_error("mkdtemp() failed");
    return std::string(dir);
}

// ============================================================
// Remove directory recursively (simple)
// ============================================================
void removeTempDir(const std::string& dir) {
    if (dir.empty() || dir == "/")
        return;
    std::string cmd = "rm -rf " + dir;
    (void)system(cmd.c_str());
}

// ============================================================
// 3.1-3.4, 5.1-5.6: PVA/SPVA benchmark
// ============================================================
BenchmarkResult runPvaBenchmark(
    ProtocolMode mode,
    ExecutionStyle style,
    size_t payloadSize,
    double durationSec,
    uint64_t warmupCount,
    uint32_t numSubscriptions,
    const std::string& serverKeychain,
    const std::string& clientKeychain)
{
    BenchmarkResult result;
    result.protocol = protocolModeStr(mode);
    result.mode = executionStyleStr(style);
    result.payloadBytes = payloadSize;

    // Enforce minimum payload size for header
    size_t effectiveSize = std::max(payloadSize, kHeaderSize);

    // Build server config
    auto sconfig = server::Config::isolated();

    if (mode == ProtocolMode::PVA) {
        sconfig.tls_disabled = true;
    } else {
        if (!serverKeychain.empty()) {
            setenv("EPICS_PVAS_TLS_KEYCHAIN", serverKeychain.c_str(), 1);
        }
        sconfig.tls_disabled = false;
#ifdef PVXS_ENABLE_EXPERT_API
        if (mode == ProtocolMode::SPVA) {
            sconfig.disableStatusCheck(true);
        } else {
            sconfig.disableStatusCheck(false);
        }
#endif
    }

    auto pv = server::SharedPV::buildReadonly();

    auto prototype = nt::NTScalar{TypeCode::UInt8A}.create();
    {
        shared_array<uint8_t> initialData(effectiveSize);
        encodePayload(initialData.data(), effectiveSize, 0, currentTimestampUs());
        prototype["value"] = initialData.freeze().castTo<const void>();
    }
    pv.open(prototype);

    const std::string pvname = "PVXPERF:BENCH";
    auto server = sconfig.build()
                      .addPV(pvname, pv)
                      .start();

    auto cconfig = server.clientConfig();
    if (mode == ProtocolMode::PVA) {
        cconfig.tls_disabled = true;
    } else {
        // Client may use a different keychain than the server (e.g. --setup-cms
        // provisions separate server.p12 and client.p12)
        const auto& ckc = clientKeychain.empty() ? serverKeychain : clientKeychain;
        if (!ckc.empty()) {
            setenv("EPICS_PVA_TLS_KEYCHAIN", ckc.c_str(), 1);
        }
        cconfig.tls_disabled = false;
#ifdef PVXS_ENABLE_EXPERT_API
        if (mode == ProtocolMode::SPVA) {
            cconfig.disableStatusCheck(true);
        } else {
            cconfig.disableStatusCheck(false);
        }
#endif
    }

    auto ctxt = cconfig.build();

    // Determine subscription count
    uint32_t numSubs = (style == ExecutionStyle::Sequential) ? 1 : numSubscriptions;

    std::vector<std::shared_ptr<SubscriptionState>> states(numSubs);
    std::vector<std::shared_ptr<client::Subscription>> subs(numSubs);
    std::atomic<uint32_t> connectedSubs{0};

    for (uint32_t i = 0; i < numSubs; i++) {
        states[i] = std::make_shared<SubscriptionState>();
        states[i]->warmupRemaining = warmupCount;
    }

    for (uint32_t i = 0; i < numSubs; i++) {
        auto& st = states[i];
        subs[i] = ctxt.monitor(pvname)
                      .record("pipeline", true)
                      .record("queueSize", int32_t(4))
                      .maskConnected(true)
                      .maskDisconnected(true)
                      .event([&st, &connectedSubs](client::Subscription& sub) {
                          try {
                              while (auto val = sub.pop()) {
                                  auto arr = val["value"].as<shared_array<const uint8_t>>();
                                  if (arr.empty())
                                      continue;

                                  uint64_t counter = decodeCounter(arr.data(), arr.size());

                                  std::lock_guard<std::mutex> lk(st->mtx);

                                  if (!st->firstUpdateSeen) {
                                      st->firstUpdateSeen = true;
                                      connectedSubs.fetch_add(1, std::memory_order_relaxed);
                                  }

                                  if (st->warmupRemaining > 0) {
                                      st->warmupRemaining--;
                                      if (st->warmupRemaining == 0) {
                                          st->warmupDone = true;
                                          st->expectedCounter = counter + 1;
                                      }
                                      continue;
                                  }

                                  if (counter == st->expectedCounter) {
                                      st->successCount++;
                                      st->expectedCounter++;
                                  } else if (counter > st->expectedCounter) {
                                      uint64_t gap = counter - st->expectedCounter;
                                      st->dropCount += gap;
                                      st->successCount++;
                                      st->expectedCounter = counter + 1;
                                  }
                              }
                          } catch (std::exception& e) {
                              std::lock_guard<std::mutex> lk(st->mtx);
                              st->errorCount++;
                          }
                      })
                      .exec();
    }

    // Wait for all subscriptions to receive the initial value from pv.open().
    // The pump must not start until connections are established, otherwise
    // the tight post() loop starves the event loop and prevents setup.
    {
        auto connDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (connectedSubs.load(std::memory_order_relaxed) < numSubs &&
               std::chrono::steady_clock::now() < connDeadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        uint32_t connected = connectedSubs.load(std::memory_order_relaxed);
        if (connected < numSubs) {
            log_warn_printf(perflog, "Only %u/%u subscriptions connected\n", connected, numSubs);
        }
        log_debug_printf(perflog, "%u/%u subscriptions connected, starting pump\n", connected, numSubs);
    }

    std::atomic<bool> stopPump{false};

    std::thread pumpThread([&]() {
        auto val = prototype.cloneEmpty();
        shared_array<uint8_t> buf(effectiveSize);
        uint64_t cnt = 0;

        while (!stopPump.load(std::memory_order_relaxed)) {
            encodePayload(buf.data(), effectiveSize, cnt, currentTimestampUs());

            auto frozen = buf.freeze().castTo<const void>();
            val["value"] = frozen;
            try {
                pv.post(val);
            } catch (std::exception& e) {
                log_debug_printf(perflog, "post() error: %s\n", e.what());
            }
            cnt++;
            buf = shared_array<uint8_t>(effectiveSize);
        }
    });

    auto warmupDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    bool allWarmedUp = false;
    while (std::chrono::steady_clock::now() < warmupDeadline) {
        allWarmedUp = true;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (!st->warmupDone) {
                allWarmedUp = false;
                break;
            }
        }
        if (allWarmedUp)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (!allWarmedUp) {
        log_warn_printf(perflog, "%s\n", "Warm-up did not complete for all subscriptions");
    }

    // Reset counters for measurement phase
    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        st->successCount = 0;
        st->dropCount = 0;
        st->errorCount = 0;
    }

    auto startTime = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(
        std::chrono::milliseconds(static_cast<int>(durationSec * 1000)));
    auto endTime = std::chrono::steady_clock::now();

    stopPump.store(true, std::memory_order_relaxed);
    pumpThread.join();

    double elapsed = std::chrono::duration<double>(endTime - startTime).count();
    uint64_t totalSuccess = 0;
    uint64_t totalDrops = 0;
    uint64_t totalErrors = 0;

    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        totalSuccess += st->successCount;
        totalDrops += st->dropCount;
        totalErrors += st->errorCount;
    }

    for (auto& sub : subs) {
        if (sub)
            sub->cancel();
    }

    result.updatesPerSecond = (elapsed > 0.0) ? (static_cast<double>(totalSuccess) / elapsed) : 0.0;
    result.totalUpdates = totalSuccess;
    result.drops = totalDrops;
    result.errors = totalErrors;
    result.durationSeconds = elapsed;

    return result;
}

// ============================================================
// 4.1-4.4: CA embedded IOC
// ============================================================

struct CaSubState {
    std::mutex mtx;
    bool warmupDone{false};
    uint64_t warmupRemaining{0};
    uint64_t expectedCounter{0};
    uint64_t successCount{0};
    uint64_t dropCount{0};
    uint64_t errorCount{0};
};

static void caMonitorCallback(struct event_handler_args args) {
    if (args.status != ECA_NORMAL || !args.usr)
        return;

    auto* st = static_cast<CaSubState*>(args.usr);
    auto* data = static_cast<const uint8_t*>(args.dbr);
    auto count = args.count;

    if (count < static_cast<long>(kCounterSize))
        return;

    uint64_t counter = decodeCounter(data, static_cast<size_t>(count));

    std::lock_guard<std::mutex> lk(st->mtx);
    if (st->warmupRemaining > 0) {
        st->warmupRemaining--;
        if (st->warmupRemaining == 0) {
            st->warmupDone = true;
            st->expectedCounter = counter + 1;
        }
        return;
    }

    if (counter == st->expectedCounter) {
        st->successCount++;
        st->expectedCounter++;
    } else if (counter > st->expectedCounter) {
        uint64_t gap = counter - st->expectedCounter;
        st->dropCount += gap;
        st->successCount++;
        st->expectedCounter = counter + 1;
    }
}

// RAII wrapper for IOC lifecycle — initialized once, reused across CA benchmarks
class EmbeddedIoc {
public:
    EmbeddedIoc() = default;
    ~EmbeddedIoc() { shutdown(); }

    EmbeddedIoc(const EmbeddedIoc&) = delete;
    EmbeddedIoc& operator=(const EmbeddedIoc&) = delete;

    bool init(size_t maxPayloadSize) {
        size_t nelm = std::max(maxPayloadSize, kHeaderSize);

        std::string dbdPath = std::string(PVXPERF_EPICS_BASE) + "/dbd/softIoc.dbd";
        if (dbLoadDatabase(dbdPath.c_str(), nullptr, nullptr) != 0) {
            log_warn_printf(perflog, "CA: could not load %s\n", dbdPath.c_str());
            return false;
        }

        registerAllRecordDeviceDrivers(pdbbase);

        std::ostringstream recDef;
        recDef << "record(waveform, \"PVXPERF:CA:BENCH\") {\n"
               << "  field(FTVL, \"UCHAR\")\n"
               << "  field(NELM, \"" << nelm << "\")\n"
               << "}\n";

        tmpDbPath_ = "/tmp/pvxperf_bench.db";
        {
            std::ofstream ofs(tmpDbPath_);
            ofs << recDef.str();
        }

        if (dbLoadRecords(tmpDbPath_.c_str(), nullptr) != 0) {
            log_warn_printf(perflog, "%s\n", "CA: could not load records");
            return false;
        }

        iocInit();

        if (dbNameToAddr("PVXPERF:CA:BENCH", &addr_) != 0) {
            log_warn_printf(perflog, "%s\n", "CA: dbNameToAddr failed");
            return false;
        }

        initialized_ = true;
        return true;
    }

    void shutdown() {
        if (initialized_) {
            iocShutdown();
            if (!tmpDbPath_.empty())
                unlink(tmpDbPath_.c_str());
            initialized_ = false;
        }
    }

    DBADDR* addr() { return &addr_; }
    bool isInitialized() const { return initialized_; }

private:
    bool initialized_{false};
    DBADDR addr_{};
    std::string tmpDbPath_;
};

BenchmarkResult runCaBenchmark(
    EmbeddedIoc& ioc,
    ExecutionStyle style,
    size_t payloadSize,
    double durationSec,
    uint64_t warmupCount,
    uint32_t numSubscriptions)
{
    BenchmarkResult result;
    result.protocol = "CA";
    result.mode = executionStyleStr(style);
    result.payloadBytes = payloadSize;

    if (!ioc.isInitialized()) {
        result.errors = 1;
        return result;
    }

    size_t effectiveSize = std::max(payloadSize, kHeaderSize);

    int caStatus = ca_context_create(ca_enable_preemptive_callback);
    if (caStatus != ECA_NORMAL) {
        log_warn_printf(perflog, "%s\n", "CA: ca_context_create failed");
        result.errors = 1;
        return result;
    }

    chid chanId = nullptr;
    caStatus = ca_create_channel("PVXPERF:CA:BENCH", nullptr, nullptr, 0, &chanId);
    if (caStatus != ECA_NORMAL || !chanId) {
        log_warn_printf(perflog, "%s\n", "CA: ca_create_channel failed");
        ca_context_destroy();
        result.errors = 1;
        return result;
    }
    ca_pend_io(5.0);

    uint32_t numSubs = (style == ExecutionStyle::Sequential) ? 1 : numSubscriptions;

    std::vector<std::shared_ptr<CaSubState>> states(numSubs);
    std::vector<evid> evids(numSubs, nullptr);

    for (uint32_t i = 0; i < numSubs; i++) {
        states[i] = std::make_shared<CaSubState>();
        states[i]->warmupRemaining = warmupCount;

        caStatus = ca_create_subscription(
            DBR_CHAR,
            static_cast<unsigned long>(effectiveSize),
            chanId,
            DBE_VALUE,
            caMonitorCallback,
            states[i].get(),
            &evids[i]);

        if (caStatus != ECA_NORMAL) {
            log_warn_printf(perflog, "CA: ca_create_subscription %u failed\n", i);
        }
    }
    ca_flush_io();

    std::atomic<bool> stopPump{false};

    // Seed phase: slow updates so CA can dispatch to all subscriptions before
    // the tight pump loop begins. Scale seed count with subscription count —
    // each dbPutField fans out to numSubs callbacks.
    {
        std::vector<uint8_t> seedBuf(effectiveSize);
        uint32_t seedCount = std::max(uint32_t(20), numSubs / 10);
        for (uint32_t i = 0; i < seedCount; i++) {
            encodePayload(seedBuf.data(), effectiveSize, 0, currentTimestampUs());
            dbPutField(ioc.addr(), DBF_UCHAR, seedBuf.data(), static_cast<long>(effectiveSize));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::thread pumpThread([&]() {
        std::vector<uint8_t> buf(effectiveSize);
        uint64_t cnt = 0;

        while (!stopPump.load(std::memory_order_relaxed)) {
            encodePayload(buf.data(), effectiveSize, cnt, currentTimestampUs());
            dbPutField(ioc.addr(), DBF_UCHAR, buf.data(), static_cast<long>(effectiveSize));
            cnt++;
            // Yield periodically so CA event dispatch can keep up with many subscribers
            if (numSubs > 100 && (cnt & 0xFF) == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    });

    double warmupTimeoutSec = std::max(30.0, static_cast<double>(numSubs) / 10.0);
    auto warmupDeadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(static_cast<int>(warmupTimeoutSec * 1000));
    bool allWarmedUp = false;
    while (std::chrono::steady_clock::now() < warmupDeadline) {
        allWarmedUp = true;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (!st->warmupDone) {
                allWarmedUp = false;
                break;
            }
        }
        if (allWarmedUp)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (!allWarmedUp) {
        uint32_t warmedCount = 0;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (st->warmupDone) warmedCount++;
        }
        log_warn_printf(perflog, "CA warm-up: only %u/%u subscriptions warmed up\n",
                        warmedCount, numSubs);
    }

    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        st->successCount = 0;
        st->dropCount = 0;
        st->errorCount = 0;
    }

    auto startTime = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(
        std::chrono::milliseconds(static_cast<int>(durationSec * 1000)));
    auto endTime = std::chrono::steady_clock::now();

    stopPump.store(true, std::memory_order_relaxed);
    pumpThread.join();

    double elapsed = std::chrono::duration<double>(endTime - startTime).count();
    uint64_t totalSuccess = 0, totalDrops = 0, totalErrors = 0;
    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        totalSuccess += st->successCount;
        totalDrops += st->dropCount;
        totalErrors += st->errorCount;
    }

    for (auto& eid : evids) {
        if (eid)
            ca_clear_subscription(eid);
    }
    ca_clear_channel(chanId);
    ca_context_destroy();

    result.updatesPerSecond = (elapsed > 0.0) ? (static_cast<double>(totalSuccess) / elapsed) : 0.0;
    result.totalUpdates = totalSuccess;
    result.drops = totalDrops;
    result.errors = totalErrors;
    result.durationSeconds = elapsed;

    return result;
}

// ============================================================
// 6.1-6.3: CSV output
// ============================================================
void writeCsvHeader(std::ostream& out) {
    out << "protocol,mode,payload_bytes,updates_per_second,total_updates,drops,errors,duration_seconds"
        << std::endl;
}

void writeCsvRow(std::ostream& out, const BenchmarkResult& r) {
    out << r.protocol << ","
        << r.mode << ","
        << r.payloadBytes << ","
        << r.updatesPerSecond << ","
        << r.totalUpdates << ","
        << r.drops << ","
        << r.errors << ","
        << r.durationSeconds
        << std::endl;
    out.flush();
}

} // namespace

// ============================================================
// 2.1: Main entry point with CLI11
// ============================================================
int main(int argc, char* argv[]) {
    try {
        logger_config_env();

        CLI::App app{
            "pvxperf — Performance benchmarking tool for CA, PVA, SPVA, SPVA+CERTMON.\n\n"
            "WARNING: Run on a network with no other active PVACMS to avoid\n"
            "interference with benchmark results.\n"
        };

        double duration = 5.0;
        uint64_t warmup = 100;
        uint32_t subscriptions = 1000;
        std::string sizesStr = "1,10,100,1000,10000,100000";
        std::string modesStr = "ca,pva,spva,spva_certmon";
        std::string keychain;
        std::string outputFile;
        bool setupCms = false;
        bool externalCms = false;
        std::string cmsDb, cmsKeychain, cmsAcf;
        bool debug = false;
        bool showVersion = false;

        app.add_option("--duration", duration, "Measurement duration per data point in seconds")
            ->default_val(5.0);
        app.add_option("--warmup", warmup, "Number of warm-up updates before measurement")
            ->default_val(100);
        app.add_option("--subscriptions", subscriptions,
                        "Number of parallel monitor subscriptions (parallel mode)")
            ->default_val(1000);
        app.add_option("--sizes", sizesStr, "Comma-separated payload sizes in bytes")
            ->default_val("1,10,100,1000,10000,100000");
        app.add_option("--modes", modesStr, "Comma-separated protocol modes: ca,pva,spva,spva_certmon")
            ->default_val("ca,pva,spva,spva_certmon");
        app.add_option("--keychain", keychain, "TLS keychain file for SPVA modes");
        app.add_option("--output", outputFile, "CSV output file (default: stdout)");
        app.add_flag("--setup-cms", setupCms,
                     "Auto-bootstrap PVACMS with temp certs for SPVA_CERTMON");
        app.add_flag("--external-cms", externalCms,
                     "Use already-running PVACMS for SPVA_CERTMON");
        app.add_option("--cms-db", cmsDb, "Path to existing PVACMS SQLite database");
        app.add_option("--cms-keychain", cmsKeychain, "Path to existing PVACMS server keychain");
        app.add_option("--cms-acf", cmsAcf, "Path to existing PVACMS ACF file");
        app.add_flag("-d,--debug", debug, "Enable PVXS debug logging");
        app.add_flag("-V,--version", showVersion, "Print version and exit");

        CLI11_PARSE(app, argc, argv);

        if (showVersion) {
            version_information(std::cout);
            return 0;
        }

        if (debug) {
            setenv("PVXS_LOG", "pvxs.*=DEBUG", 1);
            logger_config_env();
        }

        auto modes = parseModes(modesStr);
        auto sizes = parseSizes(sizesStr);

        // Open output
        std::ofstream fileOut;
        std::ostream* out = &std::cout;
        if (!outputFile.empty()) {
            fileOut.open(outputFile);
            if (!fileOut.is_open()) {
                std::cerr << "Error: cannot open output file: " << outputFile << std::endl;
                return 1;
            }
            out = &fileOut;
        }

        std::string clientKeychain;
        bool haveKeychain = !keychain.empty();

        std::string tmpCmsDir;
        std::unique_ptr<PvacmsProcess> pvacmsProc;

        if (setupCms) {
            tmpCmsDir = createTempDir();
            log_info_printf(perflog, "CMS temp directory: %s\n", tmpCmsDir.c_str());

            setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);

            pvacmsProc.reset(new PvacmsProcess());
            pvacmsProc->start(tmpCmsDir, cmsDb, cmsKeychain, cmsAcf);

            if (!waitForPvacms(30.0)) {
                std::cerr << "Error: PVACMS did not become ready within timeout" << std::endl;
                return 1;
            }

            std::string serverKc = tmpCmsDir + "/server.p12";
            std::string clientKc = tmpCmsDir + "/client.p12";

            if (!runAuthnstd("pvxperf-server", "server", serverKc)) {
                std::cerr << "Error: failed to provision server keychain" << std::endl;
                return 1;
            }
            if (!runAuthnstd("pvxperf-client", "client", clientKc)) {
                std::cerr << "Error: failed to provision client keychain" << std::endl;
                return 1;
            }

            if (keychain.empty()) {
                keychain = serverKc;
                clientKeychain = clientKc;
                haveKeychain = true;
            }

            log_info_printf(perflog, "%s\n", "CMS setup complete, keychains provisioned");
        }

        writeCsvHeader(*out);

        bool needsCa = std::any_of(modes.begin(), modes.end(),
            [](ProtocolMode m) { return m == ProtocolMode::CA; });

        EmbeddedIoc caIoc;
        if (needsCa) {
            size_t maxSize = *std::max_element(sizes.begin(), sizes.end());
            if (!caIoc.init(maxSize)) {
                std::cerr << "Warning: CA IOC init failed, CA benchmarks will be skipped" << std::endl;
            }
        }

        for (auto mode : modes) {
            if ((mode == ProtocolMode::SPVA || mode == ProtocolMode::SPVA_CERTMON) && !haveKeychain) {
                std::cerr << "Warning: skipping " << protocolModeStr(mode)
                          << " — no keychain available" << std::endl;
                continue;
            }

            if (mode == ProtocolMode::SPVA_CERTMON && !setupCms && !externalCms) {
                std::cerr << "Warning: skipping SPVA_CERTMON — no CMS configured "
                          << "(use --setup-cms or --external-cms)" << std::endl;
                continue;
            }

            if (mode == ProtocolMode::SPVA_CERTMON && externalCms) {
                if (!waitForPvacms(10.0)) {
                    std::cerr << "Warning: skipping SPVA_CERTMON — external CMS not reachable" << std::endl;
                    continue;
                }
            }

            for (auto payloadSize : sizes) {
                for (auto style : {ExecutionStyle::Sequential, ExecutionStyle::Parallel}) {
                    log_info_printf(perflog, "Benchmarking %s %s %zu bytes...\n",
                                   protocolModeStr(mode), executionStyleStr(style), payloadSize);

                    BenchmarkResult result;

                    if (mode == ProtocolMode::CA) {
                        result = runCaBenchmark(caIoc, style, payloadSize, duration,
                                               warmup, subscriptions);
                    } else {
                        result = runPvaBenchmark(mode, style, payloadSize, duration,
                                                 warmup, subscriptions, keychain, clientKeychain);
                    }

                    writeCsvRow(*out, result);

                    log_info_printf(perflog, "  -> %.1f updates/sec, %lu total, %lu drops, %lu errors\n",
                                   result.updatesPerSecond,
                                   (unsigned long)result.totalUpdates,
                                   (unsigned long)result.drops,
                                   (unsigned long)result.errors);
                }
            }
        }

        // Cleanup
        if (pvacmsProc) {
            pvacmsProc->stop();
        }
        if (!tmpCmsDir.empty()) {
            removeTempDir(tmpCmsDir);
        }

        return 0;

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
