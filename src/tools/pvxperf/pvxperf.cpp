/**
 * pvxperf — Performance benchmarking tool for CA, PVA, SPVA, and SPVA+CERTMON.
 *
 * Measures monitor subscription throughput (updates/second) across four protocol
 * modes, sweeping across configurable subscriber counts (default: 1,10,100,500,1000).
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

#ifndef HAS_registerAllRecordDeviceDrivers
extern "C" {
long registerAllRecordDeviceDrivers(struct dbBase *pdbbase);
}
#endif

// db_access.h (included by cadef.h) redefines macros from dbFldTypes.h/dbAccessDefs.h
#undef DBR_SHORT
#undef DBR_GR_LONG
#undef DBR_GR_DOUBLE
#undef DBR_CTRL_LONG
#undef DBR_CTRL_DOUBLE
#undef DBR_PUT_ACKT
#undef DBR_PUT_ACKS
#undef VALID_DB_REQ
#undef INVALID_DB_REQ
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

const char* protocol_mode_str(const ProtocolMode m) {
    switch (m) {
    case ProtocolMode::CA:           return "CA";
    case ProtocolMode::PVA:          return "PVA";
    case ProtocolMode::SPVA:         return "SPVA";
    case ProtocolMode::SPVA_CERTMON: return "SPVA_CERTMON";
    }
    return "UNKNOWN";
}

ProtocolMode parse_protocol_mode(const std::string& s) {
    if (s == "ca" || s == "CA")                       return ProtocolMode::CA;
    if (s == "pva" || s == "PVA")                     return ProtocolMode::PVA;
    if (s == "spva" || s == "SPVA")                   return ProtocolMode::SPVA;
    if (s == "spva_certmon" || s == "SPVA_CERTMON")   return ProtocolMode::SPVA_CERTMON;
    throw std::runtime_error(std::string("Unknown protocol mode: ") + s);
}

std::vector<ProtocolMode> parse_modes(const std::string& csv) {
    std::vector<ProtocolMode> modes;
    std::istringstream ss(csv);
    std::string token;
    while (std::getline(ss, token, ',')) {
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        if (!token.empty())
            modes.push_back(parse_protocol_mode(token));
    }
    return modes;
}

// ============================================================
// Parse comma-separated sizes
// ============================================================
std::vector<size_t> parse_sizes(const std::string& csv) {
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
// Parse comma-separated subscription counts
// ============================================================
std::vector<uint32_t> parse_sub_counts(const std::string& csv) {
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

// ============================================================
// Payload header encoding/decoding
// 16-byte header: [8-byte counter (NBO)][8-byte timestamp_us (NBO)]
// Minimum payload = 16 bytes; smaller payloads get counter-only (8 bytes min)
// ============================================================
constexpr size_t kHeaderSize = 16;
constexpr size_t kCounterSize = 8;

uint64_t to_network_order_64(const uint64_t val) {
    const uint32_t hi = htonl(static_cast<uint32_t>(val >> 32));
    const uint32_t lo = htonl(static_cast<uint32_t>(val & 0xFFFFFFFF));
    uint64_t result;
    std::memcpy(&result, &hi, 4);
    std::memcpy(reinterpret_cast<char*>(&result) + 4, &lo, 4);
    return result;
}

uint64_t from_network_order_64(const uint64_t val) {
    return to_network_order_64(val);
}

void encode_payload(uint8_t* buf, const size_t size, const uint64_t counter, const uint64_t timestamp_us) {
    if (size >= kCounterSize) {
        const uint64_t net_counter = to_network_order_64(counter);
        std::memcpy(buf, &net_counter, kCounterSize);
    }
    if (size >= kHeaderSize) {
        const uint64_t net_ts = to_network_order_64(timestamp_us);
        std::memcpy(buf + kCounterSize, &net_ts, kCounterSize);
    }
    const auto fill = static_cast<uint8_t>(counter & 0xFF);
    const size_t start = (size >= kHeaderSize) ? kHeaderSize : (size >= kCounterSize ? kCounterSize : 0);
    std::memset(buf + start, fill, size - start);
}

uint64_t decode_counter(const uint8_t* buf, const size_t size) {
    if (size < kCounterSize)
        return 0;
    uint64_t net_counter;
    std::memcpy(&net_counter, buf, kCounterSize);
    return from_network_order_64(net_counter);
}

uint64_t current_timestamp_us() {
    const auto now = std::chrono::system_clock::now();
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    return static_cast<uint64_t>(us);
}

// ============================================================
// Benchmark result structure
// ============================================================
struct BenchmarkResult {
    std::string protocol;
    std::string payload_mode{"raw"};
    uint32_t subscribers{0};
    size_t payload_bytes{0};
    double updates_per_second{0.0};
    double per_sub_updates_per_second{0.0};
    uint64_t total_updates{0};
    uint64_t drops{0};
    uint64_t errors{0};
    double duration_seconds{0.0};
};

// ============================================================
// Per-subscription state for counter verification
// ============================================================
struct SubscriptionState {
    std::mutex mtx;
    bool first_update_seen{false};
    bool warmup_done{false};
    uint64_t warmup_remaining{0};
    uint64_t expected_counter{0};
    uint64_t success_count{0};
    uint64_t drop_count{0};
    uint64_t error_count{0};
};

// ============================================================
// PVACMS child process management (RAII)
// ============================================================
class PvacmsProcess {
public:
    PvacmsProcess() = default;
    ~PvacmsProcess() { stop(); }

    PvacmsProcess(const PvacmsProcess&) = delete;
    PvacmsProcess& operator=(const PvacmsProcess&) = delete;

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

    void stop() {
        if (pid_ > 0) {
            log_info_printf(perflog, "Stopping pvacms PID %d\n", pid_);
            kill(pid_, SIGTERM);
            int status = 0;
            waitpid(pid_, &status, 0);
            pid_ = -1;
        }
    }

    bool is_running() const { return pid_ > 0; }

private:
    pid_t pid_{-1};
};

// ============================================================
// Wait for PVACMS readiness by probing CERT:ROOT:* PV
// ============================================================
bool wait_for_pvacms(const double timeout_sec = 30.0) {
    log_info_printf(perflog, "Waiting for PVACMS readiness (timeout %.0fs)...\n", timeout_sec);

    // Use plain PVA (no TLS) for the probe — we don't have a keychain yet.
    // PVACMS serves CERT:ROOT on both plain PVA and TLS.
    auto conf = client::Config::fromEnv();
    conf.tls_disabled = true;
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

// ============================================================
// Run authnstd to provision a keychain
// ============================================================
bool run_authnstd(const std::string& name, const std::string& usage,
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
std::string create_temp_dir() {
    char tmpl[] = "/tmp/pvxperf-cms-XXXXXX";
    const char* dir = mkdtemp(tmpl);
    if (!dir)
        throw std::runtime_error("mkdtemp() failed");
    return std::string(dir);
}

// ============================================================
// Remove directory recursively (simple)
// ============================================================
void remove_temp_dir(const std::string& dir) {
    if (dir.empty() || dir == "/")
        return;
    const std::string cmd = "rm -rf " + dir;
    if (system(cmd.c_str()) != 0) {
        log_warn_printf(perflog, "Failed to remove temp dir: %s\n", dir.c_str());
    }
}

// ============================================================
// PVA/SPVA benchmark
// ============================================================
BenchmarkResult run_pva_benchmark(
    const ProtocolMode mode,
    const size_t payload_size,
    const double duration_sec,
    const uint64_t warmup_count,
    const uint32_t num_subscriptions,
    const std::string& server_keychain,
    const std::string& client_keychain,
    const bool nt_payload)
{
    BenchmarkResult result;
    result.protocol = protocol_mode_str(mode);
    result.payload_mode = nt_payload ? "nt" : "raw";
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;

    // In raw mode, minimum payload = kHeaderSize (counter + timestamp in array).
    // In NT mode, timestamp lives in NT fields, so minimum = kCounterSize.
    const size_t min_size = nt_payload ? kCounterSize : kHeaderSize;
    const size_t effective_size = std::max(payload_size, min_size);

    auto sconfig = server::Config::isolated();

    if (mode == ProtocolMode::PVA) {
        sconfig.tls_disabled = true;
    } else {
        if (!server_keychain.empty()) {
            setenv("EPICS_PVAS_TLS_KEYCHAIN", server_keychain.c_str(), 1);
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
        shared_array<uint8_t> initial_data(effective_size);
        if (nt_payload) {
            const uint64_t net_counter = to_network_order_64(0);
            std::memcpy(initial_data.data(), &net_counter, kCounterSize);
            std::memset(initial_data.data() + kCounterSize, 0, effective_size - kCounterSize);
        } else {
            encode_payload(initial_data.data(), effective_size, 0, current_timestamp_us());
        }
        prototype["value"] = initial_data.freeze().castTo<const void>();
        if (nt_payload) {
            const auto now = std::chrono::system_clock::now();
            const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
            const auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()) - secs;
            prototype["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(secs.count());
            prototype["timeStamp.nanoseconds"] = static_cast<int32_t>(nsecs.count());
        }
    }
    pv.open(prototype);

    const std::string pvname = "PVXPERF:BENCH";
    const auto server = sconfig.build()
                      .addPV(pvname, pv)
                      .start();

    auto cconfig = server.clientConfig();
    if (mode == ProtocolMode::PVA) {
        cconfig.tls_disabled = true;
    } else {
        const auto& ckc = client_keychain.empty() ? server_keychain : client_keychain;
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

    const uint32_t num_subs = num_subscriptions;

    std::vector<std::shared_ptr<SubscriptionState>> states(num_subs);
    std::vector<std::shared_ptr<client::Subscription>> subs(num_subs);
    std::atomic<uint32_t> connected_subs{0};

    for (uint32_t i = 0; i < num_subs; i++) {
        states[i] = std::make_shared<SubscriptionState>();
        states[i]->warmup_remaining = warmup_count;
    }

    for (uint32_t i = 0; i < num_subs; i++) {
        const auto st = states[i];
        subs[i] = ctxt.monitor(pvname)
                      .record("pipeline", true)
                      .record("queueSize", int32_t(4))
                      .maskConnected(true)
                      .maskDisconnected(true)
                      .event([st, &connected_subs](client::Subscription& sub) {
                          try {
                              while (auto val = sub.pop()) {
                                  const auto arr = val["value"].as<shared_array<const uint8_t>>();
                                  if (arr.empty())
                                      continue;

                                  const uint64_t counter = decode_counter(arr.data(), arr.size());

                                  std::lock_guard<std::mutex> lk(st->mtx);

                                  if (!st->first_update_seen) {
                                      st->first_update_seen = true;
                                      connected_subs.fetch_add(1, std::memory_order_relaxed);
                                  }

                                  if (st->warmup_remaining > 0) {
                                      st->warmup_remaining--;
                                      if (st->warmup_remaining == 0) {
                                          st->warmup_done = true;
                                          st->expected_counter = counter + 1;
                                      }
                                      continue;
                                  }

                                  if (counter == st->expected_counter) {
                                      st->success_count++;
                                      st->expected_counter++;
                                  } else if (counter > st->expected_counter) {
                                      const uint64_t gap = counter - st->expected_counter;
                                      st->drop_count += gap;
                                      st->success_count++;
                                      st->expected_counter = counter + 1;
                                  }
                              }
                          } catch (std::exception& e) {
                              std::lock_guard<std::mutex> lk(st->mtx);
                              st->error_count++;
                          }
                      })
                      .exec();
    }

    // Wait for all subscriptions to receive the initial value from pv.open().
    // The pump must not start until connections are established, otherwise
    // the tight post() loop starves the event loop and prevents setup.
    {
        const auto conn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (connected_subs.load(std::memory_order_relaxed) < num_subs &&
               std::chrono::steady_clock::now() < conn_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const uint32_t connected = connected_subs.load(std::memory_order_relaxed);
        if (connected < num_subs) {
            log_warn_printf(perflog, "Only %u/%u subscriptions connected\n", connected, num_subs);
        }
        log_debug_printf(perflog, "%u/%u subscriptions connected, starting pump\n", connected, num_subs);
    }

    std::atomic<bool> stop_pump{false};

    // Pre-allocate a ring of Values so the pump never races the event loop
    // on buffer ownership. Each Value owns its own independent shared_array.
    constexpr size_t kRingSize = 64;
    std::vector<Value> ring(kRingSize);
    for (size_t i = 0; i < kRingSize; i++) {
        ring[i] = prototype.cloneEmpty();
        shared_array<uint8_t> buf(effective_size);
        ring[i]["value"] = buf.freeze().castTo<const void>();
    }

    std::thread pump_thread([&]() {
        uint64_t cnt = 0;

        while (!stop_pump.load(std::memory_order_relaxed)) {
            auto& val = ring[cnt % kRingSize];
            {
                shared_array<uint8_t> buf(effective_size);
                if (nt_payload) {
                    const uint64_t net_counter = to_network_order_64(cnt);
                    std::memcpy(buf.data(), &net_counter, kCounterSize);
                    const auto fill = static_cast<uint8_t>(cnt & 0xFF);
                    std::memset(buf.data() + kCounterSize, fill, effective_size - kCounterSize);
                } else {
                    encode_payload(buf.data(), effective_size, cnt, current_timestamp_us());
                }
                val["value"] = buf.freeze().castTo<const void>();

                if (nt_payload) {
                    const auto now = std::chrono::system_clock::now();
                    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
                    const auto nsecs = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()) - secs;
                    val["timeStamp.secondsPastEpoch"] = static_cast<int64_t>(secs.count());
                    val["timeStamp.nanoseconds"] = static_cast<int32_t>(nsecs.count());
                }
            }
            try {
                pv.post(val);
            } catch (std::exception& e) {
                log_debug_printf(perflog, "post() error: %s\n", e.what());
            }
            cnt++;
        }
    });

    auto warmup_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    bool all_warmed_up = false;
    while (std::chrono::steady_clock::now() < warmup_deadline) {
        all_warmed_up = true;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (!st->warmup_done) {
                all_warmed_up = false;
                break;
            }
        }
        if (all_warmed_up)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (!all_warmed_up) {
        log_warn_printf(perflog, "%s\n", "Warm-up did not complete for all subscriptions");
    }

    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        st->success_count = 0;
        st->drop_count = 0;
        st->error_count = 0;
    }

    const auto start_time = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(
        std::chrono::milliseconds(static_cast<int>(duration_sec * 1000)));
    const auto end_time = std::chrono::steady_clock::now();

    stop_pump.store(true, std::memory_order_relaxed);
    pump_thread.join();

    const double elapsed = std::chrono::duration<double>(end_time - start_time).count();
    uint64_t total_success = 0;
    uint64_t total_drops = 0;
    uint64_t total_errors = 0;

    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        total_success += st->success_count;
        total_drops += st->drop_count;
        total_errors += st->error_count;
    }

    for (auto& sub : subs) {
        if (sub)
            sub->cancel();
    }

    result.updates_per_second = (elapsed > 0.0) ? (static_cast<double>(total_success) / elapsed) : 0.0;
    result.per_sub_updates_per_second = (num_subs > 0) ? (result.updates_per_second / num_subs) : 0.0;
    result.total_updates = total_success;
    result.drops = total_drops;
    result.errors = total_errors;
    result.duration_seconds = elapsed;

    return result;
}

// ============================================================
// 4.1-4.4: CA embedded IOC
// ============================================================

struct CaSubState {
    std::mutex mtx;
    bool warmup_done{false};
    uint64_t warmup_remaining{0};
    uint64_t expected_counter{0};
    uint64_t success_count{0};
    uint64_t drop_count{0};
    uint64_t error_count{0};
};

static void ca_monitor_callback(struct event_handler_args args) {
    if (args.status != ECA_NORMAL || !args.usr)
        return;

    auto* st = static_cast<CaSubState*>(args.usr);
    const auto* data = static_cast<const uint8_t*>(args.dbr);
    const auto count = args.count;

    if (count < static_cast<long>(kCounterSize))
        return;

    const uint64_t counter = decode_counter(data, static_cast<size_t>(count));

    std::lock_guard<std::mutex> lk(st->mtx);
    if (st->warmup_remaining > 0) {
        st->warmup_remaining--;
        if (st->warmup_remaining == 0) {
            st->warmup_done = true;
            st->expected_counter = counter + 1;
        }
        return;
    }

    if (counter == st->expected_counter) {
        st->success_count++;
        st->expected_counter++;
    } else if (counter > st->expected_counter) {
        const uint64_t gap = counter - st->expected_counter;
        st->drop_count += gap;
        st->success_count++;
        st->expected_counter = counter + 1;
    }
}

// RAII wrapper for IOC lifecycle — initialized once, reused across CA benchmarks
class EmbeddedIoc {
public:
    EmbeddedIoc() = default;
    ~EmbeddedIoc() { shutdown(); }

    EmbeddedIoc(const EmbeddedIoc&) = delete;
    EmbeddedIoc& operator=(const EmbeddedIoc&) = delete;

    bool init(const size_t max_payload_size) {
        const size_t nelm = std::max(max_payload_size, kHeaderSize);

        setenv("EPICS_CAS_INTF_ADDR_LIST", "127.0.0.1", 1);
        setenv("EPICS_CAS_AUTO_BEACON_ADDR_LIST", "NO", 1);
        setenv("EPICS_CAS_BEACON_ADDR_LIST", "127.0.0.1", 1);
        setenv("EPICS_CA_ADDR_LIST", "127.0.0.1", 1);
        setenv("EPICS_CA_AUTO_ADDR_LIST", "NO", 1);

        const std::string dbd_path = std::string(PVXPERF_EPICS_BASE) + "/dbd/softIoc.dbd";
        if (dbLoadDatabase(dbd_path.c_str(), nullptr, nullptr) != 0) {
            log_warn_printf(perflog, "CA: could not load %s\n", dbd_path.c_str());
            return false;
        }

        registerAllRecordDeviceDrivers(pdbbase);

        std::ostringstream rec_def;
        rec_def << "record(waveform, \"PVXPERF:CA:BENCH\") {\n"
                << "  field(FTVL, \"UCHAR\")\n"
                << "  field(NELM, \"" << nelm << "\")\n"
                << "}\n";

        tmp_db_path_ = "/tmp/pvxperf_bench.db";
        {
            std::ofstream ofs(tmp_db_path_);
            ofs << rec_def.str();
        }

        if (dbLoadRecords(tmp_db_path_.c_str(), nullptr) != 0) {
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
            if (!tmp_db_path_.empty())
                unlink(tmp_db_path_.c_str());
            initialized_ = false;
        }
    }

    DBADDR* addr() { return &addr_; }
    bool is_initialized() const { return initialized_; }

private:
    bool initialized_{false};
    DBADDR addr_{};
    std::string tmp_db_path_;
};

BenchmarkResult run_ca_benchmark(
    EmbeddedIoc& ioc,
    const size_t payload_size,
    const double duration_sec,
    const uint64_t warmup_count,
    const uint32_t num_subscriptions)
{
    BenchmarkResult result;
    result.protocol = "CA";
    result.payload_mode = "raw";
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;

    if (!ioc.is_initialized()) {
        result.errors = 1;
        return result;
    }

    const size_t effective_size = std::max(payload_size, kHeaderSize);

    int ca_status = ca_context_create(ca_enable_preemptive_callback);
    if (ca_status != ECA_NORMAL) {
        log_warn_printf(perflog, "%s\n", "CA: ca_context_create failed");
        result.errors = 1;
        return result;
    }

    chid chan_id = nullptr;
    ca_status = ca_create_channel("PVXPERF:CA:BENCH", nullptr, nullptr, 0, &chan_id);
    if (ca_status != ECA_NORMAL || !chan_id) {
        log_warn_printf(perflog, "%s\n", "CA: ca_create_channel failed");
        ca_context_destroy();
        result.errors = 1;
        return result;
    }
    ca_pend_io(5.0);

    const uint32_t num_subs = num_subscriptions;

    std::vector<std::shared_ptr<CaSubState>> states(num_subs);
    std::vector<evid> evids(num_subs, nullptr);

    for (uint32_t i = 0; i < num_subs; i++) {
        states[i] = std::make_shared<CaSubState>();
        states[i]->warmup_remaining = warmup_count;

        ca_status = ca_create_subscription(
            DBR_CHAR,
            static_cast<unsigned long>(effective_size),
            chan_id,
            DBE_VALUE,
            ca_monitor_callback,
            states[i].get(),
            &evids[i]);

        if (ca_status != ECA_NORMAL) {
            log_warn_printf(perflog, "CA: ca_create_subscription %u failed\n", i);
        }
    }
    ca_flush_io();

    std::atomic<bool> stop_pump{false};

    // Seed phase: slow updates so CA can dispatch to all subscriptions before
    // the tight pump loop begins. Scale seed count with subscription count —
    // each dbPutField fans out to num_subs callbacks.
    {
        std::vector<uint8_t> seed_buf(effective_size);
        const uint32_t seed_count = std::max(uint32_t(20), num_subs / 10);
        for (uint32_t i = 0; i < seed_count; i++) {
            encode_payload(seed_buf.data(), effective_size, 0, current_timestamp_us());
            dbPutField(ioc.addr(), DBF_UCHAR, seed_buf.data(), static_cast<long>(effective_size));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::thread pump_thread([&]() {
        std::vector<uint8_t> buf(effective_size);
        uint64_t cnt = 0;

        while (!stop_pump.load(std::memory_order_relaxed)) {
            encode_payload(buf.data(), effective_size, cnt, current_timestamp_us());
            dbPutField(ioc.addr(), DBF_UCHAR, buf.data(), static_cast<long>(effective_size));
            cnt++;
            // Yield periodically so CA event dispatch can keep up with many subscribers
            if (num_subs > 100 && (cnt & 0xFF) == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    });

    const double warmup_timeout_sec = std::max(30.0, static_cast<double>(num_subs) / 10.0);
    const auto warmup_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(static_cast<int>(warmup_timeout_sec * 1000));
    bool all_warmed_up = false;
    while (std::chrono::steady_clock::now() < warmup_deadline) {
        all_warmed_up = true;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (!st->warmup_done) {
                all_warmed_up = false;
                break;
            }
        }
        if (all_warmed_up)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (!all_warmed_up) {
        uint32_t warmed_count = 0;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (st->warmup_done) warmed_count++;
        }
        log_warn_printf(perflog, "CA warm-up: only %u/%u subscriptions warmed up\n",
                        warmed_count, num_subs);
    }

    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        st->success_count = 0;
        st->drop_count = 0;
        st->error_count = 0;
    }

    const auto start_time = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(
        std::chrono::milliseconds(static_cast<int>(duration_sec * 1000)));
    const auto end_time = std::chrono::steady_clock::now();

    stop_pump.store(true, std::memory_order_relaxed);
    pump_thread.join();

    const double elapsed = std::chrono::duration<double>(end_time - start_time).count();
    uint64_t total_success = 0, total_drops = 0, total_errors = 0;
    for (auto& st : states) {
        std::lock_guard<std::mutex> lk(st->mtx);
        total_success += st->success_count;
        total_drops += st->drop_count;
        total_errors += st->error_count;
    }

    for (auto& eid : evids) {
        if (eid)
            ca_clear_subscription(eid);
    }
    ca_clear_channel(chan_id);
    ca_context_destroy();

    result.updates_per_second = (elapsed > 0.0) ? (static_cast<double>(total_success) / elapsed) : 0.0;
    result.per_sub_updates_per_second = (num_subs > 0) ? (result.updates_per_second / num_subs) : 0.0;
    result.total_updates = total_success;
    result.drops = total_drops;
    result.errors = total_errors;
    result.duration_seconds = elapsed;

    return result;
}

// ============================================================
// 6.1-6.3: CSV output
// ============================================================
void write_csv_header(std::ostream& out) {
    out << "protocol,payload_mode,subscribers,payload_bytes,updates_per_second,per_sub_updates_per_second,total_updates,drops,errors,duration_seconds"
        << std::endl;
}

void write_csv_row(std::ostream& out, const BenchmarkResult& r) {
    out << r.protocol << ","
        << r.payload_mode << ","
        << r.subscribers << ","
        << r.payload_bytes << ","
        << r.updates_per_second << ","
        << r.per_sub_updates_per_second << ","
        << r.total_updates << ","
        << r.drops << ","
        << r.errors << ","
        << r.duration_seconds
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

        app.set_help_flag("", "");  // deactivate built-in help

        bool help{false};
        bool verbose{false};
        app.add_flag("-h,--help", help);
        app.add_flag("-v,--verbose", verbose, "Verbose mode");

        double duration = 5.0;
        uint64_t warmup = 100;
        std::string subs_str = "1,10,100,500,1000";
        std::string sizes_str = "1,10,100,1000,10000,100000";
        std::string modes_str = "ca,pva,spva,spva_certmon";
        std::string keychain;
        std::string output_file;
        bool setup_cms = false;
        bool external_cms = false;
        std::string cms_db, cms_keychain, cms_acf;
        bool debug = false;
        bool show_version = false;
        bool nt_payload = false;

        app.add_option("--duration", duration, "Measurement duration per data point in seconds");
        app.add_option("--warmup", warmup, "Number of warm-up updates before measurement");
        app.add_option("--subscriptions", subs_str,
                        "Comma-separated subscriber counts to sweep (e.g. 1,10,100,500,1000)");
        app.add_option("--sizes", sizes_str, "Comma-separated payload sizes in bytes");
        app.add_option("--modes", modes_str, "Comma-separated protocol modes: ca,pva,spva,spva_certmon");
        app.add_option("--keychain", keychain, "TLS keychain file for SPVA modes");
        app.add_option("--output", output_file, "CSV output file (default: stdout)");
        app.add_flag("--setup-cms", setup_cms,
                     "Auto-bootstrap PVACMS with temp certs for SPVA_CERTMON");
        app.add_flag("--external-cms", external_cms,
                     "Use already-running PVACMS for SPVA_CERTMON");
        app.add_option("--cms-db", cms_db, "Path to existing PVACMS SQLite database");
        app.add_option("--cms-keychain", cms_keychain, "Path to existing PVACMS server keychain");
        app.add_option("--cms-acf", cms_acf, "Path to existing PVACMS ACF file");
        app.add_flag("--nt-payload", nt_payload,
                     "Use NT types for PVA payload (adds timestamp/alarm metadata overhead)");
        app.add_flag("-d,--debug", debug, "Enable PVXS debug logging");
        app.add_flag("-V,--version", show_version, "Print version and exit");

        CLI11_PARSE(app, argc, argv);

        if (help) {
            auto program_name = argv[0];
            std::cout
                << "pvxperf - PVAccess Performance Benchmarking Tool\n"
                << std::endl
                << "Measures monitor subscription throughput (updates/second) across four protocol\n"
                << "modes: CA, PVA, SPVA, and SPVA+CERTMON, sweeping across configurable subscriber\n"
                << "counts.\n"
                << std::endl
                << "WARNING: Run on a network with no other active PVACMS to avoid interference\n"
                << "with benchmark results.\n"
                << std::endl
                << "usage:\n"
                << "  " << program_name << " [options]                              Run benchmarks\n"
                << "  " << program_name << " (-h | --help)                          Show this help message and exit\n"
                << "  " << program_name << " (-V | --version)                       Print version and exit\n"
                << std::endl
                << "benchmark options:\n"
                << "        --duration <seconds>                  Measurement duration per data point. Default 5\n"
                << "        --warmup <count>                      Number of warm-up updates before measurement. Default 100\n"
                << "        --subscriptions <list>                Comma-separated subscriber counts to sweep.\n"
                << "                                              Default 1,10,100,500,1000\n"
                << "        --sizes <list>                        Comma-separated payload sizes in bytes.\n"
                << "                                              Default 1,10,100,1000,10000,100000\n"
                << "        --modes <list>                        Comma-separated protocol modes to run.\n"
                << "                                              ca,pva,spva,spva_certmon. Default all\n"
                << "        --nt-payload                          Use NT types for PVA payload (adds timestamp/alarm\n"
                << "                                              metadata overhead)\n"
                << "        --output <file>                       CSV output file. Default stdout\n"
                << std::endl
                << "TLS/CMS options:\n"
                << "        --keychain <path>                     TLS keychain file for SPVA modes\n"
                << "        --setup-cms                           Auto-bootstrap PVACMS with temp certs for\n"
                << "                                              SPVA_CERTMON\n"
                << "        --external-cms                        Use already-running PVACMS for SPVA_CERTMON\n"
                << "        --cms-db <path>                       Path to existing PVACMS SQLite database\n"
                << "        --cms-keychain <path>                 Path to existing PVACMS server keychain\n"
                << "        --cms-acf <path>                      Path to existing PVACMS ACF file\n"
                << std::endl
                << "general options:\n"
                << "  (-d | --debug)                              Enable PVXS debug logging\n"
                << "  (-v | --verbose)                            Verbose mode\n"
                << std::endl;
            exit(0);
        }

        if (show_version) {
            version_information(std::cout);
            exit(0);
        }

        if (debug) {
            setenv("PVXS_LOG", "pvxs.*=DEBUG", 1);
            logger_config_env();
        }

        const auto modes = parse_modes(modes_str);
        const auto sizes = parse_sizes(sizes_str);
        const auto sub_counts = parse_sub_counts(subs_str);

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
            tmp_cms_dir = create_temp_dir();
            log_info_printf(perflog, "CMS temp directory: %s\n", tmp_cms_dir.c_str());

            setenv("EPICS_PVA_ADDR_LIST", "127.0.0.1", 1);
            setenv("EPICS_PVA_AUTO_ADDR_LIST", "NO", 1);

            pvacms_proc.reset(new PvacmsProcess());
            pvacms_proc->start(tmp_cms_dir, cms_db, cms_keychain, cms_acf);

            if (!wait_for_pvacms(30.0)) {
                std::cerr << "Error: PVACMS did not become ready within timeout" << std::endl;
                return 1;
            }

            const std::string server_kc = tmp_cms_dir + "/server.p12";
            const std::string client_kc = tmp_cms_dir + "/client.p12";

            if (!run_authnstd("pvxperf-server", "server", server_kc)) {
                std::cerr << "Error: failed to provision server keychain" << std::endl;
                return 1;
            }
            if (!run_authnstd("pvxperf-client", "client", client_kc)) {
                std::cerr << "Error: failed to provision client keychain" << std::endl;
                return 1;
            }

            if (keychain.empty()) {
                keychain = server_kc;
                client_keychain = client_kc;
                have_keychain = true;
            }

            log_info_printf(perflog, "%s\n", "CMS setup complete, keychains provisioned");
        }

        write_csv_header(*out);

        const bool needs_ca = std::any_of(modes.begin(), modes.end(),
            [](const ProtocolMode m) { return m == ProtocolMode::CA; });

        EmbeddedIoc ca_ioc;
        if (needs_ca) {
            const size_t max_size = *std::max_element(sizes.begin(), sizes.end());
            if (!ca_ioc.init(max_size)) {
                std::cerr << "Warning: CA IOC init failed, CA benchmarks will be skipped" << std::endl;
            }
        }

        for (const auto mode : modes) {
            if ((mode == ProtocolMode::SPVA || mode == ProtocolMode::SPVA_CERTMON) && !have_keychain) {
                std::cerr << "Warning: skipping " << protocol_mode_str(mode)
                          << " — no keychain available" << std::endl;
                continue;
            }

            if (mode == ProtocolMode::SPVA_CERTMON && !setup_cms && !external_cms) {
                std::cerr << "Warning: skipping SPVA_CERTMON — no CMS configured "
                          << "(use --setup-cms or --external-cms)" << std::endl;
                continue;
            }

            if (mode == ProtocolMode::SPVA_CERTMON && external_cms) {
                if (!wait_for_pvacms(10.0)) {
                    std::cerr << "Warning: skipping SPVA_CERTMON — external CMS not reachable" << std::endl;
                    continue;
                }
            }

            for (const auto payload_size : sizes) {
                for (const auto num_subs : sub_counts) {
                    log_info_printf(perflog, "Benchmarking %s %u subs %zu bytes...\n",
                                   protocol_mode_str(mode), num_subs, payload_size);

                    BenchmarkResult result;

                    if (mode == ProtocolMode::CA) {
                        result = run_ca_benchmark(ca_ioc, payload_size, duration,
                                                  warmup, num_subs);
                    } else {
                        result = run_pva_benchmark(mode, payload_size, duration,
                                                   warmup, num_subs, keychain,
                                                   client_keychain, nt_payload);
                    }

                    write_csv_row(*out, result);

                    log_info_printf(perflog, "  -> %.1f updates/sec (%.1f/sub), %lu total, %lu drops, %lu errors\n",
                                   result.updates_per_second,
                                   result.per_sub_updates_per_second,
                                   (unsigned long)result.total_updates,
                                   (unsigned long)result.drops,
                                   (unsigned long)result.errors);
                }
            }
        }

        if (pvacms_proc) {
            pvacms_proc->stop();
        }
        if (!tmp_cms_dir.empty()) {
            remove_temp_dir(tmp_cms_dir);
        }

        return 0;

    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
