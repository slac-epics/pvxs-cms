/**
 * pvxperf — Performance benchmarking tool for CA, PVA, SPVA, and SPVA+CERTMON.
 *
 * Measures monitor subscription throughput (updates/second) across four protocol
 * modes using adaptive rate discovery (exponential ramp + binary search).
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
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
#include <vector>

#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <epicsThread.h>
#include <epicsTime.h>
#include <errlog.h>

#include <dbAccess.h>
#include <dbStaticLib.h>
#include <iocInit.h>
#include <iocsh.h>
#include <dbChannel.h>
#include <dbAddr.h>
#include <iocshRegisterCommon.h>

extern "C" {
int pvxperf_registerRecordDeviceDriver(struct dbBase *pdbbase);
}

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

/** @brief Global flag set by SIGTERM/SIGINT handler to signal server mode shutdown. */
volatile sig_atomic_t g_server_stop = 0;

/**
 * @brief POSIX signal handler that sets the global server stop flag.
 * @param sig  Signal number received (SIGTERM or SIGINT); value is not used.
 * @note Must have external linkage for use with signal(2). Writes volatile g_server_stop.
 */
extern "C" void serverSignalHandler(int /*sig*/) {
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
static constexpr uint16_t kPvacmsUdpPort = 15076u;
static constexpr uint16_t kPvacmsTcpPort = 15075u;
static constexpr uint16_t kPvacmsTlsPort = 15076u;

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

/** @brief Protocol modes supported by pvxperf benchmarks. */
enum class ProtocolMode { CA, PVA, SPVA, SPVA_CERTMON };

/**
 * @brief Convert a ProtocolMode value to its canonical string name.
 * @param m  Protocol mode to convert.
 * @return   Null-terminated string: "CA", "PVA", "SPVA", "SPVA_CERTMON", or "UNKNOWN".
 */
const char* protocolModeStr(const ProtocolMode m) {
    switch (m) {
    case ProtocolMode::CA:           return "CA";
    case ProtocolMode::PVA:          return "PVA";
    case ProtocolMode::SPVA:         return "SPVA";
    case ProtocolMode::SPVA_CERTMON: return "SPVA_CERTMON";
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
    if (s == "ca" || s == "CA")                       return ProtocolMode::CA;
    if (s == "pva" || s == "PVA")                     return ProtocolMode::PVA;
    if (s == "spva" || s == "SPVA")                   return ProtocolMode::SPVA;
    if (s == "spva_certmon" || s == "SPVA_CERTMON")   return ProtocolMode::SPVA_CERTMON;
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
 * @brief Parse a comma-separated list of payload sizes.
 * @param csv  Comma-separated byte counts (e.g. "1,10,100,1000").
 * @return     Vector of payload sizes in bytes.
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
 * @brief Parse a comma-separated list of subscription counts.
 * @param csv  Comma-separated count values (e.g. "1,10,100,500,1000").
 * @return     Vector of subscription counts.
 */
std::vector<uint32_t> parseSubCounts(const std::string& csv) {
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

/** @brief Full header size: 8-byte counter (NBO) + 8-byte timestamp_us (NBO). */
constexpr size_t kHeaderSize = 16;
/** @brief Minimum header size when only a counter is embedded (no timestamp). */
constexpr size_t kCounterSize = 8;

/**
 * @brief Convert a 64-bit value to network byte order (big-endian).
 * @param val  Host-order 64-bit value.
 * @return     Network-order 64-bit value.
 */
uint64_t toNetworkOrder64(const uint64_t val) {
    const uint32_t hi = htonl(static_cast<uint32_t>(val >> 32));
    const uint32_t lo = htonl(static_cast<uint32_t>(val & 0xFFFFFFFF));
    uint64_t result;
    std::memcpy(&result, &hi, 4);
    std::memcpy(reinterpret_cast<char*>(&result) + 4, &lo, 4);
    return result;
}

/**
 * @brief Convert a 64-bit value from network byte order to host byte order.
 * @param val  Network-order 64-bit value.
 * @return     Host-order 64-bit value.
 */
uint64_t fromNetworkOrder64(const uint64_t val) {
    return toNetworkOrder64(val);
}

/**
 * @brief Encode a counter and timestamp into a benchmark payload buffer.
 * @param buf           Output buffer to fill (must be at least @p size bytes).
 * @param size          Total size of @p buf in bytes.
 * @param counter       Monotonic send counter written in the first 8 bytes (network byte order).
 * @param timestamp_us  Send timestamp in microseconds since epoch, written in bytes 8-15 (NBO).
 * @note Buffers smaller than 8 bytes receive no header. Buffers 8-15 bytes get counter only.
 *       Remaining bytes beyond the header are filled with the low byte of @p counter.
 */
void encodePayload(uint8_t* buf, const size_t size, const uint64_t counter, const uint64_t timestamp_us) {
    if (size >= kCounterSize) {
        const uint64_t net_counter = toNetworkOrder64(counter);
        std::memcpy(buf, &net_counter, kCounterSize);
    }
    if (size >= kHeaderSize) {
        const uint64_t net_ts = toNetworkOrder64(timestamp_us);
        std::memcpy(buf + kCounterSize, &net_ts, kCounterSize);
    }
    const auto fill = static_cast<uint8_t>(counter & 0xFF);
    const size_t start = (size >= kHeaderSize) ? kHeaderSize : (size >= kCounterSize ? kCounterSize : 0);
    std::memset(buf + start, fill, size - start);
}

/**
 * @brief Decode the 64-bit counter from the first 8 bytes of a payload buffer.
 * @param buf   Payload buffer with an NBO counter at offset 0.
 * @param size  Size of @p buf in bytes.
 * @return      Host-order counter value, or 0 if @p size is less than 8 bytes.
 */
uint64_t decodeCounter(const uint8_t* buf, const size_t size) {
    if (size < kCounterSize)
        return 0;
    uint64_t net_counter;
    std::memcpy(&net_counter, buf, kCounterSize);
    return fromNetworkOrder64(net_counter);
}

void encodeSteadyTimestamp(uint8_t* buf, const size_t size) {
    if (size < kHeaderSize) return;
    const auto now = std::chrono::steady_clock::now();
    const uint64_t ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count());
    const uint64_t net_ns = toNetworkOrder64(ns);
    std::memcpy(buf + kCounterSize, &net_ns, kCounterSize);
}

uint64_t decodeSteadyTimestamp(const uint8_t* buf, const size_t size) {
    if (size < kHeaderSize) return 0;
    uint64_t net_ns;
    std::memcpy(&net_ns, buf + kCounterSize, kCounterSize);
    return fromNetworkOrder64(net_ns);
}

/**
 * @brief Return the current wall-clock time as microseconds since the Unix epoch.
 * @return Current timestamp in microseconds.
 */
uint64_t currentTimestampUs() {
    const auto now = std::chrono::system_clock::now();
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    return static_cast<uint64_t>(us);
}

/**
 * @brief Holds the outcome of a single throughput benchmark run.
 */
struct BenchmarkResult {
    std::string protocol;
    std::string payload_mode{"raw"};
    uint32_t subscribers{0};
    size_t payload_bytes{0};
    std::string topology{"loopback"};
    uint32_t iteration{1};
    double updates_per_second{0.0};
    double per_sub_updates_per_second{0.0};
    uint64_t total_updates{0};
    uint64_t drops{0};
    uint64_t errors{0};
    double duration_seconds{0.0};
};

/**
 * @brief Holds the duration of one connection phase for one benchmark iteration.
 */
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
    // all others (e.g. inner cert-status client → PVACMS) are rejected.
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

    struct tm tm_val;
    std::memset(&tm_val, 0, sizeof(tm_val));

    // Parse date/time components manually (no regex, no strptime portability issues)
    char buf[5];

    // Year
    std::memcpy(buf, msg, 4); buf[4] = '\0';
    tm_val.tm_year = std::atoi(buf) - 1900;

    // Month
    std::memcpy(buf, msg + 5, 2); buf[2] = '\0';
    tm_val.tm_mon = std::atoi(buf) - 1;

    // Day
    std::memcpy(buf, msg + 8, 2); buf[2] = '\0';
    tm_val.tm_mday = std::atoi(buf);

    // Hour
    std::memcpy(buf, msg + 11, 2); buf[2] = '\0';
    tm_val.tm_hour = std::atoi(buf);

    // Minute
    std::memcpy(buf, msg + 14, 2); buf[2] = '\0';
    tm_val.tm_min = std::atoi(buf);

    // Second
    std::memcpy(buf, msg + 17, 2); buf[2] = '\0';
    tm_val.tm_sec = std::atoi(buf);

    tm_val.tm_isdst = -1;  // let mktime determine DST

    const time_t epoch_sec = mktime(&tm_val);
    if (epoch_sec == static_cast<time_t>(-1))
        return -1;

    // Parse nanosecond fraction (9 digits after '.')
    char ns_buf[10];
    std::memcpy(ns_buf, msg + 20, 9); ns_buf[9] = '\0';
    const int64_t nanos = static_cast<int64_t>(std::strtol(ns_buf, nullptr, 10));

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
 * @param capture  Capture state object to receive timestamps from the errlog listener.
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

    // Use connection_validation timestamp if available and it precedes connected
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
 * @brief Print a throughput summary table (mean/stddev/min/max) to stderr across iterations.
 * @param results  All benchmark results to aggregate; grouped by protocol/topology/payload/subscribers.
 */
void printThroughputSummary(const std::vector<BenchmarkResult>& results) {
    if (results.empty())
        return;

    // Group key: protocol + topology + payload_bytes + subscribers
    struct GroupKey {
        std::string protocol;
        std::string topology;
        size_t payload_bytes;
        uint32_t subscribers;

        bool operator<(const GroupKey& o) const {
            if (protocol != o.protocol) return protocol < o.protocol;
            if (topology != o.topology) return topology < o.topology;
            if (payload_bytes != o.payload_bytes) return payload_bytes < o.payload_bytes;
            return subscribers < o.subscribers;
        }
    };

    std::map<GroupKey, std::vector<double>> groups;
    std::map<GroupKey, uint64_t> group_drops;

    for (const auto& r : results) {
        GroupKey key{r.protocol, r.topology, r.payload_bytes, r.subscribers};
        groups[key].push_back(r.updates_per_second);
        group_drops[key] += r.drops;
    }

    std::cerr << "\n=== Throughput Summary (across iterations) ===" << std::endl;
    std::cerr << std::left
              << std::setw(16) << "Protocol"
              << std::setw(12) << "Topology"
              << std::setw(12) << "Payload"
              << std::setw(8)  << "Subs"
              << std::setw(14) << "Mean ups"
              << std::setw(14) << "Stddev"
              << std::setw(14) << "Min"
              << std::setw(14) << "Max"
              << std::setw(10) << "Drops"
              << std::endl;

    for (const auto& kv : groups) {
        const auto& key = kv.first;
        const auto& vals = kv.second;
        const size_t n = vals.size();

        double sum = 0.0;
        double min_val = vals[0];
        double max_val = vals[0];
        for (const auto v : vals) {
            sum += v;
            if (v < min_val) min_val = v;
            if (v > max_val) max_val = v;
        }
        const double mean = sum / static_cast<double>(n);

        double stddev = 0.0;
        if (n > 1) {
            double sq_sum = 0.0;
            for (const auto v : vals) {
                const double diff = v - mean;
                sq_sum += diff * diff;
            }
            stddev = std::sqrt(sq_sum / static_cast<double>(n - 1));
        }

        std::cerr << std::left
                  << std::setw(16) << key.protocol
                  << std::setw(12) << key.topology
                  << std::setw(12) << key.payload_bytes
                  << std::setw(8)  << key.subscribers
                  << std::setw(14) << std::fixed << std::setprecision(1) << mean
                  << std::setw(14) << stddev
                  << std::setw(14) << min_val
                  << std::setw(14) << max_val
                  << std::setw(10) << group_drops[key]
                  << std::endl;
    }
    std::cerr << std::endl;
}

/**
 * @brief Run the connection phase timing benchmark for N connect/disconnect cycles.
 * @param mode             Protocol mode to benchmark (PVA, SPVA, or SPVA_CERTMON).
 * @param iterations       Number of independent connect/disconnect cycles to perform.
 * @param server_keychain  Path to TLS keychain for the benchmark server.
 * @param client_keychain  Path to TLS keychain for the client (falls back to server_keychain if empty).
 * @param cms_udp_port     PVACMS UDP port for --setup-cms (e.g. 15076); 0 means external CMS
 *                         reachable via standard EPICS_PVA_* environment variables.
 * @return                 Vector of PhaseTimingResult, one entry per phase per iteration.
 */
std::vector<PhaseTimingResult> runPvaPhaseTiming(
    const ProtocolMode mode,
    const uint32_t iterations,
    const std::string& server_keychain,
    const std::string& client_keychain,
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
        // cert-status client discovers PVACMS via standard PVA environment.
        server::Config sconfig;
        if (mode == ProtocolMode::SPVA_CERTMON && cms_udp_port == 0u) {
            sconfig = server::Config::fromEnv();
        } else {
            sconfig = loopbackServerConfig(
                (mode == ProtocolMode::SPVA_CERTMON) ? cms_udp_port : 0u);
        }

        if (mode == ProtocolMode::PVA) {
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

        auto prototype = nt::NTScalar{TypeCode::UInt8A}.create();
        {
            shared_array<uint8_t> initial_data(16);
            encodePayload(initial_data.data(), 16, 0, currentTimestampUs());
            prototype["value"] = initial_data.freeze().castTo<const void>();
        }
        pv.open(prototype);

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

        // Set port whitelist for ConnBase::state log filtering.
        // Only messages whose peerName matches the benchmark server's port
        // are accepted; inner cert-status client connections are rejected.
        if (mode == ProtocolMode::SPVA_CERTMON) {
            const auto& eff = server.config();
            capture.server_tcp_port_str = ":" + std::to_string(eff.tcp_port);
            capture.server_tls_port_str = ":" + std::to_string(eff.tls_port);
        }

        auto cconfig = server.clientConfig();
        if (mode == ProtocolMode::PVA) {
            cconfig.tls_disabled = true;
        } else {
            cconfig.tls_disabled = false;
            cconfig.tls_keychain_file = client_keychain.empty() ? server_keychain : client_keychain;
#ifdef PVXS_ENABLE_EXPERT_API
            if (mode == ProtocolMode::SPVA) {
                cconfig.disableStatusCheck(true);
            } else {
                cconfig.disableStatusCheck(false);
            }
#endif
        }

        enablePhaseTimingCapture(capture);

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
                                       // Continue popping — data values follow the Connected event
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
                    "FATAL: %s iter %u: connection is NOT using TLS — falling back to plain PVA. "
                    "Check keychain configuration.\n",
                    protocol.c_str(), iter);
                throw std::runtime_error(
                    protocol + " phase timing: connection established without TLS. "
                    "Benchmark results would be invalid.");
            }
            if (!tls_verified.load(std::memory_order_relaxed)) {
                log_warn_printf(perflog,
                    "%s iter %u: TLS verification inconclusive — Connected event not received "
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
 * @brief Print a phase timing comparison table to stderr with overhead percentages relative to PVA.
 * @param results     All phase timing results to aggregate across protocols.
 * @param iterations  Number of iterations used, shown in the table header.
 */
void printComparisonTable(const std::vector<PhaseTimingResult>& results,
                            const uint32_t iterations) {
    if (results.empty())
        return;

    // Collect unique protocols (in order: PVA, SPVA, SPVA_CERTMON)
    std::vector<std::string> protocol_order = {"PVA", "SPVA", "SPVA_CERTMON"};
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

/** @brief Result from a single measurement sub-window. */
struct SubWindowResult {
    uint32_t window_index{0};
    bool omitted{false};
    double duration_seconds{0.0};
    uint64_t total_updates{0};
    uint64_t drops{0};
    uint64_t errors{0};
    double updates_per_second{0.0};
};

/** @brief Aggregated latency benchmark result. */
struct LatencyResult {
    std::string protocol;
    uint32_t subscribers{0};
    size_t payload_bytes{0};
    uint32_t num_samples{0};
    double median_us{0.0};      // Median latency in microseconds
    double mean_us{0.0};        // Mean latency in microseconds
    double p25_us{0.0};         // 25th percentile
    double p75_us{0.0};         // 75th percentile
    double p99_us{0.0};         // 99th percentile
    double min_us{0.0};
    double max_us{0.0};
    double cv_pct{0.0};         // Coefficient of variation
    double theoretical_ups{0.0}; // 1,000,000 / median_us
};

/** @brief Result from a single burst measurement. */
struct BurstSample {
    double per_delivery_us{0.0};   // Microseconds per delivery (total_time / (burst_size * num_subs))
    double burst_duration_us{0.0}; // Total burst duration in microseconds
    uint64_t deliveries{0};        // B * num_subs
};

/** @brief Aggregated burst benchmark result. */
struct BurstResult {
    std::string protocol;
    uint32_t subscribers{0};
    size_t payload_bytes{0};
    uint32_t burst_size{0};
    uint32_t num_samples{0};
    double median_per_delivery_us{0.0};
    double mean_per_delivery_us{0.0};
    double p25_per_delivery_us{0.0};
    double p75_per_delivery_us{0.0};
    double p99_per_delivery_us{0.0};
    double min_per_delivery_us{0.0};
    double max_per_delivery_us{0.0};
    double cv_pct{0.0};
    double theoretical_ups{0.0};  // 1,000,000 / median_per_delivery_us
};

/** @brief Per-subscription state for burst benchmark — uses atomic counter for lock-free counting. */
struct BurstSubState {
    std::atomic<bool> connected{false};
    std::atomic<uint64_t> received_count{0};
};

/** @brief Compute the median of a vector (sorts in place). */
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
    const size_t lo = static_cast<size_t>(rank);
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

/**
 * @brief Per-subscription state for PVA/SPVA counter verification during benchmarks.
 */
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

struct LatencySubState {
    std::mutex mtx;
    bool first_update_seen{false};
    uint64_t last_received_counter{0};
    uint64_t recv_timestamp_ns{0};
    bool update_ready{false};
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
     * @param tmp_dir      Temporary directory that will hold all CMS state files.
     * @param override_db  Override path for the SQLite database (empty = use tmp_dir default).
     * @param override_kc  Override path for the PVACMS server keychain (empty = use tmp_dir default).
     * @param override_acf Override path for the ACF file (empty = use tmp_dir default).
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
 * @param cms_udp_port  PVACMS UDP port for --setup-cms (e.g. 15076); 0 means external CMS
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
 * @brief Create a unique temporary directory for CMS state isolation.
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
 * @brief Run an in-process PVA or SPVA throughput benchmark (loopback mode).
 * @param mode              Protocol mode: PVA, SPVA, or SPVA_CERTMON.
 * @param payload_size      Requested payload size in bytes.
 * @param duration_sec      Measurement window duration in seconds.
 * @param warmup_count      Number of updates to consume before measurement starts.
 * @param num_subscriptions Number of parallel monitor subscriptions.
 * @param server_keychain   Path to the TLS keychain for the in-process server.
 * @param client_keychain   Path to the TLS keychain for the client (falls back to server_keychain).
 * @param nt_payload        If true, encode the timestamp in NTScalar fields instead of the raw array.
 * @param cms_udp_port      PVACMS UDP port for --setup-cms (e.g. 15076); 0 means external CMS
 *                          reachable via standard EPICS_PVA_* environment variables.
 * @param post_delay_ns     Nanoseconds to sleep between each post(); 0 = fire as fast as possible.
 * @return                  BenchmarkResult populated with throughput and drop statistics.
 */
BenchmarkResult runPvaBenchmark(
    const ProtocolMode mode,
    const size_t payload_size,
    const double duration_sec,
    const uint64_t warmup_count,
    const uint32_t num_subscriptions,
    const std::string& server_keychain,
    const std::string& client_keychain,
    const bool nt_payload,
    const uint16_t cms_udp_port = 0u,
    const uint64_t post_delay_ns = 0u)
{
    BenchmarkResult result;
    result.protocol = protocolModeStr(mode);
    result.payload_mode = nt_payload ? "nt" : "raw";
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;

    // In raw mode, minimum payload = kHeaderSize (counter + timestamp in array).
    // In NT mode, timestamp lives in NT fields, so minimum = kCounterSize.
    const size_t min_size = nt_payload ? kCounterSize : kHeaderSize;
    const size_t effective_size = std::max(payload_size, min_size);

    // For --setup-cms, inject the known PVACMS port into beaconDestinations.
    // For --external-cms (cms_udp_port==0), use fromEnv() so the inner
    // cert-status client discovers PVACMS via standard PVA environment.
    server::Config sconfig;
    if (mode == ProtocolMode::SPVA_CERTMON && cms_udp_port == 0u) {
        sconfig = server::Config::fromEnv();
    } else {
        sconfig = loopbackServerConfig(
            (mode == ProtocolMode::SPVA_CERTMON) ? cms_udp_port : 0u);
    }

    if (mode == ProtocolMode::PVA) {
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

    auto prototype = nt::NTScalar{TypeCode::UInt8A}.create();
    {
        shared_array<uint8_t> initial_data(effective_size);
        if (nt_payload) {
            const uint64_t net_counter = toNetworkOrder64(0);
            std::memcpy(initial_data.data(), &net_counter, kCounterSize);
            std::memset(initial_data.data() + kCounterSize, 0, effective_size - kCounterSize);
        } else {
            encodePayload(initial_data.data(), effective_size, 0, currentTimestampUs());
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
        cconfig.tls_disabled = false;
        cconfig.tls_keychain_file = client_keychain.empty() ? server_keychain : client_keychain;
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
         const auto& st = states[i];
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

                                  const uint64_t counter = decodeCounter(arr.data(), arr.size());

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

    const auto delay = std::chrono::nanoseconds(post_delay_ns);

    std::thread pump_thread([&]() {
        uint64_t cnt = 0;

        while (!stop_pump.load(std::memory_order_relaxed)) {
            auto& val = ring[cnt % kRingSize];
            {
                shared_array<uint8_t> buf(effective_size);
                if (nt_payload) {
                    const uint64_t net_counter = toNetworkOrder64(cnt);
                    std::memcpy(buf.data(), &net_counter, kCounterSize);
                    const auto fill = static_cast<uint8_t>(cnt & 0xFF);
                    std::memset(buf.data() + kCounterSize, fill, effective_size - kCounterSize);
                } else {
                    encodePayload(buf.data(), effective_size, cnt, currentTimestampUs());
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
            if (post_delay_ns > 0u) {
                std::this_thread::sleep_for(delay);
            }
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

/**
 * @brief Find the maximum sustainable update rate (zero drops) using exponential
 *        ramp followed by binary search.
 *
 * Phase 1 (ramp): Start at initial_rate, double each probe until drops appear.
 *   Each probe runs for probe_sec seconds. This brackets the max rate in
 *   [last_clean_rate, first_drop_rate].
 *
 * Phase 2 (binary search): Narrow the bracket to within 2% precision.
 *   Each probe runs for probe_sec seconds.
 *
 * Phase 3 (confirm): Run at the discovered rate for confirm_sec seconds to
 *   verify stability. If drops appear, back off by 10% and retry once.
 *
 * @param mode              Protocol mode.
 * @param payload_size      Payload size in bytes.
 * @param num_subscriptions Number of parallel monitor subscriptions.
 * @param server_keychain   TLS keychain for server.
 * @param client_keychain   TLS keychain for client.
 * @param nt_payload        Use NTScalar timestamp encoding.
 * @param cms_udp_port      PVACMS UDP port (0 = external).
 * @param probe_sec         Duration of each probing trial in seconds.
 * @param confirm_sec       Duration of final confirmation run.
 * @return BenchmarkResult from the confirmation run at the discovered rate.
 */
BenchmarkResult runAdaptiveBenchmark(
    const ProtocolMode mode,
    const size_t payload_size,
    const uint32_t num_subscriptions,
    const std::string& server_keychain,
    const std::string& client_keychain,
    const bool nt_payload,
    const uint16_t cms_udp_port,
    const double probe_sec = 1.0,
    const double confirm_sec = 3.0)
{
    const uint64_t warmup = 50;

    auto rate_to_delay = [](double rate) -> uint64_t {
        if (rate <= 0.0) return 0u;
        return static_cast<uint64_t>(1.0e9 / rate);
    };

    auto run_probe = [&](double target_rate, double dur) -> BenchmarkResult {
        const uint64_t delay = rate_to_delay(target_rate);
        log_info_printf(perflog, "  Adaptive probe: %.0f ups target (delay %lu ns, %.1fs)\n",
                       target_rate, (unsigned long)delay, dur);
        return runPvaBenchmark(mode, payload_size, dur, warmup,
                              num_subscriptions, server_keychain, client_keychain,
                              nt_payload, cms_udp_port, delay);
    };

    // Phase 1: Exponential ramp to find the bracket [low, high]
    // Start at 1000 ups/sec, double each step
    double low_rate = 0.0;
    double high_rate = 0.0;
    double rate = 1000.0;

    log_info_printf(perflog, "Adaptive Phase 1: exponential ramp for %s %zu bytes %u subs\n",
                   protocolModeStr(mode), payload_size, num_subscriptions);

    for (int step = 0; step < 30; ++step) {
        auto r = run_probe(rate, probe_sec);
        log_info_printf(perflog, "    rate=%.0f -> %.0f ups, %lu drops\n",
                       rate, r.updates_per_second, (unsigned long)r.drops);

        if (r.drops == 0 && r.errors == 0) {
            low_rate = rate;
            rate *= 2.0;
        } else {
            high_rate = rate;
            break;
        }
    }

    if (high_rate == 0.0) {
        // Never got drops — the system can handle our max probed rate.
        // Run flood (delay=0) as confirmation.
        log_info_printf(perflog, "Adaptive: never saturated at %.0f ups, running flood confirmation\n", low_rate);
        return run_probe(0.0, confirm_sec);
    }

    if (low_rate == 0.0) {
        // Even 1000 ups/sec caused drops — start lower
        low_rate = 100.0;
        high_rate = 1000.0;
    }

    // Phase 2: Binary search within [low_rate, high_rate] to 2% precision
    log_info_printf(perflog, "Adaptive Phase 2: binary search [%.0f, %.0f]\n", low_rate, high_rate);

    double best_rate = low_rate;
    while ((high_rate - low_rate) / low_rate > 0.02) {
        const double mid = (low_rate + high_rate) / 2.0;
        auto r = run_probe(mid, probe_sec);
        log_info_printf(perflog, "    mid=%.0f -> %.0f ups, %lu drops\n",
                       mid, r.updates_per_second, (unsigned long)r.drops);

        if (r.drops == 0 && r.errors == 0) {
            best_rate = mid;
            low_rate = mid;
        } else {
            high_rate = mid;
        }
    }

    // Phase 3: Confirmation run at best_rate
    log_info_printf(perflog, "Adaptive Phase 3: confirm at %.0f ups (%.1fs)\n", best_rate, confirm_sec);
    auto result = run_probe(best_rate, confirm_sec);

    // Iterative backoff: if drops persist, keep reducing by 10% (up to 5 attempts)
    for (int backoff = 0; backoff < 5 && result.drops > 0; ++backoff) {
        best_rate *= 0.9;
        log_info_printf(perflog, "  Drops in confirmation (attempt %d), backing off to %.0f ups\n", backoff + 1, best_rate);
        result = run_probe(best_rate, confirm_sec);
    }

    return result;
}

/**
 * @brief Print a per-window summary table for a steady-state benchmark to stderr.
 */
void printLatencySummary(const LatencyResult& r) {
    std::cerr << "\n=== Latency: " << r.protocol << " " << r.subscribers
              << " subs " << r.payload_bytes << " bytes ===" << std::endl;
    std::cerr << std::fixed << std::setprecision(1)
              << "  Samples:    " << r.num_samples << std::endl
              << "  Median:     " << r.median_us << " us" << std::endl
              << "  Mean:       " << r.mean_us << " us" << std::endl
              << "  p25:        " << r.p25_us << " us" << std::endl
              << "  p75:        " << r.p75_us << " us" << std::endl
              << "  p99:        " << r.p99_us << " us" << std::endl
              << "  Min:        " << r.min_us << " us" << std::endl
              << "  Max:        " << r.max_us << " us" << std::endl
              << "  CV:         " << r.cv_pct << "%" << std::endl
              << std::setprecision(0)
              << "  Theoretical throughput: " << r.theoretical_ups << " updates/sec" << std::endl
              << std::endl;
}

void printBurstSummary(const BurstResult& r) {
    std::cerr << "\n=== Burst: " << r.protocol << " " << r.subscribers
              << " subs " << r.payload_bytes << " bytes (burst=" << r.burst_size << ") ===" << std::endl;
    std::cerr << std::fixed << std::setprecision(2)
              << "  Samples:    " << r.num_samples << std::endl
              << "  Per-delivery cost:" << std::endl
              << "    Median:   " << r.median_per_delivery_us << " us" << std::endl
              << "    Mean:     " << r.mean_per_delivery_us << " us" << std::endl
              << "    p25:      " << r.p25_per_delivery_us << " us" << std::endl
              << "    p75:      " << r.p75_per_delivery_us << " us" << std::endl
              << "    p99:      " << r.p99_per_delivery_us << " us" << std::endl
              << "    Min:      " << r.min_per_delivery_us << " us" << std::endl
              << "    Max:      " << r.max_per_delivery_us << " us" << std::endl
              << std::setprecision(1)
              << "  CV:         " << r.cv_pct << "%" << std::endl
              << std::setprecision(0)
              << "  Theoretical throughput: " << r.theoretical_ups << " updates/sec" << std::endl
              << std::endl;
}

void printSteadyStateSummary(const std::vector<SubWindowResult>& windows,
                              const char* protocol,
                              uint32_t num_subs,
                              size_t payload_bytes)
{
    std::cerr << "\n=== Steady-State: " << protocol << " " << num_subs
              << " subs " << payload_bytes << " bytes ===" << std::endl;
    std::cerr << std::left
              << std::setw(8)  << "Window"
              << std::setw(12) << "Duration"
              << std::setw(16) << "Updates/sec"
              << std::setw(10) << "Drops"
              << std::setw(12) << "Status"
              << std::endl;

    std::vector<double> measured_rates;
    for (const auto& w : windows) {
        std::cerr << std::left
                  << std::setw(8) << (w.window_index + 1)
                  << std::setw(12) << (std::to_string(w.duration_seconds).substr(0, 5) + "s")
                  << std::setw(16) << std::fixed << std::setprecision(0) << w.updates_per_second
                  << std::setw(10) << w.drops
                  << (w.omitted ? "[omitted]" : "")
                  << std::endl;
        if (!w.omitted) {
            measured_rates.push_back(w.updates_per_second);
        }
    }

    if (!measured_rates.empty()) {
        auto rates_copy = measured_rates;
        const double median = computeMedian(rates_copy);
        rates_copy = measured_rates;
        const double p25 = computePercentile(rates_copy, 25.0);
        rates_copy = measured_rates;
        const double p75 = computePercentile(rates_copy, 75.0);
        const double cv = computeCV(measured_rates);
        const double mean = std::accumulate(measured_rates.begin(), measured_rates.end(), 0.0) / measured_rates.size();

        std::cerr << "\n  Measured windows: " << measured_rates.size() << std::endl;
        std::cerr << std::fixed << std::setprecision(0)
                  << "  Median: " << median << " ups"
                  << "   p25: " << p25
                  << "   p75: " << p75 << std::endl;
        std::cerr << std::fixed << std::setprecision(1)
                  << "  Mean: " << mean << " ups"
                  << "   CV: " << cv << "%" << std::endl;
    }
    std::cerr << std::endl;
}

/**
 * @brief Run a steady-state PVA/SPVA throughput benchmark with sub-window measurement.
 *
 * Floods updates at maximum rate and measures throughput in fixed-duration
 * sub-windows, discarding the first omit_windows as warmup. This produces
 * lower-variance results than the adaptive rate-finding approach.
 */
std::vector<SubWindowResult> runSteadyStateBenchmark(
    const ProtocolMode mode,
    const size_t payload_size,
    const uint32_t num_subscriptions,
    const std::string& server_keychain,
    const std::string& client_keychain,
    const bool nt_payload,
    const uint16_t cms_udp_port,
    const uint32_t num_windows = 10,
    const double window_sec = 3.0,
    const uint32_t omit_windows = 2)
{
    std::vector<SubWindowResult> results;

    const size_t min_size = nt_payload ? kCounterSize : kHeaderSize;
    const size_t effective_size = std::max(payload_size, min_size);
    const uint64_t warmup_count = 100;

    // --- Server setup (same as runPvaBenchmark) ---
    server::Config sconfig;
    if (mode == ProtocolMode::SPVA_CERTMON && cms_udp_port == 0u) {
        sconfig = server::Config::fromEnv();
    } else {
        sconfig = loopbackServerConfig(
            (mode == ProtocolMode::SPVA_CERTMON) ? cms_udp_port : 0u);
    }

    if (mode == ProtocolMode::PVA) {
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

    auto prototype = nt::NTScalar{TypeCode::UInt8A}.create();
    {
        shared_array<uint8_t> initial_data(effective_size);
        if (nt_payload) {
            const uint64_t net_counter = toNetworkOrder64(0);
            std::memcpy(initial_data.data(), &net_counter, kCounterSize);
            std::memset(initial_data.data() + kCounterSize, 0, effective_size - kCounterSize);
        } else {
            encodePayload(initial_data.data(), effective_size, 0, currentTimestampUs());
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

    // --- Client setup ---
    auto cconfig = server.clientConfig();
    if (mode == ProtocolMode::PVA) {
        cconfig.tls_disabled = true;
    } else {
        cconfig.tls_disabled = false;
        cconfig.tls_keychain_file = client_keychain.empty() ? server_keychain : client_keychain;
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
        const auto& st = states[i];
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

                                  const uint64_t counter = decodeCounter(arr.data(), arr.size());

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

    // Wait for all subscriptions to connect
    {
        const auto conn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (connected_subs.load(std::memory_order_relaxed) < num_subs &&
               std::chrono::steady_clock::now() < conn_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const uint32_t connected = connected_subs.load(std::memory_order_relaxed);
        if (connected < num_subs) {
            log_warn_printf(perflog, "Steady-state: only %u/%u subscriptions connected\n", connected, num_subs);
        }
        log_debug_printf(perflog, "Steady-state: %u/%u subscriptions connected, starting pump\n", connected, num_subs);
    }

    std::atomic<bool> stop_pump{false};

    // Pre-allocate ring of Values (same as runPvaBenchmark)
    constexpr size_t kRingSize = 64;
    std::vector<Value> ring(kRingSize);
    for (size_t i = 0; i < kRingSize; i++) {
        ring[i] = prototype.cloneEmpty();
        shared_array<uint8_t> buf(effective_size);
        ring[i]["value"] = buf.freeze().castTo<const void>();
    }

    // Flood mode: no delay
    std::thread pump_thread([&]() {
        uint64_t cnt = 0;

        while (!stop_pump.load(std::memory_order_relaxed)) {
            auto& val = ring[cnt % kRingSize];
            {
                shared_array<uint8_t> buf(effective_size);
                if (nt_payload) {
                    const uint64_t net_counter = toNetworkOrder64(cnt);
                    std::memcpy(buf.data(), &net_counter, kCounterSize);
                    const auto fill = static_cast<uint8_t>(cnt & 0xFF);
                    std::memset(buf.data() + kCounterSize, fill, effective_size - kCounterSize);
                } else {
                    encodePayload(buf.data(), effective_size, cnt, currentTimestampUs());
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

    // Wait for warmup to complete
    {
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
            log_warn_printf(perflog, "%s\n", "Steady-state: warm-up did not complete for all subscriptions");
        }
    }

    // Sub-window measurement loop
    for (uint32_t win = 0; win < num_windows; ++win) {
        // Reset counters for this window
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            st->success_count = 0;
            st->drop_count = 0;
            st->error_count = 0;
        }

        const auto win_start = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(
            static_cast<int64_t>(window_sec * 1000)));
        const auto win_end = std::chrono::steady_clock::now();

        const double elapsed = std::chrono::duration<double>(win_end - win_start).count();
        uint64_t total_success = 0, total_drops = 0, total_errors = 0;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            total_success += st->success_count;
            total_drops += st->drop_count;
            total_errors += st->error_count;
        }

        SubWindowResult w;
        w.window_index = win;
        w.omitted = (win < omit_windows);
        w.duration_seconds = elapsed;
        w.total_updates = total_success;
        w.drops = total_drops;
        w.errors = total_errors;
        w.updates_per_second = (elapsed > 0.0) ? (static_cast<double>(total_success) / elapsed) : 0.0;
        results.push_back(w);
    }

    stop_pump.store(true, std::memory_order_relaxed);
    pump_thread.join();

    for (auto& sub : subs) {
        if (sub)
            sub->cancel();
    }

    return results;
}

LatencyResult runLatencyBenchmark(
    const ProtocolMode mode,
    const size_t payload_size,
    const uint32_t num_subscriptions,
    const std::string& server_keychain,
    const std::string& client_keychain,
    const bool nt_payload,
    const uint16_t cms_udp_port,
    const uint32_t num_samples = 500,
    const uint32_t warmup_samples = 50,
    const uint32_t send_interval_us = 1000)
{
    const size_t min_size = nt_payload ? kCounterSize : kHeaderSize;
    const size_t effective_size = std::max(payload_size, min_size);

    // --- Server setup (same as runSteadyStateBenchmark) ---
    server::Config sconfig;
    if (mode == ProtocolMode::SPVA_CERTMON && cms_udp_port == 0u) {
        sconfig = server::Config::fromEnv();
    } else {
        sconfig = loopbackServerConfig(
            (mode == ProtocolMode::SPVA_CERTMON) ? cms_udp_port : 0u);
    }

    if (mode == ProtocolMode::PVA) {
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

    auto prototype = nt::NTScalar{TypeCode::UInt8A}.create();
    {
        shared_array<uint8_t> initial_data(effective_size);
        if (nt_payload) {
            const uint64_t net_counter = toNetworkOrder64(0);
            std::memcpy(initial_data.data(), &net_counter, kCounterSize);
            std::memset(initial_data.data() + kCounterSize, 0, effective_size - kCounterSize);
        } else {
            encodePayload(initial_data.data(), effective_size, 0, currentTimestampUs());
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

    // --- Client setup ---
    auto cconfig = server.clientConfig();
    if (mode == ProtocolMode::PVA) {
        cconfig.tls_disabled = true;
    } else {
        cconfig.tls_disabled = false;
        cconfig.tls_keychain_file = client_keychain.empty() ? server_keychain : client_keychain;
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

    std::vector<std::shared_ptr<LatencySubState>> states(num_subs);
    std::vector<std::shared_ptr<client::Subscription>> subs(num_subs);
    std::atomic<uint32_t> connected_subs{0};

    for (uint32_t i = 0; i < num_subs; i++) {
        states[i] = std::make_shared<LatencySubState>();
    }

    for (uint32_t i = 0; i < num_subs; i++) {
        const auto& st = states[i];
        subs[i] = ctxt.monitor(pvname)
                      .record("pipeline", true)
                      .record("queueSize", int32_t(4))
                      .maskConnected(true)
                      .maskDisconnected(true)
                      .event([st, &connected_subs](client::Subscription& sub) {
                          try {
                              while (auto val = sub.pop()) {
                                  const auto recv_time = std::chrono::steady_clock::now();
                                  const uint64_t recv_ns = static_cast<uint64_t>(
                                      std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          recv_time.time_since_epoch()).count());

                                  const auto arr = val["value"].as<shared_array<const uint8_t>>();
                                  if (arr.empty()) continue;

                                  const uint64_t counter = decodeCounter(arr.data(), arr.size());

                                  std::lock_guard<std::mutex> lk(st->mtx);
                                  if (!st->first_update_seen) {
                                      st->first_update_seen = true;
                                      connected_subs.fetch_add(1, std::memory_order_relaxed);
                                  }
                                  st->last_received_counter = counter;
                                  st->recv_timestamp_ns = recv_ns;
                                  st->update_ready = true;
                              }
                          } catch (...) {}
                      })
                      .exec();
    }

    // Wait for all subscriptions to connect
    {
        const auto conn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (connected_subs.load(std::memory_order_relaxed) < num_subs &&
               std::chrono::steady_clock::now() < conn_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const uint32_t connected = connected_subs.load(std::memory_order_relaxed);
        if (connected < num_subs) {
            log_warn_printf(perflog, "Latency: only %u/%u subscriptions connected\n", connected, num_subs);
        }
    }

    // Seed: post a few updates so all subscribers see initial data
    for (uint32_t seed = 0; seed < 10; ++seed) {
        auto seed_val = prototype.cloneEmpty();
        {
            shared_array<uint8_t> buf(effective_size);
            encodePayload(buf.data(), effective_size, 0, currentTimestampUs());
            seed_val["value"] = buf.freeze().castTo<const void>();
        }
        pv.post(seed_val);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Pre-allocate ring of Values
    constexpr size_t kRingSize = 64;
    std::vector<Value> ring(kRingSize);
    for (size_t i = 0; i < kRingSize; i++) {
        ring[i] = prototype.cloneEmpty();
        shared_array<uint8_t> buf(effective_size);
        ring[i]["value"] = buf.freeze().castTo<const void>();
    }

    const uint32_t total_samples = warmup_samples + num_samples;
    std::vector<double> latencies_us;
    latencies_us.reserve(num_samples);

    for (uint32_t sample = 0; sample < total_samples; ++sample) {
        // Reset all subscriber ready flags
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            st->update_ready = false;
        }

        // Encode counter + steady_clock timestamp into payload
        auto& val = ring[sample % kRingSize];
        uint64_t send_ns;
        {
            shared_array<uint8_t> buf(effective_size);
            const uint64_t net_counter = toNetworkOrder64(static_cast<uint64_t>(sample));
            std::memcpy(buf.data(), &net_counter, kCounterSize);
            const auto send_time = std::chrono::steady_clock::now();
            send_ns = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    send_time.time_since_epoch()).count());
            const uint64_t net_ns = toNetworkOrder64(send_ns);
            std::memcpy(buf.data() + kCounterSize, &net_ns, kCounterSize);
            const auto fill = static_cast<uint8_t>(sample & 0xFF);
            if (effective_size > kHeaderSize)
                std::memset(buf.data() + kHeaderSize, fill, effective_size - kHeaderSize);
            val["value"] = buf.freeze().castTo<const void>();
        }

        pv.post(val);

        // Wait for ALL subscribers to receive this update (timeout 5 seconds)
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool all_received = false;
        while (std::chrono::steady_clock::now() < deadline) {
            all_received = true;
            for (auto& st : states) {
                std::lock_guard<std::mutex> lk(st->mtx);
                if (!st->update_ready || st->last_received_counter != static_cast<uint64_t>(sample)) {
                    all_received = false;
                    break;
                }
            }
            if (all_received) break;
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }

        if (!all_received) {
            log_warn_printf(perflog, "Latency sample %u: not all subscribers received (timeout)\n", sample);
            continue;
        }

        // Find the LAST subscriber to receive (worst-case fan-out latency)
        uint64_t max_recv_ns = 0;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (st->recv_timestamp_ns > max_recv_ns)
                max_recv_ns = st->recv_timestamp_ns;
        }

        const double latency_us = static_cast<double>(max_recv_ns - send_ns) / 1000.0;

        if (sample >= warmup_samples) {
            latencies_us.push_back(latency_us);
        }

        if (send_interval_us > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(send_interval_us));
        }
    }

    // Cancel subscriptions
    for (auto& sub : subs) {
        if (sub)
            sub->cancel();
    }

    LatencyResult result;
    result.protocol = protocolModeStr(mode);
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;
    result.num_samples = static_cast<uint32_t>(latencies_us.size());

    if (!latencies_us.empty()) {
        auto sorted = latencies_us;
        result.median_us = computeMedian(sorted);
        sorted = latencies_us;
        result.p25_us = computePercentile(sorted, 25.0);
        sorted = latencies_us;
        result.p75_us = computePercentile(sorted, 75.0);
        sorted = latencies_us;
        result.p99_us = computePercentile(sorted, 99.0);
        result.cv_pct = computeCV(latencies_us);
        result.mean_us = std::accumulate(latencies_us.begin(), latencies_us.end(), 0.0)
                         / static_cast<double>(latencies_us.size());
        result.min_us = *std::min_element(latencies_us.begin(), latencies_us.end());
        result.max_us = *std::max_element(latencies_us.begin(), latencies_us.end());
        result.theoretical_ups = (result.median_us > 0.0) ? (1000000.0 / result.median_us) : 0.0;
    }

    return result;
}

BurstResult runBurstBenchmark(
    const ProtocolMode mode,
    const size_t payload_size,
    const uint32_t num_subscriptions,
    const std::string& server_keychain,
    const std::string& client_keychain,
    const bool nt_payload,
    const uint16_t cms_udp_port,
    const uint32_t burst_size = 100,
    const uint32_t num_samples = 50,
    const uint32_t warmup_bursts = 5,
    const uint32_t burst_send_interval_us = 0)
{
    const size_t min_size = nt_payload ? kCounterSize : kHeaderSize;
    const size_t effective_size = std::max(payload_size, min_size);

    // --- Server setup (same as runSteadyStateBenchmark) ---
    server::Config sconfig;
    if (mode == ProtocolMode::SPVA_CERTMON && cms_udp_port == 0u) {
        sconfig = server::Config::fromEnv();
    } else {
        sconfig = loopbackServerConfig(
            (mode == ProtocolMode::SPVA_CERTMON) ? cms_udp_port : 0u);
    }

    if (mode == ProtocolMode::PVA) {
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

    auto prototype = nt::NTScalar{TypeCode::UInt8A}.create();
    {
        shared_array<uint8_t> initial_data(effective_size);
        if (nt_payload) {
            const uint64_t net_counter = toNetworkOrder64(0);
            std::memcpy(initial_data.data(), &net_counter, kCounterSize);
            std::memset(initial_data.data() + kCounterSize, 0, effective_size - kCounterSize);
        } else {
            encodePayload(initial_data.data(), effective_size, 0, currentTimestampUs());
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

    // --- Client setup ---
    auto cconfig = server.clientConfig();
    if (mode == ProtocolMode::PVA) {
        cconfig.tls_disabled = true;
    } else {
        cconfig.tls_disabled = false;
        cconfig.tls_keychain_file = client_keychain.empty() ? server_keychain : client_keychain;
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

    std::vector<std::shared_ptr<BurstSubState>> states(num_subs);
    std::vector<std::shared_ptr<client::Subscription>> subs(num_subs);

    for (uint32_t i = 0; i < num_subs; i++) {
        states[i] = std::make_shared<BurstSubState>();
    }

    for (uint32_t i = 0; i < num_subs; i++) {
        const auto& st = states[i];
        subs[i] = ctxt.monitor(pvname)
                      .record("pipeline", true)
                      .record("queueSize", int32_t(4))
                      .maskConnected(true)
                      .maskDisconnected(true)
                      .event([st](client::Subscription& sub) {
                          try {
                              while (auto val = sub.pop()) {
                                  if (!st->connected.load(std::memory_order_relaxed)) {
                                      st->connected.store(true, std::memory_order_release);
                                  }
                                  st->received_count.fetch_add(1, std::memory_order_release);
                              }
                          } catch (...) {}
                      })
                      .exec();
    }

    // Wait for all subscriptions to connect (initial value from pv.open())
    {
        const auto conn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (std::chrono::steady_clock::now() < conn_deadline) {
            bool all_connected = true;
            for (const auto& st : states) {
                if (!st->connected.load(std::memory_order_acquire)) {
                    all_connected = false;
                    break;
                }
            }
            if (all_connected) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // Pre-allocate ring of Values
    constexpr size_t kRingSize = 64;
    std::vector<Value> ring(kRingSize);
    for (size_t i = 0; i < kRingSize; i++) {
        ring[i] = prototype.cloneEmpty();
        shared_array<uint8_t> buf(effective_size);
        ring[i]["value"] = buf.freeze().castTo<const void>();
    }

    // Helper: check if all subscribers have received >= target updates
    auto all_received = [&](uint32_t target) -> bool {
        for (const auto& st : states) {
            if (st->received_count.load(std::memory_order_acquire) < target) {
                return false;
            }
        }
        return true;
    };

    // Warmup: continuous paced feed until all subs have burst_size deliveries
    for (uint32_t w = 0; w < warmup_bursts; ++w) {
        for (auto& st : states) {
            st->received_count.store(0, std::memory_order_release);
        }
        std::atomic<bool> warmup_stop{false};
        std::thread warmup_sender([&]() {
            uint32_t counter = 0;
            while (!warmup_stop.load(std::memory_order_acquire)) {
                auto& val = ring[counter % kRingSize];
                shared_array<uint8_t> buf(effective_size);
                encodePayload(buf.data(), effective_size, counter, 0);
                val["value"] = buf.freeze().castTo<const void>();
                pv.post(val);
                ++counter;
                if (burst_send_interval_us > 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(burst_send_interval_us));
                }
            }
        });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (std::chrono::steady_clock::now() < deadline) {
            if (all_received(burst_size)) break;
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        warmup_stop.store(true, std::memory_order_release);
        warmup_sender.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Measurement loop: continuous paced feed per sample
    std::vector<double> per_delivery_samples;
    per_delivery_samples.reserve(num_samples);

    for (uint32_t s = 0; s < num_samples; ++s) {
        for (auto& st : states) {
            st->received_count.store(0, std::memory_order_release);
        }

        std::atomic<bool> stop{false};
        const auto burst_start = std::chrono::steady_clock::now();

        // Sender thread: post continuously until stop flag
        std::thread sender([&]() {
            uint32_t counter = 0;
            while (!stop.load(std::memory_order_acquire)) {
                auto& val = ring[counter % kRingSize];
                shared_array<uint8_t> buf(effective_size);
                encodePayload(buf.data(), effective_size, counter, 0);
                val["value"] = buf.freeze().castTo<const void>();
                pv.post(val);
                ++counter;
                if (burst_send_interval_us > 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(burst_send_interval_us));
                }
            }
        });

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        bool all_done = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (all_received(burst_size)) {
                all_done = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }

        stop.store(true, std::memory_order_release);
        sender.join();

        const auto burst_end = std::chrono::steady_clock::now();

        if (!all_done) {
            log_warn_printf(perflog, "Burst sample %u: timeout waiting for deliveries\n", s);
            continue;
        }

        const double burst_us = std::chrono::duration<double, std::micro>(burst_end - burst_start).count();
        const uint64_t total_deliveries = static_cast<uint64_t>(burst_size) * num_subscriptions;
        const double per_delivery_us = burst_us / static_cast<double>(total_deliveries);

        per_delivery_samples.push_back(per_delivery_us);

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    for (auto& sub : subs) {
        if (sub)
            sub->cancel();
    }

    BurstResult result;
    result.protocol = protocolModeStr(mode);
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;
    result.burst_size = burst_size;
    result.num_samples = static_cast<uint32_t>(per_delivery_samples.size());

    if (!per_delivery_samples.empty()) {
        auto sorted = per_delivery_samples;
        result.median_per_delivery_us = computeMedian(sorted);
        sorted = per_delivery_samples;
        result.p25_per_delivery_us = computePercentile(sorted, 25.0);
        sorted = per_delivery_samples;
        result.p75_per_delivery_us = computePercentile(sorted, 75.0);
        sorted = per_delivery_samples;
        result.p99_per_delivery_us = computePercentile(sorted, 99.0);
        result.cv_pct = computeCV(per_delivery_samples);
        result.mean_per_delivery_us = std::accumulate(per_delivery_samples.begin(),
                                                       per_delivery_samples.end(), 0.0)
                                       / static_cast<double>(per_delivery_samples.size());
        result.min_per_delivery_us = *std::min_element(per_delivery_samples.begin(),
                                                        per_delivery_samples.end());
        result.max_per_delivery_us = *std::max_element(per_delivery_samples.begin(),
                                                        per_delivery_samples.end());
        result.theoretical_ups = (result.median_per_delivery_us > 0.0)
                                     ? (1000000.0 / result.median_per_delivery_us)
                                     : 0.0;
    }

    return result;
}

/**
 * @brief Per-subscription state for Channel Access counter verification during CA benchmarks.
 */
struct CaSubState {
    std::mutex mtx;
    bool warmup_done{false};
    uint64_t warmup_remaining{0};
    uint64_t expected_counter{0};
    uint64_t success_count{0};
    uint64_t drop_count{0};
    uint64_t error_count{0};
};

/**
 * @brief CA monitor event callback that tracks the counter sequence and records drops.
 * @param args  EPICS CA event handler arguments containing status, data pointer, and user context.
 */
static void caMonitorCallback(struct event_handler_args args) {
    if (args.status != ECA_NORMAL || !args.usr)
        return;

    auto* st = static_cast<CaSubState*>(args.usr);
    const auto* data = static_cast<const uint8_t*>(args.dbr);
    const auto count = args.count;

    if (count < static_cast<long>(kCounterSize))
        return;

    const uint64_t counter = decodeCounter(data, static_cast<size_t>(count));

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

struct CaLatencySubState {
    std::mutex mtx;
    bool first_update_seen{false};
    uint64_t last_received_counter{0};
    uint64_t recv_timestamp_ns{0};
    bool update_ready{false};
};

static void caLatencyCallback(struct event_handler_args args) {
    if (args.status != ECA_NORMAL || !args.usr) return;
    const auto recv_time = std::chrono::steady_clock::now();
    const uint64_t recv_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            recv_time.time_since_epoch()).count());

    auto* st = static_cast<CaLatencySubState*>(args.usr);
    const auto* data = static_cast<const uint8_t*>(args.dbr);
    const auto count = args.count;
    if (count < static_cast<long>(kCounterSize)) return;

    const uint64_t counter = decodeCounter(data, static_cast<size_t>(count));

    std::lock_guard<std::mutex> lk(st->mtx);
    if (!st->first_update_seen) {
        st->first_update_seen = true;
    }
    st->last_received_counter = counter;
    st->recv_timestamp_ns = recv_ns;
    st->update_ready = true;
}

/**
 * @brief RAII wrapper for the embedded EPICS IOC used by CA benchmarks.
 *
 * Initialized once and reused across all CA benchmark iterations.
 */
class EmbeddedIoc {
public:
    EmbeddedIoc() = default;
    ~EmbeddedIoc() { shutdown(); }

    EmbeddedIoc(const EmbeddedIoc&) = delete;
    EmbeddedIoc& operator=(const EmbeddedIoc&) = delete;

    /**
     * @brief Initialize the embedded IOC with a waveform record sized for the largest payload.
     * @param max_payload_size  Maximum payload size in bytes; sets NELM on the waveform record.
     * @return true on success; false if any IOC initialization step fails.
     */
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

        pvxperf_registerRecordDeviceDriver(pdbbase);

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

    /**
     * @brief Shut down the embedded IOC and remove the temporary database file.
     */
    void shutdown() {
        if (initialized_) {
            iocShutdown();
            if (!tmp_db_path_.empty())
                unlink(tmp_db_path_.c_str());
            initialized_ = false;
        }
    }

    /**
     * @brief Return a pointer to the DBADDR of the benchmark waveform record.
     * @return Pointer to the internal DBADDR; valid only after a successful init().
     */
    DBADDR* addr() { return &addr_; }

    /**
     * @brief Check whether the IOC has been successfully initialized.
     * @return true if init() completed without errors.
     */
    bool is_initialized() const { return initialized_; }

private:
    bool initialized_{false};
    DBADDR addr_{};
    std::string tmp_db_path_;
};

/**
 * @brief Run a Channel Access throughput benchmark using the embedded IOC.
 * @param ioc               Initialized EmbeddedIoc instance to use as the CA server.
 * @param payload_size      Requested payload size in bytes.
 * @param duration_sec      Measurement window duration in seconds.
 * @param warmup_count      Number of CA updates to consume before measurement starts.
 * @param num_subscriptions Number of parallel ca_create_subscription() subscriptions.
 * @return                  BenchmarkResult populated with throughput and drop statistics.
 */
BenchmarkResult runCaBenchmark(
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
            caMonitorCallback,
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
            encodePayload(seed_buf.data(), effective_size, 0, currentTimestampUs());
            dbPutField(ioc.addr(), DBF_UCHAR, seed_buf.data(), static_cast<long>(effective_size));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::thread pump_thread([&]() {
        std::vector<uint8_t> buf(effective_size);
        uint64_t cnt = 0;

        while (!stop_pump.load(std::memory_order_relaxed)) {
            encodePayload(buf.data(), effective_size, cnt, currentTimestampUs());
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

/**
 * @brief Run a steady-state CA throughput benchmark with sub-window measurement.
 */
std::vector<SubWindowResult> runCaSteadyStateBenchmark(
    EmbeddedIoc& ioc,
    const size_t payload_size,
    const uint32_t num_subscriptions,
    const uint32_t num_windows = 10,
    const double window_sec = 3.0,
    const uint32_t omit_windows = 2)
{
    std::vector<SubWindowResult> results;

    if (!ioc.is_initialized()) {
        return results;
    }

    const size_t effective_size = std::max(payload_size, kHeaderSize);
    const uint64_t warmup_count = 100;

    int ca_status = ca_context_create(ca_enable_preemptive_callback);
    if (ca_status != ECA_NORMAL) {
        log_warn_printf(perflog, "%s\n", "CA steady-state: ca_context_create failed");
        return results;
    }

    chid chan_id = nullptr;
    ca_status = ca_create_channel("PVXPERF:CA:BENCH", nullptr, nullptr, 0, &chan_id);
    if (ca_status != ECA_NORMAL || !chan_id) {
        log_warn_printf(perflog, "%s\n", "CA steady-state: ca_create_channel failed");
        ca_context_destroy();
        return results;
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
            caMonitorCallback,
            states[i].get(),
            &evids[i]);

        if (ca_status != ECA_NORMAL) {
            log_warn_printf(perflog, "CA steady-state: ca_create_subscription %u failed\n", i);
        }
    }
    ca_flush_io();

    std::atomic<bool> stop_pump{false};

    // Seed phase (same as runCaBenchmark)
    {
        std::vector<uint8_t> seed_buf(effective_size);
        const uint32_t seed_count = std::max(uint32_t(20), num_subs / 10);
        for (uint32_t i = 0; i < seed_count; i++) {
            encodePayload(seed_buf.data(), effective_size, 0, currentTimestampUs());
            dbPutField(ioc.addr(), DBF_UCHAR, seed_buf.data(), static_cast<long>(effective_size));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // Flood pump thread
    std::thread pump_thread([&]() {
        std::vector<uint8_t> buf(effective_size);
        uint64_t cnt = 0;

        while (!stop_pump.load(std::memory_order_relaxed)) {
            encodePayload(buf.data(), effective_size, cnt, currentTimestampUs());
            dbPutField(ioc.addr(), DBF_UCHAR, buf.data(), static_cast<long>(effective_size));
            cnt++;
            if (num_subs > 100 && (cnt & 0xFF) == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }
    });

    // Wait for warmup
    {
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
            log_warn_printf(perflog, "CA steady-state warm-up: only %u/%u subscriptions warmed up\n",
                            warmed_count, num_subs);
        }
    }

    // Sub-window measurement loop
    for (uint32_t win = 0; win < num_windows; ++win) {
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            st->success_count = 0;
            st->drop_count = 0;
            st->error_count = 0;
        }

        const auto win_start = std::chrono::steady_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(
            static_cast<int64_t>(window_sec * 1000)));
        const auto win_end = std::chrono::steady_clock::now();

        const double win_elapsed = std::chrono::duration<double>(win_end - win_start).count();
        uint64_t total_success = 0, total_drops = 0, total_errors = 0;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            total_success += st->success_count;
            total_drops += st->drop_count;
            total_errors += st->error_count;
        }

        SubWindowResult w;
        w.window_index = win;
        w.omitted = (win < omit_windows);
        w.duration_seconds = win_elapsed;
        w.total_updates = total_success;
        w.drops = total_drops;
        w.errors = total_errors;
        w.updates_per_second = (win_elapsed > 0.0) ? (static_cast<double>(total_success) / win_elapsed) : 0.0;
        results.push_back(w);
    }

    stop_pump.store(true, std::memory_order_relaxed);
    pump_thread.join();

    for (auto& eid : evids) {
        if (eid)
            ca_clear_subscription(eid);
    }
    ca_clear_channel(chan_id);
    ca_context_destroy();

    return results;
}

LatencyResult runCaLatencyBenchmark(
    EmbeddedIoc& ioc,
    const size_t payload_size,
    const uint32_t num_subscriptions,
    const uint32_t num_samples = 500,
    const uint32_t warmup_samples = 50,
    const uint32_t send_interval_us = 1000)
{
    LatencyResult result;
    result.protocol = "CA";
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;

    if (!ioc.is_initialized()) {
        return result;
    }

    const size_t effective_size = std::max(payload_size, kHeaderSize);

    int ca_status = ca_context_create(ca_enable_preemptive_callback);
    if (ca_status != ECA_NORMAL) {
        log_warn_printf(perflog, "%s\n", "CA latency: ca_context_create failed");
        return result;
    }

    chid chan_id = nullptr;
    ca_status = ca_create_channel("PVXPERF:CA:BENCH", nullptr, nullptr, 0, &chan_id);
    if (ca_status != ECA_NORMAL || !chan_id) {
        log_warn_printf(perflog, "%s\n", "CA latency: ca_create_channel failed");
        ca_context_destroy();
        return result;
    }
    ca_pend_io(5.0);

    const uint32_t num_subs = num_subscriptions;

    std::vector<std::shared_ptr<CaLatencySubState>> states(num_subs);
    std::vector<evid> evids(num_subs, nullptr);

    for (uint32_t i = 0; i < num_subs; i++) {
        states[i] = std::make_shared<CaLatencySubState>();

        ca_status = ca_create_subscription(
            DBR_CHAR,
            static_cast<unsigned long>(effective_size),
            chan_id,
            DBE_VALUE,
            caLatencyCallback,
            states[i].get(),
            &evids[i]);

        if (ca_status != ECA_NORMAL) {
            log_warn_printf(perflog, "CA latency: ca_create_subscription %u failed\n", i);
        }
    }
    ca_flush_io();

    // Seed phase
    {
        std::vector<uint8_t> seed_buf(effective_size);
        const uint32_t seed_count = std::max(uint32_t(20), num_subs / 10);
        for (uint32_t i = 0; i < seed_count; i++) {
            encodePayload(seed_buf.data(), effective_size, 0, currentTimestampUs());
            dbPutField(ioc.addr(), DBF_UCHAR, seed_buf.data(), static_cast<long>(effective_size));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // Wait for all subscribers to see at least one update
    {
        const auto conn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (std::chrono::steady_clock::now() < conn_deadline) {
            bool all_seen = true;
            for (auto& st : states) {
                std::lock_guard<std::mutex> lk(st->mtx);
                if (!st->first_update_seen) {
                    all_seen = false;
                    break;
                }
            }
            if (all_seen) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    const uint32_t total_samples = warmup_samples + num_samples;
    std::vector<double> latencies_us;
    latencies_us.reserve(num_samples);

    std::vector<uint8_t> buf(effective_size);

    for (uint32_t sample = 0; sample < total_samples; ++sample) {
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            st->update_ready = false;
        }

        const uint64_t net_counter = toNetworkOrder64(static_cast<uint64_t>(sample));
        std::memcpy(buf.data(), &net_counter, kCounterSize);
        const auto send_time = std::chrono::steady_clock::now();
        const uint64_t send_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                send_time.time_since_epoch()).count());
        const uint64_t net_ns = toNetworkOrder64(send_ns);
        std::memcpy(buf.data() + kCounterSize, &net_ns, kCounterSize);
        const auto fill = static_cast<uint8_t>(sample & 0xFF);
        if (effective_size > kHeaderSize)
            std::memset(buf.data() + kHeaderSize, fill, effective_size - kHeaderSize);

        dbPutField(ioc.addr(), DBF_UCHAR, buf.data(), static_cast<long>(effective_size));

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool all_received = false;
        while (std::chrono::steady_clock::now() < deadline) {
            all_received = true;
            for (auto& st : states) {
                std::lock_guard<std::mutex> lk(st->mtx);
                if (!st->update_ready || st->last_received_counter != static_cast<uint64_t>(sample)) {
                    all_received = false;
                    break;
                }
            }
            if (all_received) break;
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }

        if (!all_received) {
            log_warn_printf(perflog, "CA latency sample %u: not all subscribers received (timeout)\n", sample);
            continue;
        }

        uint64_t max_recv_ns = 0;
        for (auto& st : states) {
            std::lock_guard<std::mutex> lk(st->mtx);
            if (st->recv_timestamp_ns > max_recv_ns)
                max_recv_ns = st->recv_timestamp_ns;
        }

        const double latency_us = static_cast<double>(max_recv_ns - send_ns) / 1000.0;

        if (sample >= warmup_samples) {
            latencies_us.push_back(latency_us);
        }

        if (send_interval_us > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(send_interval_us));
        }
    }

    for (auto& eid : evids) {
        if (eid)
            ca_clear_subscription(eid);
    }
    ca_clear_channel(chan_id);
    ca_context_destroy();

    result.num_samples = static_cast<uint32_t>(latencies_us.size());

    if (!latencies_us.empty()) {
        auto sorted = latencies_us;
        result.median_us = computeMedian(sorted);
        sorted = latencies_us;
        result.p25_us = computePercentile(sorted, 25.0);
        sorted = latencies_us;
        result.p75_us = computePercentile(sorted, 75.0);
        sorted = latencies_us;
        result.p99_us = computePercentile(sorted, 99.0);
        result.cv_pct = computeCV(latencies_us);
        result.mean_us = std::accumulate(latencies_us.begin(), latencies_us.end(), 0.0)
                         / static_cast<double>(latencies_us.size());
        result.min_us = *std::min_element(latencies_us.begin(), latencies_us.end());
        result.max_us = *std::max_element(latencies_us.begin(), latencies_us.end());
        result.theoretical_ups = (result.median_us > 0.0) ? (1000000.0 / result.median_us) : 0.0;
    }

    return result;
}

struct CaBurstSubState {
    std::atomic<bool> connected{false};
    std::atomic<uint64_t> received_count{0};
    std::atomic<uint64_t> last_counter{0};
};

static void caBurstCallback(struct event_handler_args args) {
    if (args.status != ECA_NORMAL || !args.usr) return;
    auto* st = static_cast<CaBurstSubState*>(args.usr);
    if (!st->connected.load(std::memory_order_relaxed)) {
        st->connected.store(true, std::memory_order_release);
    }
    st->received_count.fetch_add(1, std::memory_order_release);

    // Track last counter seen (for debugging)
    const auto* data = static_cast<const uint8_t*>(args.dbr);
    const auto count = args.count;
    if (count >= static_cast<long>(kCounterSize)) {
        const uint64_t counter = decodeCounter(data, static_cast<size_t>(count));
        st->last_counter.store(counter, std::memory_order_release);
    }
}

BurstResult runCaBurstBenchmark(
    EmbeddedIoc& ioc,
    const size_t payload_size,
    const uint32_t num_subscriptions,
    const uint32_t burst_size = 100,
    const uint32_t num_samples = 50,
    const uint32_t warmup_bursts = 5,
    const uint32_t burst_send_interval_us = 100)
{
    BurstResult result;
    result.protocol = "CA";
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;
    result.burst_size = burst_size;

    if (!ioc.is_initialized()) {
        return result;
    }

    const size_t effective_size = std::max(payload_size, kHeaderSize);

    int ca_status = ca_context_create(ca_enable_preemptive_callback);
    if (ca_status != ECA_NORMAL) {
        log_warn_printf(perflog, "%s\n", "CA burst: ca_context_create failed");
        return result;
    }

    chid chan_id = nullptr;
    ca_status = ca_create_channel("PVXPERF:CA:BENCH", nullptr, nullptr, 0, &chan_id);
    if (ca_status != ECA_NORMAL || !chan_id) {
        log_warn_printf(perflog, "%s\n", "CA burst: ca_create_channel failed");
        ca_context_destroy();
        return result;
    }
    ca_pend_io(5.0);

    const uint32_t num_subs = num_subscriptions;

    std::vector<std::shared_ptr<CaBurstSubState>> states(num_subs);
    std::vector<evid> evids(num_subs, nullptr);

    for (uint32_t i = 0; i < num_subs; i++) {
        states[i] = std::make_shared<CaBurstSubState>();

        ca_status = ca_create_subscription(
            DBR_CHAR,
            static_cast<unsigned long>(effective_size),
            chan_id,
            DBE_VALUE,
            caBurstCallback,
            states[i].get(),
            &evids[i]);

        if (ca_status != ECA_NORMAL) {
            log_warn_printf(perflog, "CA burst: ca_create_subscription %u failed\n", i);
        }
    }
    ca_flush_io();

    // Seed: slow updates so CA dispatches to all subscriptions
    {
        std::vector<uint8_t> seed_buf(effective_size);
        const uint32_t seed_count = std::max(uint32_t(20), num_subs / 10);
        for (uint32_t i = 0; i < seed_count; i++) {
            encodePayload(seed_buf.data(), effective_size, 0, currentTimestampUs());
            dbPutField(ioc.addr(), DBF_UCHAR, seed_buf.data(), static_cast<long>(effective_size));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // Wait for all subscribers to connect
    {
        const auto conn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (std::chrono::steady_clock::now() < conn_deadline) {
            ca_pend_event(0.01);
            bool all_connected = true;
            for (const auto& st : states) {
                if (!st->connected.load(std::memory_order_acquire)) {
                    all_connected = false;
                    break;
                }
            }
            if (all_connected) break;
        }
    }

    auto ca_all_received = [&](uint32_t target) -> bool {
        for (const auto& st : states) {
            if (st->received_count.load(std::memory_order_acquire) < target) {
                return false;
            }
        }
        return true;
    };

    // Warmup: continuous paced feed until all subs have burst_size deliveries
    for (uint32_t w = 0; w < warmup_bursts; ++w) {
        for (auto& st : states) {
            st->received_count.store(0, std::memory_order_release);
            st->last_counter.store(0, std::memory_order_release);
        }
        std::atomic<bool> warmup_stop{false};
        std::thread warmup_sender([&]() {
            std::vector<uint8_t> send_buf(effective_size);
            uint32_t counter = 0;
            while (!warmup_stop.load(std::memory_order_acquire)) {
                encodePayload(send_buf.data(), effective_size, counter, 0);
                dbPutField(ioc.addr(), DBF_UCHAR, send_buf.data(), static_cast<long>(effective_size));
                ++counter;
                if (burst_send_interval_us > 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(burst_send_interval_us));
                }
            }
        });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (std::chrono::steady_clock::now() < deadline) {
            ca_pend_event(0.0001);
            if (ca_all_received(burst_size)) break;
        }
        warmup_stop.store(true, std::memory_order_release);
        warmup_sender.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    std::vector<double> per_delivery_samples;
    per_delivery_samples.reserve(num_samples);

    for (uint32_t s = 0; s < num_samples; ++s) {
        for (auto& st : states) {
            st->received_count.store(0, std::memory_order_release);
            st->last_counter.store(0, std::memory_order_release);
        }

        std::atomic<bool> stop{false};
        const auto burst_start = std::chrono::steady_clock::now();

        std::thread sender([&]() {
            std::vector<uint8_t> send_buf(effective_size);
            uint32_t counter = 0;
            while (!stop.load(std::memory_order_acquire)) {
                encodePayload(send_buf.data(), effective_size, counter, 0);
                dbPutField(ioc.addr(), DBF_UCHAR, send_buf.data(), static_cast<long>(effective_size));
                ++counter;
                if (burst_send_interval_us > 0) {
                    std::this_thread::sleep_for(std::chrono::microseconds(burst_send_interval_us));
                }
            }
        });

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        bool all_done = false;
        while (std::chrono::steady_clock::now() < deadline) {
            ca_pend_event(0.0001);
            if (ca_all_received(burst_size)) {
                all_done = true;
                break;
            }
        }

        stop.store(true, std::memory_order_release);
        sender.join();

        const auto burst_end = std::chrono::steady_clock::now();

        if (!all_done) {
            for (uint32_t i = 0; i < num_subs; ++i) {
                const uint64_t got = states[i]->received_count.load(std::memory_order_acquire);
                if (got < burst_size) {
                    log_warn_printf(perflog,
                        "CA burst sample %u: sub[%u] lagging: received %llu/%u\n",
                        s, i, static_cast<unsigned long long>(got), burst_size);
                }
            }
            log_warn_printf(perflog, "CA burst sample %u: timeout waiting for deliveries\n", s);
            continue;
        }

        const double burst_us = std::chrono::duration<double, std::micro>(burst_end - burst_start).count();
        const uint64_t total_deliveries = static_cast<uint64_t>(burst_size) * num_subscriptions;
        const double per_delivery_us = burst_us / static_cast<double>(total_deliveries);

        per_delivery_samples.push_back(per_delivery_us);

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    for (auto& eid : evids) {
        if (eid)
            ca_clear_subscription(eid);
    }
    ca_clear_channel(chan_id);
    ca_context_destroy();

    result.num_samples = static_cast<uint32_t>(per_delivery_samples.size());

    if (!per_delivery_samples.empty()) {
        auto sorted = per_delivery_samples;
        result.median_per_delivery_us = computeMedian(sorted);
        sorted = per_delivery_samples;
        result.p25_per_delivery_us = computePercentile(sorted, 25.0);
        sorted = per_delivery_samples;
        result.p75_per_delivery_us = computePercentile(sorted, 75.0);
        sorted = per_delivery_samples;
        result.p99_per_delivery_us = computePercentile(sorted, 99.0);
        result.cv_pct = computeCV(per_delivery_samples);
        result.mean_per_delivery_us = std::accumulate(per_delivery_samples.begin(),
                                                       per_delivery_samples.end(), 0.0)
                                       / static_cast<double>(per_delivery_samples.size());
        result.min_per_delivery_us = *std::min_element(per_delivery_samples.begin(),
                                                        per_delivery_samples.end());
        result.max_per_delivery_us = *std::max_element(per_delivery_samples.begin(),
                                                        per_delivery_samples.end());
        result.theoretical_ups = (result.median_per_delivery_us > 0.0)
                                     ? (1000000.0 / result.median_per_delivery_us)
                                     : 0.0;
    }

    return result;
}

void writeCsvHeader(std::ostream& out) {
    out << "protocol,payload_mode,subscribers,payload_bytes,topology,iteration,"
           "updates_per_second,per_sub_updates_per_second,total_updates,drops,errors,duration_seconds"
        << std::endl;
}

/**
 * @brief Write one throughput benchmark result as a CSV row.
 * @param out  Output stream to write to.
 * @param r    BenchmarkResult to serialize.
 */
void writeCsvRow(std::ostream& out, const BenchmarkResult& r) {
    out << r.protocol << ","
        << r.payload_mode << ","
        << r.subscribers << ","
        << r.payload_bytes << ","
        << r.topology << ","
        << r.iteration << ","
        << r.updates_per_second << ","
        << r.per_sub_updates_per_second << ","
        << r.total_updates << ","
        << r.drops << ","
        << r.errors << ","
        << r.duration_seconds
        << std::endl;
    out.flush();
}

/**
 * @brief Write the phase timing CSV header row to the given output stream.
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
 * @brief Run pvxperf in distributed server mode, serving PVXPERF:BENCH and PVXPERF:READY PVs.
 * @param mode              Protocol mode (PVA, SPVA, or SPVA_CERTMON).
 * @param bind_addr         Host:port string to bind the server socket (e.g. "0.0.0.0:0" for ephemeral).
 * @param duration_sec      Maximum run time in seconds; 0 means run until SIGTERM/SIGINT.
 * @param max_payload_size  Maximum payload size in bytes for the benchmark waveform.
 * @param keychain          Path to TLS keychain file (.p12) for SPVA modes.
 * @param nt_payload        If true, use NTScalar payload with timestamp metadata.
 * @return 0 on clean shutdown.
 */
int runServerMode(
    const ProtocolMode mode,
    const std::string& bind_addr,
    const double duration_sec,
    const size_t max_payload_size,
    const std::string& keychain,
    const bool nt_payload)
{
    const size_t min_size = nt_payload ? kCounterSize : kHeaderSize;
    const size_t effective_size = std::max(max_payload_size, min_size);

    auto sconfig = server::Config::fromEnv();

    // Parse bind_addr into host and port
    std::string bind_host = "0.0.0.0";
    unsigned short bind_port = 0;
    {
        const size_t colon = bind_addr.rfind(':');
        if (colon != std::string::npos) {
            bind_host = bind_addr.substr(0, colon);
            bind_port = static_cast<unsigned short>(std::stoul(bind_addr.substr(colon + 1)));
        }
    }

    sconfig.interfaces.clear();
    sconfig.interfaces.push_back(bind_host);
    sconfig.beaconDestinations.clear();

    if (mode == ProtocolMode::PVA) {
        sconfig.tls_disabled = true;
        sconfig.tcp_port = bind_port;
    } else {
        sconfig.tls_disabled = false;
        sconfig.tls_port = bind_port;
        if (!keychain.empty()) {
            sconfig.tls_keychain_file = keychain;
        }
#ifdef PVXS_ENABLE_EXPERT_API
        if (mode == ProtocolMode::SPVA) {
            sconfig.disableStatusCheck(true);
        } else {
            sconfig.disableStatusCheck(false);
        }
#endif
    }

    auto bench_pv = server::SharedPV::buildReadonly();

    auto prototype = nt::NTScalar{TypeCode::UInt8A}.create();
    {
        shared_array<uint8_t> initial_data(effective_size);
        if (nt_payload) {
            const uint64_t net_counter = toNetworkOrder64(0);
            std::memcpy(initial_data.data(), &net_counter, kCounterSize);
            std::memset(initial_data.data() + kCounterSize, 0, effective_size - kCounterSize);
        } else {
            encodePayload(initial_data.data(), effective_size, 0, currentTimestampUs());
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
    bench_pv.open(prototype);

    auto ready_pv = server::SharedPV::buildReadonly();
    auto ready_proto = nt::NTScalar{TypeCode::Int32}.create();
    ready_proto["value"] = int32_t(1);
    ready_pv.open(ready_proto);

    const auto srv = sconfig.build()
                   .addPV("PVXPERF:BENCH", bench_pv)
                   .addPV("PVXPERF:READY", ready_pv)
                   .start();

    // Print listening address with scheme prefix for direct use as nameserver
    const auto& conf = srv.config();
    if (mode == ProtocolMode::PVA) {
        for (const auto& iface : conf.interfaces) {
            std::cout << "PVXPERF_SERVER_ADDR=pva://" << iface << ":" << conf.tcp_port << std::endl;
        }
    } else {
        for (const auto& iface : conf.interfaces) {
            std::cout << "PVXPERF_SERVER_ADDR=pvas://" << iface << ":" << conf.tls_port << std::endl;
        }
    }
    std::cout.flush();

    // Install signal handlers
    g_server_stop = 0;
    signal(SIGTERM, serverSignalHandler);
    signal(SIGINT, serverSignalHandler);

    // Start pump thread
    std::atomic<bool> stop_pump{false};

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
                    const uint64_t net_counter = toNetworkOrder64(cnt);
                    std::memcpy(buf.data(), &net_counter, kCounterSize);
                    const auto fill = static_cast<uint8_t>(cnt & 0xFF);
                    std::memset(buf.data() + kCounterSize, fill, effective_size - kCounterSize);
                } else {
                    encodePayload(buf.data(), effective_size, cnt, currentTimestampUs());
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
                bench_pv.post(val);
            } catch (std::exception& e) {
                log_debug_printf(perflog, "server pump post() error: %s\n", e.what());
            }
            cnt++;
        }
    });

    // Wait for signal or duration timeout
    if (duration_sec > 0.0) {
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(static_cast<int64_t>(duration_sec * 1000));
        while (!g_server_stop && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } else {
        while (!g_server_stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    stop_pump.store(true, std::memory_order_relaxed);
    pump_thread.join();

    log_info_printf(perflog, "%s\n", "Server mode shutting down");
    return 0;
}

/**
 * @brief Run a PVA/SPVA throughput benchmark against a remote server (distributed client mode).
 * @param mode              Protocol mode (PVA, SPVA, or SPVA_CERTMON).
 * @param payload_size      Requested payload size in bytes.
 * @param duration_sec      Measurement window duration in seconds.
 * @param warmup_count      Number of updates to consume before measurement starts.
 * @param num_subscriptions Number of parallel monitor subscriptions to create.
 * @param client_keychain   Path to TLS client keychain file (.p12) for SPVA modes.
 * @param nt_payload        If true, use NTScalar payload with timestamp metadata.
 * @param ctxt              Pre-configured PVA client context connected to the remote server.
 * @return BenchmarkResult populated with throughput and drop statistics.
 */
BenchmarkResult runPvaBenchmarkClient(
    const ProtocolMode mode,
    const size_t payload_size,
    const double duration_sec,
    const uint64_t warmup_count,
    const uint32_t num_subscriptions,
    const std::string& client_keychain,
    const bool nt_payload,
    client::Context& ctxt)
{
    BenchmarkResult result;
    result.protocol = protocolModeStr(mode);
    result.payload_mode = nt_payload ? "nt" : "raw";
    result.subscribers = num_subscriptions;
    result.payload_bytes = payload_size;

    const std::string pvname = "PVXPERF:BENCH";
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

                                  const uint64_t counter = decodeCounter(arr.data(), arr.size());

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

    // Wait for all subscriptions to connect
    {
        const auto conn_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (connected_subs.load(std::memory_order_relaxed) < num_subs &&
               std::chrono::steady_clock::now() < conn_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const uint32_t connected = connected_subs.load(std::memory_order_relaxed);
        if (connected < num_subs) {
            log_warn_printf(perflog, "Client: only %u/%u subscriptions connected\n", connected, num_subs);
        }
        log_debug_printf(perflog, "Client: %u/%u subscriptions connected\n", connected, num_subs);
    }

    // Wait for warm-up
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
        log_warn_printf(perflog, "%s\n", "Client: warm-up did not complete for all subscriptions");
    }

    // Reset counters for measurement
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

/**
 * @brief Print a starter PVAGW v2 gateway config, ACF, pvlist, and usage example to stdout/stderr.
 * @param server_addr  Upstream server address (substituted into the gateway config).
 * @param client_addr  Client-facing downstream bind address.
 * @param keychain     Path to the gateway TLS keychain file (.p12).
 */
void printGatewayConfigOutput(const std::string& server_addr,
                                  const std::string& client_addr,
                                  const std::string& keychain)
{
    const std::string kc_path = keychain.empty() ? "<GATEWAY_KEYCHAIN_PATH>" : keychain;
    const std::string srv_addr = server_addr.empty() ? "<SERVER_ADDR>" : server_addr;
    const std::string cli_addr = client_addr.empty() ? "<CLIENT_FACING_ADDR>" : client_addr;

    std::cout << "# gateway.conf\n"
              << "{\n"
              << "  \"version\": 2,\n"
              << "  \"readOnly\": false,\n"
              << "  \"clients\": [\n"
              << "    {\n"
              << "      \"name\": \"upstream\",\n"
              << "      \"autoaddrlist\": false,\n"
              << "      \"addrlist\": \"" << srv_addr << "\",\n"
              << "      \"tls_keychain\": \"" << kc_path << "\"\n"
              << "    }\n"
              << "  ],\n"
              << "  \"servers\": [\n"
              << "    {\n"
              << "      \"name\": \"downstream\",\n"
              << "      \"clients\": [\"upstream\"],\n"
              << "      \"statusprefix\": \"GW:STS:\",\n"
              << "      \"autoaddrlist\": false,\n"
              << "      \"addrlist\": \"" << cli_addr << "\",\n"
              << "      \"tls_keychain\": \"" << kc_path << "\",\n"
              << "      \"access\": \"gateway.acf\",\n"
              << "      \"pvlist\": \"gateway.pvlist\"\n"
              << "    },\n"
              << "    {\n"
              << "      \"name\": \"downstream_status\",\n"
              << "      \"clients\": [],\n"
              << "      \"interface\": [\"127.0.0.1\"],\n"
              << "      \"statusprefix\": \"GW:STS:\"\n"
              << "    }\n"
              << "  ]\n"
              << "}\n"
              << std::endl;

    std::cout << "# gateway.acf\n"
              << "ASG(DEFAULT) {\n"
              << "    RULE(1,READ)\n"
              << "    RULE(1,WRITE)\n"
              << "}\n"
              << std::endl;

    std::cout << "# gateway.pvlist\n"
              << "PVXPERF:.* ALLOW\n"
              << std::endl;

    std::cerr << "# Example usage:\n"
              << "# 1. Start server:\n"
              << "#    pvxperf --role server --modes spva --keychain server.p12 --bind-addr 127.0.0.1:5076\n"
              << "# 2. Start gateway:\n"
              << "#    pvagw gateway.conf\n"
              << "# 3. Start client:\n"
              << "#    pvxperf --role client --modes spva --keychain client.p12 --server-addr 127.0.0.1:5077 --gateway\n"
              << std::endl;
}

} // namespace

/**
 * @brief pvxperf entry point — parses CLI options and dispatches server, client, or loopback mode.
 * @param argc  Argument count.
 * @param argv  Argument vector.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char* argv[]) {
    try {
        errlogInit2(1024 * 1024, 0);
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
        uint32_t throughput_iterations = 5;
        bool benchmark_phases = false;
        uint32_t phase_iterations = 50;
        std::string phase_output;
        std::string role = "loopback";
        std::string bind_addr = "0.0.0.0:0";
        std::string server_addr;
        bool use_gateway = false;
        bool print_gateway_config = false;
        std::string bench_mode = "steady-state";
        uint32_t num_windows = 10;
        double window_duration = 3.0;
        uint32_t omit_windows = 2;
        uint32_t latency_samples = 500;
        uint32_t latency_warmup = 50;
        uint32_t send_interval_us_opt = 1000;
        uint32_t burst_size = 100;
        uint32_t burst_samples = 50;
        uint32_t burst_warmup = 5;
        uint32_t burst_send_interval_us = 100;

        app.add_option("--duration", duration, "Measurement duration per data point in seconds");
        app.add_option("--warmup", warmup, "Number of warm-up updates before measurement");
        app.add_option("--subscriptions", subs_str,
                        "Comma-separated subscriber counts to sweep (e.g. 1,10,100,500,1000)");
        app.add_option("--sizes", sizes_str, "Comma-separated payload sizes in bytes");
        app.add_option("--modes", modes_str, "Comma-separated protocol modes: ca,pva,spva,spva_certmon");
        app.add_option("--keychain", keychain, "TLS keychain file for SPVA modes");
        app.add_option("--output", output_file, "CSV output file (default: stdout)");
        app.add_option("--throughput-iterations", throughput_iterations,
                       "Number of independent measurement iterations per data point");
        app.add_option("--bench-mode", bench_mode,
                       "Benchmark mode: adaptive, steady-state (default), latency, or burst");
        app.add_option("--num-windows", num_windows,
                       "Number of measurement sub-windows per data point");
        app.add_option("--window-duration", window_duration,
                       "Duration of each measurement sub-window in seconds");
        app.add_option("--omit-windows", omit_windows,
                       "Number of initial sub-windows to omit as warmup");
        app.add_option("--latency-samples", latency_samples,
                       "Number of measured latency samples (after warmup)");
        app.add_option("--latency-warmup", latency_warmup,
                       "Number of warmup samples to discard");
        app.add_option("--send-interval", send_interval_us_opt,
                       "Microseconds between latency sample sends (default 1000 = 1ms)");
        app.add_option("--burst-size", burst_size,
                       "Updates per burst (burst mode)");
        app.add_option("--burst-samples", burst_samples,
                       "Number of burst measurements");
        app.add_option("--burst-warmup", burst_warmup,
                       "Warmup bursts to discard");
        app.add_option("--burst-send-interval", burst_send_interval_us,
                       "Microseconds between sends in CA burst mode (default: 100). Prevents CA squashing.")->default_val(100);
        app.add_flag("--setup-cms", setup_cms,
                     "Auto-bootstrap PVACMS with temp certs for SPVA_CERTMON");
        app.add_flag("--external-cms", external_cms,
                     "Use already-running PVACMS for SPVA_CERTMON");
        app.add_option("--cms-db", cms_db, "Path to existing PVACMS SQLite database");
        app.add_option("--cms-keychain", cms_keychain, "Path to existing PVACMS server keychain");
        app.add_option("--cms-acf", cms_acf, "Path to existing PVACMS ACF file");
        app.add_flag("--nt-payload", nt_payload,
                     "Use NT types for PVA payload (adds timestamp/alarm metadata overhead)");
        app.add_flag("--benchmark-phases", benchmark_phases, "Run connection phase timing benchmark");
        app.add_option("--phase-iterations", phase_iterations,
                       "Number of connect/disconnect cycles for phase timing");
        app.add_option("--phase-output", phase_output, "Separate CSV file for phase timing output");
        app.add_option("--role", role, "Operating mode: loopback (default), server, client");
        app.add_option("--bind-addr", bind_addr, "Server bind address (host:port). Default 0.0.0.0:0");
        app.add_option("--server-addr", server_addr, "Remote server address (host:port) for client mode");
        app.add_flag("--gateway", use_gateway, "Mark benchmark topology as gateway (client mode)");
        app.add_flag("--print-gateway-config", print_gateway_config,
                     "Print example PVAGW gateway config and exit");
        app.add_flag("-d,--debug", debug, "Enable PVXS debug logging");
        app.add_flag("-V,--version", show_version, "Print version and exit");

        CLI11_PARSE(app, argc, argv);

        if (help) {
            auto program_name = argv[0];
            std::cout
                << "pvxperf - PVAccess Performance Benchmarking Tool\n"
                << std::endl
                << "Measures monitor subscription throughput (updates/second) across four protocol\n"
                << "modes: CA, PVA, SPVA, and SPVA+CERTMON using adaptive rate discovery.\n"
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
                << "        --throughput-iterations <N>            Number of independent measurement iterations per\n"
                << "                                              data point. Default 5\n"
                << "        --bench-mode <mode>                   Benchmark mode: adaptive (legacy),\n"
                << "                                              steady-state (default), latency, or burst.\n"
                << "                                              Burst sends B updates back-to-back for low-CV\n"
                << "                                              per-delivery cost measurement\n"
                << "        --num-windows <N>                     Number of measurement sub-windows per data\n"
                << "                                              point (steady-state mode). Default 10\n"
                << "        --window-duration <seconds>           Duration of each sub-window. Default 3.0\n"
                << "        --omit-windows <N>                    Initial sub-windows to discard as warmup.\n"
                << "                                              Default 2\n"
                << "        --latency-samples <N>                 Number of measured latency samples. Default 500\n"
                << "        --latency-warmup <N>                  Warmup samples to discard. Default 50\n"
                << "        --send-interval <us>                  Microseconds between latency sends. Default 1000\n"
                << "        --burst-size <N>                      Updates per burst (burst mode). Default 100\n"
                << "        --burst-samples <N>                   Number of burst measurements. Default 50\n"
                << "        --burst-warmup <N>                    Warmup bursts to discard. Default 5\n"
                << "        --burst-send-interval <us>            Microseconds between sends in CA burst mode.\n"
                << "                                              Prevents CA queue squashing. Default 100\n"
                << "        --nt-payload                          Use NT types for PVA payload (adds timestamp/alarm\n"
                << "                                              metadata overhead)\n"
                << "        --output <file>                       CSV output file. Default stdout\n"
                << std::endl
                << "phase timing options:\n"
                << "        --benchmark-phases                    Run connection phase timing benchmark\n"
                << "        --phase-iterations <N>                Number of connect/disconnect cycles for phase\n"
                << "                                              timing. Default 50\n"
                << "        --phase-output <file>                 Separate CSV file for phase timing output\n"
                << std::endl
                << "distributed mode options:\n"
                << "        --role <mode>                         Operating mode: loopback (default), server, client\n"
                << "        --bind-addr <host:port>               Server bind address. Default 0.0.0.0:0\n"
                << "        --server-addr <host:port>             Remote server address (required for --role client)\n"
                << "        --gateway                             Mark topology as gateway (client mode)\n"
                << "        --print-gateway-config                Print example PVAGW config and exit\n"
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

        const auto modes = parseModes(modes_str);
        const auto sizes = parseSizes(sizes_str);
        const auto sub_counts = parseSubCounts(subs_str);

        // Validate --role
        if (role != "loopback" && role != "server" && role != "client") {
            std::cerr << "Error: --role must be loopback, server, or client" << std::endl;
            return 1;
        }

        // --print-gateway-config: output config and exit
        if (print_gateway_config) {
            printGatewayConfigOutput(bind_addr, "0.0.0.0:5077", keychain);
            return 0;
        }

        // Validate distributed mode constraints
        if (role == "server") {
            for (const auto m : modes) {
                if (m == ProtocolMode::CA) {
                    std::cerr << "Error: CA mode is not supported in distributed mode (--role server)" << std::endl;
                    return 1;
                }
            }
        }

        if (role == "client" && server_addr.empty()) {
            std::cerr << "Error: --server-addr is required with --role client" << std::endl;
            return 1;
        }

        if (role == "client") {
            for (const auto m : modes) {
                if (m == ProtocolMode::CA) {
                    std::cerr << "Error: CA mode is not supported in distributed mode (--role client)" << std::endl;
                    return 1;
                }
            }
        }

        // Server mode: serve PVs and pump, then exit
        if (role == "server") {
            const size_t max_size = sizes.empty() ? size_t(1024) : *std::max_element(sizes.begin(), sizes.end());
            const ProtocolMode server_mode = modes.empty() ? ProtocolMode::PVA : modes[0];
            return runServerMode(server_mode, bind_addr, duration, max_size, keychain, nt_payload);
        }

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
            log_info_printf(perflog, "CMS temp directory: %s\n", tmp_cms_dir.c_str());

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

            log_info_printf(perflog, "%s\n", "CMS setup complete, keychains provisioned");
        }

        writeCsvHeader(*out);

        std::vector<BenchmarkResult> all_results;

        if (role == "client") {
            // Client mode: connect to remote server, run benchmarks
            const std::string topology = use_gateway ? "gateway" : "direct";
            const ProtocolMode client_mode = modes.empty() ? ProtocolMode::PVA : modes[0];

            auto cconfig = client::Config::fromEnv();
            cconfig.nameServers.clear();
            cconfig.addressList.clear();

            if (client_mode == ProtocolMode::PVA) {
                cconfig.tls_disabled = true;
                cconfig.nameServers.push_back(server_addr.find("://") != std::string::npos
                    ? server_addr : "pva://" + server_addr);
            } else {
                cconfig.tls_disabled = false;
                cconfig.tls_keychain_file = client_keychain.empty() ? keychain : client_keychain;
                cconfig.nameServers.push_back(server_addr.find("://") != std::string::npos
                    ? server_addr : "pvas://" + server_addr);
#ifdef PVXS_ENABLE_EXPERT_API
                if (client_mode == ProtocolMode::SPVA) {
                    cconfig.disableStatusCheck(true);
                } else {
                    cconfig.disableStatusCheck(false);
                }
#endif
            }
            cconfig.autoAddrList = false;

            auto ctxt = cconfig.build();

            // Probe PVXPERF:READY with 30s timeout
            {
                const auto ready_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
                bool ready = false;
                while (std::chrono::steady_clock::now() < ready_deadline) {
                    try {
                        const auto val = ctxt.get("PVXPERF:READY").exec()->wait(3.0);
                        if (val) {
                            ready = true;
                            break;
                        }
                    } catch (std::exception& e) {
                        log_debug_printf(perflog, "PVXPERF:READY probe: %s\n", e.what());
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                if (!ready) {
                    std::cerr << "Error: PVXPERF:READY not available on server at " << server_addr << std::endl;
                    return 1;
                }
                log_info_printf(perflog, "Server at %s is ready\n", server_addr.c_str());
            }

            for (const auto mode : modes) {
                for (const auto payload_size : sizes) {
                    for (const auto num_subs : sub_counts) {
                        for (uint32_t iter = 1; iter <= throughput_iterations; ++iter) {
                            log_info_printf(perflog, "Client benchmarking %s %u subs %zu bytes (iter %u/%u)...\n",
                                           protocolModeStr(mode), num_subs, payload_size,
                                           iter, throughput_iterations);

                            BenchmarkResult result = runPvaBenchmarkClient(
                                mode, payload_size, duration, warmup, num_subs,
                                client_keychain.empty() ? keychain : client_keychain,
                                nt_payload, ctxt);

                            result.topology = topology;
                            result.iteration = iter;

                            writeCsvRow(*out, result);
                            all_results.push_back(result);

                            log_info_printf(perflog, "  -> %.1f updates/sec (%.1f/sub), %lu total, %lu drops, %lu errors\n",
                                           result.updates_per_second,
                                           result.per_sub_updates_per_second,
                                           (unsigned long)result.total_updates,
                                           (unsigned long)result.drops,
                                           (unsigned long)result.errors);
                        }
                    }
                }
            }
        } else {
            // Loopback mode: existing in-process server+client benchmarks
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
                    std::cerr << "Warning: skipping " << protocolModeStr(mode)
                              << " — no keychain available" << std::endl;
                    continue;
                }

                if (mode == ProtocolMode::SPVA_CERTMON && !setup_cms && !external_cms) {
                    std::cerr << "Warning: skipping SPVA_CERTMON — no CMS configured "
                              << "(use --setup-cms or --external-cms)" << std::endl;
                    continue;
                }

                if (mode == ProtocolMode::SPVA_CERTMON && external_cms) {
                    if (!waitForPvacms(10.0, 0u)) {
                        std::cerr << "Warning: skipping SPVA_CERTMON — external CMS not reachable" << std::endl;
                        continue;
                    }
                }

                for (const auto payload_size : sizes) {
                    for (const auto num_subs : sub_counts) {
                        const uint32_t effective_iterations =
                            (bench_mode == "steady-state" || bench_mode == "latency" || bench_mode == "burst") ? 1 : throughput_iterations;
                        for (uint32_t iter = 1; iter <= effective_iterations; ++iter) {
                            log_info_printf(perflog, "Benchmarking %s %u subs %zu bytes (%s)...\n",
                                           protocolModeStr(mode), num_subs, payload_size,
                                           bench_mode.c_str());

                            if (bench_mode == "latency") {
                                if (mode == ProtocolMode::CA) {
                                    auto lr = runCaLatencyBenchmark(ca_ioc, payload_size,
                                        num_subs, latency_samples, latency_warmup, send_interval_us_opt);
                                    printLatencySummary(lr);
                                    BenchmarkResult r;
                                    r.protocol = "CA";
                                    r.payload_mode = "raw";
                                    r.subscribers = num_subs;
                                    r.payload_bytes = payload_size;
                                    r.iteration = 1;
                                    r.updates_per_second = lr.theoretical_ups;
                                    r.per_sub_updates_per_second = (num_subs > 0) ? (lr.theoretical_ups / num_subs) : 0.0;
                                    r.total_updates = lr.num_samples;
                                    r.drops = 0;
                                    r.errors = 0;
                                    r.duration_seconds = lr.median_us / 1e6;
                                    writeCsvRow(*out, r);
                                    all_results.push_back(r);
                                } else {
                                    const uint16_t cms_port = setup_cms ? kPvacmsUdpPort : 0u;
                                    auto lr = runLatencyBenchmark(mode, payload_size,
                                        num_subs, keychain, client_keychain, nt_payload, cms_port,
                                        latency_samples, latency_warmup, send_interval_us_opt);
                                    printLatencySummary(lr);
                                    BenchmarkResult r;
                                    r.protocol = protocolModeStr(mode);
                                    r.payload_mode = nt_payload ? "nt" : "raw";
                                    r.subscribers = num_subs;
                                    r.payload_bytes = payload_size;
                                    r.iteration = 1;
                                    r.updates_per_second = lr.theoretical_ups;
                                    r.per_sub_updates_per_second = (num_subs > 0) ? (lr.theoretical_ups / num_subs) : 0.0;
                                    r.total_updates = lr.num_samples;
                                    r.drops = 0;
                                    r.errors = 0;
                                    r.duration_seconds = lr.median_us / 1e6;
                                    writeCsvRow(*out, r);
                                    all_results.push_back(r);
                                }
                            } else if (bench_mode == "steady-state") {
                                if (mode == ProtocolMode::CA) {
                                    auto windows = runCaSteadyStateBenchmark(ca_ioc, payload_size,
                                        num_subs, num_windows, window_duration, omit_windows);
                                    printSteadyStateSummary(windows, "CA", num_subs, payload_size);
                                    uint32_t csv_iter = 1;
                                    for (const auto& w : windows) {
                                        if (w.omitted) continue;
                                        BenchmarkResult r;
                                        r.protocol = "CA";
                                        r.payload_mode = "raw";
                                        r.subscribers = num_subs;
                                        r.payload_bytes = payload_size;
                                        r.iteration = csv_iter++;
                                        r.updates_per_second = w.updates_per_second;
                                        r.per_sub_updates_per_second = (num_subs > 0) ? (w.updates_per_second / num_subs) : 0.0;
                                        r.total_updates = w.total_updates;
                                        r.drops = w.drops;
                                        r.errors = w.errors;
                                        r.duration_seconds = w.duration_seconds;
                                        writeCsvRow(*out, r);
                                        all_results.push_back(r);
                                    }
                                } else {
                                    const uint16_t cms_port = setup_cms ? kPvacmsUdpPort : 0u;
                                    auto windows = runSteadyStateBenchmark(mode, payload_size,
                                        num_subs, keychain, client_keychain, nt_payload, cms_port,
                                        num_windows, window_duration, omit_windows);
                                    printSteadyStateSummary(windows, protocolModeStr(mode), num_subs, payload_size);
                                    uint32_t csv_iter = 1;
                                    for (const auto& w : windows) {
                                        if (w.omitted) continue;
                                        BenchmarkResult r;
                                        r.protocol = protocolModeStr(mode);
                                        r.payload_mode = nt_payload ? "nt" : "raw";
                                        r.subscribers = num_subs;
                                        r.payload_bytes = payload_size;
                                        r.iteration = csv_iter++;
                                        r.updates_per_second = w.updates_per_second;
                                        r.per_sub_updates_per_second = (num_subs > 0) ? (w.updates_per_second / num_subs) : 0.0;
                                        r.total_updates = w.total_updates;
                                        r.drops = w.drops;
                                        r.errors = w.errors;
                                        r.duration_seconds = w.duration_seconds;
                                        writeCsvRow(*out, r);
                                        all_results.push_back(r);
                                    }
                                }
                            } else if (bench_mode == "burst") {
                                if (mode == ProtocolMode::CA) {
                                    auto br = runCaBurstBenchmark(ca_ioc, payload_size,
                                        num_subs, burst_size, burst_samples, burst_warmup,
                                        burst_send_interval_us);
                                    printBurstSummary(br);
                                    BenchmarkResult r;
                                    r.protocol = "CA";
                                    r.payload_mode = "raw";
                                    r.subscribers = num_subs;
                                    r.payload_bytes = payload_size;
                                    r.iteration = 1;
                                    r.updates_per_second = br.theoretical_ups;
                                    r.per_sub_updates_per_second = (num_subs > 0) ? (br.theoretical_ups / num_subs) : 0.0;
                                    r.total_updates = static_cast<uint64_t>(br.num_samples) * burst_size;
                                    r.drops = 0;
                                    r.errors = 0;
                                    r.duration_seconds = br.median_per_delivery_us / 1e6;
                                    writeCsvRow(*out, r);
                                    all_results.push_back(r);
                                } else {
                                    const uint16_t cms_port = setup_cms ? kPvacmsUdpPort : 0u;
                                    auto br = runBurstBenchmark(mode, payload_size,
                                        num_subs, keychain, client_keychain, nt_payload, cms_port,
                                        burst_size, burst_samples, burst_warmup,
                                        burst_send_interval_us);
                                    printBurstSummary(br);
                                    BenchmarkResult r;
                                    r.protocol = protocolModeStr(mode);
                                    r.payload_mode = nt_payload ? "nt" : "raw";
                                    r.subscribers = num_subs;
                                    r.payload_bytes = payload_size;
                                    r.iteration = 1;
                                    r.updates_per_second = br.theoretical_ups;
                                    r.per_sub_updates_per_second = (num_subs > 0) ? (br.theoretical_ups / num_subs) : 0.0;
                                    r.total_updates = static_cast<uint64_t>(br.num_samples) * burst_size;
                                    r.drops = 0;
                                    r.errors = 0;
                                    r.duration_seconds = br.median_per_delivery_us / 1e6;
                                    writeCsvRow(*out, r);
                                    all_results.push_back(r);
                                }
                            } else {
                                BenchmarkResult result;
                                if (mode == ProtocolMode::CA) {
                                    result = runCaBenchmark(ca_ioc, payload_size, duration,
                                                              warmup, num_subs);
                                } else {
                                    const uint16_t cms_port = setup_cms ? kPvacmsUdpPort : 0u;
                                    result = runAdaptiveBenchmark(mode, payload_size,
                                                                    num_subs, keychain,
                                                                    client_keychain, nt_payload,
                                                                    cms_port);
                                }

                                result.iteration = iter;

                                writeCsvRow(*out, result);
                                all_results.push_back(result);

                                log_info_printf(perflog, "  -> %.1f updates/sec (%.1f/sub), %lu total, %lu drops, %lu errors\n",
                                               result.updates_per_second,
                                               result.per_sub_updates_per_second,
                                               (unsigned long)result.total_updates,
                                               (unsigned long)result.drops,
                                               (unsigned long)result.errors);
                            }
                        }
                    }
                }
            }
        }

        printThroughputSummary(all_results);

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
                if (mode == ProtocolMode::CA) {
                    std::cerr << "Note: CA excluded from phase timing (incompatible protocol stages)" << std::endl;
                    continue;
                }
                if ((mode == ProtocolMode::SPVA || mode == ProtocolMode::SPVA_CERTMON) && !have_keychain) {
                    std::cerr << "Warning: skipping " << protocolModeStr(mode)
                              << " phase timing — no keychain" << std::endl;
                    continue;
                }
                if (mode == ProtocolMode::SPVA_CERTMON && !setup_cms && !external_cms) {
                    std::cerr << "Warning: skipping SPVA_CERTMON phase timing — no CMS configured" << std::endl;
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
