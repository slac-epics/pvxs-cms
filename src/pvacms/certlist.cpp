#include "certlist.h"

namespace pvxs {
namespace certs {

std::string renderCertType(const std::string &key_usage, const std::string &extended_key_usage) {
    if (key_usage.empty() && extended_key_usage.empty()) return "UNKNOWN";

    if (key_usage.find("Certificate Sign") != std::string::npos ||
        key_usage.find("keyCertSign") != std::string::npos) {
        return "CERT_AUTH";
    }

    const bool serves = extended_key_usage.find("TLS Web Server Authentication") != std::string::npos ||
                        extended_key_usage.find("serverAuth") != std::string::npos;
    const bool connects = extended_key_usage.find("TLS Web Client Authentication") != std::string::npos ||
                          extended_key_usage.find("clientAuth") != std::string::npos;

    if (serves && connects) return "IOC";
    if (serves) return "SERVER";
    if (connects) return "CLIENT";
    return "UNKNOWN";
}

}  // namespace certs
}  // namespace pvxs
