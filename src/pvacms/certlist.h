#ifndef PVXS_CERTLIST_H
#define PVXS_CERTLIST_H

#include <string>

namespace pvxs {
namespace certs {

std::string renderCertType(const std::string &key_usage, const std::string &extended_key_usage);

}  // namespace certs
}  // namespace pvxs

#endif
