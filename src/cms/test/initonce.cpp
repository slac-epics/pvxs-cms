/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "pvxs/cms/testharness.h"

#include <mutex>

#include <event2/thread.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <pvxs/log.h>

namespace pvxs {
namespace cms {
namespace test {

namespace {

DEFINE_LOGGER(harness_init, "pvxs.cms.test.init");

std::once_flag g_init_once;

void doInitOnce() noexcept {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

#if defined(EVTHREAD_USE_PTHREADS_IMPLEMENTED)
    evthread_use_pthreads();
#elif defined(EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED)
    evthread_use_windows_threads();
#endif

    log_debug_printf(harness_init, "pvxs::cms::test::initOnce() complete%s", "\n");
}

}  // namespace

void initOnce() {
    std::call_once(g_init_once, doInitOnce);
}

}  // namespace test
}  // namespace cms
}  // namespace pvxs
