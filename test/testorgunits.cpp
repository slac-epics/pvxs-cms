#include <epicsUnitTest.h>
#include <testMain.h>

#include <limits.h>
#include <unistd.h>

#include <string>

namespace {

std::string workingDirectory() {
    char buffer[PATH_MAX];
    return getcwd(buffer, sizeof(buffer)) ? std::string(buffer) : std::string("an unreadable directory");
}

void requireInput(const std::string &path, const char *description) {
    if (access(path.c_str(), R_OK) == 0) return;
    testAbort("%s is not available at \"%s\", looked for from the working directory \"%s\". "
              "Run this test from the test/O.<architecture> build directory.",
              description, path.c_str(), workingDirectory().c_str());
}

}  // namespace

MAIN(testorgunits) {
    requireInput("cert_auth.p12", "the certificate authority test keychain");
    testPlan(0);
    return testDone();
}
