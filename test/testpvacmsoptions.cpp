#include <epicsUnitTest.h>
#include <testMain.h>

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

namespace {

std::string workingDirectory() {
    char buffer[PATH_MAX];
    if (!getcwd(buffer, sizeof(buffer)))
        return std::string("an unreadable directory");
    return std::string(buffer);
}

// The pvacms program and the generated keychain files are only reachable from the architecture
// build directory. Run from anywhere else every assertion fails for the same hidden reason, so
// stop here and say which input was missing and where it was looked for.
void requireInput(const std::string &path, const int mode, const char *description) {
    if (access(path.c_str(), mode) == 0)
        return;
    testAbort("%s is not available at \"%s\", looked for from the working directory \"%s\". "
              "Run this test from the test/O.<architecture> build directory, which holds the "
              "pvacms program and the generated test keychain files.",
              description, path.c_str(), workingDirectory().c_str());
}

void requireDirectory(const std::string &path) {
    if (mkdir(path.c_str(), 0700) == 0)
        return;
    testAbort("could not create the scratch directory \"%s\": %s", path.c_str(), strerror(errno));
}

std::string runCommand(const std::string &command, int &status) {
    std::string output;
    FILE *pipe = popen((command + " 2>&1").c_str(), "r");
    if (!pipe)
        return output;

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe))
        output += buffer;
    status = pclose(pipe);
    return output;
}

bool contains(const std::string &text, const std::string &value) {
    return text.find(value) != std::string::npos;
}

// Called only when an assertion about a command has failed. Without this the test throws away
// everything it saw, and a failure that happens once in a long while cannot be explained later.
void reportCommand(const int status, const std::string &output) {
    testDiag("the command exited with status %d", status);
    if (output.empty()) {
        testDiag("the command produced no output");
        return;
    }
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line))
        testDiag("command output: %s", line.c_str());
}

}  // namespace

MAIN(testpvacmsoptions) {
    const char *arch = std::getenv("EPICS_HOST_ARCH");
    if (!arch) {
        testAbort("EPICS_HOST_ARCH is not set, so the path to the pvacms program cannot be worked "
                  "out. Run this test from the test/O.<architecture> build directory with the "
                  "EPICS environment set.");
        return 1;
    }

    const std::string pvacms = std::string("../../bin/") + arch + "/pvacms";
    requireInput(pvacms, X_OK, "the pvacms program");
    requireInput("cert_auth.p12", R_OK, "the certificate authority test keychain cert_auth.p12");
    requireInput("client2.p12", R_OK, "the client test keychain client2.p12");

    const std::string work = std::string("/tmp/pvacms-options-") + std::to_string(getpid());
    requireDirectory(work);

    testPlan(10);

    int status = 0;
    const std::string help = runCommand(pvacms + " --help", status);
    bool help_ok = testOk(status == 0, "PVACMS help exits successfully") != 0;
    help_ok &= testOk(contains(help, "--cert-auth-keychain-pwd <password>"),
                      "certificate-authority option identifies a password") != 0;
    help_ok &= testOk(contains(help, "--pvacms-keychain-pwd <password>"),
                      "PVACMS option identifies a password") != 0;
    help_ok &= testOk(contains(help, "--admin-keychain-pwd <password>"),
                      "administrator option identifies a password") != 0;
    if (!help_ok)
        reportCommand(status, help);

    const std::string missing_acf = work + "/missing.acf";
    std::ofstream bad_acf(missing_acf.c_str());
    bad_acf << "not a valid access policy" << std::endl;
    const std::string cert_auth = runCommand(
        pvacms + " --cert-auth-keychain client2.p12 --cert-auth-keychain-pwd oraclesucks"
        " --pvacms-keychain cert_auth.p12 --cert-pv-prefix SPVA --acf " + missing_acf,
        status);
    bool cert_auth_ok = testOk(status != 0,
                               "certificate-authority password is passed directly to keychain "
                               "loading, so a wrong password exits with a failure status") != 0;
    cert_auth_ok &= testOk(contains(cert_auth, "Failed to load"),
                           "certificate-authority keychain loading says it failed to load") != 0;
    if (!cert_auth_ok)
        reportCommand(status, cert_auth);

    const std::string pvacms_output = runCommand(
        pvacms + " --cert-auth-keychain cert_auth.p12 --pvacms-keychain client2.p12"
        " --pvacms-keychain-pwd oraclesucks --cert-pv-prefix SPVA --acf " + missing_acf,
        status);
    bool pvacms_ok = testOk(status != 0,
                            "PVACMS password is passed directly to keychain loading, so a wrong "
                            "password exits with a failure status") != 0;
    pvacms_ok &= testOk(contains(pvacms_output, "Failed to load"),
                        "PVACMS keychain loading says it failed to load") != 0;
    if (!pvacms_ok)
        reportCommand(status, pvacms_output);

    const std::string config = work + "/config";
    const std::string data = work + "/data";
    requireDirectory(config);
    requireDirectory(data);
    const std::string admin_keychain = work + "/admin.p12";
    const std::string admin = runCommand(
        "XDG_CONFIG_HOME=" + config + " XDG_DATA_HOME=" + data + " " + pvacms
        + " --admin-keychain-new cliadmin --admin-keychain " + admin_keychain
        + " --admin-keychain-pwd oraclesucks --acf " + work + "/admin.acf",
        status);
    bool admin_ok = testOk(status == 0,
                           "administrator password is passed directly when creating a keychain") != 0;

    std::ifstream keychain(admin_keychain.c_str());
    admin_ok &= testOk(keychain.good(),
                       "administrator keychain was created with the supplied password") != 0;
    if (!admin_ok)
        reportCommand(status, admin);

    std::remove(admin_keychain.c_str());
    std::remove(missing_acf.c_str());
    rmdir(config.c_str());
    rmdir(data.c_str());
    rmdir(work.c_str());
    return testDone();
}
