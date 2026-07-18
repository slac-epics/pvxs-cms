#include <epicsUnitTest.h>
#include <testMain.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace {

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

}  // namespace

MAIN(testpvacmsoptions) {
    const char *arch = std::getenv("EPICS_HOST_ARCH");
    if (!arch) {
        testAbort("EPICS_HOST_ARCH is not set");
        return 1;
    }

    const std::string pvacms = std::string("../../bin/") + arch + "/pvacms";
    const std::string work = std::string("/tmp/pvacms-options-") + std::to_string(getpid());
    mkdir(work.c_str(), 0700);

    testPlan(8);

    int status = 0;
    const std::string help = runCommand(pvacms + " --help", status);
    testOk(status == 0, "PVACMS help exits successfully");
    testOk(contains(help, "--cert-auth-keychain-pwd <password>"),
           "certificate-authority option identifies a password");
    testOk(contains(help, "--pvacms-keychain-pwd <password>"),
           "PVACMS option identifies a password");
    testOk(contains(help, "--admin-keychain-pwd <password>"),
           "administrator option identifies a password");

    const std::string missing_acf = work + "/missing.acf";
    std::ofstream bad_acf(missing_acf.c_str());
    bad_acf << "not a valid access policy" << std::endl;
    const std::string cert_auth = runCommand(
        pvacms + " --cert-auth-keychain client2.p12 --cert-auth-keychain-pwd oraclesucks"
        " --pvacms-keychain cert_auth.p12 --cert-pv-prefix SPVA --acf " + missing_acf,
        status);
    testOk(status != 0 && contains(cert_auth, "Failed to load"),
           "certificate-authority password is passed directly to keychain loading");

    const std::string pvacms_output = runCommand(
        pvacms + " --cert-auth-keychain cert_auth.p12 --pvacms-keychain client2.p12"
        " --pvacms-keychain-pwd oraclesucks --cert-pv-prefix SPVA --acf " + missing_acf,
        status);
    testOk(status != 0 && contains(pvacms_output, "Failed to load"),
           "PVACMS password is passed directly to keychain loading");

    const std::string config = work + "/config";
    const std::string data = work + "/data";
    mkdir(config.c_str(), 0700);
    mkdir(data.c_str(), 0700);
    const std::string admin_keychain = work + "/admin.p12";
    const std::string admin = runCommand(
        "XDG_CONFIG_HOME=" + config + " XDG_DATA_HOME=" + data + " " + pvacms
        + " --admin-keychain-new cliadmin --admin-keychain " + admin_keychain
        + " --admin-keychain-pwd oraclesucks --acf " + work + "/admin.acf",
        status);
    (void)admin;
    testOk(status == 0, "administrator password is passed directly when creating a keychain");

    std::ifstream keychain(admin_keychain.c_str());
    testOk(keychain.good(), "administrator keychain was created with the supplied password");

    std::remove(admin_keychain.c_str());
    std::remove(missing_acf.c_str());
    rmdir(config.c_str());
    rmdir(data.c_str());
    rmdir(work.c_str());
    return testDone();
}
