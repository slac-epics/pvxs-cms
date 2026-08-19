#include <epicsUnitTest.h>
#include <testMain.h>

#include <dirent.h>
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

// client2.p12 is the only generated keychain that carries a password, and this is it. See the
// client2 case in gen_test_certs.cpp.
const char *const kCorrectPassword = "oraclesucks";
const char *const kWrongPassword = "not-the-password";

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

std::string readFile(const std::string &path) {
    std::ifstream file(path.c_str(), std::ios::binary);
    std::ostringstream contents;
    contents << file.rdbuf();
    return contents.str();
}

void copyFile(const std::string &from, const std::string &to) {
    const std::string contents = readFile(from);
    if (contents.empty())
        testAbort("could not read \"%s\" to copy it to \"%s\"", from.c_str(), to.c_str());
    std::ofstream file(to.c_str(), std::ios::binary);
    file << contents;
    if (!file)
        testAbort("could not write the copy \"%s\": %s", to.c_str(), strerror(errno));
}

// Each pvacms run gets a directory of its own holding the configuration and data trees it is
// allowed to touch, so no run can see what an earlier one left behind.
std::string prepareHome(const std::string &work, const std::string &name) {
    const std::string home = work + "/" + name;
    requireDirectory(home);
    requireDirectory(home + "/config");
    requireDirectory(home + "/data");
    return home;
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

// Every pvacms run is confined to the scratch directory. Without this the program reads and
// writes the certificate store of whoever runs the test, at ~/.config/pva and ~/.local/share/pva,
// and the result then depends on the state of that machine rather than on pvacms.
std::string runPvacms(const std::string &program, const std::string &home,
                      const std::string &arguments, int &status) {
    return runCommand("XDG_CONFIG_HOME=\"" + home + "/config\" XDG_DATA_HOME=\"" + home
                          + "/data\" " + program + " " + arguments,
                      status);
}

bool contains(const std::string &text, const std::string &value) {
    return text.find(value) != std::string::npos;
}

// pvacms announces every certificate it takes out of a keychain and puts into its database on a
// line naming the certificate. Both parts have to be on the same line: a run that pre-loads some
// other certificate must not be mistaken for one that pre-loaded this one.
bool preloadedCertificate(const std::string &output, const std::string &common_name) {
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        if (contains(line, "Pre-loaded Certificate") && contains(line, common_name))
            return true;
    }
    return false;
}

// A keychain pvacms cannot open is set aside beside itself under a dated name, such as
// client2.2608170801.p12 next to client2.p12.
int countDatedBackups(const std::string &directory, const std::string &stem) {
    DIR *dir = opendir(directory.c_str());
    if (!dir)
        return -1;

    const std::string prefix = stem + ".";
    const std::string suffix = ".p12";
    int found = 0;
    while (const dirent *entry = readdir(dir)) {
        const std::string name(entry->d_name);
        if (name.size() <= prefix.size() + suffix.size())
            continue;
        if (name.compare(0, prefix.size(), prefix) == 0
            && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0)
            ++found;
    }
    closedir(dir);
    return found;
}

void removeTree(const std::string &path) {
    struct stat details;
    if (lstat(path.c_str(), &details) != 0)
        return;
    if (!S_ISDIR(details.st_mode)) {
        std::remove(path.c_str());
        return;
    }

    if (DIR *dir = opendir(path.c_str())) {
        while (const dirent *entry = readdir(dir)) {
            const std::string name(entry->d_name);
            if (name == "." || name == "..")
                continue;
            removeTree(path + "/" + name);
        }
        closedir(dir);
    }
    rmdir(path.c_str());
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

// One of the two keychain options that take a password of their own.
struct KeychainCase {
    const char *scenario;           // names the scratch directories the runs work in
    const char *description;        // names the option in the test descriptions
    const char *password_keychain;  // option naming the keychain the password has to open
    const char *password_option;    // option carrying that password
    const char *other_keychain;     // option naming the keychain that needs no password
};

// pvacms is pointed at copies of the generated keychains, never at the generated keychains
// themselves. A password that does not open a keychain is not refused: pvacms sets that file
// aside and mints a new one in its place, which would destroy the fixtures the rest of the test
// suite is built on. The unparsable access policy file stops pvacms once the keychains have been
// loaded, which it would otherwise not do, being a server.
std::string prepareCopies(const std::string &work, const std::string &name) {
    const std::string home = prepareHome(work, name);
    copyFile("client2.p12", home + "/client2.p12");
    copyFile("cert_auth.p12", home + "/cert_auth.p12");
    std::ofstream policy((home + "/invalid.acf").c_str());
    policy << "not a valid access policy" << std::endl;
    return home;
}

std::string keychainArguments(const KeychainCase &keychain_case, const std::string &home,
                              const char *password) {
    return std::string(keychain_case.password_keychain) + " " + home + "/client2.p12 "
           + keychain_case.password_option + " " + password + " " + keychain_case.other_keychain
           + " " + home + "/cert_auth.p12 --cert-pv-prefix SPVA --acf " + home + "/invalid.acf";
}

// The password, and nothing else, decides between two outcomes: the keychain is opened and the
// certificate inside it is pre-loaded, or the keychain is set aside and replaced by a new one.
// That is what shows the password reached keychain loading. The exit status does not show it:
// both outcomes exit with a failure status here, for unrelated reasons.
void checkKeychainPassword(const std::string &pvacms, const std::string &work,
                           const KeychainCase &keychain_case) {
    const std::string original = readFile("client2.p12");
    int status = 0;

    const std::string opened_home =
        prepareCopies(work, std::string(keychain_case.scenario) + "-correct-password");
    const std::string opened = runPvacms(
        pvacms, opened_home, keychainArguments(keychain_case, opened_home, kCorrectPassword),
        status);
    bool opened_ok = testOk(preloadedCertificate(opened, "client2"),
                            "the correct %s opens the keychain, so its client2 certificate is "
                            "pre-loaded",
                            keychain_case.description) != 0;
    opened_ok &= testOk(countDatedBackups(opened_home, "client2") == 0,
                        "the correct %s leaves no dated backup of the keychain",
                        keychain_case.description) != 0;
    opened_ok &= testOk(readFile(opened_home + "/client2.p12") == original,
                        "the correct %s leaves the keychain file exactly as it was",
                        keychain_case.description) != 0;
    if (!opened_ok)
        reportCommand(status, opened);

    const std::string refused_home =
        prepareCopies(work, std::string(keychain_case.scenario) + "-wrong-password");
    const std::string refused = runPvacms(
        pvacms, refused_home, keychainArguments(keychain_case, refused_home, kWrongPassword),
        status);
    const std::string replacement = readFile(refused_home + "/client2.p12");
    bool refused_ok = testOk(!preloadedCertificate(refused, "client2"),
                             "a wrong %s opens nothing, so no client2 certificate is pre-loaded",
                             keychain_case.description) != 0;
    refused_ok &= testOk(contains(refused, "Cert file backed up"),
                         "a wrong %s makes pvacms say it set the keychain aside",
                         keychain_case.description) != 0;
    refused_ok &= testOk(countDatedBackups(refused_home, "client2") == 1,
                         "a wrong %s leaves exactly one dated backup of the keychain",
                         keychain_case.description) != 0;
    refused_ok &= testOk(!replacement.empty() && replacement != original,
                         "a wrong %s puts a newly minted keychain where the original was",
                         keychain_case.description) != 0;
    if (!refused_ok)
        reportCommand(status, refused);
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

    const std::string cert_auth_before = readFile("cert_auth.p12");
    const std::string client2_before = readFile("client2.p12");
    const int backups_before = countDatedBackups(".", "cert_auth") + countDatedBackups(".", "client2");

    const std::string work = std::string("/tmp/pvacms-options-") + std::to_string(getpid());
    requireDirectory(work);

    testPlan(22);

    int status = 0;
    const std::string help_home = prepareHome(work, "help");
    const std::string help = runPvacms(pvacms, help_home, "--help", status);
    bool help_ok = testOk(status == 0, "PVACMS help exits successfully") != 0;
    help_ok &= testOk(contains(help, "--cert-auth-keychain-pwd <password>"),
                      "certificate-authority option identifies a password") != 0;
    help_ok &= testOk(contains(help, "--pvacms-keychain-pwd <password>"),
                      "PVACMS option identifies a password") != 0;
    help_ok &= testOk(contains(help, "--admin-keychain-pwd <password>"),
                      "administrator option identifies a password") != 0;
    if (!help_ok)
        reportCommand(status, help);

    const KeychainCase cert_auth_case = {"certificate-authority-keychain",
                                         "certificate authority keychain password",
                                         "--cert-auth-keychain", "--cert-auth-keychain-pwd",
                                         "--pvacms-keychain"};
    checkKeychainPassword(pvacms, work, cert_auth_case);

    const KeychainCase pvacms_case = {"pvacms-keychain", "PVACMS keychain password",
                                      "--pvacms-keychain", "--pvacms-keychain-pwd",
                                      "--cert-auth-keychain"};
    checkKeychainPassword(pvacms, work, pvacms_case);

    const std::string admin_home = prepareHome(work, "administrator-keychain");
    const std::string admin_keychain = admin_home + "/admin.p12";
    const std::string admin = runPvacms(
        pvacms, admin_home,
        "--admin-keychain-new cliadmin --admin-keychain " + admin_keychain
            + " --admin-keychain-pwd " + kCorrectPassword + " --acf " + admin_home + "/admin.acf",
        status);
    bool admin_ok = testOk(status == 0,
                           "administrator password is passed directly when creating a keychain") != 0;

    std::ifstream keychain(admin_keychain.c_str());
    admin_ok &= testOk(keychain.good(),
                       "administrator keychain was created with the supplied password") != 0;
    if (!admin_ok)
        reportCommand(status, admin);

    testOk(readFile("cert_auth.p12") == cert_auth_before
               && readFile("client2.p12") == client2_before,
           "the generated test keychain files still hold their original contents");
    testOk(countDatedBackups(".", "cert_auth") + countDatedBackups(".", "client2") == backups_before,
           "no dated backup file appeared beside the generated test keychain files");

    removeTree(work);
    return testDone();
}
