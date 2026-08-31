/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * A keychain may hold several trust anchors. Two ideas the tools used to hold as one are kept
 * apart here: the authority asked to mint the certificate being requested now, and the set of
 * roots the file trusts. Naming an authority to mint adds its root and removes nothing; only
 * `--trust-anchor` replaces the set, and it refuses to strand the identity it keeps.
 *
 * These check the rules that decide the two, the layout the keychain is written in, which anchor
 * is the primary one, and when the anchors are listed.
 */

#include <limits.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include <openssl/x509.h>

#include "auth.h"
#include "certfactory.h"
#include "certfilefactory.h"
#include "certrequestid.h"
#include "certstatus.h"
#include "certstatusmanager.h"
#include "configauthn.h"
#include "issuerlist.h"
#include "keychainreport.h"
#include "openssl.h"
#include "ownedptr.h"
#include "trustanchors.h"

using namespace pvxs;
using namespace pvxs::certs;

namespace ta = cms::cert;

namespace {

std::string show(const std::vector<std::string> &values) {
    std::string out("[");
    for (size_t i = 0; i < values.size(); i++) {
        if (i) out += ", ";
        out += values[i];
    }
    return out + "]";
}

//! The message a call refuses with, or an empty string when it does not refuse.
std::string refusalFor(const std::function<void()> &fn) {
    try {
        fn();
    } catch (const std::exception &e) {
        return e.what();
    }
    return {};
}

bool contains(const std::string &text, const std::string &value) {
    return !value.empty() && text.find(value) != std::string::npos;
}

std::string readFile(const std::string &name) {
    std::ifstream file(name.c_str(), std::ios::binary);
    std::ostringstream contents;
    contents << file.rdbuf();
    return contents.str();
}

// Every certificate these cases use, read out of the generated keychain files once. The single
// level authorities a, b, c and d are each their own issuer and their own root, which is the
// shape the acceptance rules are written against; the intermediate and the self-signed identity
// cover the two shapes that are not.
struct Material {
    CertData root_a, root_b, root_c, root_d;
    CertData client_a, client_b, client_c;
    CertData client_intermediate;
    CertData intermediate_two;
    CertData client_selfsigned;

    X509 *A{nullptr}, *B{nullptr}, *C{nullptr}, *D{nullptr}, *I{nullptr}, *I2{nullptr};
    std::string a, b, c, d;  // the whole subject key identifier of each authority

    void load() {
        root_a = IdFileFactory::createReader("ta_root_a.p12")->getCertDataFromFile();
        root_b = IdFileFactory::createReader("ta_root_b.p12")->getCertDataFromFile();
        root_c = IdFileFactory::createReader("ta_root_c.p12")->getCertDataFromFile();
        root_d = IdFileFactory::createReader("ta_root_d.p12")->getCertDataFromFile();
        client_a = IdFileFactory::createReader("ta_client_a.p12")->getCertDataFromFile();
        client_b = IdFileFactory::createReader("ta_client_b.p12")->getCertDataFromFile();
        client_c = IdFileFactory::createReader("ta_client_c.p12")->getCertDataFromFile();
        client_intermediate = IdFileFactory::createReader("ta_client_intermediate.p12")->getCertDataFromFile();
        intermediate_two = IdFileFactory::createReader("ta_intermediate_two.p12")->getCertDataFromFile();
        client_selfsigned = IdFileFactory::createReader("ta_client_selfsigned.p12")->getCertDataFromFile();

        A = ta::anchorsInChain(root_a.cert_auth_chain).front();
        B = ta::anchorsInChain(root_b.cert_auth_chain).front();
        C = ta::anchorsInChain(root_c.cert_auth_chain).front();
        D = ta::anchorsInChain(root_d.cert_auth_chain).front();
        I = ta::certsInChain(client_intermediate.cert_auth_chain).front();
        I2 = ta::certsInChain(intermediate_two.cert_auth_chain).front();

        a = CertStatus::getFullSkId(A);
        b = CertStatus::getFullSkId(B);
        c = CertStatus::getFullSkId(C);
        d = CertStatus::getFullSkId(D);
    }

    //! A one-letter name for a certificate, decided by comparing the whole encoded certificate,
    //! so a rendered chain says which certificates are in it and in what order.
    std::string label(X509 *certificate) const {
        struct Known {
            X509 *certificate;
            const char *name;
        };
        const Known known[] = {{A, "A"},
                               {B, "B"},
                               {C, "C"},
                               {D, "D"},
                               {I, "I"},
                               {I2, "I2"},
                               {client_a.cert.get(), "id_a"},
                               {client_b.cert.get(), "id_b"},
                               {client_c.cert.get(), "id_c"},
                               {client_intermediate.cert.get(), "id_i"},
                               {client_selfsigned.cert.get(), "id_self"}};
        for (const Known &entry : known)
            if (entry.certificate && certificate && X509_cmp(entry.certificate, certificate) == 0) return entry.name;
        return "?";
    }

    std::string show(const std::vector<X509 *> &certificates) const {
        std::string out("[");
        for (size_t i = 0; i < certificates.size(); i++) {
            if (i) out += ", ";
            out += label(certificates[i]);
        }
        return out + "]";
    }

    std::string show(const ossl_shared_ptr<STACK_OF(X509)> &chain) const { return show(ta::certsInChain(chain)); }
    std::string show(const ossl_ptr<STACK_OF(X509)> &chain) const {
        std::vector<X509 *> certificates;
        for (int i = 0; i < sk_X509_num(chain.get()); i++) certificates.push_back(sk_X509_value(chain.get(), i));
        return show(certificates);
    }
};

Material material;

// Files these cases write, removed before and after so no run reads what an earlier one left and
// no dated backup is made of a file that is still there.
const char *const kScratchFiles[] = {"testtrustanchors_written.p12", "testtrustanchors_reset.p12",
                                     "testtrustanchors_probe.p12",   "testtrustanchors_before.p12",
                                     "testtrustanchors_after.p12"};

void removeScratchFiles() {
    for (const char *name : kScratchFiles) std::remove(name);
}

ossl_ptr<STACK_OF(X509)> asStack(const std::vector<X509 *> &certificates) {
    ossl_ptr<STACK_OF(X509)> stack(sk_X509_new_null());
    for (X509 *certificate : certificates) sk_X509_push(stack.get(), certificate);
    return stack;
}

void writeKeychain(const std::string &file,
                   const std::shared_ptr<KeyPair> &key_pair,
                   X509 *identity,
                   const ossl_ptr<STACK_OF(X509)> &chain) {
    // Removed first, so writing the same scratch name twice does not leave a dated backup of the
    // previous one behind in the test directory.
    std::remove(file.c_str());
    IdFileFactory::create(file, "", key_pair, identity, chain.get(), "")->writeIdentityFile();
}

// Order is the meaning: the first entry is the authority asked to mint, and the order the rest
// are named in is the order they are written in.
void testTheListIsRead() {
    testDiag("Whitespace and the comma both separate, each entry is trimmed, and order is kept");

    const std::vector<std::string> both{"aaaabbbb", "ccccdddd"};
    testEq(show(ta::parseIssuerList("aaaabbbb ccccdddd")), show(both));
    testEq(show(ta::parseIssuerList("aaaabbbb,ccccdddd")), show(both));
    testEq(show(ta::parseIssuerList(" aaaabbbb , ccccdddd ")), show(both));
    testEq(show(ta::parseIssuerList("aaaabbbb\tccccdddd")), show(both));

    // A repeated entry keeps its first occurrence, because that is the occurrence whose position
    // decides the ordering
    testEq(show(ta::parseIssuerList("ccccdddd aaaabbbb ccccdddd")), show({"ccccdddd", "aaaabbbb"}));

    // Every form a certificate prints an authority in is read, and capitals are folded
    testEq(show(ta::parseIssuerList("AA:BB:CC:DD")), show({"aabbccdd"}));

    testEq(show(ta::parseIssuerList("")), show({}));

    // A value that is not an identifier is refused with that value in the message
    const auto refusal = refusalFor([] { ta::parseIssuerList("aaaabbbb zzzz"); });
    testTrue(contains(refusal, "zzzz"));

    // The semicolon is not a separator, so it is refused rather than quietly splitting
    testTrue(!refusalFor([] { ta::parseIssuerList("aaaabbbb;ccccdddd"); }).empty());
}

// One row of the acceptance tables: what was named, what the keychain held, and what that means.
struct PlanRow {
    const char *what;
    std::vector<std::string> named;
    std::vector<std::string> held;
    bool trust_anchor;
    std::string minting;
    std::vector<std::string> anchors;
    std::vector<std::string> ignored;
    bool refuses;
};

void testThePlanFollowsTheAcceptanceTable() {
    testDiag("Every row of the acceptance tables, as a decision with no file and no network");

    const std::string &a = material.a;
    const std::string &b = material.b;
    const std::string &c = material.c;
    const std::string &d = material.d;
    const std::vector<std::string> held{a, c};  // anchors A and C, an identity chaining to A
    const std::vector<std::string> none;

    const PlanRow rows[] = {
        {"--issuer B", {b}, held, false, b, {b, a, c}, {}, false},
        {"--issuer C", {c}, held, false, c, {c, a}, {}, false},
        {"--issuer \"B D\"", {b, d}, held, false, b, {b, a, c}, {d}, false},
        {"--issuer \"B A\"", {b, a}, held, false, b, {b, a, c}, {}, false},
        {"no issuer named in either place", {}, held, false, a, {a, c}, {}, false},
        {"EPICS_PVA_AUTH_ISSUER=\"B A\", no option", {b, a}, held, false, b, {b, a, c}, {}, false},
        {"EPICS_PVA_AUTH_ISSUER=\"B A\" with --issuer D", {d}, held, false, d, {d, a, c}, {}, false},
        {"--trust-anchor --issuer \"B A\"", {b, a}, held, true, "", {b, a}, {}, false},
        {"--trust-anchor with EPICS_PVA_AUTH_ISSUER=\"B A\"", {b, a}, held, true, "", {b, a}, {}, false},
        {"--trust-anchor --issuer \"B D\"", {b, d}, held, true, "", {b, d}, {}, false},
        {"--trust-anchor with nothing named", {}, held, true, "", {}, {}, true},
        // The keychain holds no anchors, so trust is being established and several may be named
        {"--issuer \"A B\" against a keychain holding nothing", {a, b}, none, false, a, {a, b}, {}, false},
        {"--trust-anchor --issuer \"B A\" against a keychain holding nothing", {b, a}, none, true, "", {b, a}, {}, false},
    };

    for (const PlanRow &row : rows) {
        ta::AnchorPlanInput input;
        input.named_issuers = row.named;
        input.held_anchor_ids = row.held;
        input.trust_anchor_option = row.trust_anchor;
        const auto plan = ta::planAnchors(input);

        testEq(plan.minting_issuer, row.minting) << " minting issuer for " << row.what;
        testEq(show(plan.anchor_ids), show(row.anchors)) << " anchors for " << row.what;
        testEq(show(plan.ignored_issuers), show(row.ignored)) << " ignored issuers for " << row.what;
        testEq(!plan.refusal.empty(), row.refuses) << " refusal for " << row.what;
    }

    // A short form names an authority the keychain already holds, because the held value is what
    // the comparison runs against, and the whole identifier comes back rather than the short one
    ta::AnchorPlanInput short_form;
    short_form.named_issuers.push_back(c.substr(0, 8));
    short_form.held_anchor_ids = held;
    testEq(ta::planAnchors(short_form).minting_issuer, c);
}

// Reading a keychain back and finding the certificates in the order they were written is what
// makes the layout worth anything, so each row is written, read, and compared certificate by
// certificate rather than checked in memory.
std::string chainWrittenAndReadBack(const std::string &file,
                                    const CertData &identity_holder,
                                    const std::vector<X509 *> &available,
                                    const std::vector<X509 *> &anchors_to_hold) {
    X509 *const identity = identity_holder.cert.get();
    const auto chain = ta::layOutChain(identity, available, anchors_to_hold);
    writeKeychain(file, identity_holder.key_pair, identity, chain);
    const auto written = IdFileFactory::createReader(file)->getCertDataFromFile();
    return material.show(written.cert_auth_chain);
}

void testTheChainIsLaidOutAfreshAroundTheIdentity() {
    testDiag("Each acceptance row's chain, written to a file and read back");

    X509 *const A = material.A;
    X509 *const B = material.B;
    X509 *const C = material.C;
    X509 *const I = material.I;
    const std::vector<X509 *> held{A, C};  // the chain the file already held

    // An ordinary request minted by a newly named authority: the new issuer leads, and both
    // anchors already held are still there
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_b, {B, A, C}, {B, A, C}),
           material.show({B, A, C}));

    // Minted by an authority already trusted: the set is unchanged while the chain is not
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_c, {C, A, C}, {C, A}),
           material.show({C, A}));

    // Nothing named, so the primary anchor mints and nothing moves
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_a, {A, A, C}, {A, C}),
           material.show({A, C}));

    // A reset that keeps an identity: B is named first and still does not lead, because element 0
    // is the kept identity's issuer
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_a, held, {B, A}),
           material.show({A, B}));

    // Establishing trust on a keychain holding nothing
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_a, {A}, {A, B}),
           material.show({A, B}));

    // A single-level authority is its own issuer and its own root, so it appears once
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_a, {A}, {A}),
           material.show({A}));

    // An identity whose issuer is an intermediate: that intermediate is carried over from the
    // chain the file held, so element 0 is still the identity's issuer
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_intermediate, {I, A}, {B, A}),
           material.show({I, A, B}));

    // A self-signed identity is its own issuer, so it takes element 0 and appears nowhere else
    testEq(chainWrittenAndReadBack("testtrustanchors_written.p12", material.client_selfsigned, {}, {}),
           material.show({material.client_selfsigned.cert.get()}));

    // A file that ends up holding no identity leads with the root of the first issuer named
    {
        const auto chain = ta::layOutChain(nullptr, {}, {B, A});
        writeKeychain("testtrustanchors_written.p12", nullptr, nullptr, chain);
        const auto written = IdFileFactory::createReader("testtrustanchors_written.p12")->getCertDataFromFile();
        testEq(material.show(written.cert_auth_chain), material.show({B, A}));
    }

    // An identity that reaches no anchor is refused rather than written, which is what both write
    // paths turn into a refusal that writes nothing
    testTrue(!refusalFor([&] { ta::layOutChain(material.client_b.cert.get(), {}, {A, C}); }).empty());
}

// Element 0 is the one position in a chain that carries any meaning, and this is what reads it.
void testTheIssuerCertificateAuthorityIsStillElementZero() {
    testDiag("getIssuerCa still answers the identity's issuer for a keychain holding two anchors");

    X509 *const A = material.A;
    X509 *const B = material.B;
    X509 *const C = material.C;

    const auto chain = ta::layOutChain(material.client_b.cert.get(), {B, A, C}, {B, A, C});
    writeKeychain("testtrustanchors_written.p12", material.client_b.key_pair, material.client_b.cert.get(), chain);
    const auto written = IdFileFactory::createReader("testtrustanchors_written.p12")->getCertDataFromFile();

    testEq(material.label(CertStatus::getIssuerCa(written.cert_auth_chain)), std::string("B"));
    testEq(CertStatus::getIssuerId(written.cert_auth_chain), CertStatus::getSkId(B));

    // and for a reset that keeps an identity issued by the authority named second
    const auto reset = ta::layOutChain(material.client_a.cert.get(), {A, C}, {B, A});
    writeKeychain("testtrustanchors_reset.p12", material.client_a.key_pair, material.client_a.cert.get(), reset);
    const auto after_reset = IdFileFactory::createReader("testtrustanchors_reset.p12")->getCertDataFromFile();
    testEq(material.label(CertStatus::getIssuerCa(after_reset.cert_auth_chain)), std::string("A"));
}

// Nothing in the file marks the primary anchor, so it is derived by walking.
void testThePrimaryAnchorIsDerivedAndNotPositional() {
    testDiag("Primary is the anchor the identity chains to, wherever that anchor sits");

    // A deliberately awkward layout: the identity is issued by C and A is written first
    writeKeychain("testtrustanchors_probe.p12", material.client_c.key_pair, material.client_c.cert.get(),
                  asStack({material.A, material.C}));
    const auto awkward = IdFileFactory::createReader("testtrustanchors_probe.p12")->getCertDataFromFile();
    testEq(material.label(ta::primaryAnchor(awkward)), std::string("C"));

    // A self-signed identity is its own issuer and its own root
    testEq(material.label(ta::primaryAnchor(material.client_selfsigned)), std::string("id_self"));

    // A file with no identity takes its first anchor
    testEq(material.label(ta::primaryAnchor(material.root_b)), std::string("B"));
    {
        const auto chain = ta::layOutChain(nullptr, {}, {material.B, material.A});
        writeKeychain("testtrustanchors_probe.p12", nullptr, nullptr, chain);
        const auto anchors_only = IdFileFactory::createReader("testtrustanchors_probe.p12")->getCertDataFromFile();
        testEq(material.label(ta::primaryAnchor(anchors_only)), std::string("B"));
    }

    // An identity under an intermediate reaches the root above it
    testEq(material.label(ta::primaryAnchor(material.client_intermediate)), std::string("A"));

    // The held anchors come back primary first, which is the order the plan reads them in
    testEq(show(ta::heldAnchorIds(awkward)), show({material.c, material.a}));
}

// A reset refuses when the identity would reach no anchor in its own file.
void testAResetRefusesToStrandTheIdentity() {
    testDiag("A reset that omits the root the identity chains to writes nothing at all");

    const auto chain = ta::layOutChain(material.client_a.cert.get(), {material.A, material.C}, {material.A, material.C});
    writeKeychain("testtrustanchors_reset.p12", material.client_a.key_pair, material.client_a.cert.get(), chain);
    const std::string before = readFile("testtrustanchors_reset.p12");

    const auto held = IdFileFactory::createReader("testtrustanchors_reset.p12")->getCertDataFromFile();
    const auto refusal = refusalFor([&] { ta::chainForAnchorReset(held, {material.B, material.D}); });

    testTrue(!refusal.empty());
    // The message names the authority the identity chains to, so an operator can name it too
    testTrue(contains(refusal, material.a));
    // There was nothing to write, so the file on disk is exactly as it was. Compared as a
    // boolean, because a keychain is binary.
    testTrue(readFile("testtrustanchors_reset.p12") == before);

    // Naming that authority as well is accepted, and being named first counts for nothing
    testEq(material.show(ta::chainForAnchorReset(held, {material.B, material.A})),
           material.show({material.A, material.B}));

    // A file holding no identity has nothing to strand
    testEq(material.show(ta::chainForAnchorReset(material.root_c, {material.B, material.A})),
           material.show({material.B, material.A}));
}

void testTheConfigurationReadsTheListFromTheEnvironment() {
    testDiag("Both accepted forms in the environment give the same ordered list");

    const std::map<std::string, std::string> unused;  // fromAuthEnv reads the real environment

    setenv("EPICS_PVA_AUTH_ISSUER", "aaaabbbb ccccdddd", 1);
    ConfigAuthN whitespace;
    whitespace.fromAuthEnv(unused);
    testEq(show(whitespace.issuer_ids), show({"aaaabbbb", "ccccdddd"}));
    testEq(whitespace.mintingIssuerId(), std::string("aaaabbbb"));

    setenv("EPICS_PVA_AUTH_ISSUER", "aaaabbbb,ccccdddd", 1);
    ConfigAuthN comma;
    comma.fromAuthEnv(unused);
    testEq(show(comma.issuer_ids), show({"aaaabbbb", "ccccdddd"}));

    std::map<std::string, std::string> defs;
    comma.updateDefs(defs);
    testEq(defs["EPICS_PVA_AUTH_ISSUER"], std::string("aaaabbbb ccccdddd"));

    unsetenv("EPICS_PVA_AUTH_ISSUER");
    ConfigAuthN nothing;
    nothing.fromAuthEnv(unused);
    testEq(show(nothing.issuer_ids), show({}));
    testEq(nothing.mintingIssuerId(), std::string(""));
}

// Taking the last value quietly is the exact failure the one-option-one-list shape exists to
// prevent, so the refusal has to be the one an operator can act on.
void testTheIssuerOptionGivenTwiceIsRefused() {
    testDiag("--issuer given twice is refused with a message saying what to write instead");

    const char *arch = std::getenv("EPICS_HOST_ARCH");
    if (!arch) {
        testSkip(3, "EPICS_HOST_ARCH is not set, so the authnstd program cannot be found");
        return;
    }
    const std::string program = std::string("../../bin/") + arch + "/authnstd";
    if (access(program.c_str(), X_OK) != 0) {
        testSkip(3, "the authnstd program was not found");
        return;
    }

    // Confined to a scratch directory, so the run cannot read or write the certificate store of
    // whoever is running the test
    const std::string scratch = std::string("/tmp/testtrustanchors-") + std::to_string(getpid());
    const std::string command = "XDG_CONFIG_HOME=\"" + scratch + "\" XDG_DATA_HOME=\"" + scratch + "\" " + program +
                                " -u client --issuer aaaabbbb --issuer ccccdddd 2>&1";
    std::string output;
    int status = -1;
    if (FILE *pipe = popen(command.c_str(), "r")) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
        status = pclose(pipe);
    }

    testTrue(status != 0);
    testTrue(contains(output, "--issuer"));
    // and it shows both accepted forms, so an operator is told what to write
    testTrue(contains(output, "aaaa,bbbb"));
}

// The listing is the only place an operator sees which anchor is the primary one, so it prints
// when the set changes and when only the primary moves, and stays quiet when neither did.
void testTheAnchorsAreListedWhenTrustChanges() {
    testDiag("The anchors are listed when the set or the primary ends up different, and not otherwise");

    X509 *const A = material.A;
    X509 *const B = material.B;
    X509 *const C = material.C;

    const auto write = [](const std::string &file, const CertData &holder, const std::vector<X509 *> &chain) {
        writeKeychain(file, holder.key_pair, holder.cert.get(), asStack(chain));
        return IdFileFactory::createReader(file)->getCertDataFromFile();
    };

    // A request that had to add the minting issuer's root: the set grew
    const auto held_one = write("testtrustanchors_before.p12", material.client_a, {A});
    const auto grew = write("testtrustanchors_after.p12", material.client_b, {B, A});
    testTrue(ta::trustChanged(held_one, grew));
    {
        std::ostringstream out;
        ta::printAnchorListing(grew, out);
        const std::string listing = out.str();
        // The primary is named first, and the label lines up with the column the tools use
        testTrue(listing.compare(0, 26, "Primary Root CA         : ") == 0);
        testTrue(contains(listing, "Trusted Root CA         : "));
        testTrue(contains(listing, "EPICS Trust Anchor b Root Certificate Authority"));
    }

    // A request minted by an authority already trusted, which moves the primary and nothing else
    const auto held_two = write("testtrustanchors_before.p12", material.client_a, {A, C});
    const auto moved = write("testtrustanchors_after.p12", material.client_c, {C, A});
    testTrue(ta::trustChanged(held_two, moved));
    {
        std::ostringstream out;
        ta::printAnchorListing(moved, out);
        testTrue(contains(out.str(), "Primary Root CA         : CN=EPICS Trust Anchor c Root Certificate Authority"));
    }

    // A request that changes neither says nothing
    const auto unchanged = write("testtrustanchors_after.p12", material.client_a, {A, C});
    testFalse(ta::trustChanged(held_two, unchanged));
}

// pvxcert -f prints its whole file report through this one helper, so the decision it takes on
// each shape a keychain can arrive in is pinned here rather than behind the command line.
void testTheKeychainReportCoversEveryKeychainShape() {
    testDiag("printKeychainReport: identity with anchors, anchors only, no anchors, and neither");

    // An identity plus two anchors: the details, then the anchor block, then the status PV name
    {
        writeKeychain("testtrustanchors_written.p12", material.client_b.key_pair, material.client_b.cert.get(),
                      asStack({material.B, material.A}));
        const auto held = IdFileFactory::createReader("testtrustanchors_written.p12")->getCertDataFromFile();

        std::ostringstream out, err;
        const std::string status_pv = ta::printKeychainReport(held, out, err);

        testEq(status_pv, CmsStatusManager::getStatusPvFromCert(held.cert));
        testTrue(contains(err.str(), "Certificate Details: "));

        std::ostringstream listing;
        ta::printAnchorListing(held, listing);
        testTrue(!listing.str().empty());
        // The anchor block is the last thing printed, which is what puts it after the details
        testTrue(out.str().size() >= listing.str().size() &&
                 out.str().compare(out.str().size() - listing.str().size(), listing.str().size(), listing.str()) == 0);
        testTrue(contains(out.str(), "Primary Root CA         : "));
        testTrue(contains(out.str(), "Trusted Root CA         : "));
    }

    // Anchors and no identity: the notice, the anchor block alone, and no status PV to query
    {
        const auto chain = ta::layOutChain(nullptr, {}, {material.B, material.A});
        writeKeychain("testtrustanchors_written.p12", nullptr, nullptr, chain);
        const auto anchors_only = IdFileFactory::createReader("testtrustanchors_written.p12")->getCertDataFromFile();

        std::ostringstream out, err;
        const std::string status_pv = ta::printKeychainReport(anchors_only, out, err);

        testEq(status_pv, std::string(""));
        testEq(err.str(), std::string("No identity certificate; trust anchors only:\n"));

        std::ostringstream listing;
        ta::printAnchorListing(anchors_only, listing);
        // The anchor lines and nothing else. Compared as a boolean.
        testTrue(out.str() == listing.str());
        testTrue(contains(out.str(), "Primary Root CA         : "));
        testTrue(contains(out.str(), "Trusted Root CA         : "));
    }

    // An identity whose chain holds no anchor: no anchor lines, the details exactly as they
    // were. A self-signed identity cannot serve here because it is its own anchor; an identity
    // under an intermediate, with only that intermediate in the chain, holds no anchor at all.
    {
        writeKeychain("testtrustanchors_written.p12", material.client_intermediate.key_pair,
                      material.client_intermediate.cert.get(), asStack({material.I}));
        const auto no_anchors = IdFileFactory::createReader("testtrustanchors_written.p12")->getCertDataFromFile();

        std::ostringstream out, err;
        const std::string status_pv = ta::printKeychainReport(no_anchors, out, err);

        testEq(status_pv, CmsStatusManager::getStatusPvFromCert(no_anchors.cert));
        testFalse(contains(out.str(), "Primary Root CA"));
        testFalse(contains(out.str(), "Trusted Root CA"));

        std::string config_id;
        try {
            config_id = CmsStatusManager::getConfigPvFromCert(no_anchors.cert);
        } catch (...) {
        }
        std::ostringstream expected;
        expected << ossl::ShowX509{no_anchors.cert.get()} << std::endl
                 << (config_id.empty() ? "" : "Config URI     : " + config_id + "\n");
        testTrue(out.str() == expected.str());
        testEq(err.str(), std::string("Certificate Details: \n"
                                      "============================================\n"
                                      "--------------------------------------------\n"));
    }

    // Neither identity nor anchors: refused with the exact message the tool already reports
    {
        const CertData holds_nothing;
        testEq(refusalFor([&] {
                   std::ostringstream out, err;
                   ta::printKeychainReport(holds_nothing, out, err);
               }),
               std::string("Failed to read certificate from file"));
    }
}

// The reply a certificate manager sends when it is asked for its trust anchor: the certificate
// it signs with, followed by the chain above it. Built exactly as `onCreateCertificate` builds
// it and read exactly as the retrieval path reads it, so what follows is fed the shape the real
// path delivers. This is as close to that path as these cases can get: everything between the
// two is a remote procedure call to a live certificate manager, which no unit test here starts.
CertData replyFrom(X509 *authority, const std::vector<X509 *> &above) {
    const ossl_ptr<X509> signing(X509_dup(authority));
    const auto chain = asStack(above);
    return certDataFromPem(CertFactory::certAndCasToPemString(signing, above.empty() ? nullptr : chain.get()));
}

// A keychain's trust anchor is a self-signed root. Writing the certificate a manager signs with
// instead put two intermediates in the file with no root above either, so nothing in it was
// self-signed, the file was no trust store at all, and the anchor listing stayed silent because
// there was correctly nothing to list.
void testEveryAnchorWrittenIsARoot() {
    testDiag("A named authority contributes the root above it, and every anchor written is self-signed");

    X509 *const A = material.A;
    X509 *const B = material.B;
    X509 *const I = material.I;

    // A manager that signs from an intermediate certificate authority answers that intermediate
    // with the root above it, and the root is what the keychain has to hold
    const CertData from_intermediate = replyFrom(I, {A});
    testEq(material.label(certs::anchorFromReply(from_intermediate)), std::string("A"));

    // A single-level authority signs with its own root and answers it directly
    const CertData from_single_level = replyFrom(B, {});
    testEq(material.label(certs::anchorFromReply(from_single_level)), std::string("B"));

    // A reply that reaches no root fails the command rather than handing back the certificate
    // that was delivered, and names the authority that answered so an operator knows which
    const CertData without_the_root = replyFrom(I, {});
    testTrue(contains(refusalFor([&] { certs::anchorFromReply(without_the_root); }),
                      CertStatus::getFullSkId(I)));

    // The ordinary certificate request resolves the same way: the authority is named by the
    // certificate it signs with, and what is held is the root the walk from there reaches
    testEq(material.label(ta::anchorForIssuerId(CertStatus::getFullSkId(I), {I, A})), std::string("A"));

    const CertData holds_nothing;

    // Two authorities under one shared root, which is the federated laboratory's arrangement.
    // The root is written once and neither intermediate is written at all.
    {
        const CertData second_intermediate = replyFrom(material.I2, {A});
        const std::vector<X509 *> anchors{certs::anchorFromReply(from_intermediate),
                                          certs::anchorFromReply(second_intermediate)};

        writeKeychain("testtrustanchors_written.p12", nullptr, nullptr,
                      ta::chainForAnchorReset(holds_nothing, anchors));
        const auto written = IdFileFactory::createReader("testtrustanchors_written.p12")->getCertDataFromFile();

        testEq(material.show(written.cert_auth_chain), material.show({A}));

        // Every certificate the file holds is self-signed, which is the assertion that fails
        // outright when an intermediate is written in place of a root
        testEq(ta::anchorsInChain(written.cert_auth_chain).size(), ta::certsInChain(written.cert_auth_chain).size());
        testTrue(contains(ta::anchorSubject(ta::anchorsInChain(written.cert_auth_chain).front()),
                          "EPICS Trust Anchor a Root Certificate Authority"));

        // So the anchors are found, the change is seen, and the listing an operator reads prints
        testEq(show(ta::heldAnchorIds(written)), show({material.a}));
        testTrue(ta::trustChanged(holds_nothing, written));
        std::ostringstream out;
        ta::printAnchorListing(written, out);
        testTrue(contains(out.str(), "Primary Root CA         : CN=EPICS Trust Anchor a Root Certificate Authority"));
    }

    // Two authorities under unrelated roots hold both roots, and both are self-signed
    {
        const std::vector<X509 *> anchors{certs::anchorFromReply(from_intermediate),
                                          certs::anchorFromReply(from_single_level)};

        writeKeychain("testtrustanchors_written.p12", nullptr, nullptr,
                      ta::chainForAnchorReset(holds_nothing, anchors));
        const auto written = IdFileFactory::createReader("testtrustanchors_written.p12")->getCertDataFromFile();

        testEq(material.show(written.cert_auth_chain), material.show({A, B}));
        testEq(ta::anchorsInChain(written.cert_auth_chain).size(), ta::certsInChain(written.cert_auth_chain).size());
    }

    // The write itself refuses a certificate that is not self-signed as an anchor, so the rule
    // holds however a caller reached it and no later path can quietly write one
    testTrue(contains(refusalFor([&] { ta::chainForAnchorReset(holds_nothing, {I}); }),
                      CertStatus::getFullSkId(I)));
}

// The generated keychains are written into the architecture build directory and opened by name,
// so they are only found when that is the working directory.
void requireFixture(const char *name) {
    if (access(name, R_OK) == 0) return;
    char directory[PATH_MAX];
    if (!getcwd(directory, sizeof(directory))) directory[0] = '\0';
    testAbort(
        "the generated test keychain \"%s\" was not found in the working directory \"%s\". Run this test from the "
        "test/O.<architecture> build directory, where the test keychain files are generated.",
        name, directory);
}

}  // namespace

MAIN(testtrustanchors) {
    for (const char *name : {"ta_root_a.p12", "ta_root_b.p12", "ta_root_c.p12", "ta_root_d.p12", "ta_client_a.p12",
                             "ta_client_b.p12", "ta_client_c.p12", "ta_client_intermediate.p12",
                             "ta_intermediate_two.p12", "ta_client_selfsigned.p12"})
        requireFixture(name);

    testPlan(132);
    removeScratchFiles();
    material.load();

    testTheListIsRead();
    testThePlanFollowsTheAcceptanceTable();
    testTheChainIsLaidOutAfreshAroundTheIdentity();
    testTheIssuerCertificateAuthorityIsStillElementZero();
    testThePrimaryAnchorIsDerivedAndNotPositional();
    testAResetRefusesToStrandTheIdentity();
    testEveryAnchorWrittenIsARoot();
    testTheConfigurationReadsTheListFromTheEnvironment();
    testTheIssuerOptionGivenTwiceIsRefused();
    testTheAnchorsAreListedWhenTrustChanges();
    testTheKeychainReportCoversEveryKeychainShape();

    removeScratchFiles();
    return testDone();
}
