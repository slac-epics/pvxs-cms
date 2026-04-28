/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <set>
#include <stdexcept>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/log.h>
#include <pvxs/unittest.h>

#include "clustertopology.h"

namespace {

using cms::test::ClusterTopology;

void testTopologyValueType() {
    testDiag("ClusterTopology factories produce expected adjacency");

    auto fm = ClusterTopology::fullMesh(3);
    testEq(fm.size(), size_t{3});
    testTrue(fm.sees(0, 1));
    testTrue(fm.sees(1, 2));
    testTrue(fm.sees(2, 0));
    testTrue(!fm.sees(0, 0));

    auto chain = ClusterTopology::linearChain(3);
    testTrue(chain.sees(0, 1));
    testTrue(chain.sees(1, 0));
    testTrue(chain.sees(1, 2));
    testTrue(chain.sees(2, 1));
    testTrue(!chain.sees(0, 2));
    testTrue(!chain.sees(2, 0));

    auto st = ClusterTopology::star(4, 0);
    testTrue(st.sees(0, 1));
    testTrue(st.sees(0, 2));
    testTrue(st.sees(0, 3));
    testTrue(st.sees(1, 0));
    testTrue(!st.sees(1, 2));

    auto e = ClusterTopology::empty(3);
    testTrue(!e.sees(0, 1));
    testTrue(!e.sees(0, 2));

    auto cu = ClusterTopology::custom(3, {{0, 1}, {1, 2}});
    testTrue(cu.sees(0, 1));
    testTrue(cu.sees(1, 2));
    testTrue(!cu.sees(1, 0));
    testTrue(!cu.sees(2, 1));
}

void testTopologyMutators() {
    testDiag("ClusterTopology mutators add/remove edges as expected");

    auto t = ClusterTopology::empty(3);
    t.addEdge(0, 1);
    testTrue(t.sees(0, 1));
    testTrue(!t.sees(1, 0));

    t.addBidirectional(1, 2);
    testTrue(t.sees(1, 2));
    testTrue(t.sees(2, 1));

    t.removeEdge(0, 1);
    testTrue(!t.sees(0, 1));

    t.removeBidirectional(1, 2);
    testTrue(!t.sees(1, 2));
    testTrue(!t.sees(2, 1));
}

void testPeersSeenBy() {
    testDiag("ClusterTopology::peersSeenBy returns all directed-out neighbours");

    auto fm = ClusterTopology::fullMesh(3);
    auto p0 = fm.peersSeenBy(0);
    std::set<size_t> p0_set(p0.begin(), p0.end());
    testEq(p0_set.size(), size_t{2});
    testTrue(p0_set.count(1) == 1);
    testTrue(p0_set.count(2) == 1);
    testTrue(p0_set.count(0) == 0);

    auto chain = ClusterTopology::linearChain(3);
    auto c0 = chain.peersSeenBy(0);
    auto c1 = chain.peersSeenBy(1);
    auto c2 = chain.peersSeenBy(2);
    testEq(c0.size(), size_t{1});
    testEq(c1.size(), size_t{2});
    testEq(c2.size(), size_t{1});
}

void testTopologyOutOfRange() {
    testDiag("ClusterTopology bounds-checks");
    auto t = ClusterTopology::empty(3);
    bool threw = false;
    try {
        t.addEdge(0, 5);
    } catch (const std::out_of_range &) {
        threw = true;
    }
    testTrue(threw);

    bool threw2 = false;
    try {
        ClusterTopology::star(3, 5);
    } catch (const std::out_of_range &) {
        threw2 = true;
    }
    testTrue(threw2);
}

}  // namespace

MAIN(testclustertopology) {
    testPlan(38);
    pvxs::logger_config_env();
    testTopologyValueType();
    testTopologyMutators();
    testPeersSeenBy();
    testTopologyOutOfRange();
    return testDone();
}
