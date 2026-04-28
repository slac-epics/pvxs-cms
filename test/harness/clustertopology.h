/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_CMS_TEST_CLUSTERTOPOLOGY_H
#define PVXS_CMS_TEST_CLUSTERTOPOLOGY_H

#include <cstddef>
#include <utility>
#include <vector>

#if defined(__GNUC__) || defined(__clang__)
#  define PVXS_CMS_TEST_CLUSTERTOPOLOGY_API __attribute__((visibility("default")))
#else
#  define PVXS_CMS_TEST_CLUSTERTOPOLOGY_API
#endif

namespace cms {
namespace test {

// Directed-edge graph describing a cluster's intra-cluster peer visibility.
// Indexes are zero-based.  Edges are directed: A having B in nameServers
// lets A's join requests reach B but not vice-versa.  The symmetric
// factories (fullMesh / linearChain / star) construct pairs of directed
// edges as a convenience.
class PVXS_CMS_TEST_CLUSTERTOPOLOGY_API ClusterTopology {
   public:
    static ClusterTopology fullMesh(size_t n);
    static ClusterTopology linearChain(size_t n);
    static ClusterTopology star(size_t n, size_t hub);
    static ClusterTopology empty(size_t n);
    static ClusterTopology custom(size_t n, std::vector<std::pair<size_t, size_t>> edges);

    ClusterTopology &addEdge(size_t from, size_t to);
    ClusterTopology &addBidirectional(size_t a, size_t b);
    ClusterTopology &removeEdge(size_t from, size_t to);
    ClusterTopology &removeBidirectional(size_t a, size_t b);

    bool sees(size_t from, size_t to) const;
    std::vector<size_t> peersSeenBy(size_t i) const;
    size_t size() const noexcept;

   private:
    explicit ClusterTopology(size_t n);
    size_t n_{0};
    std::vector<std::vector<bool>> adj_;
};

}  // namespace test
}  // namespace cms

#endif  // PVXS_CMS_TEST_CLUSTERTOPOLOGY_H
