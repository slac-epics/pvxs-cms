/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "pvxs/cms/testharness.h"

#include <stdexcept>

namespace cms {
namespace test {

ClusterTopology::ClusterTopology(size_t n) : n_(n), adj_(n, std::vector<bool>(n, false)) {}

ClusterTopology ClusterTopology::fullMesh(size_t n) {
    ClusterTopology t(n);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            if (i != j) t.adj_[i][j] = true;
        }
    }
    return t;
}

ClusterTopology ClusterTopology::linearChain(size_t n) {
    ClusterTopology t(n);
    for (size_t i = 0; i + 1 < n; ++i) {
        t.adj_[i][i + 1] = true;
        t.adj_[i + 1][i] = true;
    }
    return t;
}

ClusterTopology ClusterTopology::star(size_t n, size_t hub) {
    if (hub >= n) throw std::out_of_range("star: hub index out of range");
    ClusterTopology t(n);
    for (size_t i = 0; i < n; ++i) {
        if (i == hub) continue;
        t.adj_[hub][i] = true;
        t.adj_[i][hub] = true;
    }
    return t;
}

ClusterTopology ClusterTopology::empty(size_t n) {
    return ClusterTopology(n);
}

ClusterTopology ClusterTopology::custom(size_t n, std::vector<std::pair<size_t, size_t>> edges) {
    ClusterTopology t(n);
    for (auto &e : edges) {
        if (e.first >= n || e.second >= n) {
            throw std::out_of_range("custom: edge index out of range");
        }
        t.adj_[e.first][e.second] = true;
    }
    return t;
}

ClusterTopology &ClusterTopology::addEdge(size_t from, size_t to) {
    if (from >= n_ || to >= n_) throw std::out_of_range("addEdge: index out of range");
    adj_[from][to] = true;
    return *this;
}

ClusterTopology &ClusterTopology::addBidirectional(size_t a, size_t b) {
    addEdge(a, b);
    addEdge(b, a);
    return *this;
}

ClusterTopology &ClusterTopology::removeEdge(size_t from, size_t to) {
    if (from >= n_ || to >= n_) throw std::out_of_range("removeEdge: index out of range");
    adj_[from][to] = false;
    return *this;
}

ClusterTopology &ClusterTopology::removeBidirectional(size_t a, size_t b) {
    removeEdge(a, b);
    removeEdge(b, a);
    return *this;
}

bool ClusterTopology::sees(size_t from, size_t to) const {
    if (from >= n_ || to >= n_) return false;
    return adj_[from][to];
}

std::vector<size_t> ClusterTopology::peersSeenBy(size_t i) const {
    std::vector<size_t> out;
    if (i >= n_) return out;
    for (size_t j = 0; j < n_; ++j) {
        if (adj_[i][j]) out.push_back(j);
    }
    return out;
}

size_t ClusterTopology::size() const noexcept { return n_; }

}  // namespace test
}  // namespace cms
