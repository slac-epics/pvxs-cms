/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef OSISOCKEXT_H
#define OSISOCKEXT_H

#include <osiSock.h>

#include <string>
#include <string.h>

#include <event2/util.h>

#include <pvxs/version.h>

// added with Base 3.15
#ifndef SOCK_EADDRNOTAVAIL
#  ifdef _WIN32
#    define SOCK_EADDRNOTAVAIL WSAEADDRNOTAVAIL
#  else
#    define SOCK_EADDRNOTAVAIL EADDRNOTAVAIL
#  endif
#endif

namespace pvxs {
namespace impl {
struct ConfigCommon;
} // namespace impl

void osiSockAttachExt();

struct SockAttach {
    SockAttach() { osiSockAttachExt(); }
    SockAttach(const SockAttach&) = delete;
    SockAttach& operator=(const SockAttach&) = delete;
    ~SockAttach() { osiSockRelease(); }
};


//! representation of a network address
struct SockAddr {
    union store_t {
        sockaddr sa;
        sockaddr_in in;
#ifdef AF_INET6
        sockaddr_in6 in6;
#endif
    };
private:
    store_t  store;
public:

    explicit SockAddr(int af = AF_UNSPEC, unsigned short port=0);
    explicit SockAddr(const char *address, unsigned short port=0);
    explicit SockAddr(const sockaddr *addr, socklen_t alen=0);

    explicit SockAddr(const std::string& address, unsigned short port=0) :SockAddr(address.c_str(), port) {}

    unsigned short family() const noexcept { return store.sa.sa_family; }
    void setPort(unsigned short port);
    void setAddress(const char *, unsigned short port=0);

    void setAddress(const std::string& s, unsigned short port=0) {
        setAddress(s.c_str(), port);
    }

    SockAddr map6to4() const;

    store_t* operator->() { return &store; }
    const store_t* operator->() const { return &store; }

};

std::ostream& operator<<(std::ostream& strm, const SockAddr& addr);

struct GetAddrInfo {
    explicit GetAddrInfo(const char *name);

    ~GetAddrInfo();

    struct iterator {
        evutil_addrinfo *pos = nullptr;
        iterator() = default;
        iterator(evutil_addrinfo *pos) : pos(pos) {}
        SockAddr operator*() const {
            return SockAddr(pos->ai_addr, pos->ai_addrlen);
        }
        iterator& operator++() {
            pos = pos->ai_next;
            return *this;
        }
        iterator operator++(int) {
            auto ret(*this);
            pos = pos->ai_next;
            return ret;
        }
        bool operator==(const iterator& o) const {
            return pos==o.pos;
        }
        bool operator!=(const iterator& o) const {
            return pos!=o.pos;
        }
    };

    iterator begin() const { return iterator{info}; }
    iterator end() const { return iterator{}; }

    private:
        evutil_addrinfo *info;
};

} // namespace pvxs

#endif // OSISOCKEXT_H
