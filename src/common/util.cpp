/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <osiSock.h>

#ifdef __has_include
#  if defined(_WIN32) && __has_include(<afunix.h>)
#    include <afunix.h>
#    define WIN_HAS_AFUNIX
#  endif
#endif

#ifdef __linux__
#include <errno.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <stdlib.h>
#endif

// for signal handling
#include <signal.h>

#if defined(__linux__) || defined(__APPLE__)
#  include <sys/file.h>
#  define USE_POSIX_FLOCK
#endif

#include <sstream>
#include <stdexcept>

#include <fstream>

#ifdef _WIN32
#include <direct.h>
#else
#include <libgen.h>
#endif

#include <pvxs/util.h>

#include "utilpvt.h"

#include "certfactory.h"

namespace pvxs {

SockAddr::SockAddr(int af, unsigned short port) :store{} {
    store.sa.sa_family = af;
    switch(af) {
    case AF_INET:
        store.in.sin_port = htons(port);
        break;
    case AF_INET6:
        store.in6.sin6_port = htons(port);
        break;
    case AF_UNSPEC:
        if(port)
            throw std::invalid_argument("AF_UNSPEC can not specify port");
        break;
    default:
        throw std::invalid_argument("Unsupported address family");
    }
}

SockAddr::SockAddr(const char *address, unsigned short port) : SockAddr(AF_UNSPEC) {
    setAddress(address, port);
}

SockAddr::SockAddr(const sockaddr *addr, socklen_t alen) :SockAddr(addr ? addr->sa_family : AF_UNSPEC) {
    if(!addr)
        return; // treat NULL as AF_UNSPEC

    if(family()==AF_UNSPEC) {}
    else if(family()==AF_INET && (!alen || alen>=sizeof(sockaddr_in))) {}
    else if(family()==AF_INET6 && (!alen || alen>=sizeof(sockaddr_in6))) {}
    else
        throw std::invalid_argument("Unsupported address family");

    if(family()!=AF_UNSPEC)
        memcpy(&store, addr, family()==AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
}

void SockAddr::setPort(unsigned short port) {
    switch(store.sa.sa_family) {
    case AF_INET: store.in.sin_port = htons(port); break;
#ifdef AF_INET6
    case AF_INET6:store.in6.sin6_port = htons(port); break;
#endif
    default:
        throw std::logic_error("SockAddr: set family before port");
    }
}

void SockAddr::setAddress(const char *name, unsigned short defport)
{
    assert(name);
    // too bad evutil_parse_sockaddr_port() treats ":0" as an error...

    /* looking for
     * [ipv6]:port
     * ipv6
     * [ipv6]
     * ipv4:port
     * ipv4
     */
    // TODO: could optimize to find all of these with a single loop
    const char *firstc = strchr(name, ':'),
               *lastc  = strrchr(name, ':'),
               *openb  = strchr(name, '['),
               *closeb = strrchr(name, ']');

    if(!openb ^ !closeb) {
        // '[' w/o ']' or vis. versa
        throw std::runtime_error(SB()<<"IPv6 with mismatched brackets \""<<escape(name)<<"\"");
    }

    char scratch[INET6_ADDRSTRLEN+1];
    const char *addr, *port;
    SockAddr temp;
    void *sockaddr;

    if(!firstc && !openb) {
        // no brackets or port.
        // plain ipv4
        addr = name;
        port = nullptr;
        temp->sa.sa_family = AF_INET;
        sockaddr = (void*)&temp->in.sin_addr.s_addr;

    } else if(firstc && firstc==lastc && !openb) {
        // no bracket and only one ':'
        // ipv4 w/ port
        size_t addrlen = firstc-name;
        if(addrlen >= sizeof(scratch))
            throw std::runtime_error(SB()<<"IPv4 address too long \""<<escape(name)<<"\"");

        memcpy(scratch, name, addrlen);
        scratch[addrlen] = '\0';
        addr = scratch;
        port = lastc+1;
        temp->sa.sa_family = AF_INET;
        sockaddr = (void*)&temp->in.sin_addr.s_addr;

    } else if(firstc && firstc!=lastc && !openb) {
        // no bracket and more than one ':'
        // bare ipv6
        addr = name;
        port = nullptr;
        temp->sa.sa_family = AF_INET6;
        sockaddr = (void*)&temp->in6.sin6_addr;

    } else if(openb) {
        // brackets
        // ipv6, maybe with port
        size_t addrlen = closeb-openb-1u;
        if(addrlen >= sizeof(scratch))
            throw std::runtime_error(SB()<<"IPv6 address too long \""<<escape(name)<<"\"");

        memcpy(scratch, openb+1, addrlen);
        scratch[addrlen] = '\0';
        addr = scratch;
        if(lastc > closeb)
            port = lastc+1;
        else
            port = nullptr;
        temp->sa.sa_family = AF_INET6;
        sockaddr = (void*)&temp->in6.sin6_addr;

    } else {
        throw std::runtime_error(SB()<<"Invalid IP address form \""<<escape(name)<<"\"");
    }

    if(evutil_inet_pton(temp->sa.sa_family, addr, sockaddr)<=0) {
        // not a plain IP4/6 address.
        // Fall back to synchronous DNS lookup (could be sloooow)

        GetAddrInfo info(addr);

        // We may get a mixture of IP v4 and/or v6 addresses.
        // For maximum compatibility, we always prefer IPv4

        for(const auto addr : info) {
            if(addr.family()==AF_INET || (addr.family()==AF_INET6 && temp.family()==AF_UNSPEC)) {
                temp = addr;
                if(addr.family()==AF_INET)
                    break;
            }
        }

        if(temp.family()==AF_UNSPEC) // lookup succeeded, but no addresses.  Can this happen?
            throw std::runtime_error(SB()<<"Not a valid host name or IP address \""<<escape(name)<<"\"");
    }

    if(port)
        temp.setPort(parseTo<uint64_t>(port));
    else
        temp.setPort(defport);

    (*this) = temp;
}

SockAddr SockAddr::map6to4() const {
    constexpr uint8_t is4[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
    SockAddr ret;
    if(family()==AF_INET6 && memcmp(store.in6.sin6_addr.s6_addr, is4, 12)==0) {
        ret->in.sin_family = AF_INET;
        memcpy(&ret->in.sin_addr.s_addr,
               &store.in6.sin6_addr.s6_addr[12],
                4);
        ret->in.sin_port = store.in6.sin6_port;

    } else {
        ret = *this;
    }
    return ret;
}

std::ostream& operator<<(std::ostream& strm, const SockAddr& addr)
{
    switch(addr->sa.sa_family) {
    case AF_INET: {
        char buf[INET_ADDRSTRLEN+1];
        if(evutil_inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf))) {
            buf[sizeof(buf)-1] = '\0'; // paranoia
        } else {
            strm<<"<\?\?\?>";
        }
        strm<<buf;
        if(ntohs(addr->in.sin_port))
            strm<<':'<<ntohs(addr->in.sin_port);
        break;
    }
#ifdef AF_INET6
    case AF_INET6: {
            char buf[INET6_ADDRSTRLEN+1];
            if(evutil_inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf))) {
                buf[sizeof(buf)-1] = '\0'; // paranoia
                strm<<'['<<buf<<']';

            } else {
                strm<<"<\?\?\?>";
            }
            if(addr->in6.sin6_scope_id)
                strm<<"%"<<addr->in6.sin6_scope_id;
            if(auto port = ntohs(addr->in6.sin6_port))
                strm<<':'<<port;
            break;
    }
#endif
    case AF_UNSPEC:
        strm<<"<>";
        break;
    default:
        strm<<"<\?\?\?>";
    }
    return strm;
}

GetAddrInfo::GetAddrInfo(const char *name)
{
    // evutil_getaddrinfo() wrapper implicitly expects result pointer to be zerod
    // when applying various compatibility "hacks" on some targets.
    info = nullptr;
    if(auto err = evutil_getaddrinfo(name, nullptr, nullptr, &info)) {
        throw std::runtime_error(SB()<<"Error resolving \""<<escape(name)<<"\" : "<<evutil_gai_strerror(err));
    }
}

GetAddrInfo::~GetAddrInfo()
{
    if(info)
        evutil_freeaddrinfo(info);
}

void compat_socketpair(SOCKET sock[2])
{
    evutil_socket_t s[2];
    int err = -1;
#if !defined(_WIN32) || defined(WIN_HAS_AFUNIX)
    err = evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, s);
#endif
    if(err)
        err = evutil_socketpair(AF_INET, SOCK_STREAM, 0, s);
    if(err)
        throw std::runtime_error(SB()<<"ERROR: "<<__func__<<" "<<SOCKERRNO);
    sock[0] = (SOCKET)s[0];
    sock[1] = (SOCKET)s[1];
}

} // namespace pvxs


