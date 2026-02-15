/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef EVHELPER_H
#define EVHELPER_H

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include "evhelper.h"

#ifdef PVXS_ENABLE_OPENSSL
#  include <event2/bufferevent_ssl.h>
#endif

#include <epicsTime.h>
#include <utilpvt.h>

#include <pvxs/version.h>

#include "ownedptr.h"
#include "pvaproto.h"

namespace pvxs {namespace impl {

template<typename T>
struct ev_delete;
#define DEFINE_DELETE(TYPE) \
template<> struct ev_delete<TYPE> { \
    inline void operator()(TYPE* ev) { TYPE ## _free(ev); } \
}
DEFINE_DELETE(event_config);
DEFINE_DELETE(event_base);
DEFINE_DELETE(event);
DEFINE_DELETE(evconnlistener);
DEFINE_DELETE(bufferevent);
DEFINE_DELETE(evbuffer);
#undef DEFINE_DELETE

namespace mdetail {
struct VFunctor0 {
    VFunctor0() = default;
    VFunctor0(VFunctor0&) = delete;
    VFunctor0(const VFunctor0&) = delete;
    VFunctor0& operator=(const VFunctor0&) = delete;
    virtual ~VFunctor0() =0;
    virtual void invoke() =0;
};
template<typename Fn>
struct Functor0 final : public VFunctor0 {
    Functor0() = default;
    Functor0(Fn&& fn) : fn(std::move(fn)) {}
    virtual ~Functor0() {}

    void invoke() override final { fn(); }
private:
    Fn fn;
};
} // namespace detail

struct mfunction {
    mfunction() = default;
    template<typename Fn>
    mfunction(Fn&& fn)
        :fn{new mdetail::Functor0<Fn>(std::move(fn))}
    {}
    void operator()() const {
        fn->invoke();
    }
    explicit operator bool() const {
        return fn.operator bool();
    }
private:
    std::unique_ptr<mdetail::VFunctor0> fn;
};

struct evbase {
    evbase() = default;
    explicit evbase(const std::string& name, unsigned prio=0);
    ~evbase();

    evbase internal() const;

    void join() const;

    void sync() const;

private:
    bool _dispatch(mfunction&& fn, bool dothrow) const;
    bool _call(mfunction&& fn, bool dothrow) const;
public:

    // queue request to execute in event loop.  return after executed.
    inline
    void call(mfunction&& fn) const {
        _call(std::move(fn), true);
    }
    inline
    bool tryCall(mfunction&& fn) const {
        return _call(std::move(fn), false);
    }

    // queue request to execute in event loop.  return immediately.
    inline
    void dispatch(mfunction&& fn) const {
        _dispatch(std::move(fn), true);
    }
    inline
    bool tryDispatch(mfunction&& fn) const {
        return _dispatch(std::move(fn), false);
    }

    bool tryInvoke(bool docall, mfunction&& fn) const {
        if(docall)
            return tryCall(std::move(fn));
        else
            return tryDispatch(std::move(fn));
    }

    inline void reset() { pvt.reset(); }

private:
    struct Pvt;
    std::shared_ptr<Pvt> pvt;
public:
    event_base* base = nullptr;
};

template<typename T>
using ev_owned_ptr = pvxs::OwnedPtr<T, ev_delete<T>>;
typedef ev_owned_ptr<event_config> evconfig;
typedef ev_owned_ptr<event_base> evbaseptr;
typedef ev_owned_ptr<event> evevent;
typedef ev_owned_ptr<evconnlistener> evlisten;
typedef ev_owned_ptr<bufferevent> evbufferevent;
typedef ev_owned_ptr<evbuffer> evbuf;

} // namespace impl


#ifdef PVXS_EXPERT_API_ENABLED

struct Timer::Pvt {
    const evbase base;
    std::function<void()> cb;
    evevent timer;

    Pvt(const evbase& base, std::function<void()>&& cb)
        :base(base), cb(std::move(cb))
    {}
    ~Pvt();

    bool cancel();

    static
    Timer buildOneShot(double delay, const evbase &base, std::function<void()>&& cb);

    INST_COUNTER(Timer);
};

#endif // PVXS_EXPERT_API_ENABLED

} // namespace pvxs

#endif /* EVHELPER_H */
