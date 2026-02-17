/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// The parts of this file that are referenced by sources in this repo MUST match `evhelper.h` in the pvxs repo.
// pvxs already makes them available with in the pvxs library.  If this header
// matches exactly, then we can avoid the need to duplicate `evhelper.cpp` and simply link with pvxs lib.

#ifndef EVHELPER_H
#define EVHELPER_H

#include <memory>
#include <string>

#include <event2/event.h>

#include "ownedptr.h"

namespace pvxs {
namespace impl {

template<typename T>
struct ev_delete;
#define DEFINE_DELETE(TYPE) \
template<> struct ev_delete<TYPE> { \
    inline void operator()(TYPE* ev) { TYPE ## _free(ev); } \
}
DEFINE_DELETE(event_config);
DEFINE_DELETE(event_base);
DEFINE_DELETE(event);
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

private:
    bool _dispatch(mfunction&& fn, bool dothrow) const;
    bool _call(mfunction&& fn, bool dothrow) const;
public:

    // queue request to execute in event loop.  return after executed.
    inline
    void call(mfunction&& fn) const {
        _call(std::move(fn), true);
    }

    // queue request to execute in event loop.  return immediately.
    inline
    void dispatch(mfunction&& fn) const {
        _dispatch(std::move(fn), true);
    }

    void reset() { pvt.reset(); }

private:
    struct Pvt;
    std::shared_ptr<Pvt> pvt;
public:
    event_base* base = nullptr;
};

template<typename T>
using ev_owned_ptr = OwnedPtr<T, ev_delete<T>>;
typedef ev_owned_ptr<event_config> evconfig;
typedef ev_owned_ptr<event_base> evbaseptr;
typedef ev_owned_ptr<event> evevent;

} // namespace impl
} // namespace pvxs

#endif /* EVHELPER_H */
