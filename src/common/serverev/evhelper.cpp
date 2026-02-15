/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <osiSock.h>

#ifdef _WIN32
#  include <windows.h>
#  include <mswsock.h>
#endif

#include <cstring>
#include <system_error>
#include <deque>
#include <algorithm>

#include <event2/event.h>
#include <event2/thread.h>

#include <errlog.h>
#include <epicsEvent.h>
#include <epicsThread.h>
#include <epicsExit.h>
#include <epicsMutex.h>
#include <epicsGuard.h>

#include "evhelper.h"
#include "utilpvt.h"
#include <pvxs/log.h>

typedef epicsGuard<epicsMutex> Guard;

namespace pvxs {namespace impl {

DEFINE_LOGGER(logerr, "pvxs.loop");

namespace mdetail {
VFunctor0::~VFunctor0() {}
}

static
void evthread_init()
{
#if defined(EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED)
    evthread_use_windows_threads();

#elif defined(EVTHREAD_USE_PTHREADS_IMPLEMENTED)
    evthread_use_pthreads();

#else
#  error libevent not built with threading support for this target
    // TODO fallback to libCom ?
#endif
}

struct ThreadEvent {
    std::atomic<epicsThreadPrivateId> pvt{};

    static
    void destroy(void* raw) { delete static_cast<epicsEvent*>(raw); }

    epicsEvent* get() {
        epicsThreadPrivateId id = pvt.load();
        if (!id) {
            const auto temp = epicsThreadPrivateCreate();
            if(pvt.compare_exchange_strong(id, temp)) {
                // stored
                id = temp;
            } else {
                // race
                epicsThreadPrivateDelete(temp);
                assert(id);
            }
        }

        auto evt = static_cast<epicsEvent*>(epicsThreadPrivateGet(id));

        if (!evt) {
            evt = new epicsEvent();
            epicsThreadPrivateSet(id, evt);
            epicsAtThreadExit(destroy, evt);
        }

        return evt;
    }

    epicsEvent* operator->() { return get(); }
};

namespace {
struct evbaseRunning {
    INST_COUNTER(evbaseRunning);
};
DEFINE_INST_COUNTER(evbaseRunning);
}

struct evbase::Pvt final : public epicsThreadRunable {

    std::weak_ptr<Pvt> internal_self;

    struct Work {
        mfunction fn;
        std::exception_ptr *result;
        epicsEvent *notify;
        Work(mfunction&& fn, std::exception_ptr *result, epicsEvent *notify)
            :fn(std::move(fn)), result(result), notify(notify)
        {}
    };
    std::deque<Work> actions;

    evbaseptr base;
    evevent keepalive;
    evevent dowork;
    epicsEvent start_sync;
    epicsMutex lock;

    epicsThread worker;
    bool running = true;

    INST_COUNTER(evbase);

    Pvt(const std::string& name, unsigned prio)
        :worker(*this, name.c_str(),
                epicsThreadGetStackSize(epicsThreadStackBig),
                prio)
    {
        threadOnce<&evthread_init>();

        worker.start();
        start_sync.wait();
        if (!base) throw std::runtime_error("event_base_new() fails");
    }

    virtual ~Pvt() {}

    void join() {
        {
            Guard G(lock);
            running = false;
        }
        if(worker.isCurrentThread())
            log_crit_printf(logerr, "evbase self-joining: %s\n", worker.getNameSelf());
        if(event_base_loopexit(base.get(), nullptr))
            log_crit_printf(logerr, "evbase error while interrupting loop for %p\n", base.get());
        worker.exitWait();
    }

    void run() override {
        evbaseRunning track;
        try {
            const evconfig conf(__FILE__, __LINE__, event_config_new());
#ifdef __rtems__
            /* with libbsd circa RTEMS 5.1
             * TCP peer close/reset notifications appear to be lost.
             * Maybe due to absence of NOTE_EOF?
             * poll() seems to work though.
             */
            event_config_avoid_method(conf.get(), "kqueue");
#endif
            decltype (base) tbase(__FILE__, __LINE__, event_base_new_with_config(conf.get()));
            if (evthread_make_base_notifiable(tbase.get()))
                throw std::runtime_error("evthread_make_base_notifiable");

            evevent handle(__FILE__, __LINE__,
                           event_new(tbase.get(), -1, EV_TIMEOUT, &doWorkS, this));
            evevent ka(__FILE__, __LINE__,
                       event_new(tbase.get(), -1, EV_TIMEOUT|EV_PERSIST, &evkeepalive, this));

            base = std::move(tbase);
            dowork = std::move(handle);
            keepalive = std::move(ka);

            const timeval tick{1000,0};
            if(event_add(keepalive.get(), &tick))
                throw std::runtime_error("Can't start keepalive timer");

            start_sync.signal();

            log_info_printf(logerr, "Enter loop worker for %p using %s\n", base.get(), event_base_get_method(base.get()));

            const int ret = event_base_loop(base.get(), 0);

            auto lvl = ret ? Level::Crit : Level::Info;
            log_printf(logerr, lvl, "Exit loop worker: %d for %p\n", ret, base.get());

        } catch(std::exception& e) {
            log_exc_printf(logerr, "Unhandled exception in event_base run : %s\n", e.what());
            start_sync.signal();
        }
    }

    void doWork()
    {
        decltype (actions) todo;
        {
            Guard G(lock);
            todo = std::move(actions);
        }
        for(auto& work : todo) {
            try {
                auto fn(std::move(work.fn));
                fn();
            }catch(std::exception& e){
                if(work.result) {
                    Guard G(lock);
                    *work.result = std::current_exception();
                } else {
                    log_exc_printf(logerr, "Unhandled exception in event_base : %s : %s\n",
                                    typeid(e).name(), e.what());
                }
            }
            if(work.notify)
                work.notify->signal();
        }
    }
    static
    void doWorkS(evutil_socket_t sock, short evt, void *raw)
    {
        const auto self =static_cast<Pvt*>(raw);
        try {
            self->doWork();
        } catch(std::exception& e) {
            log_exc_printf(logerr, "Unhandled error in doWorkS callback: %s\n", e.what());
        }
    }

    static
    void evkeepalive(evutil_socket_t sock, short evt, void *raw) {
        const auto self = static_cast<Pvt*>(raw);
        log_debug_printf(logerr, "Look keepalive %p\n", self);
    }

};
DEFINE_INST_COUNTER2(evbase::Pvt, evbase);

evbase::evbase(const std::string &name, unsigned prio)
{
    auto internal(std::make_shared<Pvt>(name, prio));
    internal->internal_self = internal;

    pvt.reset(internal.get(), [internal](Pvt*) mutable {
        auto temp(std::move(internal));
        temp->join();
    });

    base = pvt->base.get();
}

evbase::~evbase() {}

bool evbase::_dispatch(mfunction&& fn, bool dothrow) const {
    bool empty;
    {
        Guard G(pvt->lock);
        if(!pvt->running) {
            if(dothrow)
                throw std::logic_error("Worker stopped");
            return false;
        }
        empty = pvt->actions.empty();
        pvt->actions.emplace_back(std::move(fn), nullptr, nullptr);
    }

    timeval now{};
    if(empty && event_add(pvt->dowork.get(), &now))
        throw std::runtime_error("Unable to wakeup dispatch()");

    return true;
}

bool evbase::_call(mfunction&& fn, bool dothrow) const {
    if(pvt->worker.isCurrentThread()) {
        fn();
        return true;
    }

    static ThreadEvent done;

    std::exception_ptr result;
    bool empty;
    {
        Guard G(pvt->lock);
        if(!pvt->running) {
            if(dothrow)
                throw std::logic_error("Worker stopped");
            return false;
        }
        empty = pvt->actions.empty();
        pvt->actions.emplace_back(std::move(fn), &result, done.get());
    }

    timeval now{};
    if(empty && event_add(pvt->dowork.get(), &now))
        throw std::runtime_error("Unable to wakeup call()");

    done->wait();
    Guard G(pvt->lock);
    if(result)
        std::rethrow_exception(result);
    return true;
}


#ifndef IPV6_ADD_MEMBERSHIP
#  define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif
#ifndef IPV6_DROP_MEMBERSHIP
#  define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif

#if defined(_WIN32) && !defined(EAFNOSUPPORT)
#  define EAFNOSUPPORT WSAESOCKTNOSUPPORT
#endif

#if EPICS_VERSION_INT<VERSION_INT(7,0,3,1)
#  define getMonotonic getCurrent
#endif

} // namespace impl
} // namespace pvxs
