/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef SERVERCONN_H
#define SERVERCONN_H

#include <atomic>
#include <memory>

#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/source.h>

#include "evhelper.h"
#include "utilpvt.h"

#include "certstatus.h"
#include "certstatusmanager.h"

namespace pvxs {namespace impl {

//! Home of the magic "server" PV used by "pvinfo"
struct ServerSource : public server::Source
{
    const std::string name;
    server::Server::Pvt* const serv;

    const Value info;

    INST_COUNTER(ServerSource);

    ServerSource(server::Server::Pvt* serv);

    virtual void onSearch(Search &op) override final;

    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&op) override final;
};

} // namespace impl

namespace server {
using namespace impl;


}} // namespace pvxs::server

#endif // SERVERCONN_H
