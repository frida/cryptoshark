#include "router.h"

#include <QMetaMethod>

Router::Router(QObject *parent) :
    QObject(parent)
{
}

void Router::attach(QObject *agent)
{
    auto agentMeta = agent->metaObject();
    auto agentMessageSignal = agentMeta->method(agentMeta->indexOfSignal("message(ScriptInstance*,QJsonObject,QByteArray)"));
    auto routerMeta = metaObject();
    auto routerOnMessageSlot = routerMeta->method(routerMeta->indexOfSlot("onMessage(ScriptInstance*,QJsonObject,QByteArray)"));
    connect(agent, agentMessageSignal, this, routerOnMessageSlot);
}

void Router::onMessage(ScriptInstance *sender, QJsonObject object, QByteArray data)
{
    printf("onMessage!!!!\n");
}
