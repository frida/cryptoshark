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
    Q_UNUSED(sender);
    Q_UNUSED(data);

    bool handled = false;

    if (object[QStringLiteral("type")] == QStringLiteral("send")) {
        auto stanza = object[QStringLiteral("payload")].toObject();
        auto name = stanza[QStringLiteral("name")];
        auto nameBytes = name.toString().toUtf8();
        if (name == QStringLiteral("modules:update")) {
            handled = true;

            // TODO
        } else if (name == QStringLiteral("thread:summary")) {
            handled = true;

            // TODO
        }
    }

    if (!handled)
        emit message(object);
}
