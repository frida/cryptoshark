#include "router.h"

#include "models.h"

#include <QMetaMethod>

Router *Router::s_instance = nullptr;

Router::Router(QObject *parent) :
    QObject(parent)
{
}

Router::~Router()
{
    s_instance = nullptr;
}

Router *Router::instance()
{
    if (s_instance == nullptr)
        s_instance = new Router();
    return s_instance;
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
        if (name == QStringLiteral("modules:update")) {
            Models::instance()->modules()->apply(stanza[QStringLiteral("payload")].toArray());
            handled = true;
        } else if (name == QStringLiteral("thread:summary")) {
            // TODO
            handled = true;
        }
    }

    if (!handled)
        emit message(object);
}
