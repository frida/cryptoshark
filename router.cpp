#include "router.h"

#include "models.h"

#include <QMetaMethod>

Router *Router::s_instance = nullptr;

Router::Router(QObject *parent) :
    QObject(parent),
    m_agent(nullptr),
    m_nextRequestId(1)
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

    m_agent = agent;
    m_postMethod = agentMeta->method(agentMeta->indexOfMethod("post(QJsonObject)"));

    auto agentMessageSignal = agentMeta->method(agentMeta->indexOfSignal("message(ScriptInstance*,QJsonObject,QByteArray)"));
    auto routerMeta = metaObject();
    auto routerOnMessageSlot = routerMeta->method(routerMeta->indexOfSlot("onMessage(ScriptInstance*,QJsonObject,QByteArray)"));
    connect(agent, agentMessageSignal, this, routerOnMessageSlot);
}

Request *Router::request(QString name, QJsonObject payload)
{
    auto id = QString("r") + QString::number(m_nextRequestId++);

    auto request = new Request(this);
    m_requests[id] = request;

    auto message = QJsonObject();
    message[QStringLiteral("id")] = id;
    message[QStringLiteral("name")] = name;
    message[QStringLiteral("payload")] = payload;
    m_postMethod.invoke(m_agent, Q_ARG(QJsonObject, message));

    return request;
}

void Router::onMessage(ScriptInstance *sender, QJsonObject object, QByteArray data)
{
    Q_UNUSED(sender);
    Q_UNUSED(data);

    bool handled = false;

    if (object[QStringLiteral("type")] == QStringLiteral("send")) {
        auto stanza = object[QStringLiteral("payload")].toObject();

        auto idValue = stanza[QStringLiteral("id")];
        if (!idValue.isNull()) {
            auto id = idValue.toString();
            auto request = m_requests[id];
            if (request != nullptr) {
                m_requests.remove(id);
                request->complete(stanza[QStringLiteral("payload")]);
                handled = true;
            }
        }

        if (!handled) {
            auto name = stanza[QStringLiteral("name")];
            if (name == QStringLiteral("modules:update")) {
                Models::instance()->modules()->update(stanza[QStringLiteral("payload")].toArray());
                handled = true;
            } else if (name == QStringLiteral("thread:summary")) {
                auto update = stanza[QStringLiteral("payload")].toObject();
                auto summary = update[QStringLiteral("summary")].toObject();
                Models::instance()->functions()->addCalls(summary);
                handled = true;
            }
        }
    }

    if (!handled)
        emit message(object);
}

Request::Request(QObject *parent) :
    QObject(parent)
{
    connect(this, &Request::completed, this, &Request::deleteLater);
}

void Request::complete(QJsonValue result)
{
    emit completed(result);
}
