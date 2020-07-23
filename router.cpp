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

    auto agentMessageSignal = agentMeta->method(agentMeta->indexOfSignal("message(ScriptInstance*,QJsonObject,QVariant)"));
    auto routerMeta = metaObject();
    auto routerOnMessageSlot = routerMeta->method(routerMeta->indexOfSlot("onMessage(ScriptInstance*,QJsonObject,QVariant)"));
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

void Router::onMessage(ScriptInstance *sender, QJsonObject object, QVariant data)
{
    Q_UNUSED(sender);
    Q_UNUSED(data);

    bool handled = false;

    if (object[QStringLiteral("type")] == QStringLiteral("send")) {
        auto stanza = object[QStringLiteral("payload")].toObject();
        auto name = stanza[QStringLiteral("name")];

        const bool isResult = name == QStringLiteral("result");
        if (isResult || name == QStringLiteral("error")) {
            auto idValue = stanza[QStringLiteral("id")];
            auto id = idValue.toString();

            auto request = m_requests[id];
            if (request != nullptr) {
                m_requests.remove(id);

                auto payload = stanza[QStringLiteral("payload")];

                if (isResult) {
                    request->complete(payload, nullptr);
                } else {
                    auto errorValue = payload.toObject();
                    auto message = errorValue[QStringLiteral("message")].toString();
                    auto stack = errorValue[QStringLiteral("stack")].toString();
                    RequestError error(message, stack);
                    request->complete(QJsonValue(), &error);
                }

                handled = true;
            }
        } else if (name == QStringLiteral("modules:update")) {
            Models::instance()->modules()->update(stanza[QStringLiteral("payload")].toArray());
            handled = true;
        } else if (name == QStringLiteral("thread:summary")) {
            auto update = stanza[QStringLiteral("payload")].toObject();
            auto summary = update[QStringLiteral("summary")].toObject();
            Models::instance()->functions()->addCalls(summary);
            handled = true;
        } else if (name == QStringLiteral("function:log")) {
            auto entry = stanza[QStringLiteral("payload")].toObject();
            auto id = entry[QStringLiteral("id")].toInt();
            auto message = entry[QStringLiteral("message")].toString();
            Models::instance()->functions()->addLogMessage(id, message);
            handled = true;
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

void Request::complete(QJsonValue result, RequestError *error)
{
    emit completed(result, error);
}

RequestError::RequestError(QString message, QString stack) :
    m_message(message),
    m_stack(stack)
{
}
