#include "router.h"

#include "models.h"
#include "radare.h"

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
    m_postMethod = agentMeta->method(agentMeta->indexOfMethod("post(QJsonArray)"));

    auto agentMessageSignal = agentMeta->method(agentMeta->indexOfSignal("message(ScriptInstance*,QJsonObject,QVariant)"));
    auto routerMeta = metaObject();
    auto routerOnMessageSlot = routerMeta->method(routerMeta->indexOfSlot("onMessage(ScriptInstance*,QJsonObject,QVariant)"));
    connect(agent, agentMessageSignal, this, routerOnMessageSlot);
}

Request *Router::request(QString name, QJsonArray args)
{
    auto id = QString("r") + QString::number(m_nextRequestId++);
    auto request = new Request(id, name, args);
    QObject::connect(request, &Request::completed, request, &QObject::deleteLater);

    QMetaObject::invokeMethod(this, "beginRequest", Qt::QueuedConnection,
        Q_ARG(Request *, request));

    return request;
}

void Router::beginRequest(Request *request)
{
    m_requests[request->id()] = request;
    m_postMethod.invoke(m_agent, Q_ARG(QJsonArray, request->payload()));
}

void Router::onMessage(ScriptInstance *sender, QJsonObject object, QVariant data)
{
    Q_UNUSED(sender);

    bool handled = false;

    if (object[QStringLiteral("type")] == QStringLiteral("send")) {
        auto payload = object[QStringLiteral("payload")];
        if (payload.isArray()) {
            handled = tryHandleRpcReply(payload.toArray(), data);
        } else if (payload.isObject()) {
            handled = tryHandleStanza(payload.toObject());
        }
    }

    if (!handled)
        emit message(object, data);
}

bool Router::tryHandleStanza(QJsonObject stanza)
{
    auto name = stanza[QStringLiteral("name")];

    if (name == QStringLiteral("modules:update")) {
        Models::instance()->modules()->update(stanza[QStringLiteral("payload")].toArray());
        return true;
    } else if (name == QStringLiteral("thread:summary")) {
        auto update = stanza[QStringLiteral("payload")].toObject();
        auto summary = update[QStringLiteral("summary")].toObject();
        Models::instance()->functions()->addCalls(summary);
        return true;
    } else if (name == QStringLiteral("function:log")) {
        auto entry = stanza[QStringLiteral("payload")].toObject();
        auto id = entry[QStringLiteral("id")].toInt();
        auto message = entry[QStringLiteral("message")].toString();
        Models::instance()->functions()->addLogMessage(id, message);
        return true;
    } else if (name == QStringLiteral("agent:ready")) {
        auto payload = stanza[QStringLiteral("payload")].toObject();
        auto platform = payload[QStringLiteral("platform")].toString();
        auto arch = payload[QStringLiteral("arch")].toString();
        auto pointerSize = payload[QStringLiteral("pointerSize")].toInt();
        RadareController::instance()->initialize(platform, arch, pointerSize);
        return true;
    }

    return false;
}

bool Router::tryHandleRpcReply(QJsonArray params, QVariant data)
{
    if (params.count() < 4)
        return false;

    if (params[0].toString() != "frida:rpc")
        return false;

    auto id = params[1].toString();
    auto request = m_requests[id];
    if (request == nullptr)
        return false;
    m_requests.remove(id);

    auto type = params[2].toString();
    if (type == "ok") {
        if (data.isNull())
            request->complete(params[3].toVariant(), nullptr);
        else
            request->complete(data, nullptr);
    } else {
        auto message = params[3].toString();
        auto stack = params[5].toString();
        RequestError error(message, stack);
        request->complete(QJsonValue(), &error);
    }

    return true;
}

Request::Request(QString id, QString name, QJsonArray args, QObject *parent) :
    QObject(parent),
    m_id(id)
{
    m_payload = {
        "frida:rpc",
        id,
        "call",
        name,
        args
    };
}

void Request::complete(QVariant result, RequestError *error)
{
    emit completed(result, error);
}

RequestError::RequestError(QString message, QString stack) :
    m_message(message),
    m_stack(stack)
{
}
