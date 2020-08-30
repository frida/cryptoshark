#ifndef ROUTER_H
#define ROUTER_H

#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QMetaMethod>
#include <QObject>

class Request;
class RequestError;
class ScriptInstance;

class Router : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(Router)

public:
    explicit Router(QObject *parent = 0);
    ~Router();

    static Router *instance();

    Q_INVOKABLE void attach(QObject *agent);
    Request *request(QString name, QJsonArray args);

signals:
    void message(QJsonObject object, QVariant data);

public slots:
    void onMessage(ScriptInstance *sender, QJsonObject object, QVariant data);

private slots:
    void beginRequest(Request *request);

private:
    bool tryHandleStanza(QJsonObject stanza);
    bool tryHandleRpcReply(QJsonArray params, QVariant data);

    QObject *m_agent;
    QMetaMethod m_postMethod;
    QHash<QString, Request *> m_requests;
    QAtomicInt m_nextRequestId;

    static Router *s_instance;
};

class Request : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(Request)

public:
    Request(QString id, QString name, QJsonArray args, QObject *parent = nullptr);

    QString id() const { return m_id; }
    QJsonArray payload() const { return m_payload; }

protected:
    void complete(QVariant result, RequestError *error);

signals:
    void completed(QVariant result, RequestError *error);

private:
    QString m_id;
    QJsonArray m_payload;

    friend class Router;
};

class RequestError : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(RequestError)

    Q_PROPERTY(QString message READ message CONSTANT)
    Q_PROPERTY(QString stack READ stack CONSTANT)

public:
    RequestError(QString message, QString stack);

    QString message() const { return m_message; }
    QString stack() const { return m_stack; }

private:
    QString m_message;
    QString m_stack;
};

#endif // ROUTER_H
