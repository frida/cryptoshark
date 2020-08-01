#ifndef ROUTER_H
#define ROUTER_H

#include <QHash>
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
    Request *request(QString name, QJsonObject payload);

signals:
    void message(QJsonObject object);

public slots:
    void onMessage(ScriptInstance *sender, QJsonObject object, QVariant data);

private:
    QObject *m_agent;
    QMetaMethod m_postMethod;
    QHash<QString, Request *> m_requests;
    int m_nextRequestId;

    static Router *s_instance;
};

class Request : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(Request)

public:
    Request(QObject *parent = 0);

protected:
    void complete(QJsonValue result, RequestError *error);

signals:
    void completed(QJsonValue result, RequestError *error);

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
