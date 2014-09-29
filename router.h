#ifndef ROUTER_H
#define ROUTER_H

#include <QHash>
#include <QJsonObject>
#include <QMetaMethod>
#include <QObject>

class Request;
class ScriptInstance;

class Router : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Router)

public:
    explicit Router(QObject *parent = 0);
    ~Router();

    static Router *instance();

    Q_INVOKABLE void attach(QObject *agent);
    Request *request(QString name, QJsonObject payload);

signals:
    void message(QJsonObject object);

public slots:
    void onMessage(ScriptInstance *sender, QJsonObject object, QByteArray data);

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
    Q_DISABLE_COPY(Request)

public:
    Request(QObject *parent = 0);

protected:
    void complete(QJsonValue result);

signals:
    void completed(QJsonValue result);

    friend class Router;
};

#endif // ROUTER_H
