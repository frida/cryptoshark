#ifndef ROUTER_H
#define ROUTER_H

#include <QJsonObject>
#include <QObject>

class ScriptInstance;

class Router : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Router)

public:
    explicit Router(QObject *parent = 0);

    Q_INVOKABLE void attach(QObject *agent);

signals:
    void message(QJsonObject object);

public slots:
    void onMessage(ScriptInstance *sender, QJsonObject object, QByteArray data);
};

#endif // ROUTER_H
