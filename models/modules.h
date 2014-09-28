#ifndef MODULES_H
#define MODULES_H

#include "tablemodel.h"

#include <QHash>
#include <QJsonArray>
#include <QSqlQuery>

class Module;

class Modules : public TableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Modules)

public:
    explicit Modules(QObject *parent = 0,
                     QSqlDatabase db = QSqlDatabase());

    Module *getByName(QString name);
    void update(QJsonArray modules);
    void addCalls(QHash<int, int> calls);

private:
    QSqlQuery m_getByName;
    QSqlQuery m_insert;
    QSqlQuery m_update;
    QSqlQuery m_addCalls;
    QHash<QString, Module *> m_cache;
};

class Module : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Module)

    Q_PROPERTY(int id READ id CONSTANT)
    Q_PROPERTY(QString name READ name CONSTANT)
    Q_PROPERTY(QString path READ path CONSTANT)
    Q_PROPERTY(quint64 base READ base CONSTANT)
    Q_PROPERTY(bool main READ main CONSTANT)

public:
    explicit Module(QObject *parent,
                    int id,
                    QString name,
                    QString path,
                    quint64 base,
                    bool main) :
        QObject(parent),
        m_id(id),
        m_name(name),
        m_path(path),
        m_base(base),
        m_main(main)
    {
    }

    int id() const { return m_id; }
    QString name() const { return m_name; }
    QString path() const { return m_path; }
    quint64 base() const { return m_base; }
    bool main() const { return m_main; }

private:
    int m_id;
    QString m_name;
    QString m_path;
    quint64 m_base;
    bool m_main;
};

#endif // MODULES_H
