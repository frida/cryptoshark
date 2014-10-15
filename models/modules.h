#ifndef MODULES_H
#define MODULES_H

#include <QAbstractListModel>
#include <QHash>
#include <QJsonArray>
#include <QSqlQuery>

class Module;

class Modules : public QAbstractListModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Modules)

public:
    explicit Modules(QObject *parent = 0,
                     QSqlDatabase db = QSqlDatabase());

    Q_INVOKABLE Module *getById(int id);
    Q_INVOKABLE Module *getByName(QString name);
    void update(QJsonArray modules);
    void addCalls(QHash<int, int> calls);

    QHash<int, QByteArray> roleNames() const { return m_roleNames; }
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    Q_INVOKABLE QVariant data(int i, QString roleName) const;
    Q_INVOKABLE QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;

private:
    int sortedIndex(Module *module, int currentIndex);

    QList<Module *> m_modules;
    QHash<int, Module *> m_moduleById;
    QHash<QString, Module *> m_moduleByName;
    QHash<int, QByteArray> m_roleNames;
    QSqlDatabase m_database;
    QSqlQuery m_insert;
    QSqlQuery m_update;
    QSqlQuery m_addCalls;
};

class Module : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Module)

    Q_PROPERTY(int id READ id CONSTANT)
    Q_PROPERTY(QString name READ name CONSTANT)
    Q_PROPERTY(QString path READ path NOTIFY pathChanged)
    Q_PROPERTY(quint64 base READ base NOTIFY baseChanged)
    Q_PROPERTY(bool main READ main CONSTANT)
    Q_PROPERTY(int calls READ calls NOTIFY callsChanged)

public:
    explicit Module(QObject *parent,
                    int id,
                    QString name,
                    QString path,
                    quint64 base,
                    bool main,
                    int calls) :
        QObject(parent),
        m_id(id),
        m_name(name),
        m_path(path),
        m_base(base),
        m_main(main),
        m_calls(calls)
    {
    }

    int id() const { return m_id; }
    QString name() const { return m_name; }
    QString path() const { return m_path; }
    quint64 base() const { return m_base; }
    bool main() const { return m_main; }
    int calls() const { return m_calls; }

signals:
    void pathChanged(QString newPath);
    void baseChanged(quint64 newBase);
    void callsChanged(int newCalls);

private:
    int m_id;
    QString m_name;
    QString m_path;
    quint64 m_base;
    bool m_main;
    int m_calls;

    friend class Modules;
};

#endif // MODULES_H
