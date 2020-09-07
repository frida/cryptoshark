#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "modules.h"

#include <QAbstractTableModel>
#include <QHash>
#include <QJsonObject>
#include <QRegExp>
#include <QSet>
#include <QSqlQuery>

class Function;

class Functions : public QAbstractTableModel
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(Functions)

public:
    explicit Functions(QObject *parent = 0,
                       QSqlDatabase db = QSqlDatabase());

    Q_INVOKABLE void load(int moduleId);

    Q_INVOKABLE Function *getById(int id);
    Q_INVOKABLE bool updateName(int functionId, QString name);

    Q_INVOKABLE void addProbe(int functionId);
    Q_INVOKABLE void removeProbe(int functionId);
    Q_INVOKABLE void updateProbe(int functionId, QString script);

    Q_INVOKABLE void symbolicate(int moduleId);

    void addCalls(QJsonObject summary);
    void addLogMessage(int functionId, QString message);

    QHash<int, QByteArray> roleNames() const override { return m_roleNames; }
    int rowCount(const QModelIndex &) const override { return m_functions.size(); }
    int columnCount(const QModelIndex &) const override { return 3; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    Q_INVOKABLE QVariant data(const QModelIndex &index, QString roleName) const;
    Q_INVOKABLE QVariant data(const QModelIndex &index, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &) const override {
        return Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren;
    }

signals:
    void discovered(QString name, int offset, Module *module);
    void renamed(Function *func);
    void logMessage(Function *func, QString message);

private:
    void sortByCallsDescending();
    void importModuleExports(QList<int> moduleIds);
    Function *createFunctionFromQuery(QSqlQuery query);
    void notifyRowChange(Function *function);
    static QString functionName(Module *module, int offset);
    static QString functionPrefix(Module *module);

    int m_currentModuleId;
    QList<Function *> m_functions;
    QHash<int, Function *> m_functionById;
    QHash<QString, Function *> m_functionBySymbol;
    QSet<int> m_importedModules;
    QHash<int, QByteArray> m_roleNames;
    QSqlDatabase m_database;
    QSqlQuery m_getAll;
    QSqlQuery m_getById;
    QSqlQuery m_getBySymbol;
    QSqlQuery m_getUnexported;
    QSqlQuery m_insert;
    QSqlQuery m_updateName;
    QSqlQuery m_updateCalls;
    QSqlQuery m_updateProbeScript;
    QSqlQuery m_checkImportNeeded;
    QSqlQuery m_updateToExported;
    static QRegExp s_ignoredPrefixCharacters;
};

class Function : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(Function)

    Q_PROPERTY(int id READ id CONSTANT)
    Q_PROPERTY(QString name READ name NOTIFY nameChanged)
    Q_PROPERTY(QString address READ address CONSTANT)
    Q_PROPERTY(Module *module READ module CONSTANT)
    Q_PROPERTY(int offset READ offset CONSTANT)
    Q_PROPERTY(bool exported READ exported NOTIFY exportedChanged)
    Q_PROPERTY(int calls READ calls NOTIFY callsChanged)
    Q_PROPERTY(QString probeScript READ probeScript NOTIFY probeScriptChanged)
    Q_PROPERTY(int probeActive READ probeActive NOTIFY probeActiveChanged)

public:
    explicit Function(QObject *parent,
                      int id,
                      QString name,
                      Module *module,
                      int offset,
                      bool exported,
                      int calls,
                      QString probeScript) :
        QObject(parent),
        m_id(id),
        m_name(name),
        m_module(module),
        m_offset(offset),
        m_exported(exported),
        m_calls(calls),
        m_probeScript(probeScript),
        m_probeActive(false)
    {
    }

    int id() const { return m_id; }
    QString name() const { return m_name; }
    QString address() const { return QStringLiteral("0x") + QString::number(m_module->base() + m_offset, 16); }
    Module *module() const { return m_module; }
    int offset() const { return m_offset; }
    bool exported() const { return m_exported; }
    int calls() const { return m_calls; }
    QString probeScript() const { return m_probeScript; }
    bool probeActive() const { return m_probeActive; }

signals:
    void nameChanged(QString newName);
    void exportedChanged(bool newExported);
    void callsChanged(int newCalls);
    void probeScriptChanged(QString newProbeScript);
    void probeActiveChanged(bool newProbeActive);

private:
    int m_id;
    QString m_name;
    Module *m_module;
    int m_offset;
    bool m_exported;
    int m_calls;
    QString m_probeScript;
    bool m_probeActive;

    friend class Functions;
};

#endif // FUNCTIONS_H
