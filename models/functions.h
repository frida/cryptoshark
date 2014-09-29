#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "modules.h"
#include "tablemodel.h"

#include <QJsonObject>
#include <QRegExp>
#include <QSet>
#include <QSqlQuery>

class Function;

class Functions : public TableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Functions)

public:
    explicit Functions(QObject *parent = 0,
                       QSqlDatabase db = QSqlDatabase());

    Q_INVOKABLE void load(int moduleId);

    Q_INVOKABLE bool updateName(int functionId, QString name);

    Q_INVOKABLE bool hasProbe(int functionId) const;
    Q_INVOKABLE void addProbe(int functionId);
    Q_INVOKABLE void removeProbe(int functionId);
    Q_INVOKABLE void updateProbe(int functionId, QString script);

    Function *getById(int id);
    void addCalls(QJsonObject summary);
    void addLogMessage(int functionId, QString message);

    Q_INVOKABLE QVariant data(int i, QString roleName) const;
    Q_INVOKABLE QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QHash<int, QByteArray> roleNames() const;

signals:
    void logMessage(Function *function, QString message);

private:
    void importModuleExports(QList<int> moduleIds);
    static QString functionName(Module *module, int offset);
    static QString functionPrefix(Module *module);

    int m_currentModuleId;
    QSet<int> m_probes;
    QSet<int> m_importedModules;
    QSqlQuery m_getById;
    QSqlQuery m_insert;
    QSqlQuery m_addCalls;
    QSqlQuery m_updateName;
    QSqlQuery m_updateProbeScript;
    QSqlQuery m_checkImportNeeded;
    QSqlQuery m_updateToExported;
    static QRegExp s_ignoredPrefixCharacters;
};

class Function : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Function)

    Q_PROPERTY(int id READ id CONSTANT)
    Q_PROPERTY(QString name READ name CONSTANT)
    Q_PROPERTY(QString address READ address CONSTANT)
    Q_PROPERTY(Module *module READ module CONSTANT)
    Q_PROPERTY(int offset READ offset CONSTANT)
    Q_PROPERTY(bool exported READ exported CONSTANT)
    Q_PROPERTY(QString probeScript READ probeScript CONSTANT)

public:
    explicit Function(QObject *parent,
                      int id,
                      QString name,
                      Module *module,
                      int offset,
                      bool exported,
                      QString probeScript) :
        QObject(parent),
        m_id(id),
        m_name(name),
        m_module(module),
        m_offset(offset),
        m_exported(exported),
        m_probeScript(probeScript)
    {
    }

    int id() const { return m_id; }
    QString name() const { return m_name; }
    QString address() const { return QStringLiteral("0x") + QString::number(m_module->base() + m_offset, 16); }
    Module *module() const { return m_module; }
    int offset() const { return m_offset; }
    bool exported() const { return m_exported; }
    QString probeScript() const { return m_probeScript; }

private:
    int m_id;
    QString m_name;
    Module *m_module;
    int m_offset;
    bool m_exported;
    QString m_probeScript;
};

#endif // FUNCTIONS_H
