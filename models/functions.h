#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "modules.h"
#include "tablemodel.h"

#include <QJsonObject>
#include <QRegExp>
#include <QSet>
#include <QSqlQuery>

class Functions : public TableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Functions)

public:
    explicit Functions(QObject *parent = 0,
                       QSqlDatabase db = QSqlDatabase());

    Q_INVOKABLE void load(int moduleId);
    void addCalls(QJsonObject summary);

private:
    void importModuleExports(QList<int> moduleIds);
    static QString functionName(Module *module, int offset);
    static QString functionPrefix(Module *module);

    int m_currentModuleId;
    QSet<int> m_importedModules;
    QSqlQuery m_insert;
    QSqlQuery m_addCalls;
    QSqlQuery m_checkImportNeeded;
    QSqlQuery m_updateToExported;
    static QRegExp s_ignoredPrefixCharacters;
};

#endif // FUNCTIONS_H
