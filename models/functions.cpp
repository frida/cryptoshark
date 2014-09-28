#include "functions.h"

#include "models.h"

QRegExp Functions::s_ignoredPrefixCharacters = QRegExp(QStringLiteral("(^lib)|([-_])|(\\.[\\w.]+$)"));

Functions::Functions(QObject *parent, QSqlDatabase db) :
    TableModel(parent, db),
    m_currentModuleId(-1)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS functions ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL UNIQUE, "
        "module INTEGER, "
        "offset INTEGER NOT NULL, "
        "exported INTEGER NOT NULL DEFAULT 0, "
        "calls INTEGER NOT NULL DEFAULT 0, "
        "probe_script TEXT, "
        "FOREIGN KEY(module) REFERENCES modules(id)"
    ")"));
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS functions_index ON functions(module, offset, calls, exported)"));

    setTable(QStringLiteral("functions"));
    setFilter(QStringLiteral("module == -1"));
    setSort(5, Qt::SortOrder::DescendingOrder);
    setEditStrategy(QSqlTableModel::OnManualSubmit);
    select();
    generateRoleNames();

    m_insert.prepare(QStringLiteral("INSERT INTO functions (name, module, offset, exported, calls) VALUES (?, ?, ?, ?, ?)"));
    m_addCalls.prepare(QStringLiteral("UPDATE functions SET calls = calls + ? WHERE module = ? AND offset = ?"));
}

void Functions::load(int moduleId)
{
    m_currentModuleId = moduleId;
    setFilter(QStringLiteral("module == ") + QString::number(moduleId));
    select();
}

void Functions::addCalls(QJsonObject summary)
{
    auto modules = Models::instance()->modules();
    QHash<int, int> moduleCalls;

    auto db = database();
    db.transaction();

    auto it = summary.constBegin();
    auto end = summary.constEnd();
    while (it != end) {
        auto entry = it.value().toObject();
        auto symbolValue = entry[QStringLiteral("symbol")];
        if (!symbolValue.isUndefined()) {
            auto symbol = symbolValue.toObject();
            auto moduleName = symbol[QStringLiteral("module")].toString();
            auto count = entry[QStringLiteral("count")].toInt();
            Module *module = modules->getByName(moduleName);
            auto moduleId = module->id();
            auto offset = symbol[QStringLiteral("offset")].toInt();
            m_addCalls.addBindValue(count);
            m_addCalls.addBindValue(moduleId);
            m_addCalls.addBindValue(offset);
            m_addCalls.exec();
            if (m_addCalls.numRowsAffected() == 0) {
                m_insert.addBindValue(functionName(module, offset));
                m_insert.addBindValue(moduleId);
                m_insert.addBindValue(offset);
                m_insert.addBindValue(false);
                m_insert.addBindValue(count);
                m_insert.exec();
                m_insert.finish();
            }
            m_addCalls.finish();

            moduleCalls[moduleId] += count;
        }
        ++it;
    }

    modules->addCalls(moduleCalls);

    db.commit();

    modules->select();
    select();
}

QString Functions::functionName(Module *module, int offset)
{
    return functionPrefix(module) + QStringLiteral("_") + QString::number(offset, 16);
}

QString Functions::functionPrefix(Module *module)
{
    if (module->main()) {
        return QStringLiteral("sub");
    } else {
        QString prefix = module->name().toLower();
        return prefix.remove(s_ignoredPrefixCharacters);
    }
}
