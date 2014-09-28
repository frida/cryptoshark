#include "functions.h"

#include "models.h"

#include <QSqlQuery>

Functions::Functions(QObject *parent, QSqlDatabase db) :
    TableModel(parent, db)
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
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS functions_index ON functions(module, calls, exported)"));

    setTable(QStringLiteral("functions"));
    setEditStrategy(QSqlTableModel::OnManualSubmit);
    select();
    generateRoleNames();

    m_insert.prepare(QStringLiteral("INSERT INTO functions (name, module, offset, exported, calls) VALUES (?, ?, ?, ?, ?)"));
    m_incrementCalls.prepare(QStringLiteral("UPDATE functions SET calls = calls + ? WHERE module = ? AND offset = ?"));
}

void Functions::updateCalls(QJsonObject summary)
{
    auto modules = Models::instance()->modules();

    auto it = summary.constBegin();
    auto end = summary.constEnd();
    while (it != end) {
        auto entry = it.value().toObject();
        auto symbolValue = entry[QStringLiteral("symbol")];
        if (!symbolValue.isUndefined()) {
            auto symbol = symbolValue.toObject();
            auto moduleName = symbol[QStringLiteral("module")].toString();
            auto count = entry[QStringLiteral("count")].toInt();
            int moduleId = modules->getId(moduleName);
            auto offset = symbol[QStringLiteral("offset")].toInt();
            m_incrementCalls.addBindValue(count);
            m_incrementCalls.addBindValue(moduleId);
            m_incrementCalls.addBindValue(offset);
            m_incrementCalls.exec();
            if (m_incrementCalls.numRowsAffected() == 0) {
                m_insert.addBindValue(QStringLiteral("sub_FIXME"));
                m_insert.addBindValue(moduleId);
                m_insert.addBindValue(offset);
                m_insert.addBindValue(false);
                m_insert.addBindValue(count);
                m_insert.exec();
                m_insert.finish();
            }
            m_incrementCalls.finish();
        }
        ++it;
    }
}
