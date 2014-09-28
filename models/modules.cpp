#include "modules.h"

#include <QJsonObject>

Modules::Modules(QObject *parent, QSqlDatabase db) :
    TableModel(parent, db)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS modules ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL UNIQUE, "
        "path TEXT NOT NULL UNIQUE, "
        "base INTEGER NOT NULL, "
        "main INTEGER NOT NULL, "
        "calls INTEGER NOT NULL DEFAULT 0"
    ")"));
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS modules_index ON modules(name, path, calls)"));

    setTable(QStringLiteral("modules"));
    setFilter(QStringLiteral("calls > 0"));
    setSort(5, Qt::SortOrder::DescendingOrder);
    setEditStrategy(QSqlTableModel::OnManualSubmit);
    select();
    generateRoleNames();

    m_insert.prepare(QStringLiteral("INSERT INTO modules (name, path, base, main) VALUES (?, ?, ?, ?)"));
    m_update.prepare(QStringLiteral("UPDATE modules SET path = ?, base = ? WHERE name = ?"));
    m_idFromName.prepare(QStringLiteral("SELECT id FROM modules WHERE name = ?"));
}

int Modules::getId(QString name)
{
    m_idFromName.addBindValue(name);
    m_idFromName.exec();
    m_idFromName.next();
    auto id = m_idFromName.value(0).toInt();
    m_idFromName.finish();
    return id;
}

void Modules::update(QJsonArray modules)
{
    auto db = database();

    foreach (QJsonValue value, modules) {
        auto mod = value.toObject();
        auto name = mod[QStringLiteral("name")].toString();
        auto path = mod[QStringLiteral("path")].toString();
        auto base = mod[QStringLiteral("base")].toString();
        auto main = mod[QStringLiteral("main")].toBool();
        m_update.addBindValue(path);
        m_update.addBindValue(base);
        m_update.addBindValue(name);
        m_update.exec();
        if (m_update.numRowsAffected() == 0) {
            m_insert.addBindValue(name);
            m_insert.addBindValue(path);
            m_insert.addBindValue(base);
            m_insert.addBindValue(main);
            m_insert.exec();
            m_insert.finish();
        }
        m_update.finish();
    }

    select();
}
