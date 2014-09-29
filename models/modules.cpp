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

    m_getById.prepare(QStringLiteral("SELECT name, path, base, main FROM modules WHERE id = ?"));
    m_getByName.prepare(QStringLiteral("SELECT id, name, path, base, main FROM modules WHERE name = ?"));
    m_insert.prepare(QStringLiteral("INSERT INTO modules (name, path, base, main) VALUES (?, ?, ?, ?)"));
    m_update.prepare(QStringLiteral("UPDATE modules SET path = ?, base = ? WHERE name = ?"));
    m_addCalls.prepare(QStringLiteral("UPDATE modules SET calls = calls + ? WHERE id = ?"));
}

Module *Modules::getById(int id)
{
    Module *module;
    auto it = m_moduleById.find(id);
    if (it != m_moduleById.end()) {
        module = it.value();
    } else {
        m_getById.addBindValue(id);
        m_getById.exec();
        if (m_getById.next()) {
            auto name = m_getById.value(0).toString();
            module = new Module(this,
                                id,
                                name,
                                m_getById.value(1).toString(),
                                m_getById.value(2).toULongLong(),
                                m_getById.value(3).toBool());
            m_moduleById[id] = module;
            m_moduleByName[name] = module;
        } else {
            module = nullptr;
        }
        m_getByName.finish();
    }
    return module;
}

Module *Modules::getByName(QString name)
{
    Module *module;
    auto it = m_moduleByName.find(name);
    if (it != m_moduleByName.end()) {
        module = it.value();
    } else {
        m_getByName.addBindValue(name);
        m_getByName.exec();
        if (m_getByName.next()) {
            auto id = m_getByName.value(0).toInt();
            module = new Module(this,
                                id,
                                m_getByName.value(1).toString(),
                                m_getByName.value(2).toString(),
                                m_getByName.value(3).toULongLong(),
                                m_getByName.value(4).toBool());
            m_moduleById[id] = module;
            m_moduleByName[name] = module;
        } else {
            module = nullptr;
        }
        m_getByName.finish();
    }
    return module;
}

void Modules::update(QJsonArray modules)
{
    auto db = database();
    db.transaction();

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

    db.commit();

    foreach (auto module, m_moduleById.values()) {
        delete module;
    }
    m_moduleById.clear();
    m_moduleByName.clear();

    select();
}

void Modules::addCalls(QHash<int, int> calls)
{
    auto it = calls.constBegin();
    while (it != calls.constEnd()) {
        auto id = it.key();
        auto count = it.value();
        m_addCalls.addBindValue(count);
        m_addCalls.addBindValue(id);
        m_addCalls.exec();
        m_addCalls.finish();
        ++it;
    }
}
