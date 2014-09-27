#include "modules.h"

#include <QJsonObject>
#include <QtSql/QSqlQuery>

Modules::Modules(QObject *parent, QSqlDatabase db) :
    QSqlTableModel(parent, db)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS modules ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL UNIQUE, "
        "path TEXT NOT NULL UNIQUE, "
        "base INTEGER NOT NULL, "
        "main INTEGER NOT NULL, "
        "calls INTEGER NOT NULL DEFAULT 0"
    ")"));
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS modules_index ON modules(name, path, calls);"));

    setTable(QStringLiteral("modules"));
    setEditStrategy(QSqlTableModel::OnManualSubmit);
    select();
}

void Modules::apply(QJsonArray updates)
{
    auto db = database();
    foreach (QJsonValue value, updates) {
        auto mod = value.toObject();
        auto name = mod[QStringLiteral("name")].toString();
        auto path = mod[QStringLiteral("path")].toString();
        auto base = mod[QStringLiteral("base")].toString();
        auto main = mod[QStringLiteral("main")].toBool();
    }

    /*
    if (tx.executeSql("SELECT 1 FROM modules WHERE name = ?", [mod.name]).rows.length === 0) {
        tx.executeSql("INSERT INTO modules (name, path, base, main) VALUES (?, ?, ?, ?)", [mod.name, mod.path, mod.base, mod.main ? 1 : 0]);
    } else {
        tx.executeSql("UPDATE modules SET path = ?, base = ? WHERE name = ?", [mod.path, mod.base, mod.name]);
    }
    */
}
