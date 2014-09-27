#include "functions.h"

#include <QtSql/QSqlQuery>

Functions::Functions(QObject *parent, QSqlDatabase db) :
    QSqlTableModel(parent, db)
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
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS functions_index ON functions(module, calls, exported);"));

    setTable(QStringLiteral("functions"));
    setEditStrategy(QSqlTableModel::OnManualSubmit);
    select();
}
