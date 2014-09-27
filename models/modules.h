#ifndef MODULES_H
#define MODULES_H

#include <QJsonArray>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlTableModel>

class Modules : public QSqlTableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Modules)

public:
    explicit Modules(QObject *parent = 0, QSqlDatabase db = QSqlDatabase());

    void apply(QJsonArray updates);
};

#endif // MODULES_H
