#ifndef MODULES_H
#define MODULES_H

#include "tablemodel.h"

#include <QJsonArray>
#include <QSqlQuery>

class Modules : public TableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Modules)

public:
    explicit Modules(QObject *parent = 0,
                     QSqlDatabase db = QSqlDatabase());

    void apply(QJsonArray updates);

private:
    QSqlQuery m_insert;
    QSqlQuery m_update;
};

#endif // MODULES_H
