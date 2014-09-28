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

    int getId(QString name);
    void update(QJsonArray modules);

private:
    QSqlQuery m_insert;
    QSqlQuery m_update;
    QSqlQuery m_idFromName;
};

#endif // MODULES_H
