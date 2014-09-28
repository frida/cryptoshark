#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "tablemodel.h"

#include <QJsonObject>
#include <QSqlQuery>

class Functions : public TableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Functions)

public:
    explicit Functions(QObject *parent = 0,
                       QSqlDatabase db = QSqlDatabase());

    void updateCalls(QJsonObject summary);

private:
    QSqlQuery m_insert;
    QSqlQuery m_incrementCalls;
};

#endif // FUNCTIONS_H
