#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "tablemodel.h"

class Functions : public TableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Functions)

public:
    explicit Functions(QObject *parent = 0,
                       QSqlDatabase db = QSqlDatabase());
};

#endif // FUNCTIONS_H
