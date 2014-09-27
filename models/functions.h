#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlTableModel>

class Functions : public QSqlTableModel
{
    Q_OBJECT
    Q_DISABLE_COPY(Functions)

public:
    explicit Functions(QObject *parent = 0, QSqlDatabase db = QSqlDatabase());
};

#endif // FUNCTIONS_H
