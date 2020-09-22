#ifndef BLOCKS_H
#define BLOCKS_H

#include <QHash>
#include <QSqlQuery>
#include <QSqlQueryModel>

class Blocks : public QSqlQueryModel
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(Blocks)

public:
    explicit Blocks(QObject *parent = 0,
                    QSqlDatabase db = QSqlDatabase());

    void addCoverage(QJsonArray blocks);
    bool updateName(int blockId, QString name);

    Q_INVOKABLE void symbolicate();

private:
    void resetQuery();

    QSqlDatabase m_database;
    QSqlQuery m_getByLocation;
    QSqlQuery m_getAddresses;
    QSqlQuery m_insert;
    QSqlQuery m_updateName;
};

#endif // BLOCKS_H
