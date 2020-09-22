#ifndef BLOCKS_H
#define BLOCKS_H

#include <QJsonArray>
#include <QJsonObject>
#include <QSqlQuery>
#include <QSqlQueryModel>

class Function;
class Module;

class Blocks : public QSqlQueryModel
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(Blocks)

public:
    explicit Blocks(QObject *parent = 0,
                    QSqlDatabase db = QSqlDatabase());

    void addCoverage(QJsonArray blocks);
    bool updateName(int blockId, QString name);

    Q_INVOKABLE Function *findNearestFunction(int blockId);
    Q_INVOKABLE QJsonObject resolveBlockAddresses(QJsonArray addresses, Module *module);
    Q_INVOKABLE void symbolicate();

private:
    void resetQuery();

    QSqlDatabase m_database;
    QSqlQuery m_getByLocation;
    QSqlQuery m_getUnnamed;
    QSqlQuery m_getNearest;
    QSqlQuery m_insert;
    QSqlQuery m_updateName;
};

#endif // BLOCKS_H
