#ifndef TABLEMODEL_H
#define TABLEMODEL_H

#include <QHash>
#include <QSqlRelationalTableModel>
#include <QVector>

class TableModel : public QSqlRelationalTableModel
{
    Q_OBJECT

public:
    explicit TableModel(QObject *parent = 0,
                        QSqlDatabase db = QSqlDatabase());

    Q_INVOKABLE QVariant data(int i, QString roleName) const;
    Q_INVOKABLE QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QHash<int, QByteArray> roleNames() const;

protected:
    void generateRoleNames();

private:
    QVector<QString> m_roleNames;
    QHash<QString, int> m_roleIds;
    QHash<int, QByteArray> m_rawRoleNames;
};

#endif // TABLEMODEL_H
