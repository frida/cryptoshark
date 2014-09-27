#include "tablemodel.h"

#include <QSqlRecord>

TableModel::TableModel(QObject *parent, QSqlDatabase db) :
    QSqlRelationalTableModel(parent, db)
{
}

QVariant TableModel::data(int i, QString roleName) const
{
    auto it = m_roleIds.find(roleName);
    if (it == m_roleIds.end())
        return QVariant();
    return data(index(i, 0), it.value());
}

QVariant TableModel::data(const QModelIndex &index, int role) const
{
    if (role < Qt::UserRole)
        return QSqlRelationalTableModel::data(index, role);

    auto row = index.row();
    if (row >= rowCount())
        return QVariant();

    auto rec = record(row);
    if (rec.isEmpty())
        return QVariant();

    auto colIndex = role - Qt::UserRole;
    if (colIndex >= m_roleNames.size())
        return QVariant();

    auto colName = m_roleNames[colIndex];
    return rec.value(colName);
}

QHash<int, QByteArray> TableModel::roleNames() const
{
    return m_rawRoleNames;
}

void TableModel::generateRoleNames()
{
    m_roleNames.clear();
    m_roleIds.clear();
    m_rawRoleNames.clear();
    auto numCols = columnCount();
    for (auto i = 0; i != numCols; i++) {
        auto id = Qt::UserRole + i;
        auto name = headerData(i, Qt::Horizontal).toString();
        m_roleNames.append(name);
        m_roleIds[name] = id;
        m_rawRoleNames[id] = name.toUtf8();
    }
}
