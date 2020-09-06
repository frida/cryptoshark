#include "modules.h"

#include <QJsonObject>

static const int IdRole = Qt::UserRole + 0;

Modules::Modules(QObject *parent, QSqlDatabase db) :
    QAbstractTableModel(parent),
    m_database(db)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS modules ( \
        id INTEGER PRIMARY KEY, \
        name TEXT NOT NULL UNIQUE, \
        path TEXT NOT NULL UNIQUE, \
        base INTEGER NOT NULL, \
        main INTEGER NOT NULL, \
        calls INTEGER NOT NULL DEFAULT 0 \
    )"));
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS modules_index ON modules(calls)"));

    QSqlQuery all(QStringLiteral("SELECT * FROM modules ORDER BY calls DESC"), db);
    all.setForwardOnly(true);
    all.exec();
    while (all.next()) {
        auto id = all.value(0).toInt();
        auto name = all.value(1).toString();
        auto path = all.value(2).toString();
        auto base = all.value(3).toULongLong();
        auto main = all.value(4).toBool();
        auto calls = all.value(5).toInt();
        auto module = new Module(this, id, name, path, base, main, calls);
        if (calls > 0)
            m_modules.append(module);
        m_moduleById[id] = module;
        m_moduleByName[name] = module;
    }

    m_roleNames[Qt::DisplayRole] = QStringLiteral("display").toUtf8();
    m_roleNames[IdRole] = QStringLiteral("id").toUtf8();

    m_insert.prepare(QStringLiteral("INSERT INTO modules (name, path, base, main) VALUES (?, ?, ?, ?)"));
    m_insert.setForwardOnly(true);
    m_update.prepare(QStringLiteral("UPDATE modules SET path = ?, base = ? WHERE id = ?"));
    m_update.setForwardOnly(true);
    m_addCalls.prepare(QStringLiteral("UPDATE modules SET calls = calls + ? WHERE id = ?"));
    m_addCalls.setForwardOnly(true);
    m_getFunctionEntries.prepare(QStringLiteral("SELECT name, offset FROM functions WHERE module = ?"));
    m_getFunctionEntries.setForwardOnly(true);
}

Module *Modules::getById(int id)
{
    return m_moduleById[id];
}

Module *Modules::getByName(QString name)
{
    return m_moduleByName[name];
}

void Modules::update(QJsonArray modules)
{
    m_database.transaction();

    foreach (QJsonValue value, modules) {
        auto data = value.toObject();
        auto name = data[QStringLiteral("name")].toString();
        auto path = data[QStringLiteral("path")].toString();
        auto base = data[QStringLiteral("base")].toString().toULongLong(nullptr, 16);
        auto main = data[QStringLiteral("main")].toBool();

        auto module = m_moduleByName[name];
        if (module != nullptr) {
            m_update.addBindValue(path);
            m_update.addBindValue(base);
            m_update.addBindValue(module->id());
            m_update.exec();
            m_update.finish();

            module->m_path = path;
            emit module->pathChanged(path);
            module->m_base = base;
            emit module->baseChanged(base);
        } else {
            m_insert.addBindValue(name);
            m_insert.addBindValue(path);
            m_insert.addBindValue(base);
            m_insert.addBindValue(main);
            m_insert.exec();
            auto id = m_insert.lastInsertId().toInt();
            m_insert.finish();

            module = new Module(this, id, name, path, base, main, 0);
            m_moduleById[id] = module;
            m_moduleByName[name] = module;
        }

        emit synchronized(module);
    }

    m_database.commit();
}

void Modules::addCalls(QHash<int, int> calls)
{
    auto i = calls.constBegin();
    auto e = calls.constEnd();
    QModelIndex noParent;
    for (; i != e; ++i) {
        auto id = i.key();
        auto count = i.value();
        m_addCalls.addBindValue(count);
        m_addCalls.addBindValue(id);
        m_addCalls.exec();
        m_addCalls.finish();

        auto module = m_moduleById[id];
        auto alreadyInserted = module->m_calls > 0;
        module->m_calls += count;
        emit module->callsChanged(module->m_calls);

        if (alreadyInserted) {
            auto row = m_modules.indexOf(module);
            auto i = index(row, 1);
            QVector<int> roles;
            roles << Qt::DisplayRole;
            emit dataChanged(i, i, roles);
        } else {
            auto row = m_modules.size();
            beginInsertRows(noParent, row, row);
            m_modules.append(module);
            endInsertRows();
        }
    }

    sortByCallsDescending();
}

static bool descendingLessThanByCalls(const QPair<Module *, int> &m1, const QPair<Module *, int> &m2)
{
    return m1.first->calls() > m2.first->calls();
}

void Modules::sortByCallsDescending()
{
    QList<QPersistentModelIndex> allParents;
    emit layoutAboutToBeChanged(allParents, VerticalSortHint);

    QList<QPair<Module *, int>> modules;
    for (int i = 0; i != m_modules.count(); i++)
        modules.append(QPair<Module *, int>(m_modules.at(i), i));

    std::sort(modules.begin(), modules.end(), descendingLessThanByCalls);

    m_modules.clear();
    QVector<int> forwarding(modules.count());
    for (int i = 0; i != modules.count(); i++) {
        m_modules.append(modules.at(i).first);
        forwarding[modules.at(i).second] = i;
    }

    QModelIndexList oldList = persistentIndexList();
    QModelIndexList newList;
    for (int i = 0; i != oldList.count(); i++)
        newList.append(index(forwarding.at(oldList.at(i).row()), 0));
    changePersistentIndexList(oldList, newList);

    emit layoutChanged(allParents, VerticalSortHint);
}

QVariant Modules::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(orientation);

    if (role != Qt::DisplayRole)
        return QVariant();

    return (section == 0) ? QStringLiteral("Name") : QStringLiteral("Calls");
}

QVariant Modules::data(const QModelIndex &index, QString roleName) const
{
    return data(index, m_roleNames.key(roleName.toUtf8()));
}

QVariant Modules::data(const QModelIndex &index, int role) const
{
    auto row = index.row();
    if (row < 0 || row >= m_modules.size())
        return QVariant();
    auto module = m_modules[row];

    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case 0:
            return module->m_name;
        case 1:
            return module->m_calls;
        }
        break;
    case IdRole:
        return module->m_id;
    }

    return QVariant();
}

void Module::enumerateFunctionEntries(std::function<void (QString, quint64)> f)
{
    QSqlQuery &query = reinterpret_cast<Modules *>(parent())->m_getFunctionEntries;
    query.addBindValue(m_id);
    query.exec();
    while (query.next()) {
        QString name = query.value(0).toString();
        int offset = query.value(1).toInt();
        quint64 address = m_base + offset;
        f(name, address);
    }
    query.finish();
}
