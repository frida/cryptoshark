#include "modules.h"

#include <QJsonObject>

static const int IdRole = Qt::UserRole + 0;
static const int NameRole = Qt::UserRole + 1;
static const int PathRole = Qt::UserRole + 2;
static const int BaseRole = Qt::UserRole + 3;
static const int MainRole = Qt::UserRole + 4;
static const int CallsRole = Qt::UserRole + 5;

Modules::Modules(QObject *parent, QSqlDatabase db) :
    QAbstractListModel(parent),
    m_database(db)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS modules ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL UNIQUE, "
        "path TEXT NOT NULL UNIQUE, "
        "base INTEGER NOT NULL, "
        "main INTEGER NOT NULL, "
        "calls INTEGER NOT NULL DEFAULT 0"
    ")"));
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

    m_roleNames[IdRole] = QStringLiteral("id").toUtf8();
    m_roleNames[NameRole] = QStringLiteral("name").toUtf8();
    m_roleNames[PathRole] = QStringLiteral("path").toUtf8();
    m_roleNames[BaseRole] = QStringLiteral("base").toUtf8();
    m_roleNames[MainRole] = QStringLiteral("main").toUtf8();
    m_roleNames[CallsRole] = QStringLiteral("calls").toUtf8();

    m_insert.prepare(QStringLiteral("INSERT INTO modules (name, path, base, main) VALUES (?, ?, ?, ?)"));
    m_insert.setForwardOnly(true);
    m_update.prepare(QStringLiteral("UPDATE modules SET path = ?, base = ? WHERE id = ?"));
    m_update.setForwardOnly(true);
    m_addCalls.prepare(QStringLiteral("UPDATE modules SET calls = calls + ? WHERE id = ?"));
    m_addCalls.setForwardOnly(true);
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

            bool notifyView = module->calls() > 0;

            module->m_path = path;
            emit module->pathChanged(path);
            module->m_base = base;
            emit module->baseChanged(base);

            if (notifyView) {
                auto i = createIndex(m_modules.indexOf(module), 1);
                QVector<int> roles;
                roles << PathRole;
                roles << BaseRole;
                emit dataChanged(i, i, roles);
            }
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
    }

    m_database.commit();
}

void Modules::addCalls(QHash<int, int> calls)
{
    QModelIndex noParent;

    auto i = calls.constBegin();
    auto e = calls.constEnd();
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
            auto oldRow = m_modules.indexOf(module);
            auto newRow = sortedRowOffset(module, oldRow);

            emit headerDataChanged(Qt::Vertical, oldRow, oldRow);
            auto i = createIndex(oldRow, 0);
            QVector<int> roles;
            roles << CallsRole;
            emit dataChanged(i, i, roles);

            if (newRow != oldRow) {
                beginMoveRows(noParent, oldRow, oldRow, noParent, newRow);
                m_modules.move(oldRow, newRow > oldRow ? newRow - 1 : newRow);
                endMoveRows();
            }
        } else {
            auto row = sortedRowOffset(module, m_modules.size());
            beginInsertRows(noParent, row, row);
            m_modules.insert(row, module);
            endInsertRows();
        }
    }
}

int Modules::sortedRowOffset(Module *module, int currentIndex)
{
    int calls = module->m_calls;
    for (int i = currentIndex - 1; i >= 0; i--) {
        if (m_modules[i]->m_calls > calls)
            return i + 1;
    }
    return 0;
}

int Modules::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return m_modules.size();
}

QVariant Modules::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(section);
    Q_UNUSED(orientation);

    switch (role) {
    case Qt::DisplayRole:
        return QStringLiteral("Name");
    case IdRole:
        return QStringLiteral("Id");
    case NameRole:
        return QStringLiteral("Name");
    case PathRole:
        return QStringLiteral("Path");
    case BaseRole:
        return QStringLiteral("Base");
    case MainRole:
        return QStringLiteral("Main");
    case CallsRole:
        return QStringLiteral("Calls");
    default:
        return QVariant();
    }
}

QVariant Modules::data(int i, QString roleName) const
{
    return data(createIndex(i, 0), m_roleNames.key(roleName.toUtf8()));
}

QVariant Modules::data(const QModelIndex &index, int role) const
{
    auto row = index.row();
    if (row < 0 || row >= m_modules.size())
        return QVariant();
    auto module = m_modules[row];

    switch (role) {
    case Qt::DisplayRole:
        return module->m_name;
    case IdRole:
        return module->m_id;
    case NameRole:
        return module->m_name;
    case PathRole:
        return module->m_path;
    case BaseRole:
        return module->m_base;
    case MainRole:
        return module->m_main;
    case CallsRole:
        return module->m_calls;
    default:
        return QVariant();
    }
}
