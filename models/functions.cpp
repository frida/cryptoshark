#include "functions.h"

#include "models.h"
#include "router.h"

static const int IdRole = Qt::UserRole + 0;
static const int NameRole = Qt::UserRole + 1;
static const int ModuleRole = Qt::UserRole + 2;
static const int OffsetRole = Qt::UserRole + 3;
static const int ExportedRole = Qt::UserRole + 4;
static const int CallsRole = Qt::UserRole + 5;
static const int ProbeScriptRole = Qt::UserRole + 6;
static const int StatusRole = Qt::UserRole + 16;

QRegExp Functions::s_ignoredPrefixCharacters = QRegExp(QStringLiteral("(^lib)|([-_])|(\\.[\\w.]+$)"));

Functions::Functions(QObject *parent, QSqlDatabase db) :
    QAbstractListModel(parent),
    m_currentModuleId(-1),
    m_database(db)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS functions ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL UNIQUE, "
        "module INTEGER, "
        "offset INTEGER NOT NULL, "
        "exported INTEGER NOT NULL DEFAULT 0, "
        "calls INTEGER NOT NULL DEFAULT 0, "
        "probe_script TEXT NOT NULL DEFAULT 'log(args[0], args[1], args[2], args[3]);', "
        "FOREIGN KEY(module) REFERENCES modules(id)"
    ")"));
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS functions_index ON functions(module, offset, calls, exported)"));

    m_roleNames[IdRole] = QStringLiteral("id").toUtf8();
    m_roleNames[NameRole] = QStringLiteral("name").toUtf8();
    m_roleNames[ModuleRole] = QStringLiteral("module").toUtf8();
    m_roleNames[OffsetRole] = QStringLiteral("offset").toUtf8();
    m_roleNames[ExportedRole] = QStringLiteral("exported").toUtf8();
    m_roleNames[CallsRole] = QStringLiteral("calls").toUtf8();
    m_roleNames[ProbeScriptRole] = QStringLiteral("probeScript").toUtf8();
    m_roleNames[StatusRole] = QStringLiteral("status").toUtf8();

    m_getAll.prepare(QStringLiteral("SELECT * FROM functions WHERE module = ? AND calls > 0 ORDER BY calls DESC"));
    m_getAll.setForwardOnly(true);
    m_getById.prepare(QStringLiteral("SELECT * FROM functions WHERE id = ?"));
    m_getById.setForwardOnly(true);
    m_getBySymbol.prepare(QStringLiteral("SELECT id FROM functions WHERE module = ? AND offset = ? LIMIT 1"));
    m_getBySymbol.setForwardOnly(true);
    m_insert.prepare(QStringLiteral("INSERT INTO functions (name, module, offset, exported) VALUES (?, ?, ?, ?)"));
    m_insert.setForwardOnly(true);
    m_updateName.prepare(QStringLiteral("UPDATE functions SET name = ? WHERE id = ?"));
    m_updateName.setForwardOnly(true);
    m_updateCalls.prepare(QStringLiteral("UPDATE functions SET calls = ? WHERE id = ?"));
    m_updateCalls.setForwardOnly(true);
    m_updateProbeScript.prepare(QStringLiteral("UPDATE functions SET probe_script to ? WHERE id = ?"));
    m_updateProbeScript.setForwardOnly(true);
    m_checkImportNeeded.prepare(QStringLiteral("SELECT 1 FROM functions WHERE module = ? AND exported = 1 LIMIT 1"));
    m_checkImportNeeded.setForwardOnly(true);
    m_updateToExported.prepare(QStringLiteral("UPDATE functions SET name = ?, exported = 1 WHERE id = ?"));
    m_updateToExported.setForwardOnly(true);
}

void Functions::load(int moduleId)
{
    beginResetModel();

    m_currentModuleId = moduleId;

    m_getAll.addBindValue(moduleId);
    m_getAll.exec();
    m_functions.clear();
    while (m_getAll.next()) {
        auto id = m_getAll.value(0).toInt();
        Function *function = m_functionById[id];
        if (function == nullptr) {
            function = createFunctionFromQuery(m_getAll);
            m_functionById[id] = function;
        }
        m_functions.append(function);
    }
    m_getAll.finish();

    endResetModel();
}

Function *Functions::getById(int id)
{
    Function *function = m_functionById[id];
    if (function == nullptr) {
        m_getById.addBindValue(id);
        m_getById.exec();
        if (m_getById.next()) {
            function = createFunctionFromQuery(m_getById);
            m_functionById[id] = function;
        }
        m_getById.finish();
    }
    return function;
}

bool Functions::updateName(int functionId, QString name)
{
    m_updateName.addBindValue(name);
    m_updateName.addBindValue(functionId);
    bool success = m_updateName.exec();
    if (success) {
        auto function = getById(functionId);

        function->m_name = name;
        emit function->nameChanged(name);

        notifyRowChange(function, NameRole);
    }
    m_updateName.finish();
    return success;
}

bool Functions::hasProbe(int functionId)
{
    auto function = getById(functionId);
    if (function == nullptr)
        return false;
    return function->probeActive();
}

void Functions::addProbe(int functionId)
{
    auto function = getById(functionId);
    if (function == nullptr)
        return;

    function->m_probeActive = true;
    emit function->probeActiveChanged(true);

    notifyRowChange(function, StatusRole);

    QJsonObject payload;
    payload[QStringLiteral("id")] = function->id();
    payload[QStringLiteral("address")] = function->address();
    payload[QStringLiteral("script")] = function->probeScript();
    Router::instance()->request(QStringLiteral("function:add-probe"), payload);
}

void Functions::removeProbe(int functionId)
{
    auto function = getById(functionId);
    if (function == nullptr)
        return;

    function->m_probeActive = false;
    emit function->probeActiveChanged(false);

    notifyRowChange(function, StatusRole);

    QJsonObject payload;
    payload[QStringLiteral("address")] = function->address();
    Router::instance()->request(QStringLiteral("function:remove-probe"), payload);
}

void Functions::updateProbe(int functionId, QString script)
{
    m_updateProbeScript.addBindValue(script);
    m_updateProbeScript.addBindValue(functionId);
    bool success = m_updateProbeScript.exec();
    m_updateProbeScript.finish();
    if (!success)
        return;

    auto function = getById(functionId);
    function->m_probeScript = script;
    emit function->probeScriptChanged(script);

    notifyRowChange(function, ProbeScriptRole);

    if (function->m_probeActive) {
        QJsonObject payload;
        payload[QStringLiteral("address")] = function->address();
        payload[QStringLiteral("script")] = function->probeScript();
        Router::instance()->request(QStringLiteral("function:update-probe"), payload);
    }
}

void Functions::addCalls(QJsonObject summary)
{
    auto modules = Models::instance()->modules();
    QHash<int, int> moduleCalls;

    m_database.transaction();

    QModelIndex noParent;

    auto i = summary.constBegin();
    auto e = summary.constEnd();
    for (; i != e; ++i) {
        auto entry = i.value().toObject();
        auto symbolValue = entry[QStringLiteral("symbol")];
        if (!symbolValue.isNull()) {
            auto symbol = symbolValue.toObject();
            auto moduleName = symbol[QStringLiteral("module")].toString();
            auto offset = symbol[QStringLiteral("offset")].toInt();
            auto count = entry[QStringLiteral("count")].toInt();

            auto symbolKey = moduleName + offset;
            auto function = m_functionBySymbol[symbolKey];
            if (function == nullptr) {
                Module *module = modules->getByName(moduleName);
                auto moduleId = module->id();
                m_getBySymbol.addBindValue(moduleId);
                m_getBySymbol.addBindValue(offset);
                m_getBySymbol.exec();
                if (m_getBySymbol.next()) {
                    function = getById(m_getBySymbol.value(0).toInt());
                } else {
                    auto name = functionName(module, offset);
                    bool exported = false;
                    m_insert.addBindValue(name);
                    m_insert.addBindValue(moduleId);
                    m_insert.addBindValue(offset);
                    m_insert.addBindValue(exported);
                    m_insert.exec();
                    auto id = m_insert.lastInsertId().toInt();
                    m_insert.finish();

                    function = getById(id);
                }
                m_getBySymbol.finish();

                m_functionBySymbol[symbolKey] = function;
            }

            auto calls = function->m_calls + count;

            m_updateCalls.addBindValue(calls);
            m_updateCalls.addBindValue(function->m_id);
            m_updateCalls.exec();
            m_updateCalls.finish();

            function->m_calls = calls;
            emit function->callsChanged(calls);

            if (function->module()->id() == m_currentModuleId) {
                auto oldRow = m_functions.indexOf(function);
                if (oldRow != -1) {
                    auto newRow = sortedRowOffset(function, oldRow);

                    emit headerDataChanged(Qt::Vertical, oldRow, oldRow);
                    auto i = createIndex(oldRow, 0);
                    QVector<int> roles;
                    roles << CallsRole;
                    emit dataChanged(i, i, roles);

                    if (newRow != oldRow) {
                        beginMoveRows(noParent, oldRow, oldRow, noParent, newRow);
                        m_functions.move(oldRow, oldRow < newRow ? newRow - 1 : newRow);
                        endMoveRows();
                    }
                } else {
                    auto row = sortedRowOffset(function, m_functions.size());
                    beginInsertRows(noParent, row, row);
                    m_functions.insert(row, function);
                    endInsertRows();
                }
            }

            moduleCalls[function->module()->id()] += count;
        }
    }

    modules->addCalls(moduleCalls);

    m_database.commit();

    importModuleExports(moduleCalls.keys());
}

int Functions::sortedRowOffset(Function *function, int currentIndex)
{
    int calls = function->m_calls;
    for (int i = currentIndex - 1; i >= 0; i--) {
        if (m_functions[i]->m_calls > calls)
            return i + 1;
    }
    return 0;
}

int Functions::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return m_functions.size();
}

QVariant Functions::headerData(int section, Qt::Orientation orientation, int role) const
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
    case ModuleRole:
        return QStringLiteral("Module");
    case OffsetRole:
        return QStringLiteral("Offset");
    case ExportedRole:
        return QStringLiteral("Exported");
    case CallsRole:
        return QStringLiteral("Calls");
    case ProbeScriptRole:
        return QStringLiteral("Probe Script");
    case StatusRole:
        return QStringLiteral("Status");
    default:
        return QVariant();
    }
}

QVariant Functions::data(int i, QString roleName) const
{
    return data(createIndex(i, 0), m_roleNames.key(roleName.toUtf8()));
}

QVariant Functions::data(const QModelIndex &index, int role) const
{
    auto row = index.row();
    if (row < 0 || row >= m_functions.size())
        return QVariant();
    auto function = m_functions[row];

    switch (role) {
    case Qt::DisplayRole:
        return function->m_name;
    case IdRole:
        return function->m_id;
    case NameRole:
        return function->m_name;
    case ModuleRole:
        return function->m_module->id();
    case OffsetRole:
        return function->m_offset;
    case ExportedRole:
        return function->m_exported;
    case CallsRole:
        return function->m_calls;
    case ProbeScriptRole:
        return function->m_probeScript;
    case StatusRole:
        return function->m_probeActive ? QStringLiteral("P") : QStringLiteral("");
    default:
        return QVariant();
    }
}

void Functions::addLogMessage(int functionId, QString message)
{
    auto function = getById(functionId);
    emit logMessage(function, message);
}

void Functions::importModuleExports(QList<int> moduleIds)
{
    auto modules = Models::instance()->modules();
    auto router = Router::instance();
    foreach (auto moduleId, QSet<int>::fromList(moduleIds).subtract(m_importedModules)) {
        m_checkImportNeeded.addBindValue(moduleId);
        m_checkImportNeeded.exec();
        bool importNeeded = m_checkImportNeeded.next() == false;
        m_checkImportNeeded.finish();

        m_importedModules += moduleId;

        if (importNeeded) {
            QJsonObject payload;
            payload[QStringLiteral("name")] = modules->getById(moduleId)->name();
            auto request = router->request(QStringLiteral("module:get-functions"), payload);
            QObject::connect(request, &Request::completed, [=] (QJsonValue result) {
                m_database.transaction();

                auto functions = result.toArray();
                foreach (auto funcValue, functions) {
                    auto func = funcValue.toArray();
                    auto name = func.at(0).toString();
                    auto offset = func.at(1).toInt();

                    m_getBySymbol.addBindValue(moduleId);
                    m_getBySymbol.addBindValue(offset);
                    m_getBySymbol.exec();
                    if (m_getBySymbol.next()) {
                        auto functionId = m_getBySymbol.value(0).toInt();
                        auto function = getById(functionId);

                        auto newName = name;
                        m_updateToExported.addBindValue(newName);
                        m_updateToExported.addBindValue(functionId);
                        int retry = 2;
                        while (!m_updateToExported.exec()) {
                            m_updateToExported.finish();
                            newName = name + QString::number(retry++);
                            m_updateToExported.addBindValue(newName);
                            m_updateToExported.addBindValue(functionId);
                        }
                        m_updateToExported.finish();

                        function->m_name = newName;
                        emit function->nameChanged(newName);

                        function->m_exported = true;
                        emit function->exportedChanged(true);

                        QVector<int> roles;
                        roles << NameRole;
                        roles << ExportedRole;
                        notifyRowChange(function, roles);
                    } else {
                        bool exported = true;
                        m_insert.addBindValue(name);
                        m_insert.addBindValue(moduleId);
                        m_insert.addBindValue(offset);
                        m_insert.addBindValue(exported);
                        int retry = 2;
                        while (!m_insert.exec()) {
                            m_insert.finish();
                            m_insert.addBindValue(name + QString::number(retry++));
                            m_insert.addBindValue(moduleId);
                            m_insert.addBindValue(offset);
                            m_insert.addBindValue(exported);
                        }
                        m_insert.finish();
                    }
                    m_getBySymbol.finish();
                }

                m_database.commit();
            });
        }
    }
}

Function *Functions::createFunctionFromQuery(QSqlQuery query)
{
    auto modules = Models::instance()->modules();
    auto id = query.value(0).toInt();
    auto name = query.value(1).toString();
    auto module = modules->getById(query.value(2).toInt());
    auto offset = query.value(3).toInt();
    auto exported = query.value(4).toBool();
    auto calls = query.value(5).toInt();
    auto probeScript = query.value(6).toString();
    return new Function(this, id, name, module, offset, exported, calls, probeScript);
}

void Functions::notifyRowChange(Function *function, int role)
{
    QVector<int> roles;
    roles << role;
    notifyRowChange(function, roles);
}

void Functions::notifyRowChange(Function *function, QVector<int> roles)
{
    if (function->module()->id() != m_currentModuleId) {
        return;
    }

    auto row = m_functions.indexOf(function);
    if (row != -1) {
        auto i = createIndex(row, 0);
        emit dataChanged(i, i, roles);
    }
}

QString Functions::functionName(Module *module, int offset)
{
    return functionPrefix(module) + QStringLiteral("_") + QString::number(offset, 16);
}

QString Functions::functionPrefix(Module *module)
{
    if (module->main()) {
        return QStringLiteral("sub");
    } else {
        QString prefix = module->name().toLower();
        return prefix.remove(s_ignoredPrefixCharacters);
    }
}
