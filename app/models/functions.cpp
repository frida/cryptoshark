#include "functions.h"

#include "../models.h"
#include "../router.h"

static const int IdRole = Qt::UserRole + 0;

QRegExp Functions::s_ignoredPrefixCharacters = QRegExp(QStringLiteral("(^lib)|([-_])|(\\.[\\w.]+$)"));

Functions::Functions(QObject *parent, QSqlDatabase db) :
    QAbstractTableModel(parent),
    m_currentModuleId(-1),
    m_database(db)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS functions ( \
        id INTEGER PRIMARY KEY, \
        name TEXT NOT NULL UNIQUE, \
        module INTEGER, \
        offset INTEGER NOT NULL, \
        exported INTEGER NOT NULL DEFAULT 0, \
        calls INTEGER NOT NULL DEFAULT 0, \
        probe_script TEXT NOT NULL DEFAULT 'log(args[0], args[1], args[2], args[3]);', \
        FOREIGN KEY(module) REFERENCES modules(id) \
    )"));
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS functions_index ON functions(module, offset, calls, exported)"));

    m_roleNames[Qt::DisplayRole] = QStringLiteral("display").toUtf8();
    m_roleNames[IdRole] = QStringLiteral("id").toUtf8();

    m_getAll.prepare(QStringLiteral("SELECT * FROM functions WHERE module = ? AND calls > 0 ORDER BY calls DESC"));
    m_getAll.setForwardOnly(true);
    m_getById.prepare(QStringLiteral("SELECT * FROM functions WHERE id = ?"));
    m_getById.setForwardOnly(true);
    m_getBySymbol.prepare(QStringLiteral("SELECT id FROM functions WHERE module = ? AND offset = ? LIMIT 1"));
    m_getBySymbol.setForwardOnly(true);
    m_getUnexported.prepare(QStringLiteral("SELECT id, offset FROM functions WHERE module = ? AND exported = 0"));
    m_getUnexported.setForwardOnly(true);
    m_insert.prepare(QStringLiteral("INSERT INTO functions (name, module, offset, exported) VALUES (?, ?, ?, ?)"));
    m_insert.setForwardOnly(true);
    m_updateName.prepare(QStringLiteral("UPDATE functions SET name = ? WHERE id = ?"));
    m_updateName.setForwardOnly(true);
    m_updateCalls.prepare(QStringLiteral("UPDATE functions SET calls = ? WHERE id = ?"));
    m_updateCalls.setForwardOnly(true);
    m_updateProbeScript.prepare(QStringLiteral("UPDATE functions SET probe_script = ? WHERE id = ?"));
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
        emit renamed(function);

        notifyRowChange(function);
    }
    m_updateName.finish();
    return success;
}

void Functions::addProbe(int functionId)
{
    auto function = getById(functionId);
    if (function == nullptr)
        return;

    function->m_probeActive = true;
    emit function->probeActiveChanged(true);

    notifyRowChange(function);

    Router::instance()->request(QStringLiteral("function:add-probe"), {
                                    function->id(),
                                    function->address(),
                                    function->probeScript()
                                });
}

void Functions::removeProbe(int functionId)
{
    auto function = getById(functionId);
    if (function == nullptr)
        return;

    function->m_probeActive = false;
    emit function->probeActiveChanged(false);

    notifyRowChange(function);

    Router::instance()->request(QStringLiteral("function:remove-probe"), {
                                    function->address()
                                });
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

    notifyRowChange(function);

    if (function->m_probeActive) {
        Router::instance()->request(QStringLiteral("function:update-probe"), {
                                        function->address(),
                                        function->probeScript()
                                    });
    }
}

void Functions::symbolicate(int moduleId)
{
    auto router = Router::instance();

    auto module = Models::instance()->modules()->getById(moduleId);
    if (module == nullptr)
        return;

    QVector<int> ids;
    QJsonArray offsets;
    m_getUnexported.addBindValue(moduleId);
    m_getUnexported.exec();
    while (m_getUnexported.next()) {
        auto id = m_getUnexported.value(0).toInt();
        auto offset = m_getUnexported.value(1).toInt();
        ids += id;
        offsets += QJsonValue(offset);
    }
    m_getUnexported.finish();

    auto request = router->request(QStringLiteral("module:symbolicate"), {
                                       module->path(),
                                       offsets
                                   });
    QObject::connect(request, &Request::completed, [=] (QVariant result, RequestError *error) {
        if (error != nullptr)
            return;

        m_database.transaction();

        int i = 0;
        foreach (auto nameValue, result.toJsonArray()) {
            if (!nameValue.isNull()) {
                int id = ids[i];

                int serial = 1;
                while (true) {
                    QString name = nameValue.toString();
                    if (serial > 1)
                        name += QString::number(serial);
                    if (updateName(id, name))
                        break;
                    serial++;
                }
            }

            i++;
        }

        m_database.commit();
    });
}

void Functions::addCalls(QJsonObject summary)
{
    auto modules = Models::instance()->modules();
    QHash<int, int> moduleCalls;

    m_database.transaction();

    bool sortNeeded = false;
    auto i = summary.constBegin();
    auto e = summary.constEnd();
    QModelIndex noParent;
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
                    emit discovered(name, offset, module);

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
                auto row = m_functions.indexOf(function);
                if (row != -1) {
                    auto i = index(row, 2);
                    emit dataChanged(i, i);
                } else {
                    row = m_functions.size();
                    beginInsertRows(noParent, row, row);
                    m_functions.append(function);
                    endInsertRows();
                }

                sortNeeded = true;
            }

            moduleCalls[function->module()->id()] += count;
        }
    }

    if (sortNeeded)
        sortByCallsDescending();

    modules->addCalls(moduleCalls);

    m_database.commit();

    importModuleExports(moduleCalls.keys());
}

static bool descendingLessThanByCalls(const QPair<Function *, int> &m1, const QPair<Function *, int> &m2)
{
    return m1.first->calls() > m2.first->calls();
}

void Functions::sortByCallsDescending()
{
    QList<QPersistentModelIndex> allParents;
    emit layoutAboutToBeChanged(allParents, VerticalSortHint);

    QList<QPair<Function *, int>> functions;
    for (int i = 0; i != m_functions.count(); i++)
        functions.append(QPair<Function *, int>(m_functions.at(i), i));

    std::sort(functions.begin(), functions.end(), descendingLessThanByCalls);

    m_functions.clear();
    QVector<int> forwarding(functions.count());
    for (int i = 0; i != functions.count(); i++) {
        m_functions.append(functions.at(i).first);
        forwarding[functions.at(i).second] = i;
    }

    QModelIndexList oldList = persistentIndexList();
    QModelIndexList newList;
    for (int i = 0; i != oldList.count(); i++)
        newList.append(index(forwarding.at(oldList.at(i).row()), 0));
    changePersistentIndexList(oldList, newList);

    emit layoutChanged(allParents, VerticalSortHint);
}

QVariant Functions::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(orientation);

    if (role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
    case 0:
        return QStringLiteral("");
    case 1:
        return QStringLiteral("Function");
    case 2:
        return QStringLiteral("Calls");
    default:
        return QVariant();
    }
}

QVariant Functions::data(const QModelIndex &index, QString roleName) const
{
    return data(index, m_roleNames.key(roleName.toUtf8()));
}

QVariant Functions::data(const QModelIndex &index, int role) const
{
    auto row = index.row();
    if (row < 0 || row >= m_functions.size())
        return QVariant();
    auto function = m_functions[row];

    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case 0:
            return function->m_probeActive ? QStringLiteral("P") : QStringLiteral("");
        case 1:
            return function->m_name;
        case 2:
            return function->m_calls;
        }
        break;
    case IdRole:
        return function->m_id;
    }

    return QVariant();
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
    foreach (auto moduleId, QSet<int>(moduleIds.begin(), moduleIds.end()).subtract(m_importedModules)) {
        m_checkImportNeeded.addBindValue(moduleId);
        m_checkImportNeeded.exec();
        bool importNeeded = m_checkImportNeeded.next() == false;
        m_checkImportNeeded.finish();

        m_importedModules += moduleId;

        if (importNeeded) {
            auto module = modules->getById(moduleId);
            auto request = router->request(QStringLiteral("module:get-functions"), {
                                               module->name()
                                           });
            QObject::connect(request, &Request::completed, [=] (QVariant result, RequestError *error) {
                if (error != nullptr) {
                    return;
                }

                m_database.transaction();

                auto functions = result.toJsonArray();
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
                        emit renamed(function);

                        function->m_exported = true;
                        emit function->exportedChanged(true);

                        notifyRowChange(function);
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
                        emit discovered(name, offset, module);
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

void Functions::notifyRowChange(Function *function)
{
    if (function->module()->id() != m_currentModuleId) {
        return;
    }

    auto row = m_functions.indexOf(function);
    if (row != -1) {
        auto topLeft = index(row, 0);
        auto bottomRight = index(row, 2);
        emit dataChanged(topLeft, bottomRight);
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
