#include "functions.h"

#include "models.h"
#include "router.h"

static const int IdRole = Qt::UserRole + 0;
static const int StatusRole = Qt::UserRole + 16;

QRegExp Functions::s_ignoredPrefixCharacters = QRegExp(QStringLiteral("(^lib)|([-_])|(\\.[\\w.]+$)"));

Functions::Functions(QObject *parent, QSqlDatabase db) :
    TableModel(parent, db),
    m_currentModuleId(-1)
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

    setTable(QStringLiteral("functions"));
    setFilter(QStringLiteral("module == -1"));
    setSort(5, Qt::SortOrder::DescendingOrder);
    setEditStrategy(QSqlTableModel::OnManualSubmit);
    select();
    generateRoleNames();

    m_getById.prepare(QStringLiteral("SELECT name, module, offset, exported, probe_script FROM functions WHERE id = ?"));
    m_insert.prepare(QStringLiteral("INSERT INTO functions (name, module, offset, exported, calls) VALUES (?, ?, ?, ?, ?)"));
    m_addCalls.prepare(QStringLiteral("UPDATE functions SET calls = calls + ? WHERE module = ? AND offset = ?"));
    m_updateName.prepare(QStringLiteral("UPDATE functions SET name = ? WHERE id = ?"));
    m_updateProbeScript.prepare(QStringLiteral("UPDATE functions SET probe_script to ? WHERE id = ?"));
    m_checkImportNeeded.prepare(QStringLiteral("SELECT 1 FROM functions WHERE module = ? AND exported = 1 LIMIT 1"));
    m_updateToExported.prepare(QStringLiteral("UPDATE functions SET name = ?, exported = 1 WHERE module = ? AND offset = ?"));
}

void Functions::load(int moduleId)
{
    m_currentModuleId = moduleId;
    setFilter(QStringLiteral("module == ") + QString::number(moduleId) + " AND calls > 0");
    select();
}

bool Functions::updateName(int functionId, QString name)
{
    m_updateName.addBindValue(name);
    m_updateName.addBindValue(functionId);
    bool success = m_updateName.exec();
    m_updateName.finish();
    return success;
}

bool Functions::hasProbe(int functionId) const
{
    return m_probes.contains(functionId);
}

void Functions::addProbe(int functionId)
{
    auto function = getById(functionId);
    if (function == nullptr)
        return;

    m_probes += functionId;

    QJsonObject payload;
    payload[QStringLiteral("id")] = function->id();
    payload[QStringLiteral("address")] = function->address();
    payload[QStringLiteral("script")] = function->probeScript();
    Router::instance()->request(QStringLiteral("function:add-probe"), payload);

    select();
}

void Functions::removeProbe(int functionId)
{
    auto function = getById(functionId);
    if (function == nullptr)
        return;

    m_probes -= functionId;

    QJsonObject payload;
    payload[QStringLiteral("address")] = function->address();
    Router::instance()->request(QStringLiteral("function:remove-probe"), payload);

    select();
}

void Functions::updateProbe(int functionId, QString script)
{
    m_updateProbeScript.addBindValue(script);
    m_updateProbeScript.addBindValue(functionId);
    m_updateProbeScript.exec();
    m_updateProbeScript.finish();

    auto function = getById(functionId);
    if (function == nullptr || !m_probes.contains(functionId))
        return;

    QJsonObject payload;
    payload[QStringLiteral("address")] = function->address();
    payload[QStringLiteral("script")] = function->probeScript();
    Router::instance()->request(QStringLiteral("function:update-probe"), payload);
}

Function *Functions::getById(int id)
{
    Function *function;
    m_getById.addBindValue(id);
    m_getById.exec();
    if (m_getById.next()) {
        auto modules = Models::instance()->modules();
        function = new Function(this,
                                id,
                                m_getById.value(0).toString(),
                                modules->getById(m_getById.value(1).toInt()),
                                m_getById.value(2).toInt(),
                                m_getById.value(3).toBool(),
                                m_getById.value(4).toString());
        function->deleteLater();
    } else {
        function = nullptr;
    }
    m_getById.finish();
    return function;
}

QVariant Functions::data(int i, QString roleName) const
{
    return TableModel::data(i, roleName);
}

QVariant Functions::data(const QModelIndex &index, int role) const
{
    if (role == StatusRole) {
        return hasProbe(data(index, IdRole).toInt()) ? QStringLiteral("P") : QStringLiteral("");
    }

    return TableModel::data(index, role);
}

QHash<int, QByteArray> Functions::roleNames() const
{
    auto names = QHash<int, QByteArray>(TableModel::roleNames());
    names[StatusRole] = QStringLiteral("status").toUtf8();
    return names;
}

void Functions::addCalls(QJsonObject summary)
{
    auto modules = Models::instance()->modules();
    QHash<int, int> moduleCalls;

    auto db = database();
    db.transaction();

    auto it = summary.constBegin();
    auto end = summary.constEnd();
    while (it != end) {
        auto entry = it.value().toObject();
        auto symbolValue = entry[QStringLiteral("symbol")];
        if (!symbolValue.isNull()) {
            auto symbol = symbolValue.toObject();
            auto moduleName = symbol[QStringLiteral("module")].toString();
            auto count = entry[QStringLiteral("count")].toInt();
            Module *module = modules->getByName(moduleName);
            auto moduleId = module->id();
            auto offset = symbol[QStringLiteral("offset")].toInt();
            m_addCalls.addBindValue(count);
            m_addCalls.addBindValue(moduleId);
            m_addCalls.addBindValue(offset);
            m_addCalls.exec();
            if (m_addCalls.numRowsAffected() == 0) {
                m_insert.addBindValue(functionName(module, offset));
                m_insert.addBindValue(moduleId);
                m_insert.addBindValue(offset);
                m_insert.addBindValue(false);
                m_insert.addBindValue(count);
                m_insert.exec();
                m_insert.finish();
            }
            m_addCalls.finish();

            moduleCalls[moduleId] += count;
        }
        ++it;
    }

    modules->addCalls(moduleCalls);

    db.commit();

    importModuleExports(moduleCalls.keys());

    modules->select();
    select();
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
                auto db = database();
                db.transaction();

                auto functions = result.toArray();
                foreach (auto funcValue, functions) {
                    auto func = funcValue.toArray();
                    auto name = func.at(0).toString();
                    auto offset = func.at(1).toInt();
                    m_updateToExported.addBindValue(name);
                    m_updateToExported.addBindValue(moduleId);
                    m_updateToExported.addBindValue(offset);
                    int retry = 2;
                    while (!m_updateToExported.exec()) {
                        m_updateToExported.finish();
                        m_updateToExported.addBindValue(name + QString::number(retry++));
                        m_updateToExported.addBindValue(moduleId);
                        m_updateToExported.addBindValue(offset);
                    }
                    if (m_updateToExported.numRowsAffected() == 0) {
                        m_insert.addBindValue(name);
                        m_insert.addBindValue(moduleId);
                        m_insert.addBindValue(offset);
                        m_insert.addBindValue(true);
                        m_insert.addBindValue(0);
                        while (!m_insert.exec()) {
                            m_insert.finish();
                            m_insert.addBindValue(name + QString::number(retry++));
                            m_insert.addBindValue(moduleId);
                            m_insert.addBindValue(offset);
                            m_insert.addBindValue(true);
                            m_insert.addBindValue(0);
                        }
                        m_insert.finish();
                    }
                    m_updateToExported.finish();
                }

                db.commit();
            });
        }
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
