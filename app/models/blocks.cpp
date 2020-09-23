#include "blocks.h"

#include "../models.h"
#include "../router.h"

Blocks::Blocks(QObject *parent, QSqlDatabase db) :
    QSqlQueryModel(parent),
    m_database(db)
{
    db.exec(QStringLiteral("CREATE TABLE IF NOT EXISTS blocks ( \
        id INTEGER PRIMARY KEY, \
        name TEXT UNIQUE, \
        module INTEGER, \
        offset INTEGER NOT NULL, \
        size INTEGER NOT NULL, \
        function INTEGER, \
        FOREIGN KEY(module) REFERENCES modules(id), \
        FOREIGN KEY(function) REFERENCES functions(id) \
    )"));
    db.exec(QStringLiteral("CREATE INDEX IF NOT EXISTS blocks_index ON blocks(module, offset, function)"));

    m_getByLocation.prepare(QStringLiteral("SELECT id FROM blocks WHERE module = ? AND offset = ? LIMIT 1"));
    m_getByLocation.setForwardOnly(true);
    m_getUnnamed.prepare(QStringLiteral("SELECT blocks.id, modules.base + blocks.offset FROM blocks "
                                        "INNER JOIN modules ON modules.id = blocks.module "
                                        "WHERE blocks.name IS NULL"));
    m_getUnnamed.setForwardOnly(true);
    m_getNearest.prepare(QStringLiteral("SELECT functions.id FROM blocks INNER JOIN functions "
                                        "ON functions.module = blocks.module AND functions.offset <= blocks.offset "
                                        "WHERE blocks.id = ? "
                                        "ORDER BY functions.offset DESC "
                                        "LIMIT 1"));
    m_getNearest.setForwardOnly(true);
    m_insert.prepare(QStringLiteral("INSERT INTO blocks (module, offset, size) VALUES (?, ?, ?)"));
    m_insert.setForwardOnly(true);
    m_updateName.prepare(QStringLiteral("UPDATE blocks SET name = ? WHERE id = ?"));
    m_updateName.setForwardOnly(true);

    resetQuery();
    setHeaderData(0, Qt::Horizontal, tr("ID"));
    setHeaderData(1, Qt::Horizontal, tr("Name"));
}

void Blocks::resetQuery()
{
    setQuery(QStringLiteral("SELECT "
                                "blocks.id, "
                                "IFNULL("
                                    "blocks.name, "
                                    "modules.name || '+' || printf('0x%x', blocks.offset)"
                                ") as 'name' "
                            "FROM blocks "
                            "INNER JOIN modules ON modules.id = blocks.module"),
             m_database);
}

void Blocks::addCoverage(QJsonArray blocks)
{
    int numRowsInserted = 0;

    m_database.transaction();

    auto modules = Models::instance()->modules();

    foreach (QJsonValue blockValue, blocks) {
        auto block = blockValue.toArray();

        auto startValue = block[0];
        if (!startValue.isArray())
            continue; // TODO: Handle dynamically generated code.

        auto start = startValue.toArray();
        auto remoteModuleId = start[0].toInt();
        auto offset = start[1].toInt();

        auto size = block[1].toInt();

        Module *module = modules->getByRemoteId(remoteModuleId);
        auto moduleId = module->id();

        m_getByLocation.addBindValue(moduleId);
        m_getByLocation.addBindValue(offset);
        m_getByLocation.exec();
        if (!m_getByLocation.next()) {
            m_insert.addBindValue(moduleId);
            m_insert.addBindValue(offset);
            m_insert.addBindValue(size);
            m_insert.exec();
            m_insert.finish();
            numRowsInserted++;
        }
        m_getByLocation.finish();
    }

    m_database.commit();

    if (numRowsInserted > 0)
        resetQuery();
}

bool Blocks::updateName(int blockId, QString name)
{
    m_updateName.addBindValue(name);
    m_updateName.addBindValue(blockId);
    bool success = m_updateName.exec();
    m_updateName.finish();
    return success;
}

Function *Blocks::findNearestFunction(int blockId)
{
    Function *result = nullptr;

    m_getNearest.addBindValue(blockId);
    m_getNearest.exec();
    if (m_getNearest.next()) {
        auto funcId = m_getNearest.value(0).toInt();
        result = Models::instance()->functions()->getById(funcId);
    }
    m_getNearest.finish();

    return result;
}

QJsonObject Blocks::resolveBlockAddresses(QJsonArray addresses, Module *module)
{
    QJsonObject result;

    auto moduleId = module->id();
    auto base = module->base();
    foreach (auto addressValue, addresses) {
        auto address = addressValue.toString().toULongLong();
        int offset = address - base;

        QJsonObject details;
        m_getByLocation.addBindValue(moduleId);
        m_getByLocation.addBindValue(offset);
        m_getByLocation.exec();
        if (m_getByLocation.next()) {
            auto blockId = m_getByLocation.value(0).toInt();
            details[QStringLiteral("id")] = blockId;
        }
        m_getByLocation.finish();

        result[QStringLiteral("0x") + QString::number(address, 16)] = details;
    }

    return result;
}

void Blocks::symbolicate()
{
    auto router = Router::instance();

    QVector<int> ids;
    QJsonArray addresses;
    m_getUnnamed.exec();
    while (m_getUnnamed.next()) {
        auto id = m_getUnnamed.value(0).toInt();
        auto address = m_getUnnamed.value(1).toULongLong();
        ids += id;
        addresses += QJsonValue(QStringLiteral("0x") + QString::number(address, 16));
    }
    m_getUnnamed.finish();

    if (ids.empty())
        return;

    QJsonArray args;
    args += addresses;
    auto request = router->request(QStringLiteral("agent:symbolicate"), args);
    QObject::connect(request, &Request::completed, [=] (QVariant result, RequestError *error) {
        if (error != nullptr)
            return;

        m_database.transaction();

        int i = 0;
        foreach (auto nameValue, result.toJsonArray()) {
            if (!nameValue.isNull()) {
                int id = ids[i];

                int serial = 0;
                const int maxAlphaOffset = 25;
                while (true) {
                    QString name = nameValue.toString() + QStringLiteral("+") + QString(static_cast<QChar>('a' + std::min(serial, maxAlphaOffset)));
                    if (serial > maxAlphaOffset)
                        name += QString::number(serial - maxAlphaOffset);
                    if (updateName(id, name))
                        break;
                    serial++;
                }
            }

            i++;
        }

        m_database.commit();

        resetQuery();
    });
}
