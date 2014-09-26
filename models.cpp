#include "models.h"

Models::Models(QObject *parent) :
    QObject(parent),
    m_modules(new Modules(this)),
    m_functions(new Functions(this))
{
}

void Models::open(QString name)
{
    Q_UNUSED(name);
}

void Models::close()
{
}
