#ifndef MODELS_H
#define MODELS_H

#include "models/functions.h"
#include "models/modules.h"

#include <QObject>

class Models : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(Models)
    Q_PROPERTY(Modules *modules READ modules CONSTANT)
    Q_PROPERTY(Functions *functions READ functions CONSTANT)

public:
    explicit Models(QObject *parent = 0);

    Q_INVOKABLE void open(QString name);
    Q_INVOKABLE void close();

    Modules *modules() const { return m_modules; }
    Functions *functions() const { return m_functions; }

signals:

public slots:

private:
    Modules *m_modules;
    Functions *m_functions;
};

#endif // MODELS_H
