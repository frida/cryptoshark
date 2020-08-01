#include "nativepointer.h"

NativePointer *NativePointer::s_instance = nullptr;

NativePointer::NativePointer(QObject *parent) :
    QObject(parent)
{
}

NativePointer::~NativePointer()
{
    s_instance = nullptr;
}

NativePointer *NativePointer::instance()
{
    if (s_instance == nullptr)
        s_instance = new NativePointer();
    return s_instance;
}

QString NativePointer::fromBaseAndOffset(QString base, int offset)
{
    int numericBase = base.startsWith("0x") ? 16 : 10;
    qlonglong result = base.toLongLong(0, numericBase) + offset;
    return (numericBase == 16 ? "0x" : "") + QString::number(result, numericBase);
}
