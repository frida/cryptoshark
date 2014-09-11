import codecs
import glob
import os
import sys

qml_dir = os.path.join(os.environ.get("QT_PREFIX"), "qml")
cryptoshark_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
output_file = os.path.join(cryptoshark_dir, "cryptoshark_qml_plugin_import.qrc")

template = """\
<RCC>
    <qresource prefix="/imports">%s
    </qresource>
</RCC>"""
imports = [
    ("QtQuick", 2),
    ("QtQuick.Controls", 1),
    ("QtQuick.Dialogs", 1),
    ("QtQuick.Layouts", 1),
    ("QtQuick.PrivateWidgets", 1),
    ("QtQuick.Window", 2),
    ("QtQuick.LocalStorage", 1),
    ("Frida", 1)
]
ignores = [
    ".prl",
    ".qmltypes",
    ".lib",
    ".dll",
    ".a",
    ".so"
]

def version_suffix(version):
    if version == 1:
        return ""
    else:
        return ".%d" % version

items = []
for imp, version in imports:
    path = os.path.join(qml_dir, imp.replace(".", os.sep) + version_suffix(version))
    assert os.path.exists(path)
    for dirpath, dirnames, all_filenames in os.walk(path):
        for resource_filename in filter(lambda n: os.path.splitext(n)[1] not in ignores, all_filenames):
            resource_path = os.path.join(dirpath, resource_filename)
            alias = resource_path[len(qml_dir) + 1:].replace('\\', '/')
            items.append("        <file alias=\"%s\">%s</file>" % (alias, resource_path))

with codecs.open(output_file , "wb", "utf-8") as f:
    file_elements = "\n" + "\n".join(items)
    f.write(template % file_elements)