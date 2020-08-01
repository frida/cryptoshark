import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Dialogs 1.2
import QtQuick.Layouts 1.1

Dialog {
    property var models: null
    property int functionId: -1
    property var _func: null
    signal rename(var func, string oldName, string newName);

    onFunctionIdChanged: {
        _func = models.functions.getById(functionId);
        if (_func !== null) {
            name.text = _func.name;
            script.text = _func.probeScript;
        } else {
            name.text = "";
            script.text = "";
        }
    }

    onAccepted: {
        var oldName = _func.name;
        var newName = name.text.trim();
        if (newName !== oldName) {
            var suffix = "";
            var count = 2;
            while (!models.functions.updateName(_func.id, newName + suffix)) {
                suffix = "_" + count;
                count++;
            }
            rename(_func, oldName, newName);
        }

        models.functions.updateProbe(_func.id, script.text);
    }

    width: 564
    height: 350
    title: qsTr("Edit function")
    modality: Qt.WindowModal
    standardButtons: AbstractDialog.Save | AbstractDialog.Cancel

    ColumnLayout {
        width: parent.width
        height: 290

        GroupBox {
            title: "Name"
            Layout.minimumWidth: 200

            TextField {
                id: name
                anchors.fill: parent
            }
        }

        GroupBox {
            title: "Probe script"
            Layout.fillWidth: true
            Layout.fillHeight: true

            TextArea {
                id: script

                anchors.fill: parent
                font.family: fixedFont
                textFormat: TextEdit.PlainText
                wrapMode: TextEdit.NoWrap
            }
        }
    }
}
