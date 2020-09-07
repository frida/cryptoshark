import QtQuick 2.2
import QtQuick.Controls 2.3
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
        const oldName = _func.name;
        const newName = name.text.trim();
        if (newName !== oldName) {
            let candidate = newName;
            let serial = 2;
            while (!models.functions.updateName(_func.id, candidate)) {
                candidate = newName + "_" + serial;
                serial++;
            }
            rename(_func, oldName, candidate);
        }

        models.functions.updateProbe(_func.id, script.text);
    }

    width: 564
    height: 350
    title: qsTr("Edit function")
    modal: true
    standardButtons: Dialog.Save | Dialog.Cancel

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
                font: fixedFont
                textFormat: TextEdit.PlainText
                wrapMode: TextEdit.NoWrap
            }
        }
    }
}
