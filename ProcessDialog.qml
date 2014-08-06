import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Dialogs 1.2

Dialog {
    property alias model: processes.model

    signal selected(var process)

    function _emitSelected() {
        var currentRow = processes.currentRow;
        if (currentRow !== -1) {
            selected(model.get(currentRow));
        }
    }

    onAccepted: {
        _emitSelected();
    }

    height: 270
    title: qsTr("Choose target process:")
    modality: Qt.WindowModal
    standardButtons: AbstractDialog.Ok | AbstractDialog.Cancel

    TableView {
        id: processes
        width: parent.width
        height: 200

        TableViewColumn {
            role: "smallIcon"
            width: 16
            delegate: Image {
                source: styleData.value
                fillMode: Image.Pad
            }
        }
        TableViewColumn { role: "pid"; title: "Pid"; width: 50 }
        TableViewColumn { role: "name"; title: "Name"; width: 100 }

        onActivated: {
            parent.close();
            parent._emitSelected();
        }
    }
}
