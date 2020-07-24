import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Dialogs 1.2
import Frida 1.0

Dialog {
    id: dialog

    signal selected(var device, var process)

    function _emitSelected() {
        var currentRow = processes.currentRow;
        if (currentRow !== -1) {
            selected(deviceModel.get(devices.currentRow), processModel.get(currentRow));
        }
    }

    onAccepted: {
        _emitSelected();
    }

    height: 270
    title: qsTr("Choose target process:")
    modality: Qt.WindowModal
    standardButtons: AbstractDialog.Ok | AbstractDialog.Cancel

    SplitView {
        width: parent.width
        height: parent.height

        TableView {
            id: devices

            TableViewColumn {
                role: "icon"
                width: 16
                delegate: Image {
                    source: styleData.value
                    fillMode: Image.Pad
                }
            }
            TableViewColumn {
                role: "name"
                title: "Name"
                width: 100
            }

            model: deviceModel

            onRowCountChanged: {
                if (rowCount > 0 && currentRow === -1) {
                    selection.select(0);
                    currentRow = 0;
                }
            }
        }

        TableView {
            id: processes

            TableViewColumn {
                role: "smallIcon"
                width: 16
                delegate: Image {
                    source: styleData.value
                    fillMode: Image.Pad
                }
            }
            TableViewColumn { role: "pid"; title: "Pid"; width: 50; }
            TableViewColumn { role: "name"; title: "Name"; width: 100; }

            model: processModel

            onActivated: {
                dialog.close();
                dialog._emitSelected();
            }
        }
    }

    DeviceListModel {
        id: deviceModel
    }

    ProcessListModel {
        id: processModel
        device: (devices.currentRow !== -1) ? deviceModel.get(devices.currentRow) : null

        onError: {
            processErrorDialog.text = message;
            processErrorDialog.open();
        }
    }

    MessageDialog {
        id: processErrorDialog
        icon: StandardIcon.Critical
    }
}
