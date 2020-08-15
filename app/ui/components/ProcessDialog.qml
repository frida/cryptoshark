import QtQuick 2.12
import QtQuick.Controls 2.13 as Controls
import Qt.labs.platform 1.1 as Labs
import Frida 1.0

Controls.Dialog {
    id: dialog

    signal selected(var device, var process)

    function _emitSelected() {
        var currentIndex = processes.currentIndex;
        if (currentIndex !== -1) {
            selected(deviceModel.get(devices.currentIndex), processModel.get(currentIndex));
        }
    }

    onAccepted: _emitSelected()

    width: parent.width - 50
    height: parent.height - 20
    anchors.centerIn: parent

    title: qsTr("Choose target process:")
    modal: true
    standardButtons: Controls.Dialog.Ok | Controls.Dialog.Cancel

    Controls.SplitView {
        anchors.fill: parent

        ListView {
            id: devices

            Controls.SplitView.minimumWidth: 50
            Controls.SplitView.preferredWidth: 150

            delegate: Controls.ItemDelegate {
                text: name
                icon.source: model.icon
                width: (parent !== null) ? parent.width : 50
                highlighted: ListView.isCurrentItem
                onClicked: devices.currentIndex = index
            }

            model: deviceModel
        }

        ListView {
            id: processes

            delegate: Controls.ItemDelegate {
                text: name
                icon.source: smallIcon
                width: (parent !== null) ? parent.width : 50
                highlighted: ListView.isCurrentItem
                onClicked: processes.currentIndex = index
                onDoubleClicked: dialog.accept()
            }

            model: processModel
        }
    }

    DeviceListModel {
        id: deviceModel
    }

    ProcessListModel {
        id: processModel
        device: (devices.currentIndex !== -1) ? deviceModel.get(devices.currentIndex) : null

        onError: {
            processErrorDialog.text = message;
            processErrorDialog.open();
        }
    }

    Labs.MessageDialog {
        id: processErrorDialog
    }
}
