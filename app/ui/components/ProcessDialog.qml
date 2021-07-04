import QtQuick 2.12
import QtQuick.Controls 2.13 as Controls
import Qt.labs.platform 1.1 as Labs
import Frida 1.0

Controls.Dialog {
    id: dialog

    signal selected(var device, var process)

    onOpened: {
        if (processModel.count !== 0) {
            processModel.refresh();
        }
    }

    onAccepted: {
        const currentIndex = processes.currentIndex;
        if (currentIndex !== -1) {
            selected(deviceModel.get(devices.currentIndex), processModel.get(currentIndex));
        }
    }

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

            model: deviceModel

            Controls.SplitView.minimumWidth: 50
            Controls.SplitView.preferredWidth: 150
            boundsBehavior: Flickable.StopAtBounds

            delegate: Controls.ItemDelegate {
                text: name
                icon.source: model.icon
                width: (parent !== null) ? parent.width : 50
                highlighted: ListView.isCurrentItem
                onClicked: devices.currentIndex = index
            }
        }

        ListView {
            id: processes

            model: processModel

            boundsBehavior: Flickable.StopAtBounds

            delegate: Controls.ItemDelegate {
                width: (parent !== null) ? parent.width : 50
                leftPadding: 35

                text: name

                Image {
                    anchors.left: parent.left
                    anchors.leftMargin: 10
                    anchors.verticalCenter: parent.verticalCenter
                    width: 16
                    fillMode: Image.PreserveAspectFit

                    source: icons[icons.length - 1] ?? ""
                }

                highlighted: ListView.isCurrentItem
                onClicked: processes.currentIndex = index
                onDoubleClicked: dialog.accept()
            }
        }
    }

    DeviceListModel {
        id: deviceModel
    }

    ProcessListModel {
        id: processModel
        device: (devices.currentIndex !== -1) ? deviceModel.get(devices.currentIndex) : null
        scope: Frida.Scope.Full

        onError: {
            processErrorDialog.text = message;
            processErrorDialog.open();
        }
    }

    Labs.MessageDialog {
        id: processErrorDialog
    }
}
