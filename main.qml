import QtQuick 2.2
import QtQuick.Controls 1.1
import QtQuick.Dialogs 1.1

import Frida 1.0

ApplicationWindow {
    id: app
    visible: true
    width: 640
    height: 480
    title: qsTr("Hello World")

    property variant currentDevice: devices.currentRow !== -1 ? devices.model[devices.currentRow] : null

    menuBar: MenuBar {
        Menu {
            title: qsTr("File")
            MenuItem {
                text: qsTr("Exit")
                onTriggered: Qt.quit();
            }
        }
    }

    SplitView {
        anchors.fill: parent
        orientation: Qt.Horizontal

        Column {
            TableView {
                id: devices
                TableViewColumn { role: "name"; title: "Name"; width: 100 }
                TableViewColumn { role: "type"; title: "Type"; width: 50 }
                model: deviceModel
            }
            Item {
                width: processes.width
                height: processes.height
                TableView {
                    id: processes
                    sortIndicatorVisible: true
                    TableViewColumn { role: "pid"; title: "Pid"; width: 50 }
                    TableViewColumn { role: "name"; title: "Name"; width: 100 }
                    model: currentDevice ? currentDevice.processes.items.filter(function (p) { return p.name === "cat"; }) : null
                    onActivated: {
                        currentDevice.inject(script, model[currentRow].pid);
                    }
                }
                BusyIndicator {
                    anchors.centerIn: parent
                    running: currentDevice ? currentDevice.processes.isLoading : false
                }
            }
        }

        Button {
            text: "Hello: " + Device.Tether
        }
    }

    MessageDialog {
        id: errorDialog
        title: "Error"
        icon: StandardIcon.Critical
    }

    DeviceListModel {
        id: deviceModel
    }

    Script {
        id: script
        url: Qt.resolvedUrl("./cryptoshark.js")

        onStatusChanged: {
            console.log("onStatusChanged: " + newStatus);
        }
        onError: {
            errorDialog.text = message;
            errorDialog.open();
        }
        onMessage: {
            console.log("woot object=" + JSON.stringify(object) + " data=" + data);
        }
    }
}
