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
                model: Frida.devices
            }
            Item {
                width: processes.width
                height: processes.height
                TableView {
                    id: processes
                    TableViewColumn { role: "pid"; title: "Pid"; width: 25 }
                    TableViewColumn { role: "name"; title: "Name"; width: 100 }
                    model: currentDevice ? currentDevice.processes.items : null
                    onActivated: {
                        var script = Frida.scripts.createFromUrl(Qt.resolvedUrl("./cryptoshark.js"));
                        script.onError.connect(function (message) {
                            errorDialog.text = message;
                            errorDialog.open();
                        });
                        script.onMessage.connect(function (message, data) {
                            console.log("woot message=" + JSON.stringify(message) + " data=" + data);
                        });
                        currentDevice.inject(script, model[currentRow].pid);
                    }
                }
                BusyIndicator {
                    anchors.centerIn: parent
                    running: currentDevice ? currentDevice.processes.isLoading : false
                }
            }
            TableView {
                id: scripts
                TableViewColumn { role: "source"; title: "Source"; width: 150 }
                TableViewColumn { role: "pid"; title: "Pid"; width: 50 }
                TableViewColumn { role: "status"; title: "Status"; width: 50 }
                model: Frida.scripts.items
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
}
