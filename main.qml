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
                width: parent.width
                TableViewColumn {
                    role: "icon";
                    width: 16
                    delegate: Image {
                        source: styleData.value
                        fillMode: Image.Pad
                    }
                }
                TableViewColumn { role: "name"; title: "Name"; width: 100 }
                model: deviceModel
            }
            Item {
                width: parent.width
                height: processes.height
                TableView {
                    id: processes
                    width: parent.width
                    sortIndicatorVisible: true
                    TableViewColumn {
                        role: "smallIcon";
                        width: 16
                        delegate: Image {
                            source: styleData.value
                            fillMode: Image.Pad
                        }
                    }
                    TableViewColumn { role: "pid"; title: "Pid"; width: 50 }
                    TableViewColumn { role: "name"; title: "Name"; width: 100 }
                    model: processModel
                    onActivated: {
                        deviceModel.get(devices.currentRow).inject(script, processModel.get(currentRow).pid);
                    }
                }
                BusyIndicator {
                    anchors.centerIn: parent
                    running: processModel.isLoading
                }
            }
            Button {
                text: "Refresh"
                onClicked: processModel.refresh()
            }
            TableView {
                id: instances
                width: parent.width
                TableViewColumn { role: "status"; title: "Status"; width: 100 }
                TableViewColumn { role: "pid"; title: "Pid"; width: 100 }
                model: script.instances
            }
            Row {
                width: parent.width
                Button {
                    text: "Stop"
                    enabled: script.instances.length > 0 && instances.currentRow !== -1
                    onClicked: script.instances[instances.currentRow].stop()
                }
                Button {
                    text: "Post"
                    enabled: script.instances.length > 0 && instances.currentRow !== -1
                    onClicked: script.instances[instances.currentRow].post({snake: 1337});
                }
            }
            Row {
                width: parent.width
                Button {
                    text: "Stop all"
                    onClicked: script.stop()
                }
                Button {
                    text: "Post all"
                    onClicked: script.post({badger: 1234});
                }
            }
        }

        Button {
            text: "Hello"
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

    ProcessListModel {
        id: processModel
        device: devices.currentRow !== -1 ? deviceModel.get(devices.currentRow) : null
        onError: {
            errorDialog.text = message;
            errorDialog.open();
        }
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
            console.log("[device='" + sender.device.name + "' pid=" + sender.pid + "] received object=" + JSON.stringify(object) + " data=" + data);
        }
    }
}
