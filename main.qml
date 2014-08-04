import QtQuick 2.2
import QtQuick.Controls 1.1
import QtQuick.Dialogs 1.2
import QtQuick.Window 2.0
import Frida 1.0

ApplicationWindow {
    title: qsTr("CryptoShark")
    width: 640
    height: 480
    visible: true

    menuBar: MenuBar {
        Menu {
            title: qsTr("File")
            MenuItem {
                text: qsTr("Attach")
                onTriggered: processSelector.visible = true
            }
            MenuItem {
                text: qsTr("Exit")
                onTriggered: Qt.quit()
            }
        }
    }

    Component.onCompleted: {
        processSelector.visible = true;
    }

    TableView {
        id: threads
        height: parent.height

        TableViewColumn { role: "id"; title: "Thread ID"; width: 63 }
        TableViewColumn { role: "tags"; title: "Tags"; width: 100 }

        model: threadsModel
    }

    Dialog {
        id: processSelector
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

            model: processModel

            onActivated: {
                processSelector.close();
                processSelector._attachToSelected();
            }
        }

        onAccepted: {
            _attachToSelected();
        }

        function _attachToSelected() {
            var currentRow = processes.currentRow;
            if (currentRow !== -1) {
                Frida.localSystem.inject(script, processModel.get(currentRow).pid);
            }
        }
    }

    MessageDialog {
        id: errorDialog
    }

    ListModel {
        id: threadsModel
    }

    ProcessListModel {
        id: processModel
        device: Frida.localSystem
        onError: {
            errorDialog.text = message;
            errorDialog.open();
        }
    }

    Script {
        id: script
        url: Qt.resolvedUrl("./agent.js")
        onError: {
            errorDialog.text = message;
            errorDialog.open();
        }
        onMessage: {
            if (object.type === 'send') {
                var event = object.payload;
                switch (event.name) {
                    case 'threads:update':
                        event.threads.forEach(function (thread) {
                            threadsModel.append({id: thread.id, tags: thread.tags.join(', ')});
                        });
                        break;
                    case 'thread:update':
                        var updatedThread = event.thread;
                        var updatedThreadId = updatedThread.id;
                        var count = threadsModel.count;
                        for (var i = 0; i !== count; i++) {
                            var thread = threadsModel.get(i);
                            if (thread.id === updatedThreadId) {
                                threadsModel.set(i, {id: updatedThread.id, tags: updatedThread.tags.join(', ')});
                                break;
                            }
                        }
                        break;
                }
            }
        }
    }
}
