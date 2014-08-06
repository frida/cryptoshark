import QtQuick 2.0
import QtQuick.Controls 1.2
import QtQuick.Layouts 1.1

import "../components"

SplitView {
    property var agentService: null
    property alias threadsModel: threads.model
    property alias functionsModel: functions.model

    orientation: Qt.Horizontal

    Item {
        width: sidebar.implicitWidth
        Layout.minimumWidth: 5

        ColumnLayout {
            id: sidebar
            spacing: 5

            anchors {
                fill: parent
                margins: 1
            }

            TableView {
                id: threads
                Layout.fillWidth: true

                TableViewColumn { role: "status"; title: ""; width: 20 }
                TableViewColumn { role: "id"; title: "Thread ID"; width: 63 }
                TableViewColumn { role: "tags"; title: "Tags"; width: 100 }
            }
            Row {
                id: actions
                Layout.fillWidth: true

                Button {
                    text: qsTr("Probe")
                    enabled: !!threadsModel && threadsModel.get(threads.currentRow) !== undefined && threadsModel.get(threads.currentRow).status === ''
                    onClicked: {
                        var index = threads.currentRow;
                        threadsModel.setProperty(index, 'status', 'P');
                        agentService.probe(threadsModel.get(index).id);
                    }
                }
            }
            TableView {
                id: functions
                Layout.fillWidth: true
                Layout.fillHeight: true

                TableViewColumn { role: "name"; title: "Function"; width: 63 }
                TableViewColumn { role: "calls"; title: "Calls"; width: 63 }
                TableViewColumn { role: "threads"; title: "Thread IDs"; width: 70 }

                onCurrentRowChanged: {
                    var func = model.get(currentRow);
                    if (func) {
                        agentService.disassemble(func.address, function (instructions) {
                            disassembly.render(instructions);
                        });
                    }
                }
            }
        }
    }

    DisassemblyView {
        id: disassembly
    }
}
