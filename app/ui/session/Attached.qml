import Cryptoshark 1.0

import QtQuick 2.12
import QtQuick.Controls 2.13
import QtQuick.Layouts 1.1
import Frida 1.0

import "../components"

SplitView {
    id: attachedView

    property var agentService: null
    property alias threadsModel: threadsView.model
    property var models: null
    property var functionDialog: null

    property var currentModule: null
    property var currentFunction: null

    property var endReason: ""

    property var _scriptInstance: agentService.instances[0] ?? null

    onCurrentModuleChanged: {
        models.functions.load(currentModule !== null ? currentModule.id : -1);
        functionsView.currentRow = -1;
        if (currentModule !== null) {
            functionsView.currentRow = 0;
        }
    }

    onCurrentFunctionChanged: {
        _refreshDisassembly();
    }

    Connections {
        target: models.functions

        function onRenamed(func) {
            Qt.callLater(_refreshDisassembly);
        }
    }

    function _refreshDisassembly() {
        disassembly.text = "";

        const func = currentFunction;
        if (func === null)
            return;

        disassembly.loading = true;
        agentService.disassemble(func, text => {
            disassembly.text = text;
            disassembly.loading = false;
        });
    }

    orientation: Qt.Horizontal

    Item {
        SplitView.preferredWidth: 250
        SplitView.minimumWidth: 50

        onWidthChanged: {
            threadsView.forceLayout();
            modulesView.forceLayout();
            functionsView.forceLayout();
        }

        ColumnLayout {
            id: sidebar
            anchors.fill: parent
            spacing: 0

            Rectangle {
                height: 210
                Layout.fillWidth: true

                border {
                    width: 1
                    color:  "#666"
                }

                color: "#ccc"

                ColumnLayout {
                    x: 1
                    y: 1
                    width: parent.width - 2
                    height: parent.height - 2

                    SimpleTableView {
                        id: threadsView

                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        columnTitles: ["", qsTr("Thread ID"), qsTr("Tags")]
                        columnWidths: [20, 63, -1]
                    }
                    Row {
                        visible: _scriptInstance !== null

                        leftPadding: 5
                        rightPadding: 5
                        bottomPadding: 5

                        Button {
                            id: followButton

                            property string _action: typeof _forcedUpdates === "number" &&
                                                     (threadsView.currentRow !== -1 && threadsModel !== null &&
                                                      threadsModel.getRow(threadsView.currentRow).status === "F")
                                                     ? "unfollow" : "follow"
                            property int _forcedUpdates: 0

                            text: (_action === "follow") ? qsTr("Follow") : qsTr("Unfollow")
                            enabled: threadsView.currentRow !== -1 && threadsModel !== null

                            onClicked: {
                                const row = threadsView.currentRow;
                                const index = threadsModel.index(row, 0);
                                const thread = threadsModel.getRow(row);

                                if (_action === "follow") {
                                    threadsModel.setData(index, "display", "F");
                                    agentService.follow(thread.id);
                                } else {
                                    threadsModel.setData(index, "display", "");
                                    agentService.unfollow(thread.id);
                                }

                                _forcedUpdates++;
                            }
                        }
                    }
                }
            }

            Rectangle {
                height: 150
                Layout.fillWidth: true

                border {
                    width: 1
                    color:  "#666"
                }

                color: "#ccc"

                SimpleTableView {
                    id: modulesView

                    model: models.modules

                    x: 1
                    y: 1
                    width: parent.width - 2
                    height: parent.height - 2

                    columnTitles: [qsTr("Name"), qsTr("Calls")]
                    columnWidths: [-1, 80]

                    onCurrentRowChanged: {
                        const currentId = model.data(model.index(currentRow, 0), "id") || null;
                        if (currentId !== null) {
                            if (currentModule === null || currentModule.id !== currentId) {
                                currentModule = model.getById(currentId);
                            }
                        } else if (currentModule !== null) {
                            currentModule = null;
                        }
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true

                border {
                    width: 1
                    color:  "#666"
                }

                color: "#ccc"

                ColumnLayout {
                    x: 1
                    y: 1
                    width: parent.width - 2
                    height: parent.height - 2

                    SimpleTableView {
                        id: functionsView

                        model: models.functions

                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        columnTitles: ["", qsTr("Function"), qsTr("Calls")]
                        columnWidths: [20, -1, 80]

                        onCurrentRowChanged: {
                            const currentId = model.data(model.index(currentRow, 0), "id") || null;
                            if (currentId !== null) {
                                if (currentFunction === null || currentFunction.id !== currentId) {
                                    currentFunction = model.getById(currentId);
                                }
                            } else if (currentFunction !== null) {
                                currentFunction = null;
                            }
                        }

                        onActivated: {
                            functionDialog.functionId = currentFunction.id;
                            functionDialog.open();
                        }
                    }
                    RowLayout {
                        visible: _scriptInstance !== null

                        Layout.rightMargin: 5
                        Layout.bottomMargin: 5
                        Layout.leftMargin: 5

                        Button {
                            Layout.fillWidth: true
                            Layout.maximumWidth: 150
                            property string _action: currentFunction !== null && currentFunction.probeActive ? "remove" : "add"
                            text: _action === "add" ? qsTr("Add Probe") : qsTr("Remove Probe")
                            enabled: currentFunction !== null
                            onClicked: {
                                if (_action === "add") {
                                    models.functions.addProbe(currentFunction.id);
                                } else {
                                    models.functions.removeProbe(currentFunction.id);
                                }
                            }
                        }
                        Button {
                            text: qsTr("Symbolicate")
                            enabled: currentModule !== null

                            onClicked:  {
                                models.functions.symbolicate(currentModule.id);
                            }
                        }
                    }
                }
            }
        }
    }

    ColumnLayout {
        spacing: 0

        Frame {
            visible: _scriptInstance === null

            Layout.fillWidth: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 10

                Label {
                    text: endReason + "."
                    Layout.alignment: Qt.AlignHCenter
                    color: "lavender"
                    font.bold: true
                }
                Button {
                    text: qsTr("Close")
                    Layout.alignment: Qt.AlignHCenter
                    onClicked: endSession()
                }
            }

            background: Rectangle {
                color: "crimson"
            }
        }

        Frame {
            visible: _scriptInstance !== null && _scriptInstance.processState === ScriptInstance.ProcessState.Paused

            Layout.fillWidth: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 10

                Label {
                    text: qsTr("Process is paused near its entrypoint.")
                    Layout.alignment: Qt.AlignHCenter
                    color: "#444"
                    font.bold: true
                }
                Button {
                    text: qsTr("Resume")
                    Layout.alignment: Qt.AlignHCenter
                    onClicked: agentService.resumeProcess()
                }
            }

            background: Rectangle {
                color: "lightgreen"
            }
        }

        SplitView {
            Layout.fillWidth: true
            Layout.fillHeight: true

            orientation: Qt.Vertical

            DisassemblyView {
                id: disassembly

                visible: _scriptInstance !== null

                SplitView.fillWidth: true
                SplitView.fillHeight: true
            }

            ColumnLayout {
                SplitView.fillWidth: true
                SplitView.preferredHeight: 300

                spacing: 0

                ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    TextArea {
                        id: log

                        property int _bufferLength: 1000
                        property var _lineLengths: []

                        function appendMessage(message) {
                            message.split("<br />").forEach(line => {
                                const lengthBefore = length;
                                append(line);
                                const lengthAfter = length;
                                const lineLength = lengthAfter - lengthBefore;
                                _lineLengths.push(lineLength);
                                if (_lineLengths.length === _bufferLength + 1) {
                                    const firstLineLength = _lineLengths.splice(0, 1)[0];
                                    remove(0, firstLineLength);
                                }
                            });

                            log.cursorPosition = length;
                        }

                        background: Rectangle {
                            color: "black"
                        }
                        palette.text: "#c7c7c7"
                        font: fixedFont
                        textFormat: TextEdit.RichText
                        wrapMode: TextEdit.NoWrap
                        readOnly: true
                        selectByKeyboard: true
                        selectByMouse: true

                        Connections {
                            target: models.functions

                            function onLogMessage(func, message) {
                                log.appendMessage("<font color=\"#ffffff\"><a href=\"" + func.id + "\">" + func.name + "</a>: </font><font color=\"#808080\">" + message + "</font>");
                            }
                        }

                        Connections {
                            target: functionDialog

                            function onRename(func, oldName, newName) {
                                log.text = log.text.replace(new RegExp("(<a href=\"" + func.id + "\">.*?)\\b" + oldName + "\\b(.*?<\\/a>)", "g"), "$1" + newName + "$2");
                            }
                        }

                        onLinkActivated: {
                            functionDialog.functionId = parseInt(link, 10);
                            functionDialog.open();
                        }
                    }
                }

                TextField {
                    Layout.fillWidth: true
                    Layout.margins: 4

                    onAccepted: {
                        const command = text;
                        if (command.length === "")
                            return;

                        text = ""
                        log.appendMessage(command)
                        agentService.executeRadareCommand(command, result => {
                                                              const resultWithoutTrailingLineFeed = result.substr(0, result.lastIndexOf("<br />"));
                                                              log.appendMessage(resultWithoutTrailingLineFeed);
                                                          });
                    }
                }
            }
        }
    }
}
