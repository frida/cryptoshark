import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Controls.Styles 1.1
import QtQuick.Dialogs 1.2
import QtQuick.Layouts 1.1
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
                onTriggered: {
                    processModel.refresh();
                    processSelector.visible = true;
                }
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

    SplitView {
        anchors.fill: parent
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

                    model: threadsModel
                }
                Row {
                    id: actions
                    Layout.fillWidth: true

                    Button {
                        text: qsTr("Probe")
                        enabled: threadsModel.get(threads.currentRow) !== undefined && threadsModel.get(threads.currentRow).status === ''
                        onClicked: {
                            var index = threads.currentRow;
                            threadsModel.setProperty(index, 'status', 'P');
                            script.probe(threadsModel.get(index).id);
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

                    model: functionsModel

                    onCurrentRowChanged: {
                        var func = model.get(currentRow);
                        if (func) {
                            script.disassemble(func.address, function (instructions) {
                                code.render(instructions);
                            });
                        }
                    }
                }
            }
        }

        TextArea {
            id: code

            style: TextAreaStyle {
                backgroundColor: "#060606"
            }
            font.family: "Lucida Console"
            textFormat: TextEdit.RichText
            font.pointSize: 14
            readOnly: true

            function render(instructions) {
                var immediates = /((0x|[0-9])[0-9a-f]*)/g;
                var registers = /([re][abcd]x|[re][sd]i]|[re][bs]p|[re]ip)/g;
                var lines = instructions.map(function (insn) {
                    var line = "<font color=\"#ff8689\">" + _zeroPad(insn.address.substr(2)) + "</font>&nbsp;";
                    line += "<font color=\"#6064f6\"><b>" + insn.mnemonic + "</b>";
                    if (insn.opStr) {
                        line += " " + insn.opStr
                            .replace(immediates, "<font color=\"#ffae6c\">$1</font>")
                            .replace(registers, "<font color=\"#dfde92\">$1</font>");
                    }
                    line += "</font>";
                    return line;
                });
                text = lines.join("<br />");
            }

            function _zeroPad(s) {
                var result = s;
                while (result.length < 8) {
                    result = "0" + result;
                }
                return result;
            }
        }
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

    ListModel {
        id: functionsModel
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

        property var _functions: Object()
        property var _requests: Object()
        property var _nextRequestId: 1

        function probe(threadId, callback) {
            _request('thread:probe', {id: threadId}, callback);
        }

        function disassemble(address, callback) {
            _request('function:disassemble', {address: address}, callback);
        }

        function _request(name, payload, callback) {
            _requests[_nextRequestId] = callback || function () {};
            post({id: _nextRequestId, name: name, payload: payload});
            _nextRequestId++;
        }

        function _onThreadsUpdate(threads) {
            threads.forEach(function (thread) {
                threadsModel.append({id: thread.id, tags: thread.tags.join(', '), status: ''});
            });
        }

        function _onThreadUpdate(updatedThread) {
            var updatedThreadId = updatedThread.id;
            var count = threadsModel.count;
            for (var i = 0; i !== count; i++) {
                var thread = threadsModel.get(i);
                if (thread.id === updatedThreadId) {
                    threadsModel.setProperty(i, 'tags', updatedThread.tags.join(', '));
                    break;
                }
            }
        }

        function _onThreadSummary(thread, summary) {
            for (var address in summary) {
                if (summary.hasOwnProperty(address)) {
                    var entry = summary[address];
                    var index = _functions[address];
                    if (!index) {
                        index = functionsModel.count;
                        _functions[address] = index;
                        functionsModel.append({
                            name: entry.symbol ? entry.symbol.module + "+0x" + entry.symbol.offset.toString(16) : address,
                            address: address,
                            calls: entry.count,
                            threads: "" + thread.id,
                            symbol: entry.symbol
                        });
                    } else {
                        functionsModel.setProperty(index, 'calls', functionsModel.get(index).calls + entry.count);
                    }
                }
            }
        }

        onError: {
            errorDialog.text = message;
            errorDialog.open();
        }
        onMessage: {
            if (object.type === 'send') {
                var id = object.payload.id;
                if (id) {
                    var callback = _requests[id];
                    delete _requests[id];
                    callback(object.payload.payload);
                    return;
                }

                var stanza = object.payload;
                var payload = stanza.payload;
                switch (stanza.name) {
                    case 'threads:update':
                        _onThreadsUpdate(payload);
                        break;
                    case 'thread:update':
                        _onThreadUpdate(payload);
                        break;
                     case 'thread:summary':
                         _onThreadSummary(payload.thread, payload.summary);
                         break;
                     default:
                         console.log('Unhandled: ' + JSON.stringify(stanza));
                         break;
                }
            } else {
                console.log('ERROR: ' + JSON.stringify(object));
            }
        }
    }
}
