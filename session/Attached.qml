import QtQuick 2.0
import QtQuick.Controls 1.2
import QtQuick.Controls.Styles 1.1
import QtQuick.Layouts 1.1

import "../components"

SplitView {
    id: attachedView

    property var agentService: null
    property alias threadsModel: threadsView.model
    property var models: null

    property var currentModule: null
    property var currentFunction: null

    property var _functionsObservable: null

    Component.onDestruction: {
        _updateFunctionsObservable(null);
    }

    onCurrentModuleChanged: {
        _updateFunctionsObservable(currentModule ? models.functions.allInModule(currentModule) : null);
    }

    onCurrentFunctionChanged: {
        var func = currentFunction;
        if (func) {
            agentService.disassemble(func.address, function (instructions) {
                disassembly.render(instructions);
            });
        }
    }

    function _updateFunctionsObservable(observable) {
        if (_functionsObservable) {
            _functionsObservable.removeObserver(functions);
            _functionsObservable = null;
        }
        _functionsObservable = observable;
        if (_functionsObservable) {
            _functionsObservable.addObserver(functions);
            if (functions.count > 0) {
                functionsView.currentRow = 0;
                functionsView.selection.clear();
                functionsView.selection.select(0);
                currentFunction = _functionsObservable.items[0];
            } else {
                functionsView.currentRow = -1;
                functionsView.selection.clear();
                currentFunction = null;
            }
        }
    }

    orientation: Qt.Horizontal

    ListModel {
        id: functions

        function addProbe(func) {
            agentService.addProbe(func.address, func.probe.script, function (id) {
                models.functions.updateProbeId(func, id);
            });
        }

        function removeProbe(func) {
            agentService.removeProbe(func.address, function (id) {
                models.functions.updateProbeId(func, -1);
            });
        }

        function onFunctionsUpdate(items, partialUpdate) {
            if (partialUpdate) {
                var index = partialUpdate[0];
                var func = items[index];
                var property = partialUpdate[1];
                var value = partialUpdate[2];
                if (property === 'name' || property === 'calls') {
                    setProperty(index, property, value);
                } else if (property === 'probe.script') {
                    agentService.updateProbe(func.address, value);
                }

                if (currentFunction && func.id === currentFunction.id) {
                    currentFunction = func;
                }
            } else {
                clear();
                for (var i = 0; i !== items.length; i++) {
                    append(modelObject(items[i]));
                }
            }
        }

        function onFunctionsAdd(index, func) {
            insert(index, modelObject(func));
        }

        function onFunctionsMove(oldIndex, newIndex) {
            move(oldIndex, newIndex, 1);
        }

        function modelObject(func) {
            return {
                name: func.name,
                calls: func.calls
            };
        }
    }

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
                id: threadsView
                Layout.fillWidth: true

                TableViewColumn { role: "status"; title: ""; width: 20 }
                TableViewColumn { role: "id"; title: "Thread ID"; width: 63 }
                TableViewColumn { role: "tags"; title: "Tags"; width: 100 }
            }
            Row {
                Layout.fillWidth: true

                Button {
                    property string _action: !!threadsModel && threadsModel.get(threadsView.currentRow) && threadsModel.get(threadsView.currentRow).status === 'F' ? 'unfollow' : 'follow'
                    text: _action === 'follow' ? qsTr("Follow") : qsTr("Unfollow")
                    enabled: !!threadsModel && threadsModel.get(threadsView.currentRow) !== undefined
                    onClicked: {
                        var index = threadsView.currentRow;
                        if (_action === 'follow') {
                            threadsModel.setProperty(index, 'status', 'F');
                            agentService.follow(threadsModel.get(index).id);
                        } else {
                            threadsModel.setProperty(index, 'status', '');
                            agentService.unfollow(threadsModel.get(index).id);
                        }
                    }
                }
            }
            ComboBox {
                id: modulesView

                property var observable: null
                property bool _updating: false

                Component.onCompleted: {
                    observable = models.modules.allWithCalls();
                    observable.addObserver(this);
                }

                Component.onDestruction: {
                    observable.removeObserver(this);
                }

                function onModulesUpdate(items) {
                    var selectedModuleId = currentModule ? currentModule.id : null;
                    _updating = true;
                    model = items;
                    var selectedModuleValid = false;
                    if (selectedModuleId) {
                        for (var i = 0; i !== items.length; i++) {
                            var module = items[i];
                            if (module.id === selectedModuleId) {
                                if (!currentModule || currentModule.id !== selectedModuleId) {
                                    currentModule = module;
                                }
                                currentIndex = i;
                                selectedModuleValid = true;
                                break;
                            }
                        }
                    }
                    if (!selectedModuleValid) {
                        var firstModule = model[0] || null;
                        if (currentModule !== firstModule) {
                            currentModule = firstModule;
                        }
                        currentIndex = currentModule ? 0 : -1;
                    }
                    _updating = false;
                }

                onCurrentIndexChanged: {
                    if (_updating) {
                        return;
                    }

                    var current = model[currentIndex] || null;
                    if (currentModule !== current) {
                        currentModule = current;
                    }
                }

                model: []
                textRole: 'name'
            }
            TableView {
                id: functionsView

                onCurrentRowChanged: {
                    currentFunction = _functionsObservable.items[currentRow] || null;
                }

                model: functions
                Layout.fillWidth: true
                Layout.fillHeight: true

                TableViewColumn { role: "name"; title: "Function"; width: 83 }
                TableViewColumn { role: "calls"; title: "Calls"; width: 63 }
            }
            Row {
                Layout.fillWidth: true

                Button {
                    property string _action: !!currentFunction && currentFunction.probe.id !== -1 ? 'remove' : 'add'
                    text: _action === 'add' ? qsTr("Add Probe") : qsTr("Remove Probe")
                    enabled: !!currentFunction
                    onClicked: {
                        if (_action === 'add') {
                            functions.addProbe(currentFunction);
                        } else {
                            functions.removeProbe(currentFunction);
                        }
                    }
                }
            }
        }
    }

    SplitView {
        orientation: Qt.Vertical

        DisassemblyView {
            id: disassembly
            Layout.fillHeight: true
        }

        TextArea {
            id: log

            property var _lineLengths: []

            Component.onCompleted: {
                models.functions.addLogHandler(onLogMessage);
            }

            Component.onDestruction: {
                models.functions.removeLogHandler(onLogMessage);
            }

            function onLogMessage(func, message) {
                var lengthBefore = length;
                append("<font color=\"#ffffff\"><a href=\"" + func.address + "\">" + func.name + "</a>: </font><font color=\"#808080\">" + message + "</font>");
                var lengthAfter = length;
                var lineLength = lengthAfter - lengthBefore;
                _lineLengths.push(lineLength);
                if (_lineLengths.length === 11) {
                    var firstLineLength = _lineLengths.splice(0, 1)[0];
                    remove(0, firstLineLength);
                }
            }

            onLinkActivated: {
                scriptDialog.functionAddress = link;
                scriptDialog.open();
            }

            Layout.minimumHeight: 200
            style: TextAreaStyle {
                backgroundColor: "#060606"
            }
            font.family: "Lucida Console"
            textFormat: TextEdit.RichText
            wrapMode: TextEdit.NoWrap
            readOnly: true

            ScriptDialog {
                id: scriptDialog

                models: attachedView.models
            }
        }
    }
}
