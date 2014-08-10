import QtQuick 2.0
import QtQuick.Controls 1.2
import QtQuick.Layouts 1.1

import "../components"
import "../vendor.js" as Vendor

SplitView {
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
            var address = _bigInt(currentModule.base).add(_bigInt(func.offset)).toString();
            agentService.disassemble(address, function (instructions) {
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
                currentFunction = functions.get(0);
            } else {
                functionsView.currentRow = -1;
                functionsView.selection.clear();
                currentFunction = null;
            }
        }
    }

    function _bigInt(value) {
        if (typeof value === 'string' && value.indexOf("0x") === 0) {
            return Vendor.bigInt(value.substr(2), 16);
        } else {
            return Vendor.bigInt(value);
        }
    }

    orientation: Qt.Horizontal

    ListModel {
        id: functions

        function onFunctionsUpdate(items, partialUpdate) {
            if (partialUpdate) {
                var index = partialUpdate[0];
                var property = partialUpdate[1];
                var value = partialUpdate[2];
                setProperty(index, property, value);
            } else {
                clear();
                for (var i = 0; i !== items.length; i++) {
                    append(items[i]);
                }
            }
        }

        function onFunctionsAdd(index, func) {
            insert(index, func);
        }

        function onFunctionsMove(oldIndex, newIndex) {
            move(oldIndex, newIndex, 1);
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
                id: actions
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
                    currentFunction = model.get(currentRow) || null;
                }

                model: functions
                Layout.fillWidth: true
                Layout.fillHeight: true

                TableViewColumn { role: "name"; title: "Function"; width: 83 }
                TableViewColumn { role: "calls"; title: "Calls"; width: 63 }
            }
        }
    }

    DisassemblyView {
        id: disassembly
    }
}
