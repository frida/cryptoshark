import QtQuick 2.0
import QtQuick.Controls 1.2
import QtQuick.Layouts 1.1

import "../components"
import "../vendor.js" as Vendor

SplitView {
    property var agentService: null
    property alias threadsModel: threadsView.model
    property var modulesModel: null
    property var functionsModel: null

    property var modules: []
    property alias functions: _functions
    property var currentModule: null
    property var currentFunction: null
    property bool _refreshingModels: false

    onModulesModelChanged: {
        modelRefreshTimer.schedule('modules');
    }

    onFunctionsModelChanged: {
        modelRefreshTimer.schedule('functions');
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

    function _bigInt(value) {
        if (typeof value === 'string' && value.indexOf("0x") === 0) {
            return Vendor.bigInt(value.substr(2), 16);
        } else {
            return Vendor.bigInt(value);
        }
    }

    orientation: Qt.Horizontal

    ListModel {
        id: _functions
    }

    Timer {
        id: modelRefreshTimer

        property var _changes: Object()
        property bool _pendingFlush: false
        property var _lastRefresh: null

        function schedule() {
            Array.prototype.forEach.call(arguments, function (model) {
                _changes[model] = true;
            });
            var now = new Date();
            var elapsed = _lastRefresh ? now - _lastRefresh : 500;
            var staleData = elapsed >= 500;
            if (staleData) {
                if (!_pendingFlush) {
                    _pendingFlush = true;
                    stop();
                    interval = 10;
                    start();
                }
            } else {
                var nextRefreshDelay = Math.max(500 - elapsed, 10);
                stop();
                interval = nextRefreshDelay;
                start();
            }
        }

        onTriggered: {
            refreshNow();
        }

        function refreshNow() {
            stop();
            _pendingFlush = false;
            _lastRefresh = new Date();

            var selectedModuleId = currentModule ? currentModule.id : null;
            var selectedFunctionId = currentFunction ? currentFunction.id : null;

            var changes = {};
            for (var model in _changes) {
                if (_changes.hasOwnProperty(model)) {
                    changes[model] = _changes[model];
                }
            }
            var pending = Object.keys(_changes).length;
            var results = {};

            function complete(model, items) {
                delete changes[model];
                results[model] = items;
                if (--pending === 0) {
                    var i;

                    _refreshingModels = true;

                    var moduleItems = results['modules'];
                    if (moduleItems) {
                        modules = moduleItems;

                        if (selectedModuleId) {
                            var selectedModuleValid = false;
                            for (i = 0; i !== moduleItems.length; i++) {
                                var moduleItem = moduleItems[i];
                                if (moduleItem.id === selectedModuleId) {
                                    currentModule = moduleItem;
                                    modulesView.currentIndex = i;
                                    selectedModuleValid = true;
                                    break;
                                }
                            }
                            if (!selectedModuleValid) {
                                currentModule = moduleItems[0] || null;
                            }
                        }
                    }

                    var functionItems = results['functions'];
                    if (functionItems) {
                        _functions.clear();
                        functionItems.forEach(function (func) {
                            _functions.append(func);
                        });

                        if (selectedFunctionId) {
                            var selectedFunctionValid = false;
                            for (i = 0; i !== functionItems.length; i++) {
                                var functionItem = functionItems[i];
                                if (functionItem.id === selectedFunctionId) {
                                    currentFunction = functionItem;
                                    functionsView.currentRow = i;
                                    selectedFunctionValid = true;
                                    break;
                                }
                            }
                            if (!selectedFunctionValid) {
                                currentFunction = functionItems[0] || null;
                            }
                        }
                    }

                    _refreshingModels = false;
                } else {
                    processNext();
                }
            }

            function processNext() {
                if (changes['modules']) {
                    if (modulesModel) {
                        modulesModel.allWithCalls(function (items) {
                            if (!selectedModuleId) {
                                selectedModuleId = items.length > 0 ? items[0].id : null;
                            }
                            complete('modules', items);
                        });
                    } else {
                        complete('modules', []);
                    }
                    return;
                }

                if (changes['functions']) {
                    if (functionsModel && selectedModuleId) {
                        functionsModel.findByModule(selectedModuleId, function (items) {
                            if (!selectedFunctionId) {
                                selectedFunctionId = items.length > 0 ? items[0].id : null;
                            }
                            complete('functions', items);
                        });
                    } else {
                        complete('functions', []);
                    }
                    return;
                }
            }
            processNext();

            _changes = {};
        }

        interval: 5000
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
                    text: qsTr("Probe")
                    enabled: !!threadsModel && threadsModel.get(threadsView.currentRow) !== undefined && threadsModel.get(threadsView.currentRow).status === ''
                    onClicked: {
                        var index = threadsView.currentRow;
                        threadsModel.setProperty(index, 'status', 'P');
                        agentService.probe(threadsModel.get(index).id);
                    }
                }
            }
            ComboBox {
                id: modulesView

                onCurrentIndexChanged: {
                    if (_refreshingModels) {
                        return;
                    }

                    currentModule = model[currentIndex] || null;
                    modelRefreshTimer.schedule('functions');
                    if (pressed) {
                        modelRefreshTimer.refreshNow();
                    }
                }

                model: modules
                textRole: 'name'
            }
            TableView {
                id: functionsView

                onCurrentRowChanged: {
                    if (_refreshingModels) {
                        return;
                    }

                    currentFunction = model.get(currentRow) || null;
                }

                model: functions
                Layout.fillWidth: true
                Layout.fillHeight: true

                TableViewColumn { role: "name"; title: "Function"; width: 63 }
                TableViewColumn { role: "calls"; title: "Calls"; width: 63 }
                TableViewColumn { role: "threads"; title: "Thread IDs"; width: 70 }
            }
        }
    }

    DisassemblyView {
        id: disassembly
    }
}
