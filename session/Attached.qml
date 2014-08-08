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
    property var _modules: []
    property var _currentModule: null

    onModulesModelChanged: {
        _refreshModules();
    }

    onFunctionsModelChanged: {
        _refreshFunctions();
    }

    function _refreshModules() {
        if (modulesModel) {
            modulesModel.allWithCalls(function (modules) {
                _modules = modules;
            });
        } else {
            _modules = [];
        }
    }

    function _refreshFunctions() {
        if (functionsModel && _currentModule) {
            functionsModel.findByModule(_currentModule.id, function (items) {
                functions.clear();
                items.forEach(function (func) {
                    functions.append(func);
                });
            });
        } else {
            functions.clear();
        }
    }

    orientation: Qt.Horizontal

    ListModel {
        id: functions
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
                    _currentModule = model[currentIndex] || null;
                    _refreshFunctions();
                }

                model: _modules
                textRole: 'name'
            }
            TableView {
                id: functionsView

                onCurrentRowChanged: {
                    var func = model.get(currentRow);
                    if (func) {
                        var address = _bigInt(_currentModule.base).add(_bigInt(func.offset)).toString();
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
