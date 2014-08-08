import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Dialogs 1.2
import QtQuick.LocalStorage 2.0
import QtQuick.Window 2.0
import Frida 1.0

import "components"
import "session"
import "models.js" as Models

ApplicationWindow {
    id: app

    property var _modulesModel: null
    property var _functionsModel: null

    property var _process: null
    property var _loadingModels: false

    Component.onCompleted: {
        Models.modules.listen(_onModulesChange);
        Models.functions.listen(_onFunctionsChange);
        processDialog.open();
    }

    function attach(process) {
        if (_process !== null && process.pid === _process.pid) {
            return;
        }
        _process = process;
        _loadingModels = true;
        Models.open(process, function () {
            _loadingModels = false;
            Frida.localSystem.inject(agent, process.pid);
        });
    }

    function detach() {
        agent.instances[0].stop();
        _process = null;
        Models.close();
    }

    function _onModulesChange() {
        _modulesModel = null;
        _modulesModel = Models.modules;
    }

    function _onFunctionsChange() {
        _functionsModel = null;
        _functionsModel = Models.functions;
    }

    title: qsTr("CryptoShark")
    width: 640
    height: 480
    visible: true

    menuBar: MenuBar {
        Menu {
            title: qsTr("File")
            MenuItem {
                id: attach
                text: qsTr("Attach")
                onTriggered: {
                    processModel.refresh();
                    processDialog.open();
                }
            }
            MenuItem {
                id: detach
                text: qsTr("Detach")
                onTriggered: {
                    detach();
                }
            }
            MenuItem {
                text: qsTr("Exit")
                onTriggered: Qt.quit()
            }
        }
    }

    Loader {
        id: loader
        anchors.fill: parent
        sourceComponent: detachedComponent

        states: [
            State {
                name: 'detached'
                when: agent.instances.length === 0 || agent.instances[0].status > 5
                PropertyChanges { target: attach; enabled: true }
                PropertyChanges { target: detach; enabled: false }
                PropertyChanges { target: loader; sourceComponent: detachedComponent }
            },
            State {
                name: 'attaching'
                when: _loadingModels || (agent.instances.length > 0 && agent.instances[0].status < 5)
                PropertyChanges { target: attach; enabled: false }
                PropertyChanges { target: detach; enabled: false }
                PropertyChanges { target: loader; sourceComponent: attachingComponent }
            },
            State {
                name: 'attached'
                when: agent.instances.length > 0 && agent.instances[0].status === 5
                PropertyChanges { target: attach; enabled: false }
                PropertyChanges { target: detach; enabled: true }
                PropertyChanges { target: loader; sourceComponent: attachedComponent }
            }
        ]
    }

    ProcessDialog {
        id: processDialog

        onSelected: {
            app.attach(process);
        }

        model: processModel
    }

    Component {
        id: detachedComponent

        Detached {
            onAttach: {
                processModel.refresh();
                processDialog.open();
           }
        }
    }

    Component {
        id: attachingComponent

        Attaching {
        }
    }

    Component {
        id: attachedComponent

        Attached {
            agentService: agent
            threadsModel: _threadsModel
            modulesModel: _modulesModel
            functionsModel: _functionsModel
        }
    }

    MessageDialog {
        id: errorDialog
    }

    ListModel {
        id: _threadsModel
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
        id: agent
        url: Qt.resolvedUrl("./agent.js")

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

        function _onThreadsUpdate(updatedThreads) {
            _threadsModel.clear();
            updatedThreads.forEach(function (thread) {
                _threadsModel.append({id: thread.id, tags: thread.tags.join(', '), status: ''});
            });
        }

        function _onThreadUpdate(updatedThread) {
            var updatedThreadId = updatedThread.id;
            var count = _threadsModel.count;
            for (var i = 0; i !== count; i++) {
                var thread = _threadsModel.get(i);
                if (thread.id === updatedThreadId) {
                    _threadsModel.setProperty(i, 'tags', updatedThread.tags.join(', '));
                    break;
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
                    case 'modules:update':
                        Models.modules.update(payload);
                        break;
                    case 'threads:update':
                        _onThreadsUpdate(payload);
                        break;
                    case 'thread:update':
                        _onThreadUpdate(payload);
                        break;
                     case 'thread:summary':
                         Models.functions.update(payload);
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
