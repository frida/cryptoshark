import CryptoShark 1.0

import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Dialogs 1.2
import QtQuick.Window 2.0
import Frida 1.0

import "components"
import "session"

// qmlimportscanner needs to see this one for static linking:
import QtQuick.PrivateWidgets 1.1

ApplicationWindow {
    id: app

    property var _process: null
    property var _models: null

    Component.onCompleted: {
        processDialog.open();
    }

    function attach(device, process) {
        if (_process !== null && process.pid === _process.pid) {
            return;
        }
        _process = process;
        Models.open(process.name);
        _models = Models;
        device.inject(agent, process.pid);
    }

    function detach() {
        loader.item.dispose();
        agent.instances[0].stop();
        _process = null;
        _models.close();
        _models = null;
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
                    processDialog.open();
                }
            }
            MenuItem {
                id: detach
                text: qsTr("Detach")
                onTriggered: {
                    app.detach();
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
                when: !_models || (agent.instances.length > 0 && agent.instances[0].status < 5)
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

    Component {
        id: detachedComponent

        Detached {
            onAttach: {
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
            models: _models
            functionDialog: funcDialog
        }
    }

    ProcessDialog {
        id: processDialog

        onSelected: {
            app.attach(device, process);
        }
    }

    FunctionDialog {
        id: funcDialog

        models: _models
    }

    MessageDialog {
        id: errorDialog
        icon: StandardIcon.Critical;
    }

    ListModel {
        id: _threadsModel
    }

    Script {
        id: agent
        url: Qt.resolvedUrl("./agent.js")
        runtime: Script.Runtime.V8

        property var _requests: Object()
        property var _nextRequestId: 1

        Component.onCompleted: {
            Router.attach(this);
            Router.message.connect(_onMessage);
        }

        onError: {
            errorDialog.text = message;
            errorDialog.open();
        }

        function follow(threadId, callback) {
            _request('thread:follow', { id: threadId }, callback);
        }

        function unfollow(threadId, callback) {
            _request('thread:unfollow', { id: threadId }, callback);
        }

        function disassemble(address, callback) {
            _request('function:disassemble', { address: address }, callback);
        }

        function _request(name, payload, callback) {
            if (callback === undefined) {
                callback = _noop;
            }

            var id = 'a' + _nextRequestId++;
            _requests[id] = callback;
            post({ id: id, name: name, payload: payload });
        }

        function _onResponse(id, type, payload) {
            var callback = _requests[id];
            delete _requests[id];

            var result, error;
            if (type === 'result') {
                result = payload;
                error = null;
            } else {
                result = null;
                error = new Error(payload.message);
                error.stack = payload.stack;
            }

            callback(error, result);
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

        function _onMessage(object) {
            if (object.type === 'send') {
                var stanza = object.payload;
                var name = stanza.name;
                var payload = stanza.payload;

                switch (name) {
                    case 'threads:update':
                        _onThreadsUpdate(payload);
                        break;
                    case 'thread:update':
                        _onThreadUpdate(payload);
                        break;
                    case 'result':
                    case 'error':
                        _onResponse(stanza.id, name, payload);
                        break;
                    default:
                         console.log('Unhandled: ' + JSON.stringify(stanza));
                         break;
                }
            } else {
                console.log('ERROR: ' + JSON.stringify(object));
            }
        }

        function _noop() {
        }
    }
}
