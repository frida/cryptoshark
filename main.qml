import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Dialogs 1.2
import QtQuick.Window 2.0
import Frida 1.0

import "components"
import "session"

ApplicationWindow {
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
                    agent.instances[0].stop();
                }
            }
            MenuItem {
                text: qsTr("Exit")
                onTriggered: Qt.quit()
            }
        }
    }

    Component.onCompleted: {
        processDialog.open();
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
                when: agent.instances.length > 0 && agent.instances[0].status < 5
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
            Frida.localSystem.inject(agent, process.pid);
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
            threadsModel: threads
            functionsModel: functions
            agentService: agent
        }
    }

    MessageDialog {
        id: errorDialog
    }

    ListModel {
        id: threads
    }

    ListModel {
        id: functions
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

        function _onThreadsUpdate(updatedThreads) {
            updatedThreads.forEach(function (thread) {
                threads.append({id: thread.id, tags: thread.tags.join(', '), status: ''});
            });
        }

        function _onThreadUpdate(updatedThread) {
            var updatedThreadId = updatedThread.id;
            var count = threads.count;
            for (var i = 0; i !== count; i++) {
                var thread = threads.get(i);
                if (thread.id === updatedThreadId) {
                    threads.setProperty(i, 'tags', updatedThread.tags.join(', '));
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
                        index = functions.count;
                        _functions[address] = index;
                        functions.append({
                            name: entry.symbol ? entry.symbol.module + "+0x" + entry.symbol.offset.toString(16) : address,
                            address: address,
                            calls: entry.count,
                            threads: "" + thread.id,
                            symbol: entry.symbol
                        });
                    } else {
                        functions.setProperty(index, 'calls', functions.get(index).calls + entry.count);
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
