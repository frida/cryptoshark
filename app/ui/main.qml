import Cryptoshark 1.0

import QtQuick 2.0
import QtQuick.Controls 2.3
import Qt.labs.platform 1.1
import Qt.labs.qmlmodels 1.0
import Frida 1.0

import "components"
import "session"

ApplicationWindow {
    id: app

    property var _state: "detached"
    property var _endReason: null
    property var _models: null

    function spawn(device, program, options) {
        _endReason = null;

        let name = program;
        const slashStart = name.lastIndexOf("/");
        if (slashStart !== -1) {
            name = program.substr(slashStart + 1);
        }
        Models.open(name);
        _models = Models;

        device.inject(agent, program, options);
    }

    function attach(device, process) {
        _endReason = null;

        Models.open(process.name);
        _models = Models;

        device.inject(agent, process.pid);
    }

    function endSession() {
        if (agent.instances.length > 0)
            agent.instances[0].stop();
        _endReason = null;
        _models.close();
        _models = null;
    }

    title: qsTr("Cryptoshark")
    width: 1024
    height: 633
    visible: true

    MenuBar {
        Menu {
            title: qsTr("File")
            MenuItem {
                id: attachItem
                text: qsTr("Attach…")
                onTriggered: processDialog.open()
            }
            MenuItem {
                id: spawnItem
                text: qsTr("Spawn…")
                onTriggered: programDialog.open()
            }
            MenuItem {
                id: closeItem
                text: qsTr("Close")
                onTriggered: app.endSession()
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
                name: "detached"
                when: _models === null
                PropertyChanges { target: app; _state: "detached" }
                PropertyChanges { target: attachItem; enabled: true }
                PropertyChanges { target: spawnItem; enabled: true }
                PropertyChanges { target: closeItem; enabled: false }
                PropertyChanges { target: loader; sourceComponent: detachedComponent }
            },
            State {
                name: "attaching"
                when: agent.instances.length > 0 && agent.instances[0].status < ScriptInstance.Status.Started
                PropertyChanges { target: app; _state: "attaching" }
                PropertyChanges { target: attachItem; enabled: false }
                PropertyChanges { target: spawnItem; enabled: false }
                PropertyChanges { target: closeItem; enabled: false }
                PropertyChanges { target: loader; sourceComponent: attachingComponent }
            },
            State {
                name: "attached"
                when: (agent.instances.length > 0 && agent.instances[0].status === ScriptInstance.Status.Started) ||
                      (agent.instances.length === 0 && _models !== null)
                PropertyChanges { target: app; _state: "attached" }
                PropertyChanges { target: attachItem; enabled: false }
                PropertyChanges { target: spawnItem; enabled: false }
                PropertyChanges { target: closeItem; enabled: true }
                PropertyChanges { target: loader; sourceComponent: attachedComponent }
            }
        ]
    }

    Component {
        id: detachedComponent

        Detached {
            onAttach: processDialog.open()
            onSpawn: programDialog.open()
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
            endReason: _endReason
            agentService: agent
            threadsModel: _threadsModel
            models: _models
            functionDialog: funcDialog
        }
    }

    ProgramDialog {
        id: programDialog

        onSelected: app.spawn(device, program, options)
    }

    ProcessDialog {
        id: processDialog

        onSelected: app.attach(device, process)
    }

    FunctionDialog {
        id: funcDialog

        models: _models
    }

    TableModel {
        id: _threadsModel

        TableModelColumn { display: "status" }
        TableModelColumn { display: "id" }
        TableModelColumn { display: "tags" }
    }

    Script {
        id: agent
        url: Qt.resolvedUrl("../agent.js")
        runtime: Script.Runtime.V8

        property var _requests: Object()
        property var _nextRequestId: 1
        property var _radareRequests: ({})

        Component.onCompleted: {
            Router.attach(this);
            Router.message.connect(_onMessage);
            radare.executeResponse.connect(_onRadareResponse);
        }

        onError: {
            _endReason = message;
        }

        function follow(threadId, callback) {
            _request("thread:follow", [ threadId ], callback);
        }

        function unfollow(threadId, callback) {
            _request("thread:unfollow", [ threadId ], callback);
        }

        function disassemble(func, callback) {
            executeRadareCommand([
                "s 0x" + func.address.toString(16),
                "af-",
                "af",
                "afn base64:" + Qt.btoa(func.name),
                "pdf",
            ].join("; "), callback);
        }

        function executeRadareCommand(command, callback) {
            const id = radare.execute(command);
            _radareRequests[id] = callback;
        }

        function _onRadareResponse(response, requestId) {
            const callback = _radareRequests[requestId];
            if (callback === undefined)
                return;
            delete _radareRequests[requestId];
            callback(response);
        }

        function _request(name, args, callback = _noop) {
            const id = "a" + _nextRequestId++;
            _requests[id] = callback;
            post([
                "frida:rpc",
                id,
                "call",
                name,
                args
            ]);
        }

        function _tryHandleRpcReply(params, data) {
            if (params.length < 4 || params[0] !== "frida:rpc")
                return false;

            const id = params[1];
            const callback = _requests[id];
            if (callback === undefined)
                return true;
            delete _requests[id];

            const type = params[2];
            if (type === "ok") {
                if (data === undefined)
                    callback(null, params[3]);
                else
                    callback(null, data);
            } else {
                const e = new Error(params[3]);
                e.name = params[4];
                e.stack = params[5];
                callback(e, null);
            }

            return true;
        }

        function _tryHandleStanza(stanza) {
            const { name, payload } = stanza;

            switch (name) {
                case "threads:update":
                    _onThreadsUpdate(payload);
                    break;
                case "thread:update":
                    _onThreadUpdate(payload);
                    break;
                default:
                    return false;
            }

            return true;
        }

        function _onThreadsUpdate(updatedThreads) {
            _threadsModel.clear();
            updatedThreads.forEach(thread => {
                _threadsModel.appendRow({ id: thread.id, tags: thread.tags.join(", "), status: "" });
            });
        }

        function _onThreadUpdate(updatedThread) {
            const updatedThreadId = updatedThread.id;
            let i = 0;
            for (const thread of _threadsModel.rows) {
                if (thread.id === updatedThreadId) {
                    _threadsModel.setData(_threadsModel.index(i, 2), "display", updatedThread.tags.join(", "));
                    break;
                }
                i++;
            }
        }

        function _onMessage(message, data) {
            if (message.type === "send") {
                const p = message.payload;

                let handled;
                if (p instanceof Array)
                    handled = _tryHandleRpcReply(p, data);
                else
                    handled = _tryHandleStanza(p);

                if (!handled)
                    console.log("Unhandled: " + JSON.stringify(p));
            } else {
                console.log("ERROR: " + JSON.stringify(message));
            }
        }

        function _noop() {
        }
    }
}
