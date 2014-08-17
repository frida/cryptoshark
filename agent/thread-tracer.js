"use strict";

module.exports = ThreadTracer;

function ThreadTracer(moduleMap) {
    this.handlers = {
        'thread:follow': this.follow,
        'thread:unfollow': this.unfollow,
        'function:add-probe': this.addProbe,
        'function:remove-probe': this.removeProbe,
        'function:update-probe': this.updateProbe
    };
    this._probes = {};
    this._moduleMap = moduleMap;
    Object.freeze(this);
}

ThreadTracer.prototype.follow = function (thread) {
    return new Promise(function (resolve) {
        let threadId = thread.id;
        Stalker.follow(threadId, {
            events: {
                call: true,
                ret: false,
                exec: false
            },
            onCallSummary: function (summary) {
                const enrichedSummary = {};
                for (let address in summary) {
                    if (summary.hasOwnProperty(address)) {
                        enrichedSummary[address] = {
                            symbol: this._moduleMap.symbol(address),
                            count: summary[address]
                        };
                    }
                }
                send({
                    name: 'thread:summary',
                    payload: {
                        thread: {
                            id: threadId
                        },
                        summary: enrichedSummary
                    }
                });
            }.bind(this)
        });
        resolve({});
    }.bind(this));
};

ThreadTracer.prototype.unfollow = function (thread) {
    return new Promise(function (resolve) {
        Stalker.unfollow(thread.id);
        resolve({});
    });
};

ThreadTracer.prototype.addProbe = function (func) {
    return new Promise(function (resolve) {
        let probe = this._probes[func.address];
        if (!probe) {
            let handlerHolder;
            try {
                handlerHolder = [handler(func.script)];
            } catch (e) {
                resolve(-1);
                return;
            }
            const id = Stalker.addCallProbe(ptr(func.address), probeCallback(func.address, handlerHolder));
            probe = {
                id: id,
                handlerHolder: handlerHolder
            };
            this._probes[func.address] = probe;
        }
        resolve(probe.id);
    }.bind(this));
};

ThreadTracer.prototype.removeProbe = function (func) {
    return new Promise(function (resolve) {
        const probe = this._probes[func.address];
        if (probe) {
            Stalker.removeCallProbe(probe.id);
            delete this._probes[func.address];
        }
        resolve(!!probe);
    }.bind(this));
};

ThreadTracer.prototype.updateProbe = function (func) {
    return new Promise(function (resolve) {
        const probe = this._probes[func.address];
        if (probe) {
            try {
                probe.handlerHolder[0] = handler(func.script);
            } catch (e) {
                resolve(false);
                return;
            }
        }
        resolve(!!probe);
    }.bind(this));
};

function handler(script) {
    return new Function('args', 'log', script);
}

function probeCallback(address, handlerHolder) {
    function log() {
        send({
            name: 'function:log',
            payload: {
                address: address,
                message: Array.prototype.slice.call(arguments).map(toString).join(", ")
            }
        });
    }
    function toString(arg) {
        return arg.toString();
    }

    return function (args) {
        handlerHolder[0].call(this, args, log);
    };
}
