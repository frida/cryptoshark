"use strict";

module.exports = ThreadTracer;

function ThreadTracer(moduleMap) {
    this.handlers = {
        'thread:follow': this.follow,
        'thread:unfollow': this.unfollow,
        'function:add-probe': this.addProbe,
        'function:remove-probe': this.removeProbe
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
        let id = this._probes[func.address];
        if (!id) {
            try {
                id = Stalker.addCallProbe(ptr(func.address), probeCallback(func));
            } catch (e) {
                resolve(-1);
                return;
            }
            this._probes[func.address] = id;
        }
        resolve(id);
    }.bind(this));
};

ThreadTracer.prototype.removeProbe = function (func) {
    return new Promise(function (resolve) {
        const id = this._probes[func.address];
        if (id) {
            Stalker.removeCallProbe(id);
            delete this._probes[func.address];
        }
        resolve(typeof id !== 'undefined');
    }.bind(this));
};

function probeCallback(func) {
    const address = func.address;
    const toString = function (arg) {
        return arg.toString();
    };
    function log() {
        send({
            name: 'function:log',
            payload: {
                address: address,
                message: Array.prototype.slice.call(arguments).map(toString).join(", ")
            }
        });
    }

    const handler = new Function('args', 'log', func.script);
    return function (args) {
        handler.call(this, args, log);
    };
}
