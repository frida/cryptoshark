"use strict";

module.exports = ThreadProber;

function ThreadProber(moduleMap) {
    this.handlers = {
        'thread:probe': this.probe
    };
    this._moduleMap = moduleMap;
    Object.freeze(this);
}

ThreadProber.prototype.probe = function (thread) {
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
                            symbol: this._moduleMap.resolve(address),
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
