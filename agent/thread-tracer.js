"use strict";

module.exports = ThreadTracer;

function ThreadTracer(moduleMap) {
    this.handlers = {
        'thread:follow': this.follow,
        'thread:unfollow': this.unfollow
    };
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
