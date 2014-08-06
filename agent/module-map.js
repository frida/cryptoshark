"use strict";

var bigInt = require('big-integer');

module.exports = {
    build: function () {
        return new Promise(function (resolve) {
            var modules = [];
            Process.enumerateModules({
                onMatch: function (mod) {
                    const base = bigInt(mod.base.toString(10));
                    modules.push([base, base.add(mod.size), mod.name]);
                },
                onComplete: function () {
                    resolve(new ModuleMap(modules));
                }
            });
        });
    }
};

function ModuleMap(modules) {
    this._modules = modules;
    this._cache = {};
}

ModuleMap.prototype.resolve = function (address) {
    const cachedResult = this._cache[address];
    if (cachedResult) {
        return cachedResult;
    }

    let result = null;
    const addressValue = typeof address === 'string' ? bigInt(address.substr(2), 16) : bigInt(address.toString(10));
    for (let i = 0; i !== this._modules.length; i++) {
        const entry = this._modules[i];
        const start = entry[0];
        const end = entry[1];
        const name = entry[2];
        if (addressValue.greaterOrEquals(start) && addressValue.lesser(end)) {
            const offset = addressValue.subtract(start).valueOf();
            result = {
                module: name,
                offset: offset
            };
            break;
        }
    }

    this._cache[address] = result;

    return result;
};
