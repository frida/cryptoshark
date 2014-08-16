"use strict";

const bigInt = require('big-integer');
const mixIn = require('mout/object/mixIn');

module.exports = {
    build: function () {
        return new Promise(function (resolve) {
            const modules = [];
            let index = 0;
            Process.enumerateModules({
                onMatch: function (mod) {
                    modules.push(mixIn({main: index === 0}, mod));
                    index++;
                },
                onComplete: function () {
                    resolve(new ModuleMap(modules));
                }
            });
        });
    }
};

function ModuleMap(modules) {
    modules = resolveCollisions(modules);
    this.modules = modules;
    this._bases = modules.reduce(function (bases, mod) {
        bases[mod.name] = mod.base;
        return bases;
    }, {});
    this._items = modules.map(function (mod) {
        const base = bigInt(mod.base.toString(10));
        return [base, base.add(mod.size), mod.name];
    });
    this._cache = {};
}

ModuleMap.prototype.base = function (name) {
    return this._bases[name] || null;
};

ModuleMap.prototype.symbol = function (address) {
    const cachedResult = this._cache[address];
    if (cachedResult) {
        return cachedResult;
    }

    let result = null;
    const addressValue = typeof address === 'string' ? bigInt(address.substr(2), 16) : bigInt(address.toString(10));
    for (let i = 0; i !== this._items.length; i++) {
        const entry = this._items[i];
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

function resolveCollisions(modules) {
    const nameCounts = modules.reduce(function (names, mod) {
        const count = names[mod.name] || 0;
        names[mod.name] = count + 1;
        return names;
    });
    const pathCounts = modules.reduce(function (paths, mod) {
        const count = paths[mod.path] || 0;
        paths[mod.path] = count + 1;
        return paths;
    });
    const nameIds = {};
    const pathIds = {};
    return modules.map(function (mod) {
        let name = mod.name;
        if (nameCounts[name] > 1) {
            const nameId = nameIds[name] || 1;
            nameIds[name] = nameId + 1;
            name += "_" + nameId;
        }
        let path = mod.path;
        if (pathCounts[path] > 1) {
            const pathId = pathIds[path] || 1;
            pathIds[path] = pathId + 1;
            path += "_" + pathId;
        }
        return mixIn({}, mod, {name: name, path: path});
    });
}
