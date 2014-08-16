"use strict";

module.exports = ModuleMonitor;

function ModuleMonitor(moduleMap) {
    this.handlers = {
        'module:get-functions': this.getFunctions
    };
    this._moduleMap = moduleMap;
    Object.freeze(this);

    this._sendModules(moduleMap.modules);
}

ModuleMonitor.prototype._sendModules = function (modules) {
    send({name: 'modules:update', payload: modules});
};

ModuleMonitor.prototype.getFunctions = function (module) {
    return new Promise(function (resolve) {
        const functions = [];
        const base = this._moduleMap.base(module.name);
        Module.enumerateExports(module.name, {
            onMatch: function (exp) {
                if (exp.type === 'function') {
                    functions.push([exp.name, exp.address.sub(base).toInt32()]);
                }
            },
            onComplete: function () {
                resolve(functions);
            }
        });
    }.bind(this));
};
