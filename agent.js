(function(){"use strict";var e=1e7,r=7,n={positive:!1,negative:!0},t=function(e,r){for(var n=e.value,t=r.value,i=n.length>t.length?n.length:t.length,u=0;i>u;u++)n[u]=n[u]||0,t[u]=t[u]||0;for(var u=i-1;u>=0&&(0===n[u]&&0===t[u]);u--)n.pop(),t.pop();n.length||(n=[0],t=[0]),e.value=n,r.value=t},i=function(e,u){if("object"==typeof e)return e;e+="";var o=n.positive,v=[];"-"===e[0]&&(o=n.negative,e=e.slice(1));var e=e.split("e");if(e.length>2)throw new Error("Invalid integer");if(e[1]){var s=e[1];if("+"===s[0]&&(s=s.slice(1)),s=i(s),s.lesser(0))throw new Error("Cannot include negative exponent part for integers");for(;s.notEquals(0);)e[0]+="0",s=s.prev()}e=e[0],"-0"===e&&(e="0");var l=/^([0-9][0-9]*)$/.test(e);if(!l)throw new Error("Invalid integer");for(;e.length;){var f=e.length>r?e.length-r:0;v.push(+e.slice(f)),e=e.slice(0,f)}var c=a(v,o);return u&&t(u,c),c},u=function(e,r){var e=a(e,n.positive),r=a(r,n.positive);if(e.equals(0))throw new Error("Cannot divide by 0");var t=0;do{for(var i=1,u=a(e.value,n.positive),o=u.times(10);o.lesser(r);)u=o,i*=10,o=o.times(10);for(;u.lesserOrEquals(r);)r=r.minus(u),t+=i}while(e.lesserOrEquals(r));return{remainder:r.value,result:t}},a=function(s,l){var f={value:s,sign:l},c={value:s,sign:l,negate:function(e){var r=e||f;return a(r.value,!r.sign)},abs:function(e){var r=e||f;return a(r.value,n.positive)},add:function(r,u){var o,v,s=f;if(u?(s=i(r))&&(v=i(u)):v=i(r,s),o=s.sign,s.sign!==v.sign)return s=a(s.value,n.positive),v=a(v.value,n.positive),o===n.positive?c.subtract(s,v):c.subtract(v,s);t(s,v);for(var l=s.value,g=v.value,p=[],h=0,d=0;d<l.length||h>0;d++){var m=(l[d]||0)+(g[d]||0)+h;h=m>=e?1:0,m-=h*e,p.push(m)}return a(p,o)},plus:function(e,r){return c.add(e,r)},subtract:function(r,t){var u,o=f;if(t?(o=i(r))&&(u=i(t)):u=i(r,o),o.sign!==u.sign)return c.add(o,c.negate(u));if(o.sign===n.negative)return c.subtract(c.negate(u),c.negate(o));if(-1===c.compare(o,u))return c.negate(c.subtract(u,o));for(var v=o.value,s=u.value,l=[],g=0,p=0;p<v.length;p++){var h=v[p]-g;g=h<s[p]?1:0;var d=g*e+h-s[p];l.push(d)}return a(l,n.positive)},minus:function(e,r){return c.subtract(e,r)},multiply:function(r,n){var t,u,o=f;n?(o=i(r))&&(u=i(n)):u=i(r,o),t=o.sign!==u.sign;for(var v=o.value,s=u.value,l=[],c=0;c<v.length;c++){l[c]=[];for(var g=c;g--;)l[c].push(0)}for(var p=0,c=0;c<v.length;c++)for(var h=v[c],g=0;g<s.length||p>0;g++){var d=s[g],m=d?h*d+p:p;p=m>e?Math.floor(m/e):0,m-=p*e,l[c].push(m)}for(var w=-1,c=0;c<l.length;c++){var b=l[c].length;b>w&&(w=b)}for(var q=[],p=0,c=0;w>c||p>0;c++){for(var E=p,g=0;g<l.length;g++)E+=l[g][c]||0;p=E>e?Math.floor(E/e):0,E-=p*e,q.push(E)}return a(q,t)},times:function(e,r){return c.multiply(e,r)},divmod:function(e,r){var t,o,v=f;if(r?(v=i(e))&&(o=i(r)):o=i(e,v),t=v.sign!==o.sign,a(v.value,v.sign).equals(0))return{quotient:a([0],n.positive),remainder:a([0],n.positive)};if(o.equals(0))throw new Error("Cannot divide by zero");for(var s=v.value,l=o.value,c=[],g=[],p=s.length-1;p>=0;p--){var e=[s[p]].concat(g),h=u(l,e);c.push(h.result),g=h.remainder}return c.reverse(),{quotient:a(c,t),remainder:a(g,v.sign)}},divide:function(e,r){return c.divmod(e,r).quotient},over:function(e,r){return c.divide(e,r)},mod:function(e,r){return c.divmod(e,r).remainder},remainder:function(e,r){return c.mod(e,r)},pow:function(e,r){var n,t=f;r?(t=i(e))&&(n=i(r)):n=i(e,t);var u=t,s=n;if(a(u.value,u.sign).equals(0))return o;if(s.lesser(0))return o;if(s.equals(0))return v;var l=a(u.value,u.sign);if(s.mod(2).equals(0)){var c=l.pow(s.over(2));return c.times(c)}return l.times(l.pow(s.minus(1)))},next:function(e){var r=e||f;return c.add(r,1)},prev:function(e){var r=e||f;return c.subtract(r,1)},compare:function(e,r){var u,a=f;if(r?(a=i(e))&&(u=i(r,a)):u=i(e,a),t(a,u),1===a.value.length&&1===u.value.length&&0===a.value[0]&&0===u.value[0])return 0;if(u.sign!==a.sign)return a.sign===n.positive?1:-1;for(var o=a.sign===n.positive?1:-1,v=a.value,s=u.value,l=v.length-1;l>=0;l--){if(v[l]>s[l])return 1*o;if(s[l]>v[l])return-1*o}return 0},compareTo:function(e,r){return c.compare(e,r)},compareAbs:function(e,r){var t,u=f;return r?(u=i(e))&&(t=i(r,u)):t=i(e,u),u.sign=t.sign=n.positive,c.compare(u,t)},equals:function(e,r){return 0===c.compare(e,r)},notEquals:function(e,r){return!c.equals(e,r)},lesser:function(e,r){return c.compare(e,r)<0},greater:function(e,r){return c.compare(e,r)>0},greaterOrEquals:function(e,r){return c.compare(e,r)>=0},lesserOrEquals:function(e,r){return c.compare(e,r)<=0},isPositive:function(e){var r=e||f;return r.sign===n.positive},isNegative:function(e){var r=e||f;return r.sign===n.negative},isEven:function(e){var r=e||f;return r.value[0]%2===0},isOdd:function(e){var r=e||f;return r.value[0]%2===1},toString:function(t){for(var i=t||f,u="",a=i.value.length;a--;)u+=8===i.value[a].toString().length?i.value[a]:(e.toString()+i.value[a]).slice(-r);for(;"0"===u[0];)u=u.slice(1);if(u.length||(u="0"),"0"===u)return u;var o=i.sign===n.positive?"":"-";return o+u},toJSNumber:function(e){return+c.toString(e)},valueOf:function(e){return c.toJSNumber(e)}};return c},o=a([0],n.positive),v=a([1],n.positive),s=a([1],n.negative),l=function(e,r){function n(e){var r=e[t].toLowerCase();if(0===t&&"-"===e[t])return void(v=!0);if(/[0-9]/.test(r))a.push(i(r));else if(/[a-z]/.test(r))a.push(i(r.charCodeAt(0)-87));else{if("<"!==r)throw new Error(r+" is not a valid character");var n=t;do t++;while(">"!==e[t]);a.push(i(e.slice(n+1,t)))}}r=i(r);var t,u=o,a=[],v=!1;for(t=0;t<e.length;t++)n(e);for(a.reverse(),t=0;t<a.length;t++)u=u.add(a[t].times(r.pow(t)));return v?-u:u},f=function(e,r){return"undefined"==typeof e?o:"undefined"!=typeof r?l(e,r):i(e)};f.zero=o,f.one=v,f.minusOne=s,Object.defineProperty(this,"bigInt",{enumerable:!0,value:f})}).call(this);

(function () {
    "use strict";

    const moduleMap = [];
    const addrCache = {};

    function onEvent(event) {
        if (event.name === 'thread:probe') {
            let threadId = event.thread.id;
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
                                symbol: resolveModuleAddress(address),
                                count: summary[address]
                            };
                        }
                    }
                    send({name: 'thread:summary', thread: {id: threadId}, summary: enrichedSummary});
                }
            });
        }

        recv(onEvent);
    }
    recv(onEvent);

    initModuleMap()
    .then(sendThreads)
    .then(function () {
        let apis = [
            {
                module: {
                    "windows": "ws2_32.dll",
                    "darwin": "libSystem.B.dylib",
                    "linux": "libc-2.19.so"
                },
                functions: [
                    "connect",
                    "recv",
                    "send",
                    "read",
                    "write"
                ],
                onEnter: function (args) {
                    const fd = args[0].toInt32();
                    switch (Socket.type(fd)) {
                        case 'tcp':
                        case 'udp':
                        case 'tcp6':
                        case 'udp6':
                            return 'net';
                        case 'unix:stream':
                        case 'unix:dgram':
                            return 'ipc';
                        default:
                            return 'file';
                    }
                }
            },
            {
                module: {
                    "darwin": "libcommonCrypto.dylib"
                },
                functions: [
                    "CCCryptor"
                ],
                onEnter: function () {
                    return 'crypto';
                }
            },
            {
                module: {
                    "darwin": "CoreGraphics"
                },
                functions: [
                    "CGContextDrawImage"
                ],
                onEnter: function () {
                    return 'gui';
                }
            }
        ];
        monitor(apis);
    });

    function initModuleMap() {
        return new Promise(function (resolve) {
            Process.enumerateModules({
                onMatch: function (mod) {
                    const base = bigInt(mod.base.toString(10));
                    moduleMap.push([base, base.add(mod.size), mod.name]);
                },
                onComplete: function () {
                    resolve();
                }
            });
        });
    }

    function resolveModuleAddress(address) {
        const cachedResult = addrCache[address];
        if (cachedResult) {
            return cachedResult;
        }

        let result = null;
        const addressValue = typeof address === 'string' ? bigInt(address.substr(2), 16) : bigInt(address.toString(10));
        for (let i = 0; i !== moduleMap.length; i++) {
            const entry = moduleMap[i];
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

        addrCache[address] = result;

        return result;
    }

    function sendThreads() {
        return new Promise(function (resolve) {
            const threads = [];
            Process.enumerateThreads({
                onMatch: function (thread) {
                    threads.push({id: thread.id, tags: []});
                },
                onComplete: function () {
                    send({name: 'threads:update', threads: threads});
                    resolve();
                }
            });
        });
    }

    function monitor(apis) {
        apis.forEach(function (api) {
            const moduleName = api.module[Process.platform];
            if (!moduleName) {
                return;
            }

            const callbacks = {};
            if (api.onEnter) {
                callbacks.onEnter = function (args) {
                    invokeApiHandler.call(this, api.onEnter, args);
                };
            }
            if (api.onLeave) {
                callbacks.onLeave = function (retval) {
                    invokeApiHandler.call(this, api.onLeave, retval);
                };
            }

            Module.enumerateExports(moduleName, {
                onMatch: function (exp) {
                    if (exp.type === 'function' && isApiFunction(exp.name)) {
                        Interceptor.attach(exp.address, callbacks);
                    }
                },
                onComplete: function () {
                }
            });

            function isApiFunction(name) {
                return api.functions.some(function (f) {
                    return name.indexOf(f) === 0;
                });
            }
        });
    }

    const threadTags = {};
    function invokeApiHandler(handler, data) {
        const tag = handler(data);
        if (tag) {
            const threadId = this.threadId;
            let tags = threadTags[threadId];
            if (!tags) {
                tags = [];
                threadTags[threadId] = tags;
            }
            if (tags.indexOf(tag) === -1) {
                tags.push(tag);
                send({name: 'thread:update', thread: {id: threadId, tags: tags}});
            }
        }
    }
}).call(this);
