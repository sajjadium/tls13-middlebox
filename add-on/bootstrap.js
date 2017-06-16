"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");

let prefs = new Preferences({defaultBranch: true});

let configurations = [
    {max_version: 4, fallback_limit: 4, is_tls13: true, website: "enabled.tls13.com"},
    {max_version: 4, fallback_limit: 4, is_tls13: false, website: "disabled.tls13.com"},
    {max_version: 4, fallback_limit: 3, is_tls13: true, website: "www.allizom.org"},
    {max_version: 4, fallback_limit: 3, is_tls13: false, website: "control.tls12.com"},
    {max_version: 3, fallback_limit: 3, is_tls13: true, website: "enabled.tls13.com"},
    {max_version: 3, fallback_limit: 3, is_tls13: false, website: "short.tls13.com"}
];

async function testConfigurations() {
    let output = [];

    for (let config of configurations) {
        output.push(await makeRequest(config));
    }

    return output;
}

function getError(xhr) {
    let result = {};

    try {
        result.status = xhr.channel.QueryInterface(Ci.nsIRequest).status;

        let secInfo = xhr.channel.securityInfo;

        if (secInfo instanceof Ci.nsITransportSecurityInfo) {
            secInfo.QueryInterface(Ci.nsITransportSecurityInfo);

            result.securityState = secInfo.securityState;
            result.errorMessage = secInfo.errorMessage;

            // For secure connections (SSL), this gives the common name (CN) of the certifying authority (Privacy Concern?)
            result.shortSecurityDescription = secInfo.shortSecurityDescription;
        }
    } catch(err) {
        result.exception = err.message;
    }

    return result;
}

function makeRequest(config) {
    return new Promise(function(resolve, reject) {
        function reportResult(origin, xhr) {
            let result = Object.assign({origin: origin}, config);

            if (origin !== "load")
                result = Object.assign(result, getError(xhr));

            resolve(result);
        }

        try {
            prefs.set("security.tls.version.max", config.max_version);
            prefs.set("security.tls.version.fallback-limit", config.fallback_limit);

            let xhr = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);

            xhr.open("GET", "https://" + config.website, true);

            xhr.timeout = 10000;

            xhr.channel.loadFlags |= Ci.nsIRequest.LOAD_ANONYMOUS;
            xhr.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
            xhr.channel.loadFlags |= Ci.nsIRequest.INHIBIT_CACHING;

            xhr.addEventListener("load", function(e) {
                reportResult("load", e.target);
            }, false);

            xhr.addEventListener("error", function(e) {
                reportResult("error", e.target);
            }, false);

            xhr.addEventListener("abort", function(e) {
                reportResult("abort", e.target);
            }, false);

            xhr.addEventListener("timeout", function(e) {
                reportResult("timeout", e.target);
            }, false);

            xhr.send();
        } catch (err) {
            resolve(Object.assign({origin: "exception", exception: err.message}, config));
        }
    });
}

function startup() {}

function shutdown() {}

function install() {
    let current_max = prefs.get("security.tls.version.max");
    let current_fallback = prefs.get("security.tls.version.fallback-limit");

    testConfigurations().then(result => {
        prefs.set("security.tls.version.max", current_max);
        prefs.set("security.tls.version.fallback-limit", current_fallback);

        TelemetryController.submitExternalPing("tls13-middlebox", result);

        console.log(result);
    });
}

function uninstall() {}
