"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");

let prefs = new Preferences();

// all combination of configurations we care about.
// for is_tls13 == true we need a server that supports TLS 1.3
// for is_tls13 == false we need a server that DOES NOT support TLS 1.3
let configurations = [
    {max_version: 4, fallback_limit: 4, is_tls13: true, website: "enabled.tls13.com"},
    {max_version: 4, fallback_limit: 4, is_tls13: false, website: "disabled.tls13.com"},
    {max_version: 4, fallback_limit: 3, is_tls13: true, website: "www.allizom.org"},
    {max_version: 4, fallback_limit: 3, is_tls13: false, website: "control.tls12.com"},
    {max_version: 3, fallback_limit: 3, is_tls13: true, website: "localhost:8888"},
    {max_version: 3, fallback_limit: 3, is_tls13: false, website: "short.tls13.com"}
];

// run 
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
        // this is the most important value based on which we can find out the problem
        result.status = xhr.channel.QueryInterface(Ci.nsIRequest).status;

        let secInfo = xhr.channel.securityInfo;

        if (secInfo instanceof Ci.nsITransportSecurityInfo) {
            secInfo.QueryInterface(Ci.nsITransportSecurityInfo);

            result.securityState = secInfo.securityState;

            // Error message on connection failure. I am not sure if we can get this error message using status code.
            // It is safer to collect this information as well.
            result.errorMessage = secInfo.errorMessage;

            // For secure connections (SSL), this gives the common name (CN) of the certifying authority (Privacy Concern?)
            result.shortSecurityDescription = secInfo.shortSecurityDescription;
        }
    } catch(ex) {
        result.exception = ex.message;
    }

    return result;
}

function makeRequest(config) {
    return new Promise(function(resolve, reject) {
        // prepare the result and call the resolve
        function reportResult(origin, xhr) {
            let result = Object.assign({origin: origin}, config);

            if (origin !== "load")
                result = Object.assign(result, getError(xhr));

            resolve(result);
        }

        try {
            // set the configuration to onces that passed to this function
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
        } catch (ex) {
            resolve(Object.assign({origin: "exception", exception: ex.message}, config));
        }
    });
}

function startup() {}

function shutdown() {}

function install() {
    // record the current values before the experiment starts
    let current_max = prefs.get("security.tls.version.max");
    let current_fallback = prefs.get("security.tls.version.fallback-limit");

    testConfigurations().then(result => {
        // restore the old values after experiment finished
        prefs.set("security.tls.version.max", current_max);
        prefs.set("security.tls.version.fallback-limit", current_fallback);

        TelemetryController.submitExternalPing("tls13-middlebox", {value: result});
    });
}

function uninstall() {}
