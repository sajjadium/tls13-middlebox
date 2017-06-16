"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");

let prefs = new Preferences({defaultBranch: true});

function getError(xhr) {
    let result = {};

    try {
        result.status = xhr.channel.QueryInterface(Ci.nsIRequest).status;

        let secInfo = xhr.channel.securityInfo;

        if (secInfo instanceof Ci.nsITransportSecurityInfo) {
            secInfo.QueryInterface(Ci.nsITransportSecurityInfo);

            result.securityState = secInfo.securityState;

            if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) === Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
                result.shortSecurityDescription = secInfo.shortSecurityDescription;
                result.errorMessage = secInfo.errorMessage;
            }
        }
    } catch(err) {
        result.exception = err.message;
    }

    return result;
}

function checkTLS(version, url) {
    return new Promise(function(resolve, reject) {
        try {
            prefs.set("security.tls.version.max", version);
            prefs.set("security.tls.version.fallback-limit", version);

            let request = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);

            request.open("GET", url, true);

            request.timeout = 10000;

            request.channel.loadFlags |= Ci.nsIRequest.LOAD_ANONYMOUS;
            request.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
            request.channel.loadFlags |= Ci.nsIRequest.INHIBIT_CACHING;

            request.addEventListener("load", function(e) {
                let result = getError(e.target);
                result.origin = "load";
                resolve(result);
            }, false);

            request.addEventListener("error", function(e) {
                let result = getError(e.target);
                result.origin = "error";
                resolve(result);
            }, false);

            request.addEventListener("abort", function(e) {
                let result = getError(e.target);
                result.origin = "abort";
                resolve(result);
            }, false);

            request.addEventListener("timeout", function(e) {
                let result = getError(e.target);
                result.origin = "timeout";
                resolve(result);
            }, false);

            request.send();
        } catch (err) {
            let result = {};
            result.origin = "exception";
            result.exception = err.message;
            resolve(result);
        }
    });
}

function startup() {}

function shutdown() {}

function install() {
    let current_max = prefs.get("security.tls.version.max");
    let current_fallback = prefs.get("security.tls.version.fallback-limit");

    checkTLS(4, "https://enabled.tls13.com").then(function(error4) {
        checkTLS(3, "https://enabled.tls13.com").then(function(error3) {
            TelemetryController.submitExternalPing("tls13-middlebox", {"1.3": error4, "1.2": error3});

            prefs.set("security.tls.version.max", current_max);
            prefs.set("security.tls.version.fallback-limit", current_fallback);
        });
    });
}

function uninstall() {}
