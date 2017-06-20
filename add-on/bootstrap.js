"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");

const VERSION_MAX_PREF = "security.tls.version.max";
const FALLBACK_LIMIT_PREF = "security.tls.version.fallback-limit";

let readwrite_prefs = new Preferences({defaultBranch: true});

// all combination of configurations we care about.
// for is_tls13 == true we need a server that supports TLS 1.3
// for is_tls13 == false we need a server that DOES NOT support TLS 1.3
let configurations = [
    {max_version: 4, fallback_limit: 4, is_tls13: true, website: "enabled.tls13.com"},
    {max_version: 4, fallback_limit: 4, is_tls13: false, website: "disabled.tls13.com"},
    {max_version: 4, fallback_limit: 3, is_tls13: true, website: "www.allizom.org"},
    {max_version: 4, fallback_limit: 3, is_tls13: false, website: "control.tls12.com"},
    {max_version: 3, fallback_limit: 3, is_tls13: true, website: "tls13.crypto.mozilla.org"},
    {max_version: 3, fallback_limit: 3, is_tls13: false, website: "short.tls13.com"}
];

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
        function reportResult(event, xhr) {
            let output = Object.assign({result: {event: event}}, config);

            if (event !== "load")
                output.result = Object.assign(output.result, getError(xhr));

            resolve(output);
        }

        try {
            // set the configuration to the values that were passed to this function
            readwrite_prefs.set("security.tls.version.max", config.max_version);
            readwrite_prefs.set("security.tls.version.fallback-limit", config.fallback_limit);

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
            resolve(Object.assign({result: {event: "exception", description: ex.toSource()}}, config));
        }
    });
}

// shuffle the array randomly
function shuffleArray(original_array) {
    let copy_array = original_array.slice();

    let output_array = [];

    while (copy_array.length > 0) {
        let x = Math.floor(Math.random() * copy_array.length);
        output_array.push(copy_array.splice(x, 1)[0]);
    }

    return output_array;
}

// make the request for each configuration
async function runConfigurations() {
    let result = [];

    for (let config of shuffleArray(configurations)) {
        // we wait until the result is ready for the current configuration
        // and then move on to the next configuration
        result.push(await makeRequest(config));
    }

    return result;
}

// check if either of VERSION_MAX_PREF or FALLBACK_LIMIT_PREF was set by the user
function hasUserSetPreference() {
    let readonly_prefs = new Preferences();

    if (readonly_prefs.isSet(VERSION_MAX_PREF) || readonly_prefs.isSet(FALLBACK_LIMIT_PREF)) {
        // reports the current values as well as whether they were set by the user
        TelemetryController.submitExternalPing("tls13-middlebox", {
            max_version: {
                value: readonly_prefs.get(VERSION_MAX_PREF),
                is_userset: readonly_prefs.isSet(VERSION_MAX_PREF)
            },
            fallback_limit: {
                value: readonly_prefs.get(FALLBACK_LIMIT_PREF),
                is_userset: readonly_prefs.isSet(FALLBACK_LIMIT_PREF)
            }
        });

        return true;
    }

    return false;
}

function startup() {}

function shutdown() {}

function install() {
    // abort if either of VERSION_MAX_PREF or FALLBACK_LIMIT_PREF was set by the user
    if (hasUserSetPreference())
        return;

    // record the default values before the experiment starts
    let default_max_version = readwrite_prefs.get(VERSION_MAX_PREF);
    let default_fallback_limit = readwrite_prefs.get(FALLBACK_LIMIT_PREF);

    runConfigurations().then(result => {
        // report the test results
        TelemetryController.submitExternalPing("tls13-middlebox", {
            default_max_version: default_max_version,
            default_fallback_limit: default_fallback_limit,
            tests: result
        });

        // restore the default values after experiment is over
        readwrite_prefs.set(VERSION_MAX_PREF, default_max_version);
        readwrite_prefs.set(FALLBACK_LIMIT_PREF, default_fallback_limit);
    });
}

function uninstall() {}
