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
    // {max_version: 4, fallback_limit: 4, is_tls13: false, website: "disabled.tls13.com"},
    // {max_version: 4, fallback_limit: 3, is_tls13: true, website: "www.allizom.org"},
    // {max_version: 4, fallback_limit: 3, is_tls13: false, website: "control.tls12.com"},
    // {max_version: 3, fallback_limit: 3, is_tls13: true, website: "tls13.crypto.mozilla.org"},
    // {max_version: 3, fallback_limit: 3, is_tls13: false, website: "short.tls13.com"}
];

function getFieldValue(obj, name) {
	try {
		return obj[name];
	} catch (ex) {
		return undefined;
	}
}

function getInfo(xhr) {
    let result = {};

    try {
        let channel = xhr.channel;

        // this is the most important value based on which we can find out the problem
        channel.QueryInterface(Ci.nsIRequest);
        result.status = getFieldValue(channel, 'status');

        let securityInfo = getFieldValue(channel, 'securityInfo');

        if (securityInfo instanceof Ci.nsITransportSecurityInfo) {
            securityInfo.QueryInterface(Ci.nsITransportSecurityInfo);

            result.securityState = getFieldValue(securityInfo, 'securityState');

            // Error message on connection failure. I am not sure if we can get this error message using status code.
            // It is safer to collect this information as well.
            result.errorMessage = getFieldValue(securityInfo, 'errorMessage');
        }

        if (securityInfo instanceof Ci.nsISSLStatusProvider) {
            securityInfo.QueryInterface(Ci.nsISSLStatusProvider);
            let sslStatus = securityInfo.SSLStatus;

            if (sslStatus) {
                sslStatus.QueryInterface(Ci.nsISSLStatus);
                let serverCert = sslStatus.serverCert;

                console.log(sslStatus);
                console.log(serverCert);

                result.certChain = [];

                // extracting the certificate chain including the root CA.
                // if isBuiltInRoot == false, it means there is middlebox on the way
                let cert = serverCert;
                while (cert) {
                	result.certChain.push({
                		certType: getFieldValue(cert, 'certType'),
                		isBuiltInRoot: getFieldValue(cert, 'isBuiltInRoot'),
                		isSelfSigned: getFieldValue(cert, 'isSelfSigned'),
                		keyUsages: getFieldValue(cert, 'keyUsages'),
                		tokenName: getFieldValue(cert, 'tokenName')
                	});

                	cert = getFieldValue(cert, 'issuer');
                }

                // extracting some other info from the connection that are not violating privacy
                result.certificateTransparencyStatus = getFieldValue(sslStatus, 'certificateTransparencyStatus');
                result.cipherName = getFieldValue(sslStatus, 'cipherName');
                result.isDomainMismatch = getFieldValue(sslStatus, 'isDomainMismatch');
                result.isExtendedValidation = getFieldValue(sslStatus, 'isExtendedValidation');
                result.isNotValidAtThisTime = getFieldValue(sslStatus, 'isNotValidAtThisTime');
                result.isUntrusted = getFieldValue(sslStatus, 'isUntrusted');
                result.keyLength = getFieldValue(sslStatus, 'keyLength');
                result.protocolVersion = getFieldValue(sslStatus, 'protocolVersion');
                result.secretKeyLength = getFieldValue(sslStatus, 'secretKeyLength');
            }
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

            output.result = Object.assign(output.result, getInfo(xhr));

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
