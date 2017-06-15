"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");

let prefs = new Preferences({defaultBranch: true});

function getSecurityInfo(xhr) {
    let result = {};

    try {
        let secInfo = xhr.channel.securityInfo;

        if (secInfo instanceof Ci.nsITransportSecurityInfo) {
            secInfo.QueryInterface(Ci.nsITransportSecurityInfo);

            result.securityStateCode = secInfo.securityState;

            if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) === Ci.nsIWebProgressListener.STATE_IS_SECURE) {
                result.securityStateMessage = "STATE_IS_SECURE";
            } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) === Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
                result.securityStateMessage = "STATE_IS_INSECURE";
            } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) === Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
                result.securityStateMessage = "STATE_IS_BROKEN";
                result.shortSecurityDescription = secInfo.shortSecurityDescription;
                result.errorMessage = secInfo.errorMessage;
            }
        }

        if (secInfo instanceof Ci.nsISSLStatusProvider) {
            let sslStatus = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;

            if (sslStatus) {
                let cert = sslStatus.QueryInterface(Ci.nsISSLStatus).serverCert;

                result.cert = {};

                result.cert.commonName = cert.commonName;
                result.cert.issuerOrganization = cert.issuerOrganization;
                result.cert.organization = cert.organization;
                result.cert.sha1Fingerprint = cert.sha1Fingerprint;

                result.cert.validity = {};
                var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
                result.cert.validity.notBeforeGMT = validity.notBeforeGMT;
                result.cert.validity.notAfterGMT = validity.notAfterGMT;
            }
        }
    } catch(err) {
        result.exception = err.message;
    }

    return result;
}

function checkTLS(version) {
    return new Promise(function(resolve, reject) {
        prefs.set("security.tls.version.max", version);
        prefs.set("security.tls.version.fallback-limit", version);

        try {
            let request = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);

            request.open("GET", "https://enabled.tls13.com/", true);

            request.timeout = 10000;

            request.channel.loadFlags |= Ci.nsIRequest.LOAD_ANONYMOUS;
            request.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
            request.channel.loadFlags |= Ci.nsIRequest.INHIBIT_CACHING;

            request.addEventListener("load", function(e) {
                resolve({"origin": "load"});
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

    checkTLS(4).then(function(error4) {
        checkTLS(3).then(function(error3) {
            error3.version = 3;
            TelemetryController.submitExternalPing("tls13-middlebox", error3);
        });
    });
}

function uninstall() {}
