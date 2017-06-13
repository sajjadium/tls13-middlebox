"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");
Cu.import("resource://gre/modules/Task.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/AppConstants.jsm");

let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(Ci.nsINSSErrorsService);
let nativeJSON = Cc["@mozilla.org/dom/json;1"].createInstance(Ci.nsIJSON);

function getError(xhr) {
    let result = {};

    try {
        result.errorCode = xhr.channel.QueryInterface(Ci.nsIRequest).status;

        if ((result.errorCode & 0xff0000) === 0x5a0000) {
            let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(Ci.nsINSSErrorsService);

            try {
                let errorClass = nssErrorsService.getErrorClass(result.errorCode);

                if (errorClass === Ci.nsINSSErrorsService.ERROR_CLASS_BAD_CERT) {
                    result.errorClass = 'CERTIFICATE';
                } else {
                    result.errorClass = 'PROTOCOL';
                }
            } catch (ex) {
                result.errorClass = 'PROTOCOL';
            }

            // NSS_SEC errors (happen below the base value because of negative vals)
            if ((result.errorCode & 0xffff) < Math.abs(Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE)) {
                // The bases are actually negative, so in our positive numeric space, we
                // need to subtract the base off our value.
                let nssErr = Math.abs(Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE) - (result.errorCode & 0xffff);

                switch (nssErr) {
                    case 11: // SEC_ERROR_EXPIRED_CERTIFICATE, sec(11)
                        result.errorMessage = 'SEC_ERROR_EXPIRED_CERTIFICATE';
                        break;
                    case 12: // SEC_ERROR_REVOKED_CERTIFICATE, sec(12)
                        result.errorMessage = 'SEC_ERROR_REVOKED_CERTIFICATE';
                        break;
                    case 13: // SEC_ERROR_UNKNOWN_ISSUER, sec(13)
                        result.errorMessage = 'SEC_ERROR_UNKNOWN_ISSUER';
                        break;
                    case 20: // SEC_ERROR_UNTRUSTED_ISSUER, sec(20)
                        result.errorMessage = 'SEC_ERROR_UNTRUSTED_ISSUER';
                        break;
                    case 21: // SEC_ERROR_UNTRUSTED_CERT, sec(21)
                        result.errorMessage = 'SEC_ERROR_UNTRUSTED_CERT';
                        break;
                    case 36: // SEC_ERROR_CA_CERT_INVALID, sec(36)
                        result.errorMessage = 'SEC_ERROR_CA_CERT_INVALID';
                        break;
                    case 90: // SEC_ERROR_INADEQUATE_KEY_USAGE, sec(90)
                        result.errorMessage = 'SEC_ERROR_INADEQUATE_KEY_USAGE';
                        break;
                    case 176: // SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED, sec(176)
                        result.errorMessage = 'SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED';
                        break;
                    default:
                        result.errorMessage = 'SEC_ERROR_OTHER';
                        break;
                }
            } else {
                let sslErr = Math.abs(Ci.nsINSSErrorsService.NSS_SSL_ERROR_BASE) - (result.errorCode & 0xffff);

                switch (sslErr) {
                    case 3: // SSL_ERROR_NO_CERTIFICATE, ssl(3)
                        result.errorMessage = 'SSL_ERROR_NO_CERTIFICATE';
                        break;
                    case 4: // SSL_ERROR_BAD_CERTIFICATE, ssl(4)
                        result.errorMessage = 'SSL_ERROR_BAD_CERTIFICATE';
                        break;
                    case 8: // SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE, ssl(8)
                        result.errorMessage = 'SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE';
                        break;
                    case 9: // SSL_ERROR_UNSUPPORTED_VERSION, ssl(9)
                        result.errorMessage = 'SSL_ERROR_UNSUPPORTED_VERSION';
                        break;
                    case 12: // SSL_ERROR_BAD_CERT_DOMAIN, ssl(12)
                        result.errorMessage = 'SSL_ERROR_BAD_CERT_DOMAIN';
                        break;
                    default:
                        result.errorMessage = 'SSL_ERROR_OTHER';
                        break;
                }
            }
        } else {
            result.errorClass = 'NETWORK';

            switch (result.errorCode) {
                // connect to host:port failed
                case 0x804B000C: // NS_ERROR_CONNECTION_REFUSED, network(13)
                    result.errorMessage = 'NS_ERROR_CONNECTION_REFUSED';
                    break;
                // network timeout error
                case 0x804B000E: // NS_ERROR_NET_TIMEOUT, network(14)
                    result.errorMessage = 'NS_ERROR_NET_TIMEOUT';
                    break;
                // hostname lookup failed
                case 0x804B001E: // NS_ERROR_UNKNOWN_HOST, network(30)
                    result.errorMessage = 'NS_ERROR_UNKNOWN_HOST';
                    break;
                case 0x804B0047: // NS_ERROR_NET_INTERRUPT, network(71)
                    result.errorMessage = 'NS_ERROR_NET_INTERRUPT';
                    break;
                default:
                    result.errorMessage = 'NS_ERROR_OTHER';
                    break;
            }
        }

        let secInfo = xhr.channel.securityInfo;

        if (secInfo instanceof Ci.nsITransportSecurityInfo) {
            secInfo.QueryInterface(Ci.nsITransportSecurityInfo);

            result.securityState = secInfo.securityState;

            if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE) === Ci.nsIWebProgressListener.STATE_IS_SECURE) {
                result.securityStateDesc = "STATE_IS_SECURE";
            } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE) === Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
                result.securityStateDesc = "STATE_IS_INSECURE";
            } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN) === Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
                result.securityStateDesc = "STATE_IS_BROKEN";
                result.shortSecurityDescription = secInfo.shortSecurityDescription;
                result.errorMessage = secInfo.errorMessage;
            }
        }

        if (secInfo instanceof Ci.nsISSLStatusProvider) {
            var cert = secInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus.QueryInterface(Ci.nsISSLStatus).serverCert;

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
    } catch(err) {
        result.exception = err.message;
    }

    return result;
}

function checkTLS(version) {
  return new Promise(function(resolve, reject) {
    Services.prefs.setIntPref("security.tls.version.max", version);
    Services.prefs.setIntPref("security.tls.version.fallback-limit", version);

    try {
        let request = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);

        request.open("GET", "https://disabled.tls13.com/", true);

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
    checkTLS(4).then(function(error4) {
        error4.version = 4;
        console.log(JSON.stringify(error4));

        checkTLS(3).then(function(error3) {
            error3.version = 3;
            console.log(JSON.stringify(error3));
        });
    });
}

function uninstall() {}
