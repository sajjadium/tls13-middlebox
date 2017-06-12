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

function get_runtime_info() {
    let nss_info = Cc["@mozilla.org/security/nssversion;1"].getService(Ci.nsINSSVersion);

    return {
        nssVersion: "NSS " + nss_info.NSS_Version,
        nsprVersion: "NSPR " + nss_info.NSPR_Version,
        branch: AppConstants.MOZ_UPDATE_CHANNEL,
        appVersion: AppConstants.MOZ_APP_VERSION_DISPLAY
    };
}

function getError(xhr) {
    let result = {};

    result.errorCode = xhr.channel.QueryInterface(Ci.nsIRequest).status;

    if ((result.errorCode & 0xff0000) === 0x5a0000) {
        let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(Ci.nsINSSErrorsService);

        try {
            result.errorClass = nssErrorsService.getErrorClass(result.errorCode);

            if (result.errorClass === Ci.nsINSSErrorsService.ERROR_CLASS_BAD_CERT) {
                result.errorClassDesc = 'CERTIFICATE';
            } else {
                result.errorClassDesc = 'PROTOCOL';
            }
        } catch (ex) {
            result.errorClass = null;
            result.errorClassDesc = 'PROTOCOL';
        }

        // NSS_SEC errors (happen below the base value because of negative vals)
        if ((result.errorCode & 0xffff) < Math.abs(Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE)) {
            // The bases are actually negative, so in our positive numeric space, we
            // need to subtract the base off our value.
            let nssErr = Math.abs(Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE) - (result.errorCode & 0xffff);

            switch (nssErr) {
                case 11: // SEC_ERROR_EXPIRED_CERTIFICATE, sec(11)
                    result.errorCodeDesc = 'SEC_ERROR_EXPIRED_CERTIFICATE';
                    break;
                case 12: // SEC_ERROR_REVOKED_CERTIFICATE, sec(12)
                    result.errorCodeDesc = 'SEC_ERROR_REVOKED_CERTIFICATE';
                    break;
                case 13: // SEC_ERROR_UNKNOWN_ISSUER, sec(13)
                    result.errorCodeDesc = 'SEC_ERROR_UNKNOWN_ISSUER';
                    break;
                case 20: // SEC_ERROR_UNTRUSTED_ISSUER, sec(20)
                    result.errorCodeDesc = 'SEC_ERROR_UNTRUSTED_ISSUER';
                    break;
                case 21: // SEC_ERROR_UNTRUSTED_CERT, sec(21)
                    result.errorCodeDesc = 'SEC_ERROR_UNTRUSTED_CERT';
                    break;
                case 36: // SEC_ERROR_CA_CERT_INVALID, sec(36)
                    result.errorCodeDesc = 'SEC_ERROR_CA_CERT_INVALID';
                    break;
                case 90: // SEC_ERROR_INADEQUATE_KEY_USAGE, sec(90)
                    result.errorCodeDesc = 'SEC_ERROR_INADEQUATE_KEY_USAGE';
                    break;
                case 176: // SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED, sec(176)
                    result.errorCodeDesc = 'SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED';
                    break;
                default:
                    result.errorCodeDesc = 'SEC_ERROR_OTHER';
                    break;
            }
        } else {
            let sslErr = Math.abs(Ci.nsINSSErrorsService.NSS_SSL_ERROR_BASE) - (result.errorCode & 0xffff);

            switch (sslErr) {
                case 3: // SSL_ERROR_NO_CERTIFICATE, ssl(3)
                    result.errorCodeDesc = 'SSL_ERROR_NO_CERTIFICATE';
                    break;
                case 4: // SSL_ERROR_BAD_CERTIFICATE, ssl(4)
                    result.errorCodeDesc = 'SSL_ERROR_BAD_CERTIFICATE';
                    break;
                case 8: // SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE, ssl(8)
                    result.errorCodeDesc = 'SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE';
                    break;
                case 9: // SSL_ERROR_UNSUPPORTED_VERSION, ssl(9)
                    result.errorCodeDesc = 'SSL_ERROR_UNSUPPORTED_VERSION';
                    break;
                case 12: // SSL_ERROR_BAD_CERT_DOMAIN, ssl(12)
                    result.errorCodeDesc = 'SSL_ERROR_BAD_CERT_DOMAIN';
                    break;
                default:
                    result.errorCodeDesc = 'SSL_ERROR_OTHER';
                    break;
            }
        }
    } else {
        result.errorClassDesc = 'NETWORK';

        switch (result.errorCode) {
            // connect to host:port failed
            case 0x804B000C: // NS_ERROR_CONNECTION_REFUSED, network(13)
                result.errorCodeDesc = 'NS_ERROR_CONNECTION_REFUSED';
                break;
            // network timeout error
            case 0x804B000E: // NS_ERROR_NET_TIMEOUT, network(14)
                result.errorCodeDesc = 'NS_ERROR_NET_TIMEOUT';
                break;
            // hostname lookup failed
            case 0x804B001E: // NS_ERROR_UNKNOWN_HOST, network(30)
                result.errorCodeDesc = 'NS_ERROR_UNKNOWN_HOST';
                break;
            case 0x804B0047: // NS_ERROR_NET_INTERRUPT, network(71)
                result.errorCodeDesc = 'NS_ERROR_NET_INTERRUPT';
                break;
            default:
                result.errorCodeDesc = 'NS_ERROR_OTHER';
                break;
        }
    }

    try {
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

function check_tls(version) {
  return new Promise(function(resolve, reject) {
    // Services.prefs.setIntPref("security.tls.version.max", version);
    // Services.prefs.setIntPref("security.tls.version.fallback-limit", version);

    function load_handler(msg) {
        let result = getError(msg.target);
        result.origin = "load";
        resolve(result);
    }

    function error_handler(msg) {
        let result = getError(msg.target);
        result.origin = "error";
        resolve(result);
    }

    function abort_handler(msg) {
        let result = getError(msg.target);
        result.origin = "abort";
        resolve(result);
    }

    function timeout_handler(msg) {
        let result = getError(msg.target);
        result.origin = "timeout";
        resolve(result);
    }

    let request = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);

    try {
        request.mozBackgroundRequest = true;
        request.open("GET", "https://disabled.tls13.com", true);
        request.timeout = 10000;
        request.channel.loadFlags |= Ci.nsIRequest.LOAD_ANONYMOUS
            | Ci.nsIRequest.LOAD_BYPASS_CACHE
            | Ci.nsIRequest.INHIBIT_PERSISTENT_CACHING
            | Ci.nsIRequest.VALIDATE_NEVER;
        request.addEventListener("load", load_handler, false);
        request.addEventListener("error", error_handler, false);
        request.addEventListener("abort", abort_handler, false);
        request.addEventListener("timeout", timeout_handler, false);
        request.send(null);
    } catch (err) {
        let result = getError(request);
        result.error = err.message;
        resolve(result);
    }
  });
}

function startup() {}

function shutdown() {}

function install() {
    check_tls(4).then(function(result4) {
        check_tls(3).then(function(result3) {
            // console.log("4: " + nativeJSON.stringify(result4));
            // console.log("3: " + nativeJSON.stringify(result3));
            console.log("4:", (result4));
            console.log("3:", (result3));
        });
    });
}

function uninstall() {}
