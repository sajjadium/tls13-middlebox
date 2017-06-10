"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");
Cu.import("resource://gre/modules/Task.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/AppConstants.jsm");

const nsINSSErrorsService = Ci.nsINSSErrorsService;
let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(nsINSSErrorsService);
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

function collect_request_info(xhr) {
    // Much of this is documented in https://developer.mozilla.org/en-US/docs/Web/API/
    // XMLHttpRequest/How_to_check_the_secruity_state_of_an_XMLHTTPRequest_over_SSL
    let info = {};
    info.status = xhr.channel.QueryInterface(Ci.nsIRequest).status;
    info.original_uri = xhr.channel.originalURI.asciiSpec;
    info.uri = xhr.channel.URI.asciiSpec;

    try {
        info.error_class = nssErrorsService.getErrorClass(info.status);
    } catch (e) {
        info.error_class = null;
    }

    info.security_info_status = false;
    info.transport_security_info_status = false;
    info.ssl_status_status = false;

    // Try to query security info
    let sec_info = xhr.channel.securityInfo;
    if (sec_info == null) return info;
    info.security_info_status = true;

    if (sec_info instanceof Ci.nsITransportSecurityInfo) {
        sec_info.QueryInterface(Ci.nsITransportSecurityInfo);
        info.transport_security_info_status = true;
        info.security_state = sec_info.securityState;
        info.security_description = sec_info.shortSecurityDescription;
        info.raw_error = sec_info.errorMessage;
    }

    if (sec_info instanceof Ci.nsISSLStatusProvider) {
        info.ssl_status_status = false;
        let ssl_status = sec_info.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
        if (ssl_status != null) {
            info.ssl_status_status = true;
            info.ssl_status = ssl_status.QueryInterface(Ci.nsISSLStatus);
            // TODO: Find way to extract this py-side.
            try {
                let usages = {};
                let usages_string = {};
                info.ssl_status.server_cert.getUsagesString(true, usages, usages_string);
                info.certified_usages = usages_string.value;
            } catch (e) {
                info.certified_usages = null;
            }
        }
    }

    if (info.ssl_status_status) {
        let server_cert = info.ssl_status.serverCert;
        let cert_chain = [];
        if (server_cert.sha1Fingerprint) {
            cert_chain.push(server_cert.getRawDER({}));
            let chain = server_cert.getChain().enumerate();
            while (chain.hasMoreElements()) {
                let child_cert = chain.getNext().QueryInterface(Ci.nsISupports)
                    .QueryInterface(Ci.nsIX509Cert);
                cert_chain.push(child_cert.getRawDER({}));
            }
        }
        info.certificate_chain_length = cert_chain.length;
        info.certificate_chain = cert_chain;
    }

    if (info.ssl_status_status) {
        // Some values might be missing from the connection state, for example due
        // to a broken SSL handshake. Try to catch exceptions before report_result's
        // JSON serializing does.
        let sane_ssl_status = {};
        info.ssl_status_errors = [];
        for (let key in info.ssl_status) {
            if (!info.ssl_status.hasOwnProperty(key)) continue;
            try {
                sane_ssl_status[key] = info.ssl_status[key];
                // sane_ssl_status[key] = nativeJSON.decode(nativeJSON.encode(info.ssl_status[key]));
            } catch (e) {
                sane_ssl_status[key] = null;
                info.ssl_status_errors.push({key: e.toString()});
            }
        }
        info.ssl_status = sane_ssl_status;
    }

    return info;
}

function check_tls(version) {
  return new Promise(function(resolve, reject) {
    // Services.prefs.setIntPref("security.tls.version.max", version);

    function load_handler(msg) {
      resolve({origin: "load_handler", info: collect_request_info(msg.target)});
    }

    function error_handler(msg) {
      resolve({origin: "error_handler", info: collect_request_info(msg.target)});
    }

    function abort_handler(msg) {
      resolve({origin: "abort_handler", info: collect_request_info(msg.target)});
    }

    function timeout_handler(msg) {
      resolve({origin: "timeout_handler", info: collect_request_info(msg.target)});
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
    } catch (error) {
        resolve({origin: "request_error", error: error, info: collect_request_info(request)});
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
    })
  });
}

function uninstall() {}
