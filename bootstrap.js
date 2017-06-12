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
    let error_ = {};

    // error_.code = xhr.channel.QueryInterface(Ci.nsIRequest).status;

    // if ((error_.code & 0xff0000) === 0x5a0000) {
    //     let nssErrorsService = Cc['@mozilla.org/nss_errors_service;1'].getService(Ci.nsINSSErrorsService);

    //     try {
    //         error_.class = nssErrorsService.getErrorClass(error_.code);

    //         if (error_.class === Ci.nsINSSErrorsService.ERROR_CLASS_BAD_CERT) {
    //             error_.class_name = 'CERTIFICATE';
    //         } else {
    //             error_.class_name = 'PROTOCOL';
    //         }
    //     } catch (ex) {
    //         error_.class_name = 'PROTOCOL';
    //         error_.class = null;
    //     }

    //     // NSS_SEC errors (happen below the base value because of negative vals)
    //     if ((error_.code & 0xffff) < Math.abs(Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE)) {
    //         // The bases are actually negative, so in our positive numeric space, we
    //         // need to subtract the base off our value.
    //         let nssErr = Math.abs(Ci.nsINSSErrorsService.NSS_SEC_ERROR_BASE) - (error_.code & 0xffff);

    //         switch (nssErr) {
    //             case 11: // SEC_ERROR_EXPIRED_CERTIFICATE, sec(11)
    //                 error_.code_name = 'SEC_ERROR_EXPIRED_CERTIFICATE';
    //                 break;
    //             case 12: // SEC_ERROR_REVOKED_CERTIFICATE, sec(12)
    //                 error_.code_name = 'SEC_ERROR_REVOKED_CERTIFICATE';
    //                 break;
    //             case 13: // SEC_ERROR_UNKNOWN_ISSUER, sec(13)
    //                 error_.code_name = 'SEC_ERROR_UNKNOWN_ISSUER';
    //                 break;
    //             case 20: // SEC_ERROR_UNTRUSTED_ISSUER, sec(20)
    //                 error_.code_name = 'SEC_ERROR_UNTRUSTED_ISSUER';
    //                 break;
    //             case 21: // SEC_ERROR_UNTRUSTED_CERT, sec(21)
    //                 error_.code_name = 'SEC_ERROR_UNTRUSTED_CERT';
    //                 break;
    //             case 36: // SEC_ERROR_CA_CERT_INVALID, sec(36)
    //                 error_.code_name = 'SEC_ERROR_CA_CERT_INVALID';
    //                 break;
    //             case 90: // SEC_ERROR_INADEQUATE_KEY_USAGE, sec(90)
    //                 error_.code_name = 'SEC_ERROR_INADEQUATE_KEY_USAGE';
    //                 break;
    //             case 176: // SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED, sec(176)
    //                 error_.code_name = 'SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED';
    //                 break;
    //             default:
    //                 error_.code_name = 'SEC_ERROR_OTHER';
    //                 break;
    //         }
    //     } else {
    //         let sslErr = Math.abs(Ci.nsINSSErrorsService.NSS_SSL_ERROR_BASE) - (error_.code & 0xffff);

    //         switch (sslErr) {
    //             case 3: // SSL_ERROR_NO_CERTIFICATE, ssl(3)
    //                 error_.code_name = 'SSL_ERROR_NO_CERTIFICATE';
    //                 break;
    //             case 4: // SSL_ERROR_BAD_CERTIFICATE, ssl(4)
    //                 error_.code_name = 'SSL_ERROR_BAD_CERTIFICATE';
    //                 break;
    //             case 8: // SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE, ssl(8)
    //                 error_.code_name = 'SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE';
    //                 break;
    //             case 9: // SSL_ERROR_UNSUPPORTED_VERSION, ssl(9)
    //                 error_.code_name = 'SSL_ERROR_UNSUPPORTED_VERSION';
    //                 break;
    //             case 12: // SSL_ERROR_BAD_CERT_DOMAIN, ssl(12)
    //                 error_.code_name = 'SSL_ERROR_BAD_CERT_DOMAIN';
    //                 break;
    //             default:
    //                 error_.code_name = 'SSL_ERROR_OTHER';
    //                 break;
    //         }
    //     }
    // } else {
    //     error_.class_name = 'NETWORK';

    //     switch (error_.code) {
    //         // connect to host:port failed
    //         case 0x804B000C: // NS_ERROR_CONNECTION_REFUSED, network(13)
    //             error_.code_name = 'NS_ERROR_CONNECTION_REFUSED';
    //             break;
    //         // network timeout error
    //         case 0x804B000E: // NS_ERROR_NET_TIMEOUT, network(14)
    //             error_.code_name = 'NS_ERROR_NET_TIMEOUT';
    //             break;
    //         // hostname lookup failed
    //         case 0x804B001E: // NS_ERROR_UNKNOWN_HOST, network(30)
    //             error_.code_name = 'NS_ERROR_UNKNOWN_HOST';
    //             break;
    //         case 0x804B0047: // NS_ERROR_NET_INTERRUPT, network(71)
    //             error_.code_name = 'NS_ERROR_NET_INTERRUPT';
    //             break;
    //         default:
    //             error_.code_name = 'NS_ERROR_OTHER';
    //             break;
    //     }
    // }

    return error_;
}

function dumpSecurityInfo(xhr, error) {
  let channel = xhr.channel;
 
  try {
    dump("Connection error_.code:\n");

    if (!error) {
      dump("\tsucceeded\n");
    } else {
      dump("\tfailed: " + error.name + "\n");
    }
 
    let secInfo = channel.securityInfo;

    // Print general connection security state
    dump("Security Information:\n");

    if (secInfo instanceof Ci.nsITransportSecurityInfo) {
      secInfo.QueryInterface(Ci.nsITransportSecurityInfo);
      dump("\tSecurity state of connection: ");

      // Check security state flags
      if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_SECURE)
           == Ci.nsIWebProgressListener.STATE_IS_SECURE) {
        dump("secure connection\n");
      } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_INSECURE)
                  == Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
        dump("insecure connection\n");
      } else if ((secInfo.securityState & Ci.nsIWebProgressListener.STATE_IS_BROKEN)
                  == Ci.nsIWebProgressListener.STATE_IS_BROKEN) {
        dump("unknown\n");
        dump("\tSecurity description: " + secInfo.shortSecurityDescription + "\n");
        dump("\tSecurity error message: " + secInfo.errorMessage + "\n");
      }
    } else {
      dump("\tNo security info available for this channel\n");
    }

    // Print SSL certificate details
    if (secInfo instanceof Ci.nsISSLerror_.codeProvider) {
      var cert = secInfo.QueryInterface(Ci.nsISSLerror_.codeProvider)
                        .SSLerror_.code.QueryInterface(Ci.nsISSLerror_.code).serverCert;
            
      dump("\tCommon name (CN) = " + cert.commonName + "\n");
      dump("\tIssuer = " + cert.issuerOrganization + "\n");
      dump("\tOrganisation = " + cert.organization + "\n");  
      dump("\tSHA1 fingerprint = " + cert.sha1Fingerprint + "\n");
       
      var validity = cert.validity.QueryInterface(Ci.nsIX509CertValidity);
      dump("\tValid from " + validity.notBeforeGMT + "\n");
      dump("\tValid until " + validity.notAfterGMT + "\n");
    }
  } catch(err) {
    alert(err);
  }
}

function collect_request_info(xhr) {
    // Much of this is documented in https://developer.mozilla.org/en-US/docs/Web/API/
    // XMLHttpRequest/How_to_check_the_secruity_state_of_an_XMLHTTPRequest_over_SSL
    let info = {};
    info.error_.code = xhr.channel.QueryInterface(Ci.nsIRequest).error_.code;
    info.original_uri = xhr.channel.originalURI.asciiSpec;
    info.uri = xhr.channel.URI.asciiSpec;
    info.error_ = getError(xhr);

    try {
        info.error_class = nssErrorsService.getErrorClass(info.error_.code);
    } catch (e) {
        info.error_class = null;
    }

    info.security_info_error_.code = false;
    info.transport_security_info_error_.code = false;
    info.ssl_error_.code_error_.code = false;

    // Try to query security info
    let sec_info = xhr.channel.securityInfo;
    if (sec_info == null) return info;
    info.security_info_error_.code = true;

    if (sec_info instanceof Ci.nsITransportSecurityInfo) {
        sec_info.QueryInterface(Ci.nsITransportSecurityInfo);
        info.transport_security_info_error_.code = true;
        info.security_state = sec_info.securityState;
        info.security_description = sec_info.shortSecurityDescription;
        info.raw_error = sec_info.errorMessage;
    }

    if (sec_info instanceof Ci.nsISSLerror_.codeProvider) {
        info.ssl_error_.code_error_.code = false;
        let ssl_error_.code = sec_info.QueryInterface(Ci.nsISSLerror_.codeProvider).SSLerror_.code;
        if (ssl_error_.code != null) {
            info.ssl_error_.code_error_.code = true;
            info.ssl_error_.code = ssl_error_.code.QueryInterface(Ci.nsISSLerror_.code);
            // TODO: Find way to extract this py-side.
            try {
                let usages = {};
                let usages_string = {};
                info.ssl_error_.code.server_cert.getUsagesString(true, usages, usages_string);
                info.certified_usages = usages_string.value;
            } catch (e) {
                info.certified_usages = null;
            }
        }
    }

    if (info.ssl_error_.code_error_.code) {
        let server_cert = info.ssl_error_.code.serverCert;
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

    if (info.ssl_error_.code_error_.code) {
        // Some values might be missing from the connection state, for example due
        // to a broken SSL handshake. Try to catch exceptions before report_result's
        // JSON serializing does.
        let sane_ssl_error_.code = {};
        info.ssl_error_.code_errors = [];
        for (let key in info.ssl_error_.code) {
            if (!info.ssl_error_.code.hasOwnProperty(key)) continue;
            try {
                sane_ssl_error_.code[key] = info.ssl_error_.code[key];
                // sane_ssl_error_.code[key] = nativeJSON.decode(nativeJSON.encode(info.ssl_error_.code[key]));
            } catch (e) {
                sane_ssl_error_.code[key] = null;
                info.ssl_error_.code_errors.push({key: e.toString()});
            }
        }
        info.ssl_error_.code = sane_ssl_error_.code;
    }

    return info;
}

function check_tls(version) {
  return new Promise(function(resolve, reject) {
    // Services.prefs.setIntPref("security.tls.version.max", version);

    function load_handler(msg) {
      resolve({origin: "load_handler", info: getError(msg.target)});
    }

    function error_handler(msg) {
      resolve({origin: "error_handler", info: getError(msg.target)});
    }

    function abort_handler(msg) {
      resolve({origin: "abort_handler", info: getError(msg.target)});
    }

    function timeout_handler(msg) {
      resolve({origin: "timeout_handler", info: getError(msg.target)});
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
        resolve({origin: "request_error", error: error, info: getError(request)});
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
