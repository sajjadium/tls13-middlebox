"use strict";

const VERSION_MAX_PREF = "security.tls.version.max";
const FALLBACK_LIMIT_PREF = "security.tls.version.fallback-limit";

const POPUP_NOTIFICATION_ID = "tls13-middlebox-popup";

const CERT_USAGE_SSL_CLIENT      = 0x0001;
const CERT_USAGE_SSL_SERVER      = 0x0002;
const CERT_USAGE_SSL_CA          = 0x0008;
const CERT_USAGE_EMAIL_SIGNER    = 0x0010;
const CERT_USAGE_EMAIL_RECIPIENT = 0x0020;
const CERT_USAGE_OBJECT_SIGNER   = 0x0040;

const XHR_TIMEOUT = 10000;

const TELEMETRY_PING_NAME = "tls13-middlebox-ui-testing";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

// all combination of configurations we care about
let configurations = [
  {maxVersion: 4, fallbackLimit: 4, website: "enabled.tls13.com"},
  {maxVersion: 4, fallbackLimit: 4, website: "disabled.tls13.com"},
  {maxVersion: 3, fallbackLimit: 3, website: "control.tls12.com"}
];

let readwrite_prefs = new Preferences({defaultBranch: true});

let certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);

// generate random UUID for identifying probes uniquely
function generateProbeId() {
  let uuidGenerator = Cc["@mozilla.org/uuid-generator;1"].getService(Ci.nsIUUIDGenerator);
  let uuid = uuidGenerator.generateUUID();
  return uuid.toString();
}

let PROBE_ID = generateProbeId();

// get currnet window
let windowMediator = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);
let domWindow = windowMediator.getMostRecentWindow("navigator:browser");

function debug(msg) {
  console.log(msg); // eslint-disable-line no-console
}

// some fields are not available sometimes, so we have to catch the errors and return undefined.
function getFieldValue(obj, name) {
  try {
    return obj[name];
  } catch (ex) {
    return undefined;
  }
}

// enumerate nsIX509CertList data structure and put elements in the array
function nsIX509CertListToArray(list) {
  let array = [];

  let iter = list.getEnumerator();

  while (iter.hasMoreElements()) {
    array.push(iter.getNext().QueryInterface(Ci.nsIX509Cert));
  }

  return array;
}

// verifies the cert using either SSL_SERVER or SSL_CA usages and extracts the chain
// returns null in case an error occurs
function getCertChain(cert, usage) {
  return new Promise((resolve, reject) => {
    certDB.asyncVerifyCertAtTime(cert, usage, 0, null, Date.now() / 1000, (aPRErrorCode, aVerifiedChain, aHasEVPolicy) => {
      if (aPRErrorCode === 0) {
        resolve(nsIX509CertListToArray(aVerifiedChain));
      } else {
        resolve(null);
      }
    });
  });
}

// returns list of non-builtin root certificates installed
async function getNonBuiltInRootCertsInstalled() {
  let certs = nsIX509CertListToArray(certDB.getCerts());

  let non_builtin_certs = [];

  for (let cert of certs) {
    let chain = await getCertChain(cert, CERT_USAGE_SSL_CA);

    if (chain !== null && chain.length === 1 && !chain[0].isBuiltInRoot) {
      non_builtin_certs.push(cert);
    }
  }

  return non_builtin_certs;
}

// convert byte array to base64
function byteArrayToBase64(bytes) {
  let str = "";

  for (let b of bytes)
    str += String.fromCharCode(b);

  return domWindow.btoa(str);
}

// get extra info from the XHR connections
async function getInfo(xhr) {
  let result = {};

  try {
    let channel = xhr.channel;

    // this is the most important value based on which we can find out the problem
    channel.QueryInterface(Ci.nsIRequest);
    result.status = getFieldValue(channel, "status");

    let securityInfo = getFieldValue(channel, "securityInfo");

    if (securityInfo instanceof Ci.nsITransportSecurityInfo) {
      securityInfo.QueryInterface(Ci.nsITransportSecurityInfo);

      // extract security state and error code by which we can identify the reasons the connection failed
      result.securityState = getFieldValue(securityInfo, "securityState");
      result.errorCode = getFieldValue(securityInfo, "errorCode");
    }

    if (securityInfo instanceof Ci.nsISSLStatusProvider) {
      securityInfo.QueryInterface(Ci.nsISSLStatusProvider);
      let sslStatus = getFieldValue(securityInfo, "SSLStatus");

      if (sslStatus) {
        sslStatus.QueryInterface(Ci.nsISSLStatus);

        // in case cert verification failed, we need to extract the cert chain from failedCertChain attribute
        // otherwise, we extract cert chain using certDB.asyncVerifyCertAtTime API
        let chain = null;

        if (getFieldValue(securityInfo, "failedCertChain")) {
          chain = nsIX509CertListToArray(securityInfo.failedCertChain);
        } else {
          chain = await getCertChain(getFieldValue(sslStatus, "serverCert"), CERT_USAGE_SSL_SERVER);
        }

        // check the root cert to see if it is builtin certificate
        result.isBuiltInRoot = (chain !== null && chain.length > 0) ? 
                                getFieldValue(chain[chain.length - 1], "isBuiltInRoot") : null;

        // if the root cert is not builtin, extract its DER format and convert it to base64
        if (!result.isBuiltInRoot)
          result.certChain = chain;

        // extracting sha256 fingerprint for the leaf cert in the chain
        result.serverSha256Fingerprint = getFieldValue(chain[0], "sha256Fingerprint");

        // record the detailed info about SSL connection Firefox ended up negotiating
        result["cipherName"] = getFieldValue(sslStatus, "cipherName");
        result["protocolVersion"] = getFieldValue(sslStatus, "protocolVersion");
        result["keyLength"] = getFieldValue(sslStatus, "keyLength");
        result["secretKeyLength"] = getFieldValue(sslStatus, "secretKeyLength");
      }
    }
  } catch (ex) {
    result.exception = ex.message;
    debug(ex);
  }

  return result;
}

function makeRequest(config) {
  return new Promise((resolve, reject) => {
    // put together the configuration and the info collected from the connection
    async function reportResult(event, xhr) {
      let output = Object.assign({"result": {"event": event, "responseCode": xhr.status}}, config);
      output.result = Object.assign(output.result, await getInfo(xhr));
      resolve(output);
      return true;
    }

    try {
      // set the configuration to the values that were passed to this function
      readwrite_prefs.set(VERSION_MAX_PREF, config.maxVersion);
      readwrite_prefs.set(FALLBACK_LIMIT_PREF, config.fallbackLimit);

      let xhr = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);

      xhr.open("GET", `https://${config.website}`, true);

      xhr.timeout = XHR_TIMEOUT;

      xhr.channel.loadFlags |= Ci.nsIRequest.LOAD_ANONYMOUS;
      xhr.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
      xhr.channel.loadFlags |= Ci.nsIRequest.INHIBIT_CACHING;

      xhr.addEventListener("load", e => {
        reportResult("load", e.target);
      });

      xhr.addEventListener("loadend", e => {
        reportResult("loadend", e.target);
      });

      xhr.addEventListener("error", e => {
        reportResult("error", e.target);
      });

      xhr.addEventListener("abort", e => {
        reportResult("abort", e.target);
      });

      xhr.addEventListener("timeout", e => {
        reportResult("timeout", e.target);
      });

      xhr.send();
    } catch (ex) {
      resolve(Object.assign({result: {"event": "exception", "description": ex.toSource()}}, config));
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

// pretty print the cert
function dumpCertText(cert) {
  let asn1Tree = Cc["@mozilla.org/security/nsASN1Tree;1"].createInstance(Ci.nsIASN1Tree);
  asn1Tree.loadASN1Structure(cert.ASN1Structure);

  let cert_text = `Certificate "${asn1Tree.getCellText(0, null).trim()}"\n`;

  for (let i = 1; i < asn1Tree.rowCount; i++) {
    cert_text += "\t".repeat(asn1Tree.getLevel(i) - 1);

    cert_text += `${asn1Tree.getCellText(i, null).trim()}:\n`;

    if (asn1Tree.getDisplayData(i).trim() !== "") {
      cert_text += "\t".repeat(asn1Tree.getLevel(i));
      cert_text += asn1Tree.getDisplayData(i).trim().replace(/\n(?=.+)/g, "\n" + "\t".repeat(asn1Tree.getLevel(i))) + "\n";
    }
  }

  // extract PEM format
  var pem = "-----BEGIN CERTIFICATE-----\n" +
            byteArrayToBase64(cert.getRawDER({})).replace(/(\S{64}(?!$))/g, "$1\n") +
            "\n-----END CERTIFICATE-----\n";

  return cert_text + pem;
}

// shows the popup notification to the user in which it puts the non-builtin cert info
function askForUserPermission(cert_chain) {
  return new Promise((resolve, reject) => {
    // show the actual popup
    domWindow.PopupNotifications.show(domWindow.gBrowser.selectedBrowser,
      POPUP_NOTIFICATION_ID,
      "We have detected a middlebox on your network that is blocking secure connections. Help Mozilla to fix this issue by reporting it.",
      null,
      {
        label: "Report to Mozilla",
        accessKey: "R",
        callback: function() {
          resolve(true);
        }
      },
      [
        {
          label: "Not Now",
          accessKey: "N",
          callback: function() {
            resolve(false);
          }
        }
      ],
      {
        removeOnDismissal: true,
        eventCallback: function(reason) {
          try {
            if (reason === "shown") {
              let notification = domWindow.document.getElementById(POPUP_NOTIFICATION_ID + "-notification");

              if (!notification.querySelector("popupnotificationcontent")) {
                // add the learn more link
                // if the user clicks on it, it shows the cert info
                let notificationcontent = domWindow.document.createElement("popupnotificationcontent");
                let view_cert_link = domWindow.document.createElement("label");
                view_cert_link.className = "text-link";
                view_cert_link.setAttribute("useoriginprincipal", true);
                view_cert_link.setAttribute("value", "View Certificate Chain ...");

                view_cert_link.onclick = function() {
                  let cert_chain_text = "";

                  for (let i = cert_chain.length - 1; i >= 0; i--) {
                    cert_chain_text += dumpCertText(cert_chain[i]) + "\n\n";
                  }

                  // open a popup showing the pretty print of the cert
                  let supportsString = Cc["@mozilla.org/supports-string;1"].createInstance(Ci.nsISupportsString);
                  supportsString.data = "data:;charset=utf-8," + encodeURIComponent(cert_chain_text.trim());
                  let windowWatcher = Cc["@mozilla.org/embedcomp/window-watcher;1"].getService(Ci.nsIWindowWatcher);
                  windowWatcher.openWindow(null, "chrome://global/content/viewSource.xul", "_blank",
                                          "scrollbars,resizable,chrome,dialog=no", supportsString);
                }

                notificationcontent.appendChild(view_cert_link);
                notification.append(notificationcontent);
              }
            } else if (reason === "removed") {
              resolve(null);
            }
          } catch (err) {
            domWindow.console.log(err);
            resolve(null);
          }
        }
      }
    );
  });
}

// keep showing the popup notification until the user gives his/her permission or denies our request
async function isPermitted(cert_chain) {
  while (true) {
    let res = await askForUserPermission(cert_chain);

    if (res !== null) {
      return res;
    }
  }
}

// check if either of VERSION_MAX_PREF or FALLBACK_LIMIT_PREF was set by the user
function hasUserSetPreference() {
  let readonly_prefs = new Preferences();

  if (readonly_prefs.isSet(VERSION_MAX_PREF) || readonly_prefs.isSet(FALLBACK_LIMIT_PREF)) {
    return {
      "maxVersion": {
        "value": readonly_prefs.get(VERSION_MAX_PREF),
        "isUserset": readonly_prefs.isSet(VERSION_MAX_PREF)
      },
      "fallbackLimit": {
        "value": readonly_prefs.get(FALLBACK_LIMIT_PREF),
        "isUserset": readonly_prefs.isSet(FALLBACK_LIMIT_PREF)
      }
    };
  }

  return null;
}

function sendToTelemetry(data) {
  TelemetryController.submitExternalPing(TELEMETRY_PING_NAME, Object.assign({
    "id": PROBE_ID,
  }, data));
}

function startup() {
}

function shutdown() {
}

function install() {
  // send start of the test probe
  sendToTelemetry({"status": "started"});

  let final_output = {};

  // get all of the non-builtin root certs
  getNonBuiltInRootCertsInstalled().then(non_builtin_root_certs => {
    return new Promise((resolve, reject) => {
      final_output["isNonBuiltInRootCertInstalled"] = non_builtin_root_certs.length > 0;

      // abort if either of VERSION_MAX_PREF or FALLBACK_LIMIT_PREF was set by the user
      let user_set_prefs = hasUserSetPreference();

      if (user_set_prefs !== null) {
        // abort the XHR requests
        final_output["status"] = "aborted";
        final_output = Object.assign(final_output, user_set_prefs);
        resolve(null);
      } else {
        // record the default values before the experiment starts
        let default_max_version = readwrite_prefs.get(VERSION_MAX_PREF);
        let default_fallback_limit = readwrite_prefs.get(FALLBACK_LIMIT_PREF);

        runConfigurations().then(tests_result => {
          // restore the default values after the experiment is over
          readwrite_prefs.set(VERSION_MAX_PREF, default_max_version);
          readwrite_prefs.set(FALLBACK_LIMIT_PREF, default_fallback_limit);

          // add the result into the final output
          final_output["status"] = "finished";
          final_output["defaultMaxVersion"] = default_max_version;
          final_output["defaultFallbackLimit"] = default_fallback_limit;
          final_output["tests"] = tests_result;

          // find if there was a middlebox involved while we are negotiating TLS 1.3
          // if yes, we record the root cert
          let cert_chain = null;

          for (let tr of final_output.tests) {
            if (tr.website.toLowerCase() === "enabled.tls13.com" &&
                tr.result.certChain &&
                tr.result.event.toLowerCase() === "error") {
              cert_chain = tr.result.certChain;
            }

            delete tr.result.certChain;
          }

          resolve(cert_chain);
        }).catch(err => {
          // restore the default values after the experiment is over
          readwrite_prefs.set(VERSION_MAX_PREF, default_max_version);
          readwrite_prefs.set(FALLBACK_LIMIT_PREF, default_fallback_limit);

          debug(err);
          reject(err);
        });
      }
    });
  }).then((cert_chain) => {
    // report the results to telemetry
    sendToTelemetry(final_output);

    // ask for user permission if there was middle box involved
    if (cert_chain) {
      isPermitted(cert_chain).then(is_permitted => {
        if (is_permitted) {
          // report the middlebox's root cert to telemetry
          let cert_chain_der = [];

          for (let cert of cert_chain) {
            cert_chain_der.push(byteArrayToBase64(cert.getRawDER({})));
          }

          sendToTelemetry({
            "status": "allowed",
            "certChain": cert_chain_der
          });
        } else {
          // report to telemetry the fact that user disallowed reporting the middlebox's root cert
          sendToTelemetry({"status": "disallowed"});
        }

        return true;
      }).catch(err => {
        debug(err);
      });
    }
  }).catch(err => {
    debug(err);
  });
}

function uninstall() {
}
