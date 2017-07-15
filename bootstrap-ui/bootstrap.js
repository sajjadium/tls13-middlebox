"use strict";

const VERSION_MAX_PREF = "security.tls.version.max";
const FALLBACK_LIMIT_PREF = "security.tls.version.fallback-limit";

const POPUP_NOTIFICATION_ID = "tls13-middlebox-popup";
const POPUP_NOTIFICATION_SIZE_FACTOR = 0.3;

const CERT_USAGE_SSL_CLIENT      = 0x0001;
const CERT_USAGE_SSL_SERVER      = 0x0002;
const CERT_USAGE_SSL_CA          = 0x0008;
const CERT_USAGE_EMAIL_SIGNER    = 0x0010;
const CERT_USAGE_EMAIL_RECIPIENT = 0x0020;
const CERT_USAGE_OBJECT_SIGNER   = 0x0040;

const XHR_TIMEOUT = 10000;

const TELEMETRY_PING_NAME = "tls13-middlebox-testing";

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

        // extracting the DER format of root cert and convert it to base64
        result.rootCert = (chain !== null && chain.length > 0) ?
                          byteArrayToBase64(chain[chain.length - 1].getRawDER({})) : null;

        // extracting sha256 fingerprint for the leaf cert in the chain
        result.serverSha256Fingerprint = getFieldValue(chain[0], "sha256Fingerprint");

        // check the root cert to see if it is builtin certificate
        result.isBuiltInRoot = (chain !== null && chain.length > 0) ? 
                                getFieldValue(chain[chain.length - 1], "isBuiltInRoot") : null;

        // record the detailed info about SSL connection Firefox ended up negotiating
        let ssl_status_fields = [
          "certificateTransparencyStatus",
          "cipherName",
          "isDomainMismatch",
          "isExtendedValidation",
          "isNotValidAtThisTime",
          "isUntrusted",
          "keyLength",
          "protocolVersion",
          "secretKeyLength"
        ];

        for (let field of ssl_status_fields) {
          result[field] = getFieldValue(sslStatus, field);
        }
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

// shows the popup notification to the user in which it puts the non-builtin cert info
function askForUserPermission(non_builtin_root_certs) {
  return new Promise((resolve, reject) => {
    // show the actual popup
    domWindow.PopupNotifications.show(domWindow.gBrowser.selectedBrowser,
      POPUP_NOTIFICATION_ID,
      "We have detected a Middlebox in your network. Help Mozilla by reporting it.",
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
                let learn_more_link = domWindow.document.createElement("label");
                learn_more_link.className = "text-link";
                learn_more_link.setAttribute("useoriginprincipal", true);
                learn_more_link.setAttribute("value", "Learn more ...");

                learn_more_link.onclick = function() {
                  // extract extra info for user
                  let info = [];

                  for (let cert of non_builtin_root_certs) {
                    info.push({
                      "Common Name": cert.commonName,
                      "Organization": cert.organization,
                      "Organizational Unit": cert.organizationalUnit,
                    });
                  }

                  // show the popup window and pass the cert info to it
                  let width = domWindow.screen.width * POPUP_NOTIFICATION_SIZE_FACTOR;
                  let height = domWindow.screen.height * POPUP_NOTIFICATION_SIZE_FACTOR;
                  var left = (domWindow.screen.width / 2) - (width / 2);
                  var top = (domWindow.screen.height / 2) - (height / 2);

                  let win = domWindow.open(
                    "chrome://tls13-middlebox/content/moreinfo.html?data=" + encodeURIComponent(JSON.stringify(info)),
                    "certinfo_popup",
                    `toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=no,resizable=no,copyhistory=no,
                    width=${width},height=${height},top=${top},left=${left}`
                  );
                }

                notificationcontent.appendChild(learn_more_link);
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
async function isPermitted(non_builtin_root_certs) {
  while (true) {
    let res = await askForUserPermission(non_builtin_root_certs);

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

function startup() {
}

function shutdown() {
}

function install() {
  // send start of the test probe
  TelemetryController.submitExternalPing(TELEMETRY_PING_NAME, {
    "id": PROBE_ID,
    "status": "started"
  });

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
        resolve(non_builtin_root_certs);
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

          // if there is no non-builtin root certs installed, no need to keep the root cert for the connection
          if (non_builtin_root_certs.length === 0) {
            for (let tr of tests_result) {
              delete tr.result.rootCert;
            }
          }

          resolve(non_builtin_root_certs);
        }).catch(err => {
          // restore the default values after the experiment is over
          readwrite_prefs.set(VERSION_MAX_PREF, default_max_version);
          readwrite_prefs.set(FALLBACK_LIMIT_PREF, default_fallback_limit);

          debug(err);
          reject(err);
        });
      }
    });
  }).then(non_builtin_root_certs => {
    return new Promise((resolve, reject) => {
      // ask for user permission
      if (non_builtin_root_certs.length > 0) {
        isPermitted(non_builtin_root_certs).then(is_permitted => {
          if (is_permitted) {
            // extract DER format of non-builtin root certs
            final_output["nonBuiltInRootCerts"] = [];

            for (let cert of non_builtin_root_certs) {
              final_output["nonBuiltInRootCerts"].push(byteArrayToBase64(cert.getRawDER({})));
            }
          } else {
            // remove the root cert from test results
            if (final_output.tests) {
              for (let tr of final_output.tests) {
                delete tr.result.rootCert;
              }
            }
          }

          resolve();

          return true;
        }).catch(err => {
          debug(err);
          reject(err);
        });
      } else {
        resolve(non_builtin_root_certs);
      }
    });
  }).then(() => {
    TelemetryController.submitExternalPing(TELEMETRY_PING_NAME, Object.assign({
      "id": PROBE_ID,
    }, final_output));

    return true;
  }).catch(err => {
    debug(err);
  });
}

function uninstall() {
}
