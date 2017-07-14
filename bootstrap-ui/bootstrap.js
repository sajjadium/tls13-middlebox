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

const TELEMETRY_PING_NAME = "tls13-middlebox-testing";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

let readwrite_prefs = new Preferences({defaultBranch: true});

// all combination of configurations we care about.
let configurations = [
  {maxVersion: 4, fallbackLimit: 4, website: "enabled.tls13.com"},
  {maxVersion: 4, fallbackLimit: 4, website: "disabled.tls13.com"},
  {maxVersion: 3, fallbackLimit: 3, website: "control.tls12.com"}
];

let certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);

// generate random UUID for identifying probes uniquely
function generateProbeId() {
  let uuidGenerator = Cc["@mozilla.org/uuid-generator;1"].getService(Ci.nsIUUIDGenerator);
  let uuid = uuidGenerator.generateUUID();
  return uuid.toString();
}

let PROBE_ID = generateProbeId();

let windowMediator = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);
let domWindow = windowMediator.getMostRecentWindow("navigator:browser");

function prettyPrintCert(cert) {
  let info = {};

  info = {
    CN: cert.commonName,
    O: cert.organization,
    OU: cert.organizationalUnit,
  };

  // info.subject = {
  //   commonName: cert.commonName,
  //   organization: cert.organization,
  //   organizationalUnit: cert.organizationalUnit,
  // };

  // info.issuer = {
  //   commonName: cert.issuerCommonName,
  //   organization: cert.issuerOrganization,
  //   organizationUnit: cert.issuerOrganizationUnit,
  // };

  // info.validity = {
  //   start: cert.validity.notBeforeLocalDay,
  //   end: cert.validity.notAfterLocalDay,
  // };

  // info.fingerprint = {
  //   sha1: cert.sha1Fingerprint,
  //   sha256: cert.sha256Fingerprint,
  // };

  return JSON.stringify(info, null, "  ");
}

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

function byteArrayToBase64(bytes) {
  let str = "";

  for (let b of bytes)
    str += String.fromCharCode(b);

  return domWindow.btoa(str);
}

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

        result.certChain = null;

        if (chain !== null) {
          result.certChain = [];

          for (let cert of chain) {
            result.certChain.push(byteArrayToBase64(cert.getRawDER({})));
          }
        }

        console.log(chain[0]);

        console.log(sslStatus);

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
    debug(ex);
    result.exception = ex.message;
  }

  console.log(result);

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

function sendToTelemetry(status, data) {
  TelemetryController.submitExternalPing(TELEMETRY_PING_NAME, Object.assign({
    "id": PROBE_ID,
    "status": status
  }, data));
}

// show the popup notification to the user
function askForUserPermission(non_builtin_root_cert) {
  return new Promise((resolve, reject) => {
    // show the actual popup
    domWindow.PopupNotifications.show(domWindow.gBrowser.selectedBrowser,
      POPUP_NOTIFICATION_ID,
      "You have a MITM box in your network.",
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
                let notificationcontent = domWindow.document.createElement("popupnotificationcontent");
                let learn_more_link = domWindow.document.createElement("label");
                learn_more_link.className = "text-link";
                learn_more_link.setAttribute("useoriginprincipal", true);
                learn_more_link.setAttribute("value", "Learn more ...");

                learn_more_link.onclick = function() {
                  let win = domWindow.open(
                    "chrome://tls13-middlebox/content/moreinfo.html?data=" + encodeURIComponent(JSON.stringify({name: "value"})),
                    "certinfo_popup",
                    "menubar=no,location=no,resizable=no,status=no"
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
async function isPermitted(non_builtin_root_cert) {
  while (true) {
    let res = await askForUserPermission(non_builtin_root_cert);

    if (res !== null) {
      return res;
    }
  }
}

// check if either of VERSION_MAX_PREF or FALLBACK_LIMIT_PREF was set by the user
function hasUserSetPreference() {
  let readonly_prefs = new Preferences();

  if (readonly_prefs.isSet(VERSION_MAX_PREF) || readonly_prefs.isSet(FALLBACK_LIMIT_PREF)) {
    // reports the current values as well as whether they were set by the user
    getNonBuiltInRootCertsInstalled().then(non_builtin_root_certs => {
      let final_output = {
        "maxVersion": {
          "value": readonly_prefs.get(VERSION_MAX_PREF),
          "isUserset": readonly_prefs.isSet(VERSION_MAX_PREF)
        },
        "fallbackLimit": {
          "value": readonly_prefs.get(FALLBACK_LIMIT_PREF),
          "isUserset": readonly_prefs.isSet(FALLBACK_LIMIT_PREF)
        }
      };

      if (non_builtin_root_certs.length > 0) {
        isPermitted(non_builtin_root_certs[0]).then(is_permitted => {
          if (is_permitted) {
            final_output["nonBuiltInRootCertificates"] = non_builtin_root_certs;
          } else {
            final_output["isNonBuiltInRootCertInstalled"] = non_builtin_root_certs.length > 0;
          }

          sendToTelemetry("aborted", final_output);
        }).catch(err => {
          debug(err);
          final_output["isNonBuiltInRootCertInstalled"] = non_builtin_root_certs.length > 0;
          sendToTelemetry("aborted", final_output);
        });

      return true;
    }).catch(err => {
      debug(err);
    });

    return true;
  }

  return false;
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

  // abort if either of VERSION_MAX_PREF or FALLBACK_LIMIT_PREF was set by the user
  if (hasUserSetPreference()) {
    return;
  }

  // record the default values before the experiment starts
  let defaultMaxVersion = readwrite_prefs.get(VERSION_MAX_PREF);
  let defaultFallbackLimit = readwrite_prefs.get(FALLBACK_LIMIT_PREF);

  runConfigurations().then(tests_result => {
    // restore the default values after the experiment is over
    readwrite_prefs.set(VERSION_MAX_PREF, defaultMaxVersion);
    readwrite_prefs.set(FALLBACK_LIMIT_PREF, defaultFallbackLimit);

    // report the test results to telemetry
    getNonBuiltInRootCertsInstalled().then(non_builtin_certs => {
      // ask for user permission
      isPermitted(non_builtin_certs, tests_result).then(is_permitted => {
        let final_output = {
          "defaultMaxVersion": defaultMaxVersion,
          "defaultFallbackLimit": defaultFallbackLimit,
          "tests": tests_result
        };

        if (is_permitted) {
          final_output["nonBuiltInRootCertificates"] = non_builtin_certs;
        } else {
          final_output["isNonBuiltInRootCertInstalled"] = non_builtin_certs.length > 0;

          for (let tr of tests_result) {
            delete tr["certChain"];
          }
        }
      }).catch(err => {
        debug(err);
      });

      return true;
    }).catch(err => {
      debug(err);
    });

    return true;
  }).catch(err => {
    // restore the default values after the experiment is over
    readwrite_prefs.set(VERSION_MAX_PREF, defaultMaxVersion);
    readwrite_prefs.set(FALLBACK_LIMIT_PREF, defaultFallbackLimit);

    debug(err);
  });
}

function uninstall() {
}
