"use strict";

let {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import("resource://gre/modules/Preferences.jsm");
Cu.import("resource://gre/modules/TelemetryController.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const VERSION_MAX_PREF = "security.tls.version.max";
const FALLBACK_LIMIT_PREF = "security.tls.version.fallback-limit";

let readwrite_prefs = new Preferences({defaultBranch: true});

// all combination of configurations we care about.
let configurations = [
  {maxVersion: 4, fallbackLimit: 4, website: "enabled.tls13.com"},
  {maxVersion: 4, fallbackLimit: 4, website: "disabled.tls13.com"},
  {maxVersion: 3, fallbackLimit: 3, website: "control.tls12.com"}
];

const CERT_USAGE_SSL_CLIENT      = 0x0001;
const CERT_USAGE_SSL_SERVER      = 0x0002;
const CERT_USAGE_SSL_CA          = 0x0008;
const CERT_USAGE_EMAIL_SIGNER    = 0x0010;
const CERT_USAGE_EMAIL_RECIPIENT = 0x0020;
const CERT_USAGE_OBJECT_SIGNER   = 0x0040;

let certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);

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

// veries the cert using either SSL_SERVER or SSL_CA usages and extracts the chain
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

// returns true if there is at least one non-builtin root certificate is installed
async function isNonBuiltInRootCertInstalled() {
  let certs = nsIX509CertListToArray(certDB.getCerts());

  for (let cert of certs) {
    let chain = await getCertChain(cert, CERT_USAGE_SSL_CA);

    if (chain !== null && chain.length === 1 && !chain[0].isBuiltInRoot) {
      return true;
    }
  }

  return false;
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

        // extracting sha256 fingerprint for the leaf cert in the chain
        result.serverSha256Fingerprint = getFieldValue(chain[0], "sha256Fingerprint");

        // check the root cert to see if it is builtin certificate
        result.isBuiltInRoot = (chain !== null && chain.length > 0) ? getFieldValue(chain[chain.length - 1], "isBuiltInRoot") : null;

        // record the tls version Firefox ended up negotiating
        result.protocolVersion = getFieldValue(sslStatus, "protocolVersion");
      }
    }
  } catch (ex) {
    result.exception = ex.message;
  }

  return result;
}

function makeRequest(config) {
  return new Promise((resolve, reject) => {
    // put together the configuration and the info collected from the connection
    function reportResult(event, xhr) {
      getInfo(xhr).then(info => {
        let output = Object.assign({"result": {"event": event, "responseCode": xhr.status}}, config);
        output.result = Object.assign(output.result, info);
        resolve(output);

        return true;
      }).catch();
    }

    try {
      // set the configuration to the values that were passed to this function
      readwrite_prefs.set(VERSION_MAX_PREF, config.maxVersion);
      readwrite_prefs.set(FALLBACK_LIMIT_PREF, config.fallbackLimit);

      let xhr = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);

      xhr.open("GET", `https://${config.website}`, true);

      xhr.timeout = 10000;

      xhr.channel.loadFlags |= Ci.nsIRequest.LOAD_ANONYMOUS;
      xhr.channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE;
      xhr.channel.loadFlags |= Ci.nsIRequest.INHIBIT_CACHING;

      xhr.addEventListener("load", e => {
        reportResult("load", e.target);
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

// check if either of VERSION_MAX_PREF or FALLBACK_LIMIT_PREF was set by the user
function hasUserSetPreference() {
  let readonly_prefs = new Preferences();

  if (readonly_prefs.isSet(VERSION_MAX_PREF) || readonly_prefs.isSet(FALLBACK_LIMIT_PREF)) {
    // reports the current values as well as whether they were set by the user
    isNonBuiltInRootCertInstalled().then(non_builtin_result => {
      TelemetryController.submitExternalPing("tls13-middlebox", {
        maxVersion: {
          value: readonly_prefs.get(VERSION_MAX_PREF),
          isUserset: readonly_prefs.isSet(VERSION_MAX_PREF)
        },
        fallbackLimit: {
          value: readonly_prefs.get(FALLBACK_LIMIT_PREF),
          isUserset: readonly_prefs.isSet(FALLBACK_LIMIT_PREF)
        },
        isNonBuiltInRootCertInstalled: non_builtin_result
      });

      return true;
    }).catch();

    return true;
  }

  return false;
}

function startup() {}

function shutdown() {}

function install() {
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
    isNonBuiltInRootCertInstalled().then(non_builtin_result => {
      TelemetryController.submitExternalPing("tls13-middlebox", {
        "defaultMaxVersion": defaultMaxVersion,
        "defaultFallbackLimit": defaultFallbackLimit,
        "isNonBuiltInRootCertInstalled": non_builtin_result,
        "tests": tests_result
      });

      return true;
    }).catch();

    return true;
  }).catch();
}

function uninstall() {}
