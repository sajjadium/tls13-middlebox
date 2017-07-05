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

// some fields are not available sometimes, so we have to catch the errors and return undefined.
function getFieldValue(obj, name) {
  try {
    return obj[name];
  } catch (ex) {
    return undefined;
  }
}

// extracting the root certificate from the chain
function extractRootCert(cert) {
  let root_cert = cert;

  while (getFieldValue(root_cert, "issuer")) {
    root_cert = getFieldValue(root_cert, "issuer");
  }

  return root_cert;
}

// returns true if there is at least one non-builtin root certificate is installed
function isNonBuiltInRootCertInstalled() {
  let certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);

  let iter = certDB.getCerts().getEnumerator();

  while (iter.hasMoreElements()) {
    let cert = iter.getNext().QueryInterface(Ci.nsIX509Cert);

    // extract the root certificate for the current certificate
    let root_cert = extractRootCert(cert);

    if (getFieldValue(root_cert, "isBuiltInRoot") === false &&
      // There are some root certificates that are built-in but their isBuiltInRoot is false.
      // That is why we check their tokenName as well
      getFieldValue(root_cert, "tokenName").toLowerCase() !== "Builtin Object Token".toLowerCase()) {
      return true;
    }
  }

  return false;
}

function getInfo(xhr) {
  let result = {};

  try {
    let channel = xhr.channel;

    // this is the most important value based on which we can find out the problem
    channel.QueryInterface(Ci.nsIRequest);
    result.status = getFieldValue(channel, "status");

    let securityInfo = getFieldValue(channel, "securityInfo");

    if (securityInfo instanceof Ci.nsITransportSecurityInfo) {
      securityInfo.QueryInterface(Ci.nsITransportSecurityInfo);

      result.securityState = getFieldValue(securityInfo, "securityState");

      // Error message on connection failure. I am not sure if we can get this error message using status code.
      // It is safer to collect this information as well.
      result.errorMessage = getFieldValue(securityInfo, "errorMessage");
    }

    if (securityInfo instanceof Ci.nsISSLStatusProvider) {
      securityInfo.QueryInterface(Ci.nsISSLStatusProvider);
      let sslStatus = securityInfo.SSLStatus;

      if (sslStatus) {
        sslStatus.QueryInterface(Ci.nsISSLStatus);

        // extracting sha256 fingerprint for the leaf cert
        result.serverCertSha256Fingerprint = getFieldValue(sslStatus.serverCert, "sha256Fingerprint");

        let root_cert = extractRootCert(sslStatus.serverCert);

        // if the root certificate is not built-in, it means that there is middlebox on the way
        // we need both of them to identify whether it is truly a built-in root certificate
        result.rootCertIsBuiltIn = getFieldValue(root_cert, "isBuiltInRoot");
        result.rootCertTokenName = getFieldValue(root_cert, "tokenName");

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
      let output = Object.assign({"result": {"event": event, "responseCode": xhr.status}}, config);
      output.result = Object.assign(output.result, getInfo(xhr));
      resolve(output);
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
    TelemetryController.submitExternalPing("tls13-middlebox-v1", {
      maxVersion: {
        value: readonly_prefs.get(VERSION_MAX_PREF),
        isUserset: readonly_prefs.isSet(VERSION_MAX_PREF)
      },
      fallbackLimit: {
        value: readonly_prefs.get(FALLBACK_LIMIT_PREF),
        isUserset: readonly_prefs.isSet(FALLBACK_LIMIT_PREF)
      },
      isNonBuiltInRootCertInstalled: isNonBuiltInRootCertInstalled()
    });

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

  runConfigurations().then(result => {
    // restore the default values after the experiment is over
    readwrite_prefs.set(VERSION_MAX_PREF, defaultMaxVersion);
    readwrite_prefs.set(FALLBACK_LIMIT_PREF, defaultFallbackLimit);

    // report the test results to telemetry
    TelemetryController.submitExternalPing("tls13-middlebox", {
      "defaultMaxVersion": defaultMaxVersion,
      "defaultFallbackLimit": defaultFallbackLimit,
      "isNonBuiltInRootCertInstalled": isNonBuiltInRootCertInstalled(),
      "tests": result
    });

    return true;
  }).catch();
}

function uninstall() {}
