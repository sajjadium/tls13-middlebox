# Sample Output with User-Set Preferences

```
{
  "max_version": {
    "value": 4,
    "is_userset": true
  },
  "fallback_limit": {
    "value": 3,
    "is_userset": false
  }
}
```

# Sample Output with Default Preferences

```
{
  "default_max_version": 3,
  "default_fallback_limit": 3,
  "tests": [
    {
      "result": {
        "event": "load",
        "status": 0,
        "securityState": 262146,
        "errorMessage": "",
        "certChain": [
          {
            "certType": 0,
            "isBuiltInRoot": false,
            "isSelfSigned": false,
            "keyUsages": "Signing"
          },
          {
            "certType": 1,
            "isBuiltInRoot": false,
            "isSelfSigned": false,
            "keyUsages": "Signing,Certificate Signer"
          },
          {
            "certType": 1,
            "isBuiltInRoot": true,
            "isSelfSigned": true,
            "keyUsages": "Certificate Signer"
          }
        ],
        "certificateTransparencyStatus": 0,
        "cipherName": "TLS_AES_128_GCM_SHA256",
        "isDomainMismatch": false,
        "isExtendedValidation": false,
        "isNotValidAtThisTime": false,
        "isUntrusted": false,
        "keyLength": 128,
        "protocolVersion": 4,
        "secretKeyLength": 128
      },
      "max_version": 4,
      "fallback_limit": 4,
      "is_tls13": true,
      "website": "enabled.tls13.com"
    },
    {
      "result": {
        "event": "error",
        "status": 2152398878
      },
      "max_version": 4,
      "fallback_limit": 4,
      "is_tls13": false,
      "website": "disabled.tls13.com"
    },
    {
      "result": {
        "event": "error",
        "status": 2152398920
      },
      "max_version": 4,
      "fallback_limit": 3,
      "is_tls13": true,
      "website": "tls13.crypto.mozilla.org"
    },
    {
      "result": {
        "event": "error",
        "status": 2153390067,
        "securityState": 4,
        "errorMessage": "control.tls12.com uses an invalid security certificate.\n\nThe certificate is not trusted because the issuer certificate is unknown.\nThe server might not be sending the appropriate intermediate certificates.\nAn additional root certificate may need to be imported.\n\nError code: <a id=\"errorCode\" title=\"SEC_ERROR_UNKNOWN_ISSUER\">SEC_ERROR_UNKNOWN_ISSUER</a>\n",
        "certChain": [
          {
            "certType": 0,
            "isBuiltInRoot": false,
            "isSelfSigned": false,
            "keyUsages": ""
          },
          {
            "certType": 1,
            "isBuiltInRoot": false,
            "isSelfSigned": true,
            "keyUsages": "Certificate Signer"
          }
        ],
        "certificateTransparencyStatus": 0,
        "isDomainMismatch": false,
        "isExtendedValidation": false,
        "isNotValidAtThisTime": false,
        "isUntrusted": true
      },
      "max_version": 4,
      "fallback_limit": 3,
      "is_tls13": false,
      "website": "control.tls12.com"
    },
    {
      "result": {
        "event": "load",
        "status": 0,
        "securityState": 67371010,
        "errorMessage": "",
        "certChain": [
          {
            "certType": 0,
            "isBuiltInRoot": false,
            "isSelfSigned": false,
            "keyUsages": ""
          },
          {
            "certType": 1,
            "isBuiltInRoot": false,
            "isSelfSigned": true,
            "keyUsages": "Certificate Signer"
          }
        ],
        "certificateTransparencyStatus": 0,
        "cipherName": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "isDomainMismatch": false,
        "isExtendedValidation": false,
        "isNotValidAtThisTime": false,
        "isUntrusted": true,
        "keyLength": 128,
        "protocolVersion": 3,
        "secretKeyLength": 128
      },
      "max_version": 3,
      "fallback_limit": 3,
      "is_tls13": true,
      "website": "www.allizom.org"
    },
    {
      "result": {
        "event": "load",
        "status": 0,
        "securityState": 262146,
        "errorMessage": "",
        "certChain": [
          {
            "certType": 0,
            "isBuiltInRoot": false,
            "isSelfSigned": false,
            "keyUsages": ""
          },
          {
            "certType": 1,
            "isBuiltInRoot": false,
            "isSelfSigned": true,
            "keyUsages": "Certificate Signer"
          }
        ],
        "certificateTransparencyStatus": 0,
        "cipherName": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "isDomainMismatch": false,
        "isExtendedValidation": false,
        "isNotValidAtThisTime": false,
        "isUntrusted": false,
        "keyLength": 128,
        "protocolVersion": 3,
        "secretKeyLength": 128
      },
      "max_version": 3,
      "fallback_limit": 3,
      "is_tls13": false,
      "website": "short.tls13.com"
    }
  ]
}
```
