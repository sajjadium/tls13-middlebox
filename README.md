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
        "event": "error",
        "status": 2153390067,
        "securityState": 4,
        "errorMessage": "disabled.tls13.com uses an invalid security certificate.\n\nThe certificate is not trusted because the issuer certificate is unknown.\nThe server might not be sending the appropriate intermediate certificates.\nAn additional root certificate may need to be imported.\n\nError code: <a id=\"errorCode\" title=\"SEC_ERROR_UNKNOWN_ISSUER\">SEC_ERROR_UNKNOWN_ISSUER</a>\n"
      },
      "max_version": 4,
      "fallback_limit": 4,
      "is_tls13": false,
      "website": "disabled.tls13.com"
    },
    {
      "result": {
        "event": "error",
        "status": 2152398919,
        "securityState": 4,
        "errorMessage": "An error occurred during a connection to localhost:8888.\n\nEncountered end of file\n\nError code: <a id=\"errorCode\" title=\"PR_END_OF_FILE_ERROR\">PR_END_OF_FILE_ERROR</a>\n"
      },
      "max_version": 3,
      "fallback_limit": 3,
      "is_tls13": false,
      "website": "localhost:8888"
    },
    {
      "result": {
        "event": "error",
        "status": 2152398861
      },
      "max_version": 3,
      "fallback_limit": 3,
      "is_tls13": true,
      "website": "localhost:8888"
    },
    {
      "result": {
        "event": "load"
      },
      "max_version": 4,
      "fallback_limit": 3,
      "is_tls13": true,
      "website": "www.allizom.org"
    },
    {
      "result": {
        "event": "load"
      },
      "max_version": 4,
      "fallback_limit": 4,
      "is_tls13": true,
      "website": "enabled.tls13.com"
    },
    {
      "result": {
        "event": "load"
      },
      "max_version": 4,
      "fallback_limit": 3,
      "is_tls13": false,
      "website": "control.tls12.com"
    }
  ]
}
```