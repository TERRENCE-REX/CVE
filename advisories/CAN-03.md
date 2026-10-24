# SpringBlade iframe route DOM XSS

## Summary

The SPA iframe route assigns the url query value directly to iframe src without restricting dangerous schemes.

## Affected product

- Vendor/project: **chillzhuang**
- Product: **SpringBlade web frontend**
- Affected version: **5.0.2**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Victim is logged in and opens an attacker-crafted hash URL; no attacker account is required to construct the URL.

Verified flow: `hash route query url -> $route.query.url -> iframe :src -> javascript: execution in the application origin`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Construct /#/iframe?url= with a javascript: URL that writes a fresh marker into the parent window.
2. Open the crafted route in a logged-in browser.
3. Read the rendered iframe src and the parent marker value from the browser context.

Sanitized request shape used during verification:

```http
GET <BASE_URL>/#/iframe?url=javascript:parent.__xss='gt48261022if3'

# Browser verification
iframe.src === "javascript:parent.__xss='gt48261022if3'"
window.__xss === "gt48261022if3"
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
components/iframe/main.vue:1-32
<iframe :src="src" class="iframe" ref="iframe" />

computed: {
    src () {
        return this.$route.query.url.replace(/#/g, "&")
    }
}
```

Root cause: The route query is bound directly to a navigable iframe attribute with no URL parser or scheme allowlist.

## Recommended remediation

Parse the URL and allow only required http/https origins. Explicitly reject javascript:, data:, blob: and other active schemes.

## References

- Official source: https://github.com/chillzhuang/Saber/blob/df87608e5d2d08235da6f1f5c396ce8bc328ad7b/src/components/iframe/main.vue#L1-L32

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-03 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-03/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-03 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-03/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-03 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-03/03-source-github-v3.png)
