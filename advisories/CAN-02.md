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

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-02 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-02/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-02 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-02/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-02 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-02/03-source-github-v3.png)
