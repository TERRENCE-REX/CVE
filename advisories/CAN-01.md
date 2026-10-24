# UReport preview title reflected XSS

## Summary

UReport decodes the preview _title parameter, or falls back to the decoded _u value, and emits it inside the HTML title element without context-appropriate encoding.

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

Authenticated attacker; victim opens the crafted preview URL.

Verified flow: `preview _title or fallback _u -> buildTitle()/decode() -> Velocity title -> <title>${title}</title>`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a title payload that closes the title element and adds an event-capable HTML marker.
2. URL-encode the value three times so filtering observes only the encoded form.
3. Request the preview with _title, or the fallback _u parameter, and inspect the returned head markup.

Sanitized request shape used during verification:

```http
GET <BASE_URL>/blade-report/ureport/preview
blade-auth: bearer <JWT>

?_u=<ANY>&_title=URLENCODEx3('</title><img src=x onerror=self[`al`+`ert`](`gt48261022t2c`)>')

# Fallback variant: place the triple-encoded value in _u and omit _title.
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
HtmlPreviewServletAction.java:147-163
private String buildTitle(HttpServletRequest req) {
    String title = req.getParameter("_title");
    if (StringUtils.isNotBlank(title)) {
        title = decode(title);
    } else {
        title = decode(req.getParameter("_u"));
    }
    return title + "-ureport";
}

ureport-html/html-preview.html:10
<title>${title}</title>
```

Root cause: Decoded request data is treated as trusted document-title markup and Velocity performs no context-aware escaping.

## Recommended remediation

HTML-encode title text at the template boundary and remove repeated decoding of security-sensitive request parameters.

## References

- Official source: https://github.com/youseries/ureport/blob/master/ureport2-console/src/main/java/com/bstek/ureport/console/html/HtmlPreviewServletAction.java

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-01 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-01/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-01 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-01/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-01 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-01/03-source-github-v3.png)
