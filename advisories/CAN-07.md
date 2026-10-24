# UReport report-filename stored XSS in two views

## Summary

saveReportFile double-decodes and persists an unrestricted filename. The name is later inserted as HTML by OpenDialog and into an inline JavaScript string by the preview template.

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

Authenticated report author; victim opens the report list or previews the crafted stored report.

Verified flow: `triple-encoded report filename -> decodeFileName() -> database -> OpenDialog HTML / preview inline JavaScript`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Save a minimal report using a triple-encoded filename carrying HTML or JavaScript-string syntax.
2. Confirm the decoded filename is returned by loadReportProviders and persisted.
3. Open the designer report list or the matching preview and inspect the corresponding HTML/inline-script Sink.

Sanitized request shape used during verification:

```http
POST <BASE_URL>/blade-report/ureport/designer/saveReportFile
blade-auth: bearer <JWT>

file=URLENCODE×3("blade-fnlf<img ... gt48261022n3c>.ureport.xml")
content=URLENCODE×2(<MINIMAL_REPORT_XML>)

GET <BASE_URL>/blade-report/ureport/designer/loadReportProviders
# Victim opens the designer Open dialog.

# Inline-JS variant uses a stored quote-breaking filename and previews it by name.
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
DesignerServletAction.java:163-187
file = ReportUtils.decodeFileName(file);
reportProvider.saveReport(file, content);
return loadReportProviders();

OpenDialog.js:59
tr.append(`<td style="vertical-align: middle;">${file.name}</td>`);

ureport-html/html-preview.html:123
submitSearchForm("${file}","${customParameters}");
```

Root cause: Unrestricted decoded filenames become persistent application data and are reused in both HTML and JavaScript contexts without the encoding required by either context.

## Recommended remediation

Enforce a conservative filename grammar before storage and apply separate HTML-text and JavaScript-string encoders at the two output Sinks.

## References

- Official source: https://github.com/youseries/ureport

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-07 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-07/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-07 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-07/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-07 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-07/03-source-github-v3.png)
