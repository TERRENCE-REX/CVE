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

- **Zhong Guangyuan, Fudan University**

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

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-10 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-10/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-10 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-10/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-10 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-10/03-source-github-v3.png)
