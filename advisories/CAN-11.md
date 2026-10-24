# RuoYi profile userName attribute stored XSS

## Summary

RuoYi 4.8.3 contains stored cross-site scripting in the role user-view page. Any authenticated user can update their own userName; the role view formatter later concatenates that value into a data-search HTML attribute without attribute encoding. A crafted display name executes script when a privileged user views role membership details.

## Affected product

- Vendor/project: **yangzongzhuan**
- Product: **RuoYi**
- Affected version: **4.8.3**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (5.4)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

Authenticated attacker; victim can view role membership details.

Verified flow: `self-service userName → role user list JSON → searchKey → data-search attribute`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Update the attacker's own display name with a quote-breaking attribute payload.
2. Confirm the exact value is stored and returned by the role user-list endpoint.
3. Open the role membership view and interact with the crafted user card.

Sanitized request shape used during verification:

```http
# Any authenticated user updates their own profile
POST <BASE_URL>/system/user/profile/update
Cookie: <SESSION_COOKIE>
Content-Type: application/x-www-form-urlencoded

userName=gt481022%22%20onclick%20%3D%20eval%28name%29
sex=0
email=gt481022ry43@example.test
phonenumber=<BENIGN_VALUE>

# A role viewer loads the stored user record
POST <BASE_URL>/system/role/authUser/allocatedList
Cookie: <PRIVILEGED_SESSION_COOKIE>

roleId=1&pageNum=1&pageSize=50
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.


## Confirmed source and Sink

```text
role/view.html:593-596
var searchKey = [u.userName || '', u.loginName || '', u.phonenumber || '']
    .join('|').toLowerCase();
var card = [
    '<div class="user-card" data-search="' + searchKey + '">',
    ...
].join('');
```

Root cause: A self-service profile field is copied into searchKey and concatenated into a double-quoted data-search attribute. Quotes are not attribute-encoded.

## Recommended remediation

Build the card with DOM APIs and set dataset.search, or apply HTML attribute encoding to every value before interpolation.

## References

- Official source: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/resources/templates/system/role/view.html

## Evidence images

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-11 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-11/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-11 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-11/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-11 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-11/03-source-github-v3.png)
