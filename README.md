# Security advisories

This repository contains public-safe vulnerability research advisories and supporting evidence prepared by **Zhong Guangyuan (钟广源), Fudan University**.

The `CAN-01` through `CAN-19` labels are local tracking identifiers only. They are **not CVE IDs**. CVE assignment is pending. Each advisory was independently verified on a researcher-controlled deployment with three consecutive successful runs, and all authentication values, private addresses, internal identifiers, document keys, and one-time tokens have been redacted.

Evidence images are renderings made from saved HTTP, DOM, database, and source-code evidence. They are clearly labelled and are not presented as live browser screenshots.

## Advisory index

| Tracking ID | Product | Vulnerability | Advisory |
| --- | --- | --- | --- |
| CAN-01 | UReport 2.2.9 | Preview title reflected XSS | [Details](advisories/CAN-01.md) |
| CAN-02 | UReport 2.2.9 | `customParameters` JavaScript-string XSS | [Details](advisories/CAN-02.md) |
| CAN-03 | SpringBlade 5.0.2 | iframe route DOM XSS | [Details](advisories/CAN-03.md) |
| CAN-04 | UReport 2.2.9 | Decoded exception-message reflected XSS | [Details](advisories/CAN-04.md) |
| CAN-05 | UReport 2.2.9 | SQL-error stack stored XSS | [Details](advisories/CAN-05.md) |
| CAN-06 | UReport 2.2.9 | `link-url` attribute stored XSS | [Details](advisories/CAN-06.md) |
| CAN-07 | UReport 2.2.9 | Report-filename stored XSS in two views | [Details](advisories/CAN-07.md) |
| CAN-08 | UReport 2.2.9 | Chart-label script-element escape | [Details](advisories/CAN-08.md) |
| CAN-09 | UReport 2.2.9 | Font-family style-element escape | [Details](advisories/CAN-09.md) |
| CAN-10 | UReport 2.2.9 | Search-form label stored XSS | [Details](advisories/CAN-10.md) |
| CAN-11 | RuoYi 4.8.3 | Profile `userName` attribute stored XSS | [Details](advisories/CAN-11.md) |
| CAN-12 | RuoYi 4.8.3 | Menu icon attribute stored XSS | [Details](advisories/CAN-12.md) |
| CAN-13 | phpBB 3.3.19 | `rank_image` attribute stored XSS | [Details](advisories/CAN-13.md) |
| CAN-14 | HumHub 1.18.6 | FriendshipButton display-name stored XSS | [Details](advisories/CAN-14.md) |
| CAN-15 | HumHub User Location Map 1.2.5 | Popup stored XSS | [Details](advisories/CAN-15.md) |
| CAN-16 | ONLYOFFICE for HumHub 4.0.0 | Notification stored XSS | [Details](advisories/CAN-16.md) |
| CAN-17 | HumHub Q&A 1.1.3 | Answer display-name stored XSS | [Details](advisories/CAN-17.md) |
| CAN-18 | HumHub Let's Meet 1.1.5 | Invitation notification stored XSS | [Details](advisories/CAN-18.md) |
| CAN-19 | HumHub REST 0.11.5 | Bearer-auth response display-name XSS | [Details](advisories/CAN-19.md) |

## Scope and contact

The reports document the affected versions, prerequisites, reproduction shape, three-run verification evidence, source-to-Sink flow, and remediation guidance. Questions or coordinated-disclosure updates can be sent through the corresponding public GitHub Issue.
