# Security advisories

This repository contains public-safe vulnerability research advisories and supporting evidence prepared by **Zhong Guangyuan (钟广源), Fudan University**.

The `CAN-01` through `CAN-19` labels are local tracking identifiers only. They are **not CVE IDs**. CVE assignment is pending. Each advisory was independently verified on a researcher-controlled deployment with three consecutive successful runs, and all authentication values, private addresses, internal identifiers, document keys, and one-time tokens have been redacted.

Evidence images are renderings made from saved HTTP, DOM, database, and source-code evidence. They are clearly labelled and are not presented as live browser screenshots.

## Advisory index

| Tracking ID | Product | Vulnerability | Advisory |
| --- | --- | --- | --- |
| CAN-01 | UReport 2.2.9 | Preview title reflected XSS | [Advisory](advisories/CAN-01.md) · [Issue #3](https://github.com/TERRENCE-REX/CVE/issues/3) |
| CAN-02 | UReport 2.2.9 | `customParameters` JavaScript-string XSS | [Advisory](advisories/CAN-02.md) · [Issue #4](https://github.com/TERRENCE-REX/CVE/issues/4) |
| CAN-03 | SpringBlade 5.0.2 | iframe route DOM XSS | [Advisory](advisories/CAN-03.md) · [Issue #5](https://github.com/TERRENCE-REX/CVE/issues/5) |
| CAN-04 | UReport 2.2.9 | Decoded exception-message reflected XSS | [Advisory](advisories/CAN-04.md) · [Issue #6](https://github.com/TERRENCE-REX/CVE/issues/6) |
| CAN-05 | UReport 2.2.9 | SQL-error stack stored XSS | [Advisory](advisories/CAN-05.md) · [Issue #7](https://github.com/TERRENCE-REX/CVE/issues/7) |
| CAN-06 | UReport 2.2.9 | `link-url` attribute stored XSS | [Advisory](advisories/CAN-06.md) · [Issue #8](https://github.com/TERRENCE-REX/CVE/issues/8) |
| CAN-07 | UReport 2.2.9 | Report-filename stored XSS in two views | [Advisory](advisories/CAN-07.md) · [Issue #9](https://github.com/TERRENCE-REX/CVE/issues/9) |
| CAN-08 | UReport 2.2.9 | Chart-label script-element escape | [Advisory](advisories/CAN-08.md) · [Issue #10](https://github.com/TERRENCE-REX/CVE/issues/10) |
| CAN-09 | UReport 2.2.9 | Font-family style-element escape | [Advisory](advisories/CAN-09.md) · [Issue #11](https://github.com/TERRENCE-REX/CVE/issues/11) |
| CAN-10 | UReport 2.2.9 | Search-form label stored XSS | [Advisory](advisories/CAN-10.md) · [Issue #12](https://github.com/TERRENCE-REX/CVE/issues/12) |
| CAN-11 | RuoYi 4.8.3 | Profile `userName` attribute stored XSS | [Advisory](advisories/CAN-11.md) · [Issue #13](https://github.com/TERRENCE-REX/CVE/issues/13) |
| CAN-12 | RuoYi 4.8.3 | Menu icon attribute stored XSS | [Advisory](advisories/CAN-12.md) · [Issue #14](https://github.com/TERRENCE-REX/CVE/issues/14) |
| CAN-13 | phpBB 3.3.19 | `rank_image` attribute stored XSS | [Advisory](advisories/CAN-13.md) · [Issue #15](https://github.com/TERRENCE-REX/CVE/issues/15) |
| CAN-14 | HumHub 1.18.6 | FriendshipButton display-name stored XSS | [Advisory](advisories/CAN-14.md) · [Issue #16](https://github.com/TERRENCE-REX/CVE/issues/16) |
| CAN-15 | HumHub User Location Map 1.2.5 | Popup stored XSS | [Advisory](advisories/CAN-15.md) · [Issue #17](https://github.com/TERRENCE-REX/CVE/issues/17) |
| CAN-16 | ONLYOFFICE for HumHub 4.0.0 | Notification stored XSS | [Advisory](advisories/CAN-16.md) · [Issue #18](https://github.com/TERRENCE-REX/CVE/issues/18) |
| CAN-17 | HumHub Q&A 1.1.3 | Answer display-name stored XSS | [Advisory](advisories/CAN-17.md) · [Issue #19](https://github.com/TERRENCE-REX/CVE/issues/19) |
| CAN-18 | HumHub Let's Meet 1.1.5 | Invitation notification stored XSS | [Advisory](advisories/CAN-18.md) · [Issue #20](https://github.com/TERRENCE-REX/CVE/issues/20) |
| CAN-19 | HumHub REST 0.11.5 | Bearer-auth response display-name XSS | [Advisory](advisories/CAN-19.md) · [Issue #21](https://github.com/TERRENCE-REX/CVE/issues/21) |

## Scope and contact

The reports document the affected versions, prerequisites, reproduction shape, three-run verification evidence, source-to-Sink flow, and remediation guidance. Questions or coordinated-disclosure updates can be sent through the corresponding public GitHub Issue.
