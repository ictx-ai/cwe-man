#!/usr/bin/env python3
"""OWASP Top 10:2025 overlay. Categories map to CWE IDs; no extra examples.

CWE lists are the official mapped sets from owasp.org/Top10/2025/ (scraped
2026-11-15). Descriptions are short paraphrases of the 2025 background text.
"""

EDITION = "2025"
SOURCE = "OWASP Top 10:2025"
URL = "https://owasp.org/Top10/2025/"
# Official pages, one per category.
PAGE_URL = "https://owasp.org/Top10/2025/%s/"

CATEGORIES = [
{
 "id": "A01",
 "man": "OWASP-A01",
 "file": "owasp-a01",
 "slug": "A01_2025-Broken_Access_Control",
 "name": "Broken Access Control",
 "rank": 1,
 "prev": "A01:2021; A10:2021 SSRF folded in",
 "n_cwe_official": 40,
 "desc": [
  "The application does not enforce what an authenticated user is allowed "
  "to do. Attackers access other users' data, change object IDs in the URL, "
  "or reach admin functions. Server-Side Request Forgery is in this category "
  "in 2025.",
 ],
 "cwes": [22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284,
          285, 352, 359, 377, 379, 402, 424, 425, 441, 497, 538, 540, 548,
          552, 566, 601, 615, 639, 668, 732, 749, 862, 863, 918, 922, 1275],
},
{
 "id": "A02",
 "man": "OWASP-A02",
 "file": "owasp-a02",
 "slug": "A02_2025-Security_Misconfiguration",
 "name": "Security Misconfiguration",
 "rank": 2,
 "prev": "A05:2021",
 "n_cwe_official": 16,
 "desc": [
  "The stack is not hardened: default accounts, open cloud shares, extra "
  "ports, verbose errors, missing security headers, or XXE left enabled. "
  "Moved up in 2025 as more behaviour is driven by configuration.",
 ],
 "cwes": [5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942,
          1004, 1174],
},
{
 "id": "A03",
 "man": "OWASP-A03",
 "file": "owasp-a03",
 "slug": "A03_2025-Software_Supply_Chain_Failures",
 "name": "Software Supply Chain Failures",
 "rank": 3,
 "prev": "A06:2021 Vulnerable and Outdated Components, expanded",
 "n_cwe_official": 5,
 "desc": [
  "Compromise in dependencies, the build, or distribution: poisoned "
  "packages, compromised CI, unsigned updates. Few CWEs in the data; high "
  "exploit and impact scores. Community survey ranked this first.",
 ],
 "cwes": [447, 1035, 1104, 1329, 1357, 1395],
},
{
 "id": "A04",
 "man": "OWASP-A04",
 "file": "owasp-a04",
 "slug": "A04_2025-Cryptographic_Failures",
 "name": "Cryptographic Failures",
 "rank": 4,
 "prev": "A02:2021",
 "n_cwe_official": 32,
 "desc": [
  "Secrets in transit or at rest are weakly protected: old ciphers, "
  "hard-coded keys, missing TLS, homemade crypto. Often leads to data "
  "exposure or full compromise.",
 ],
 "cwes": [261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329,
          330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 523, 757,
          759, 760, 780, 916, 1240, 1241],
},
{
 "id": "A05",
 "man": "OWASP-A05",
 "file": "owasp-a05",
 "slug": "A05_2025-Injection",
 "name": "Injection",
 "rank": 5,
 "prev": "A03:2021",
 "n_cwe_official": 38,
 "desc": [
  "Untrusted input is interpreted as code or query: XSS, SQL, OS command, "
  "LDAP, expression language. Most CVE volume of any 2025 category.",
 ],
 "cwes": [20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95,
          96, 97, 98, 99, 103, 104, 112, 113, 114, 115, 116, 129, 159, 470,
          493, 500, 564, 610, 643, 644, 917],
},
{
 "id": "A06",
 "man": "OWASP-A06",
 "file": "owasp-a06",
 "slug": "A06_2025-Insecure_Design",
 "name": "Insecure Design",
 "rank": 6,
 "prev": "A04:2021",
 "n_cwe_official": 39,
 "desc": [
  "Missing or ineffective control design, not a single implementation bug. "
  "Threat modeling and secure patterns were never applied. Distinct from "
  "insecure implementation of a sound design.",
 ],
 "cwes": [73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419,
          434, 436, 444, 451, 454, 472, 501, 522, 525, 539, 598, 602, 628,
          642, 646, 653, 656, 657, 676, 693, 799, 807, 841, 1021, 1022, 1125],
},
{
 "id": "A07",
 "man": "OWASP-A07",
 "file": "owasp-a07",
 "slug": "A07_2025-Authentication_Failures",
 "name": "Authentication Failures",
 "rank": 7,
 "prev": "A07:2021 Identification and Authentication Failures",
 "n_cwe_official": 36,
 "desc": [
  "Login, session, and credential handling fail: hard-coded passwords, "
  "broken certificate checks, missing authentication on a critical function, "
  "session fixation.",
 ],
 "cwes": [258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299,
          300, 302, 303, 304, 305, 306, 307, 308, 309, 346, 350, 384, 521,
          613, 620, 640, 798, 940, 941, 1390, 1391, 1392, 1393],
},
{
 "id": "A08",
 "man": "OWASP-A08",
 "file": "owasp-a08",
 "slug": "A08_2025-Software_or_Data_Integrity_Failures",
 "name": "Software or Data Integrity Failures",
 "rank": 8,
 "prev": "A08:2021 Software and Data Integrity Failures",
 "n_cwe_official": 14,
 "desc": [
  "Untrusted code or data is treated as trusted: unsigned updates, "
  "deserialization of untrusted data, plugins from a CDN without integrity "
  "checks. Lower layer than A03 supply chain.",
 ],
 "cwes": [345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915,
          926],
},
{
 "id": "A09",
 "man": "OWASP-A09",
 "file": "owasp-a09",
 "slug": "A09_2025-Security_Logging_and_Alerting_Failures",
 "name": "Security Logging and Alerting Failures",
 "rank": 9,
 "prev": "A09:2021 Security Logging and Monitoring Failures",
 "n_cwe_official": 5,
 "desc": [
  "Security-relevant events are not logged, logs are not protected, or "
  "nothing alerts. Logs without alerting are of little use in an incident.",
 ],
 "cwes": [117, 221, 223, 532, 778],
},
{
 "id": "A10",
 "man": "OWASP-A10",
 "file": "owasp-a10",
 "slug": "A10_2025-Mishandling_of_Exceptional_Conditions",
 "name": "Mishandling of Exceptional Conditions",
 "rank": 10,
 "prev": "new in 2025",
 "n_cwe_official": 24,
 "desc": [
  "Unusual conditions are not prevented, not detected, or handled by "
  "failing open: sensitive error messages, NULL dereference, missing "
  "parameter, insufficient privileges ignored.",
 ],
 "cwes": [209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396,
          397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756],
},
]
