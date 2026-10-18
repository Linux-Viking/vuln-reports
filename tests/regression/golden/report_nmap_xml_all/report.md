# Vulnerability Intelligence Report
**Generated on:** 2026-10-17 12:00 | **Scanner:** nmap_xml | **Target:** nmap.xml


## 📊 Summary Statistics
| Metric | Value |
| :--- | :--- |
| **HOSTS** | 3 |
| **Total Unique CVEs** | 6 |
| **Critical Risks (CVSS >= 9.0)** | 2 |
| **KEV Exploited (Active)** | 1 |

---


## [CVE-2021-44228] Apache Log4j2 JNDI lookups reach attacker controlled LDAP endpoints
**CVSS Score:** `10.0` | **KEV:** `Yes` | **Exploitability:** `Exploited in the wild` | **Threat Vector:** `NETWORK`

### 1. Description
Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP endpoints. An attacker who controls log messages can execute arbitrary code.

### 2. Affected Products
- **Apache Log4j2**: 2.0-beta9 to <2.3.1, 2.4 to <2.12.2, 2.13.0 to <2.15.0


<div style="page-break-after: always;"></div>

### 3. Affected Hosts
- `app02.example.test` (443/tcp)


<div style="page-break-after: always;"></div>

### 4. Remediation Recommendation
**Upgrade to Log4j 2.17.1 or later; remove the JndiLookup class as an interim mitigation.**

### 5. Intelligence & References
- 🚀 **Exploit PoC Link**: [https://www.exploit-db.com/exploits/00000](https://www.exploit-db.com/exploits/00000)
- 🔗 [https://nvd.nist.gov/vuln/detail/CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- 🔗 [https://www.cve.org/CVERecord?id=CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228)
- 🔗 [https://logging.apache.org/log4j/2.x/security.html](https://logging.apache.org/log4j/2.x/security.html)
- 🔗 [https://www.exploit-db.com/exploits/00000](https://www.exploit-db.com/exploits/00000)


---

## [CVE-2026-42945] nginx: synthetic heap overflow in HTTP/3 module
**CVSS Score:** `9.2` | **KEV:** `No` | **Exploitability:** `Theoretical / Unknown` | **Threat Vector:** `NETWORK`

### 1. Description
A synthetic heap overflow in the nginx HTTP/3 module allows remote attackers to crash worker processes. Users are recommended to upgrade to 1.29.9, which fixes the issue.

### 2. Affected Products
- **nginx**: 1.29.8


<div style="page-break-after: always;"></div>

### 3. Affected Hosts
- `web01.example.test (192.0.2.10)` (80/tcp)


<div style="page-break-after: always;"></div>

### 4. Remediation Recommendation
**Upgrade to 1 or later.**

### 5. Intelligence & References
- 🔗 [https://nvd.nist.gov/vuln/detail/CVE-2026-42945](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
- 🔗 [https://www.cve.org/CVERecord?id=CVE-2026-42945](https://www.cve.org/CVERecord?id=CVE-2026-42945)
- 🔗 [https://nginx.example.test/en/security_advisories.html](https://nginx.example.test/en/security_advisories.html)


---

## [CVE-2024-6387] OpenSSH: Race Condition
**CVSS Score:** `8.1` | **KEV:** `No` | **Exploitability:** `Theoretical / Unknown` | **Threat Vector:** `NETWORK`

### 1. Description
A signal handler race condition was found in OpenSSH's server (sshd), where a client does not authenticate within LoginGraceTime seconds. This issue is fixed in version 9.8p1.

### 2. Affected Products
- **OpenSSH**: 8.5p1 to <9.8p1


<div style="page-break-after: always;"></div>

### 3. Affected Hosts
- `web01.example.test (192.0.2.10)` (22/tcp)
- `192.0.2.11` (22/tcp)


<div style="page-break-after: always;"></div>

### 4. Remediation Recommendation
**Upgrade to 9 or later.**

### 5. Intelligence & References
- 🔗 [https://nvd.nist.gov/vuln/detail/CVE-2024-6387](https://nvd.nist.gov/vuln/detail/CVE-2024-6387)
- 🔗 [https://www.cve.org/CVERecord?id=CVE-2024-6387](https://www.cve.org/CVERecord?id=CVE-2024-6387)
- 🔗 [https://www.openssh.example.test/txt/release-9.8](https://www.openssh.example.test/txt/release-9.8)


---

## [CVE-2022-0001] Intel(R) Processors: Information Disclosure
**CVSS Score:** `6.5` | **KEV:** `No` | **Exploitability:** `Theoretical / Unknown` | **Threat Vector:** `LOCAL`

### 1. Description
Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may allow an authorized user to potentially enable information disclosure via local access.

### 2. Affected Products
- **Intel(R) Processors**: See references


<div style="page-break-after: always;"></div>

### 3. Affected Hosts
- `web01.example.test (192.0.2.10)` (80/tcp)


<div style="page-break-after: always;"></div>

### 4. Remediation Recommendation
**Apply the latest security patches from the vendor.**

### 5. Intelligence & References
- 🔗 [https://nvd.nist.gov/vuln/detail/CVE-2022-0001](https://nvd.nist.gov/vuln/detail/CVE-2022-0001)
- 🔗 [https://www.cve.org/CVERecord?id=CVE-2022-0001](https://www.cve.org/CVERecord?id=CVE-2022-0001)


---

## [CVE-2023-48795] OpenSSH: Terrapin
**CVSS Score:** `5.9` | **KEV:** `No` | **Exploitability:** `PoC Available` | **Threat Vector:** `NETWORK`

### 1. Description
The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted, aka a Terrapin attack.

### 2. Affected Products
- **OpenSSH**: 9.6


<div style="page-break-after: always;"></div>

### 3. Affected Hosts
- `web01.example.test (192.0.2.10)` (22/tcp)
- `192.0.2.11` (22/tcp)


<div style="page-break-after: always;"></div>

### 4. Remediation Recommendation
**Review vendor advisory and apply available patches: https://example.test/security-advisory/2023-48795**

### 5. Intelligence & References
- 🚀 **Exploit PoC Link**: [https://github.com/example-org/CVE-2023-48795-poc](https://github.com/example-org/CVE-2023-48795-poc)
- 🔗 [https://nvd.nist.gov/vuln/detail/CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795)
- 🔗 [https://www.cve.org/CVERecord?id=CVE-2023-48795](https://www.cve.org/CVERecord?id=CVE-2023-48795)
- 🔗 [https://terrapin-attack.example.test/](https://terrapin-attack.example.test/)
- 🔗 [https://example.test/security-advisory/2023-48795](https://example.test/security-advisory/2023-48795)


---

## [CVE-2021-41773] Apache HTTP Server: Mapping urls to files outside the expected document root
**CVSS Score:** `3.1` | **KEV:** `No` | **Exploitability:** `Theoretical / Unknown` | **Threat Vector:** `NETWORK`

### 1. Description
A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49 that allows mapping URLs to files outside the expected document root.

### 2. Affected Products
- **Apache HTTP Server**: 2.4.49


<div style="page-break-after: always;"></div>

### 3. Affected Hosts
- `app02.example.test` (443/tcp)


<div style="page-break-after: always;"></div>

### 4. Remediation Recommendation
**Apply the latest security patches from the vendor.**

### 5. Intelligence & References
- 🔗 [https://nvd.nist.gov/vuln/detail/CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)
- 🔗 [https://www.cve.org/CVERecord?id=CVE-2021-41773](https://www.cve.org/CVERecord?id=CVE-2021-41773)
- 🔗 [https://httpd.example.test/security/vulnerabilities_24.html](https://httpd.example.test/security/vulnerabilities_24.html)


---


*Generated by Vuln-Reports Suite*