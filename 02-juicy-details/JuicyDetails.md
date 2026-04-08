# THM — Juicy Details
**Platform:** TryHackMe | **Category:** Log Analysis | **Difficulty:** Easy

## Scenario
A juice shop web application was breached. Investigate provided log files 
(access.log, vsftpd.log, auth.log) to reconstruct the attack chain.

## Tools Used
- grep / cat (log parsing)

## Attack Reconstruction

### Reconnaissance & Initial Access
Attacker conducted staged reconnaissance using multiple tools identified 
via User-Agent strings in access.log — in order of occurrence: 
**nmap, hydra, sqlmap, curl, feroxbuster**

### Brute Force
Hydra targeted `/rest/user/login`. Attack was successful — confirmed via 
HTTP 200 response at `11/Apr/2021:09:16:31 +0000`

### SQL Injection
sqlmap exploited `/rest/products/search` via parameter `q`, extracting 
**email and password** fields from the database.

### Data Exfiltration
Attacker accessed `/ftp` endpoint to retrieve files:
- `coupons_2013.md.bak`
- `www-data.bak`

Retrieved via **ftp, anonymous** login.

### Reconnaissance — User Enumeration
Attacker scraped customer email addresses from the **product reviews** section.

### Persistence/Shell Access
Shell access gained via **ssh, www-data** — confirmed in auth.log.

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Network Scanning | T1595 |
| Brute Force | T1110 |
| SQL Injection | T1190 |
| Data from Info Repositories | T1213 |
| Exfiltration over unencrypted protocol | T1048.003 |

## Defensive Takeaways
- Rate limiting on login endpoints prevents brute force
- Parameterized queries eliminate SQL injection risk
- FTP anonymous access should be disabled
- Monitor auth.log for SSH logins from web service accounts
