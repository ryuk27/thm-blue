# THM: Juicy Details
**Platform:** TryHackMe | **Category:** Log Analysis | **Difficulty:** Easy

## Scenario
A juice shop web application was breached. Investigate provided log files 
(access.log, vsftpd.log, auth.log) to reconstruct the attack chain.

## Tools Used
- Text Editor (manual log analysis)

## Attack Reconstruction

### Reconnaissance & Initial Access
Attacker conducted staged reconnaissance using multiple tools identified 
via User-Agent strings in access.log — in order of occurrence:
**nmap, hydra, sqlmap, curl, feroxbuster**

![User-Agent strings in access.log](screenshots/recon_useragent.png)

### Brute Force
Hydra targeted `/rest/user/login`. Attack was successful — confirmed via 
HTTP 200 response at `11/Apr/2021:09:16:31 +0000`

![Hydra brute force success in access.log](screenshots/bruteforce_success.png)

### SQL Injection
sqlmap exploited `/rest/products/search` via parameter `q`, extracting
**email and password** fields from the database.

![SQLmap activity in access.log](screenshots/sqli_endpoint.png)

### User Enumeration
Attacker scraped customer email addresses from the **product reviews** 
section via abnormal query patterns in access.log.

![Product reviews scraping in access.log](screenshots/email_scrape.png)

### Data Exfiltration
Attacker accessed `/ftp` endpoint to retrieve files:
- `coupons_2013.md.bak`
- `www-data.bak`

Retrieved via **ftp, anonymous** login — confirmed in vsftpd.log.

![FTP file retrieval in vsftpd.log](screenshots/ftp_exfil.png)

### Persistence / Shell Access
Shell access gained via **ssh, www-data** — confirmed in auth.log.

![SSH login in auth.log](screenshots/ssh_access.png)

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Network Scanning | T1595 |
| Brute Force | T1110 |
| Exploitation of Public-Facing Application (SQLi) | T1190 |
| Data from Information Repositories | T1213 |
| Exfiltration over Unencrypted Protocol (FTP) | T1048.003 |
| Remote Services: SSH | T1021.004 |

## Defensive Takeaways
- Rate limiting on login endpoints prevents brute force
- Parameterized queries eliminate SQL injection risk
- FTP anonymous access should be disabled
- Monitor auth.log for SSH logins from web service accounts
- Restrict FTP access to authenticated users only
