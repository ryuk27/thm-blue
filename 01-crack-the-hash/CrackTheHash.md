# THM — Crack the Hash
**Platform:** TryHackMe | **Category:** Cryptography / Password Cracking | **Difficulty:** Easy

## Tools Used
- Hashcat
- Wordlist: rockyou.txt
- md5decrypt.net (fallback for MD4)

## Objective
Identify and crack hashes across two difficulty levels using offline 
cracking and online lookup tools. Understanding cracking mechanics 
directly informs why password storage policies matter.

## Hash Identification Methodology
Before cracking, algorithm identification was performed using:
- Hash length (MD5=32, SHA1=40, SHA256=64, SHA512=128)
- Prefix patterns ($2y$ = bcrypt, $6$ = sha512crypt, $1$ = md5crypt)
- hashid tool + Hashcat example hashes page as ground truth when tools disagreed

## Key Findings

| Hash | Algorithm | Hashcat Mode | Result |
|------|-----------|-------------|--------|
| 48bb6e... | MD5 | -m 0 | easy |
| CBFDAC... | SHA1 | -m 100 | password123 |
| 1C8BFE... | SHA256 | -m 1400 | letmein |
| $2y$12$... | bcrypt | -m 3200 | bleh |
| 279412... | MD4 | -m 900 | Eternity22 |
| F09EDC... | SHA256 | -m 1400 | paule |
| 1DFECA... | NTLM | -m 1000 | n63umy8lkf4i |
| $6$aReally... | sha512crypt | -m 1800 | waka99 |
| e5d887...:tryhackme | HMAC-SHA1 | -m 160 | 481616481616 |

## Notable Observations
- MD4 (279412...) — visually identical to MD5 at 32 chars but different 
  algorithm. MD4 is the basis of Windows NTLM authentication — encountering 
  it in the wild signals legacy systems or Windows credential dumps
- NTLM (1DFECA...) — same length as MD5, wrong mode gives zero results. 
  Critical distinction for Windows AD environments
- bcrypt ($2y$12$) — cost factor of 12 means 4096 iterations per attempt, 
  making mass cracking impractical even with weak passwords
- HMAC-SHA1 — salt must be appended as hash:salt format in Hashcat, 
  not treated as plain SHA1

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| OS Credential Dumping: NTLM | T1003.002 |
| Brute Force: Password Cracking | T1110.002 |

## Defensive Takeaways
- Never use MD5, SHA1, or unsalted SHA256 for password storage
- bcrypt, Argon2, or scrypt are the current recommended standards
- NTLM hashes in Windows environments are high-value targets — 
  enforce strong passwords and consider disabling NTLMv1
- sha512crypt is the Linux /etc/shadow default — adequate when 
  combined with strong passwords
