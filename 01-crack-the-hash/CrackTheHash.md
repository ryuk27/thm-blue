# Crack the Hash: TryHackMe Writeup

**Room:** [https://tryhackme.com/room/crackthehash](https://tryhackme.com/room/crackthehash)  
**Difficulty:** Easy  
**Category:** Cryptography / Password Cracking

---

## Overview

This room covers hash identification and offline password cracking using Hashcat and online tools. Understanding *how* hashes are cracked directly informs why certain password policies and hashing algorithms matter.

**Primary tool:** [Hashcat](https://hashcat.net/hashcat/)  
**Wordlist:** `/usr/share/wordlists/rockyou.txt`  
**Reference:** [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

---

## Hash Identification

Before cracking, you need to know what you're dealing with. Key identification approaches:

- **Hash length:** MD5 = 32 chars, SHA1 = 40, SHA256 = 64, SHA512 = 128
- **Prefix clues:** `$2y$` or `$2a$` = bcrypt; `$6$` = sha512crypt (Linux shadow); `$1$` = md5crypt
- **Tools:** `hashid`, `hash-identifier`, or [hashes.com](https://hashes.com/en/tools/hash_identifier)
- **Hashcat's example hashes page** is the most reliable reference when tools disagree

---

## Level 1

### 1. `48bb6e862e54f2a795ffc4e541caed4d`

**Identification:** 32-character hex string → MD5 (Hashcat mode `-m 0`)

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --show
```

**Result:** `easy`

**Note:** MD5 is cryptographically broken and should never be used for password storage. No salt, no computational cost, cracked instantly.

---

### 2. `CBFDAC6008F9CAB4083784CBD1874F76618D2A97`

**Identification:** 40-character hex string → SHA1 (Hashcat mode `-m 100`)

SHA1 produces a 160-bit (40 hex character) digest. Confirmed using `hashid`.

```bash
hashcat -m 100 hash.txt /usr/share/wordlists/rockyou.txt --show
```

**Result:** `password123`

**Note:** SHA1 has been deprecated by NIST since 2011 and is collision-vulnerable. Like MD5, it lacks salting and computational cost, making it trivial to crack against a wordlist.

---

### 3. `1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032`

**Identification:** 64-character hex string → SHA256 (Hashcat mode `-m 1400`)

```bash
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt --show
```

**Result:** `letmein`

**Note:** SHA256 is cryptographically strong, but using it *unsalted* for passwords is still a bad practice — identical passwords produce identical hashes, enabling precomputed rainbow table attacks.

---

### 4. `$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom`

**Identification:** `$2y$` prefix → bcrypt (Hashcat mode `-m 3200`)

The `12` is the cost factor; bcrypt runs 2^12 = 4096 iterations per attempt, making it orders of magnitude slower to crack than MD5 or SHA-family hashes.

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `bleh`

**Note:** bcrypt is a purpose-built password hashing algorithm. Even with a weak password like "bleh", the high cost factor makes mass cracking impractical. This is why bcrypt (and Argon2, scrypt) are the recommended standards for password storage.

---

### 5. `279412f945939ba78ce0758d3fd83daa`

**Identification:** 32-character hex string — looks like MD5, but hashid returns MD4 (Hashcat mode `-m 900`)

```bash
hashcat -m 900 hash.txt /usr/share/wordlists/rockyou.txt
```

Hashcat didn't find a match in rockyou.txt. Fell back to an online lookup tool: [md5decrypt.net/en/Md4](https://md5decrypt.net/en/Md4/)

**Result:** `Eternity22`

**Note:** MD4 is largely obsolete but still appears in Windows NTLM authentication (NT hashes are MD4-based). Encountering MD4 in the wild is a signal of legacy systems or Windows credential dumps.

---

## Level 2

This level introduces less common algorithms and salted hashes. All answers are in rockyou.txt, but online tools alone won't cut it here.

---

### 1. `F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85`

**Identification:** 64-character hex string → SHA256 (Hashcat mode `-m 1400`)

Same length as Task 1 Q3, same identification approach.

```bash
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `paule`

---

### 2. `1DFECA0C002AE40B8619ECF94819CC1B`

**Identification:** 32-character hex string → NTLM (Hashcat mode `-m 1000`)

Despite looking like MD5 at first glance (same length), this is an NTLM hash. NTLM hashes are MD4-based and used extensively in Windows environments. This distinction matters — treating an NTLM hash as MD5 will give you no results.

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `n63umy8lkf4i`

---

### 3. `$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.`  
**Salt:** `aReallyHardSalt`

**Identification:** `$6$` prefix → sha512crypt, the default Linux shadow password format (Hashcat mode `-m 1800`)

This is a salted hash, so the hash file format must include the full string including the salt (already embedded in the hash).

```bash
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `waka99`

**Note:** sha512crypt is the default hashing scheme in `/etc/shadow` on modern Linux systems. Unlike raw SHA512, it includes a salt and multiple rounds, significantly increasing cracking difficulty.

---

### 4. `e5d8870e5bdd26602cab8dbe07a942c8669e56d6`  
**Salt:** `tryhackme`

**Identification:** 40-character hex + a separate salt → HMAC-SHA1 (Hashcat mode `-m 160`)

This looks like a plain SHA1 hash at first glance (Task 1 Q2 was the same length), but the presence of a separate salt and the room context indicate HMAC-SHA1. HMAC uses the salt as a key in the hashing process, not just appended to the input.

For salted hashes in Hashcat, the format in the hash file must be `hash:salt`:

```bash
echo "e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme" > hash.txt
hashcat -m 160 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `481616481616`

---

## Defensive Takeaways

| Algorithm | Status | Where You'll See It |
|-----------|--------|---------------------|
| MD5 | Broken — never use for passwords | Legacy web apps, file integrity checks |
| SHA1 | Deprecated — collision-vulnerable | Old certificate chains, Git commits |
| SHA256/SHA512 (unsalted) | Strong algo, wrong use case | Misconfigured apps |
| MD4/NTLM | Obsolete — Windows legacy | Active Directory, Windows credential dumps |
| bcrypt | Recommended | Modern web apps, password managers |
| sha512crypt | Recommended | Linux `/etc/shadow` |
