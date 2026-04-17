# THM Block
**Platform:** TryHackMe | **Category:** Network Forensics / Credential Analysis | **Difficulty:** Medium

## Scenario
Two recently fired employees retained active credentials and used them 
to access private files on a company server. Investigate using a network 
capture (pcap) and LSASS memory dump to identify the users, recover 
credentials, and retrieve accessed files.

## Tools Used
- Wireshark (network traffic analysis + SMB3 decryption)
- pypykatz (LSASS memory dump credential extraction)
- Hashcat (NTLM hash cracking)
- Python script (SMB3 session key derivation)

## Investigation Findings

### User Identification
Filtered Wireshark for successful SMB2 NEGOTIATE handshakes using:

`smb2.cmd == 0x01`

Two users identified with successful connections:
- **User 1:** `mrealman`
- **User 2:** `eshelltsrop`

### Credential Recovery: User 1
LSASS dump parsed using pypykatz to extract NT hashes:

`pypykatz lsa minidump lsass.DMP`

**mrealman NT hash cracked via Hashcat:**  
**Password:** `Blockbuster1`

### SMB3 Traffic Decryption: User 1
SMB3 traffic is encrypted by default. Session key derived using a 
Python script requiring SessionID, NT hash, and NTProofString from 
Wireshark. Session key loaded into Wireshark via:

`Edit → Preferences → Protocols → SMB2 → Session Key`

SessionID extracted from Wireshark in little-endian hex and reversed 
to big-endian before input. Decrypted SMB objects exported via 
`File → Export Objects → SMB`.

**File accessed:** `clients156.csv`  
**Flag:** `THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}`

### Credential Recovery: User 2
**eshelltsrop NT hash:** `3f29138a04aadc19214e9c04028bf381`  
Hash was not crackable — Python script modified to accept raw NT hash 
instead of plaintext password for session key derivation.

### SMB3 Traffic Decryption: User 2
Same decryption process applied using NT hash directly. Decrypted 
SMB objects exported successfully.

**Flag:** `THM{No_PasSw0Rd?_No_Pr0bl3m}`

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Valid Accounts | T1078 |
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Network Sniffing | T1040 |
| Brute Force: Password Cracking (NTLM) | T1110.002 |
| Data from Network Shared Drive | T1039 |

## Defensive Takeaways
- Offboard employees immediately; retained credentials are a 
  significant insider threat vector
- LSASS memory should be protected via Credential Guard to 
  prevent hash extraction
- SMB3 encryption does not prevent forensic analysis when 
  LSASS dumps are available; full disk encryption and 
  credential hygiene are both required
- Monitor SMB access from terminated employee accounts via 
  SIEM alerting on EventCode=4624 with known offboarded usernames
- NTLM hashes from LSASS can decrypt SMB3 sessions even without 
  plaintext passwords; highlights risk of hash-based attacks
