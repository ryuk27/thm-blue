# THM Directory
**Platform:** TryHackMe | **Category:** Network Forensics / Active Directory Attack Analysis | **Difficulty:** Hard

## Scenario
A small music company was hit by a threat actor. Only a Wireshark 
capture was available for analysis — no SIEM, no endpoint artifacts. 
Reconstruct the full attack chain from network traffic alone.

## Tools Used
- Wireshark (traffic inspection)
- TShark (command-line packet analysis)
- Hashcat (Kerberos AS-REP hash cracking)
- decrypt-winrm (WinRM traffic decryption)
- John the Ripper / krbpa2john (Kerberos hash extraction)

## Investigation Findings

### Phase 1: Port Scan Detection
Initial traffic analysis revealed SYN requests followed by RST-ACK 
responses; classic signature of a TCP port scan. First 3610 packets 
were scan-related. TShark filtered for SYN-ACK responses (open port 
indicators) within this range to identify responsive services:

```bash
tshark -r traffic.pcap -c 3610 -T fields -e tcp.srcport \
-Y "tcp.flags.syn == 1 && tcp.flags.ack == 1" | sort -n | uniq | paste -sd ','
```

`-c 3610` limits processing to scan packets only. SYN-ACK responses 
indicate the server accepted the connection — confirming open ports.

**Open ports identified:**
`53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5357`

Port 88 (Kerberos) and 389/636 (LDAP/LDAPS) confirm this is an 
Active Directory environment; high-value target for credential attacks.

### Phase 2: Kerberos Username Enumeration
Post-scan traffic shifted to Kerberos (KRB5) starting at packet 4667. 
Multiple AS-REQ attempts returned `UNKNOWN_PRINCIPAL` errors, 
indicating username enumeration via Kerberos pre-authentication probing.

Errors ceased after packet 4785. Packet 4817 showed a successful 
AS-REQ with no error, confirming valid username discovery.

TShark extracted the authenticated principal:

```bash
tshark -r traffic.pcap -Y "kerberos" -T fields \
-e kerberos.CNameString -e kerberos.crealm | awk 'NF==2 {print $2 "\\" $1}'
```

`kerberos.CNameString` is the client principal name field in Kerberos 
packets. Filtering for entries with both username and realm (NF==2) 
isolates successful authentications from failed probes.

**Valid username:** `directory.thm\larry.doe`

### Phase 3: AS-REP Roasting
Kerberos AS-REP Roasting exploits accounts with pre-authentication 
disabled, the KDC returns an encrypted ticket without verifying the 
requester's identity first, allowing offline cracking.

Kerberos cipher extracted from the successful AS-REP (packet 4817) 
and reconstructed into Hashcat format:

```bash
tshark -r traffic.pcap -Y "frame.number==4817" -T fields \
-e kerberos.cipher -e kerberos.CNameString -e kerberos.crealm | \
awk -F'\t' '{split($1,a,","); print "$krb5asrep$23$"$2"@"$3":"a[2]}' | \
awk -F':' '{prefix_len=length($1) + 33; print substr($0, 1, prefix_len) "$" substr($0, prefix_len+1)}'
```

The `$krb5asrep$23$` prefix identifies this as a Kerberos 5 etype 23 
AS-REP hash, the format Hashcat mode 18200 expects. The cipher is 
split into checksum and encrypted blob, separated by `$`.

**Last 30 characters of hash:** `55616532b664cd0b50cda8d4ba469f`

Cracked using rockyou.txt:

```bash
hashcat -a0 -m18200 directory.hash /usr/share/wordlists/rockyou.txt
```

**Password:** `Password1!`

### Phase 4: Remote Command Execution via WinRM
Post-authentication traffic appeared on port 5985 (WinRM — Windows 
Remote Management), indicating the attacker used recovered credentials 
to execute commands remotely. WinRM traffic is encrypted by default 
using NTLM/Negotiate, but decryptable when the plaintext password 
is known.

Decrypted using decrypt-winrm tool with recovered password:

```bash
python3 decrypt_winrm.py -p 'Password1!' traffic.pcap > decrypted_traffic.txt
```

WinRM commands are base64-encoded inside XML `<rsp:Arguments>` tags. 
Extracted and decoded:

```bash
grep -oP '(?<=<rsp:Arguments>).*?(?=</rsp:Arguments>)' decrypted_traffic.txt > encoded_arguments.txt

while read line; do
  echo "$line" | base64 --decode >> arguments.txt
  echo "" >> arguments.txt
done < encoded_arguments.txt

grep -a '<S N="V">' arguments.txt | awk -F'[<>]' '{print $3}'
```

**Commands 2 and 3 executed by attacker:**
```
reg save HKLM\SYSTEM C:\SYSTEM
reg save HKLM\SAM C:\SAM
```

`reg save HKLM\SAM` dumps the Security Account Manager database 
containing local password hashes. Combined with SYSTEM hive (which 
holds the boot key needed to decrypt SAM), this gives the attacker 
all local credentials offline — a classic credential harvesting 
technique post-foothold.

**Flag:** `THM{Ya_G0t_R0aSt3d!}`

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Network Service Scanning | T1046 |
| Kerberoasting / AS-REP Roasting | T1558.004 |
| Brute Force: Password Cracking | T1110.002 |
| Remote Services: Windows Remote Management | T1021.006 |
| OS Credential Dumping: SAM | T1003.002 |
| Credential Access: Valid Accounts | T1078 |

## Defensive Takeaways
- Enforce Kerberos pre-authentication on all accounts, disabling 
  it enables AS-REP Roasting without any credential required
- Monitor for high-volume AS-REQ failures in a short timeframe, 
  strong indicator of Kerberos username enumeration
- Port 5985 (WinRM) activity from non-admin accounts should 
  trigger immediate SIEM alerting
- reg save HKLM\SAM and HKLM\SYSTEM executed together is a 
  high-confidence credential dumping indicator, alert on this 
  command combination
- Weak passwords (Password1!) remain the primary enabler of 
  AS-REP Roasting success — enforce strong password policies 
  and monitor for accounts with pre-auth disabled via AD auditing
