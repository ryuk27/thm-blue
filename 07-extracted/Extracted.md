# THM Extracted
**Platform:** TryHackMe | **Category:** Network Forensics / DFIR | **Difficulty:** Medium

## Scenario
Suspicious traffic generated from a workstation was captured via network 
device after SIEM ingestion failed. Analyze the pcap to identify the 
exfiltrated data, recover encoded payloads, and extract credentials from 
a KeePass database.

## Tools Used
- Wireshark / TShark (traffic analysis + payload extraction)
- Python (custom XOR + base64 decryption scripts)
- keepass_dump (KeePass memory analysis)
- John the Ripper (KeePass hash cracking)
- kpcli (KeePass database access)

## Investigation Findings

### Suspicious Traffic Identification
Unusual HTTP traffic observed on non-standard port **1337** in 
traffic.pcapng — immediate indicator of covert C2 or data exfiltration channel.

### Payload Extraction
TShark used to filter and extract HTTP payload from port 1337:

```bash
tshark -r traffic.pcapng -T fields -Y 'tcp.dstport == 1337 and frame.len > 100' -e data.data | xxd -ps -r > 539.dmp
```

### Layer 1 Decryption Base64 + XOR key 'A'
Extracted payload was base64-encoded and XOR'd with key `A`. 
Custom Python script written to reverse both transformations:

```python
import base64

with open('539.dmp', 'r') as file:
    encoded_data = file.read()

binary_data = base64.b64decode(encoded_data)
xor_key = b'A'
decrypted_data = bytearray(len(binary_data))

for i in range(len(binary_data)):
    decrypted_data[i] = binary_data[i] ^ xor_key[i % len(xor_key)]

with open('1337.dmp', 'wb') as file:
    file.write(decrypted_data)
```

### Layer 2 Decryption Base64 + XOR key 'B'
Output contained a second base64-encoded layer XOR'd with key `B` — 
decrypted to reveal a KeePass database file:

```python
import base64

with open('Database1337', 'r') as file:
    encoded_data = file.read()

binary_data = base64.b64decode(encoded_data)
xor_key = b'B'
decrypted_data = bytearray(len(binary_data))

for i in range(len(binary_data)):
    decrypted_data[i] = binary_data[i] ^ xor_key[i % len(xor_key)]

with open('Database1337.kdbx', 'wb') as file:
    file.write(decrypted_data)
```

### KeePass Credential Recovery
keepass_dump used to extract partial password from memory dump:

```bash
python3 keepass_dump.py -f ../1337.dmp --skip --debug
```

**Partial password recovered:** `NoWaYIcanF0rGetThis123`  
Missing first character identified via brute-force wordlist:

```python
l = '!"#$%&\'()+,-./0123456789:;?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}~'
w = 'NoWaYIcanF0rGetThis123'
for char in l:
    print(char + w)
```

```bash
keepass2john Database1337.kdbx > hash.txt
john hash.txt --wordlist=passlist.txt
```

### Flag Retrieval
KeePass database accessed via kpcli using recovered password.  
Flag retrieved from database entry.

**Flag:** `THM{B3tt3r_Upd4t3_Y0ur_K33p455}`

## MITRE ATT&CK Mapping
| Technique | ID |
|---|---|
| Exfiltration Over Non-Standard Port | T1048.003 |
| Obfuscated Files: XOR Encoding | T1027.001 |
| Credentials from Password Stores | T1555 |
| Data Encoding: Standard Encoding (Base64) | T1132.001 |

## Defensive Takeaways
- Non-standard port traffic (e.g. port 1337) should trigger 
  immediate SIEM alerting — legitimate applications rarely use 
  such ports for outbound connections
- Layered encoding (XOR + base64) is a common evasion technique — 
  content inspection beyond protocol headers is essential
- KeePass memory dumps can expose partial credentials — 
  endpoint memory protection and process isolation matter
- Password managers should use strong master passwords not 
  susceptible to partial recovery via memory analysis
