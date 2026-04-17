## Scripts Used

### Script 1: Session Key Derivation (Password-based)
Used for User 1 (mrealman) where plaintext password was recoverable.
Takes username, domain, password, NTProofStr, and Encrypted Session Key 
from Wireshark to derive the Random Session Key for SMB3 decryption.

```python
import hashlib
import hmac
import argparse
from Cryptodome.Cipher import ARC4

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    return cipher.encrypt(exportedSessionKey)

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--user", required=True)
parser.add_argument("-d", "--domain", required=True)
parser.add_argument("-p", "--password", required=True)
parser.add_argument("-n", "--ntproofstr", required=True)
parser.add_argument("-k", "--key", required=True)
args = parser.parse_args()

user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')
passw = args.password.encode('utf-16le')
password = hashlib.new('md4', passw).digest()

h = hmac.new(password, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

NTproofStr = bytes.fromhex(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))
print("Random SK: " + RsessKey.hex())
```

### Script 2: Session Key Derivation (Hash-based)
Used for User 2 (eshelltsrop) where NT hash was uncrackable. 
Modified to accept raw NTLM hash directly instead of plaintext password.

```python
import hashlib
import hmac
import argparse
from Cryptodome.Cipher import ARC4

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    return cipher.encrypt(exportedSessionKey)

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--user", required=True)
parser.add_argument("-d", "--domain", required=True)
parser.add_argument("-n", "--ntproofstr", required=True)
parser.add_argument("-k", "--key", required=True)
parser.add_argument("--ntlmhash", required=True)
args = parser.parse_args()

user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')
password = bytes.fromhex(args.ntlmhash)

h = hmac.new(password, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

NTproofStr = bytes.fromhex(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))
print("Random SK: " + RsessKey.hex())
```
