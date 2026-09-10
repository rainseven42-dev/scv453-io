#!/usr/bin/env python3
"""Decode EtherHiding dead-drop resolver payloads (selector 0x3bc5de30).
Mirrors the malware's JS loader exactly: static crypto, no PHP execution.
ABI layout: word0=offset(0x20), word1=len, data=r
  r[63]        = keylen (y)
  f=data[64:64+y] = keylen bytes:
       f[0] = w (xorkey len)
       f[1:1+w]  = xor key i
       f[1+w:]   = O (ciphertext)
  x = XOR(O, i)
  x[0] = E (enc key len), x[1:1+E] = U (enc key for /w channel), x[1+E:] = plaintext
"""
import json, re, sys

CONTRACTS = [
    "0x9A4752cAA1C15868487A0ACb691F81bfA901E063",
    "0x839d1cE5c3F259e8d3D17114d7186EDabdbeA94b",
    "0x6d2c5435EF70196740a48904B69377935D50abBB",
]

# ETH RPC endpoint — replace with your preferred public node
RPC = "https://ethereum-rpc.publicnode.com"


def call(contract):
    data = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "eth_call",
                       "params": [{"data": "0x3bc5de30", "to": contract}, "latest"]}).encode()
    # Use YOUR proxy for privacy. Without proxy: remove -x flag
    r = subprocess.run(["curl", "-s", "--max-time", "20",
                        "-X", "POST", "-H", "Content-Type: application/json",
                        "--data", data, RPC], capture_output=True)
    return json.loads(r.stdout)["result"][2:]

def xor(b, k):
    return bytes(x ^ k[i % len(k)] for i, x in enumerate(b))


for c in CONTRACTS:
    try:
        raw = bytes.fromhex(call(c))
    except Exception as e:
        print(f"=== {c} FETCH FAIL: {e} ===")
        continue
    data = raw                           # JS uses FULL result bytes (incl. ABI head)
    y = data[63]                         # keylen = last byte of ABI length word
    f = data[64:64 + y]
    if len(f) < 3:
        print(f"=== {c}: payload too short ==="); continue
    w = f[0]
    i = f[1:1 + w]                       # xor key
    O = f[1 + w:]                        # ciphertext
    x = xor(O, i)
    if not x:
        print(f"=== {c}: empty after XOR ==="); continue
    E = x[0]
    U = x[1:1 + E]                       # enc key (used for /w exfil channel)
    pt = x[1 + E:]                       # plaintext = C2 URL list
    print(f"=== {c} ===")
    print(f"keylen={y} xorkeylen={w} encKey({E}B)={U.hex()}")
    urls = pt.decode("utf-8", "replace").splitlines()
    for u in urls:
        if u.strip():
            print("  C2:", u.strip())
    print()
