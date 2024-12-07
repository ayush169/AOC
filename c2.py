#!/usr/bin/python3
from pwn import *
from struct import pack

# HiPerConTracer packet elements
MAGIC = 0x320DF570
TTL = 179
ROUND = 217
SEQ = 61225

# Encrypted data
enc1 = bytes.fromhex(
    "6d0f7fd16b2d0147c24de857e00ad1374963e1fbde9889386cb12f881101c33e1bab31f3"
)
enc2 = bytes.fromhex(
    "4f21e72256422ed61d1619eeed35518dbab07ed6b1cc3128fae51a004fb07aaf081574f1"
)
secret = b"k8sntSoh7jhsc6lwspj"


def try_decrypt(data, key, description):
    print(f"\n{description}:")
    result = b""
    for i in range(len(data)):
        result += bytes([data[i] ^ key[i % len(key)]])
    print("Result:", result)
    try:
        print("As string:", result.decode("utf-8", errors="ignore"))
    except:
        pass


# 1. Try with HiPerConTracer header
header = pack(">IIII", MAGIC, TTL, ROUND, SEQ)
try_decrypt(enc1, header, "Using HiPerConTracer header")

# 2. Try with magic + secret
combined = pack(">I", MAGIC) + secret
try_decrypt(enc1, combined, "Using Magic + Secret")

# 3. Try with sequence based approach
seq_secret = pack(">I", SEQ) + secret
try_decrypt(enc1, seq_secret, "Using Sequence + Secret")

# 4. Try just magic and TTL
magic_ttl = pack(">IB", MAGIC, TTL)
try_decrypt(enc1, magic_ttl, "Using Magic + TTL")

# 5. Try magic + round + sequence
magic_round_seq = pack(">III", MAGIC, ROUND, SEQ)
try_decrypt(enc1, magic_round_seq, "Using Magic + Round + Sequence")
